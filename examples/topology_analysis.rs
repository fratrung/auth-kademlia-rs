//! Topology test for AuthKademlia-RS.
//!
//! Launches NUM_NODES nodes and exercises:
//!   - Phase 1: publish NUM_RECORDS authenticated DID records from rotating writers
//!   - Phase 2: retrieve every record from a node offset by half the cluster size
//!     (forces a real multi-hop DHT lookup, not a local cache hit)
//!
//! Diagnostic output:
//!   1. SET/GET latency and local-vs-remote GET paths
//!   2. Replication count and global XOR-placement summaries
//!   3. Exact local FIND_NODE top-k verification
//!   4. Bucket partition invariants and routing convergence
//!   5. A final PASS/WARN/FAIL table whose failures affect the exit status
//!
//! Pass `--verbose` to include DID Documents, per-key storage placement,
//! full bucket contents, and flat routing tables.
//!
//! Run:
//!   cargo run --release --example topology_analysis                # k=20 alpha=3
//!   cargo run --release --example topology_analysis -- 3 3         # k=3  alpha=3
//!   cargo run --release --example topology_analysis -- 5 2         # k=5  alpha=2
//!   cargo run --release --example topology_analysis -- 3 3 --verbose
//!   RUST_LOG=info cargo run --release --example topology_analysis -- 3

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::did::{
    canonical_bytes, derive_did, key_of_did, DID_PREFIX, PLACEHOLDER,
};
use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::{digest_bytes, ID_LEN};
use primitive_types::U256;

use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use tokio::time::timeout;

const BASE_PORT: u16 = 15810;
const NUM_NODES: usize = 30;
const NUM_RECORDS: usize = 100;
const OP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Default)]
struct ReplicationReport {
    records: usize,
    zero_copies: usize,
    under_replicated: usize,
    exact_replicas: usize,
    over_replicated: usize,
    min_copies: usize,
    max_copies: usize,
}

#[derive(Debug, Default)]
struct PlacementReport {
    records: usize,
    full: usize,
    partial: usize,
    none: usize,
    with_extras: usize,
}

#[derive(Debug, Default)]
struct LocalTopKReport {
    queries: usize,
    mismatches: usize,
}

#[derive(Debug, Default)]
struct BucketReport {
    nodes: usize,
    buckets: usize,
    peers: usize,
    violations: usize,
    converged: bool,
}

// ─── record helpers ──────────────────────────────────────────────────────────

fn base64url(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// The DHT key of a DID made by `new_record`: its suffix, decoded.
fn dht_key(did: &str) -> [u8; ID_LEN] {
    key_of_did(did).expect("a DID made by new_record")
}

/// The first characters of a DID's suffix, to tell records apart in the output.
fn short(did: &str) -> &str {
    did.get(DID_PREFIX.len()..DID_PREFIX.len() + 8)
        .unwrap_or(did)
}

fn build_signed_record(doc: &Value, sk: &MlDsa65KeyPair) -> Vec<u8> {
    let doc_bytes = canonical_bytes(doc).expect("a DID Document in canonical form");
    let mut alg = [0u8; 12];
    alg[..9].copy_from_slice(b"ML-DSA-65");
    let sig = sk.sign(&doc_bytes).expect("ML-DSA-65 signing");
    let sig_bytes = sig.as_slice();
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

/// The draft of version 0 of a new DID (ADR 0005): its own DID written as
/// the placeholder, no `id`, and the hash of the next public key.
fn build_version_zero_draft(signing_pk: &[u8], next_pk: &[u8]) -> Value {
    let did = PLACEHOLDER;
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65", "pub": base64url(signing_pk) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "service": [{ "id": format!("{}#device", did), "type": "DeviceAgent",
                      "serviceEndpoint": "http://example.com/device" }],
        "seq": 0,
        "nextKeyHash": base64url(&digest_bytes(next_pk)),
    })
}

/// Returns (did_uri, key, record_bytes) for version 0 of a new DID; the key
/// that `set` and `get` take is the DID itself.
fn new_record() -> (String, String, Vec<u8>) {
    let dsk = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
    let dpk = dsk.public_key().to_vec();
    let next = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
    let draft = build_version_zero_draft(&dpk, next.public_key());
    let (did, doc) = derive_did(&draft).expect("version 0 gives its DID");
    let record = build_signed_record(&doc, &dsk);
    (did.clone(), did, record)
}

/// Extract the DID Document JSON from a raw wire record (skip alg + sig header).
fn extract_doc(record: &[u8]) -> Option<serde_json::Value> {
    const SIG_LEN: usize = 3309; // ML-DSA-65
    let doc_start = 12 + SIG_LEN;
    if record.len() <= doc_start {
        return None;
    }
    serde_json::from_slice(&record[doc_start..]).ok()
}

async fn start_node(port: u16, ksize: usize, alpha: usize) -> Arc<Server> {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));
    let mut server = Server::new(handler, ksize, alpha, None, None, true);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    Arc::new(server)
}

// ─── diagnostic sections ─────────────────────────────────────────────────────

/// Print a few full DID Documents so the record structure is visible.
fn print_sample_docs(published: &[(String, String, Vec<u8>)]) {
    println!("━━━ Sample DID Documents ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    for (did, key_str, record) in published.iter().take(3) {
        let dkey_hex = hex::encode(dht_key(key_str));
        println!("  DID URI : {did}");
        println!("  DHT key : {dkey_hex}");
        match extract_doc(record) {
            Some(doc) => {
                for line in serde_json::to_string_pretty(&doc)
                    .unwrap_or_default()
                    .lines()
                {
                    println!("  {line}");
                }
            }
            None => println!("  (could not parse DID Document)"),
        }
        println!();
    }
}

/// Collect the physical record layout. Detailed per-node output is opt-in
/// because the full 30-node table is intentionally very large.
fn collect_storage_layout(
    nodes: &[(Arc<Server>, u16)],
    key_to_did: &HashMap<String, String>,
    verbose: bool,
) -> HashMap<String, Vec<u16>> {
    if verbose {
        println!("━━━ Storage Tables (records per node) ━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    let mut key_holders: HashMap<String, Vec<u16>> = HashMap::new();

    for (server, port) in nodes {
        let entries = server.storage.iter_all();
        let mut keys: Vec<String> = entries.iter().map(|(k, _)| hex::encode(k)).collect();
        keys.sort_unstable();

        if verbose {
            println!("  Node :{port}  ({} records)", keys.len());
            if keys.is_empty() {
                println!("    (empty)");
            }
        }

        for key in keys {
            if verbose {
                let did_hint = key_to_did
                    .get(&key)
                    .map(|did| format!("  →  {}", &did[..did.len().min(50)]))
                    .unwrap_or_default();
                println!("    {key}{did_hint}");
            }
            key_holders.entry(key).or_default().push(*port);
        }

        if verbose {
            println!();
        }
    }

    key_holders
}

/// Summarise the physical replica count for every successfully published key.
fn print_replication_summary(
    key_holders: &HashMap<String, Vec<u16>>,
    expected_keys: &[String],
    ksize: usize,
    verbose: bool,
) -> ReplicationReport {
    println!("━━━ Replication Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut keys = expected_keys.to_vec();
    keys.sort_unstable();

    if verbose {
        println!("  {:>40}  copies  holders", "DHT key (hex)");
        println!("  {}  ------  -------", "-".repeat(40));
    }

    let mut report = ReplicationReport {
        records: keys.len(),
        min_copies: usize::MAX,
        ..ReplicationReport::default()
    };
    let mut distribution: HashMap<usize, usize> = HashMap::new();

    for key in &keys {
        let holders = key_holders.get(key).map(Vec::as_slice).unwrap_or(&[]);
        let copies = holders.len();
        report.min_copies = report.min_copies.min(copies);
        report.max_copies = report.max_copies.max(copies);
        *distribution.entry(copies).or_insert(0) += 1;

        match copies.cmp(&ksize) {
            std::cmp::Ordering::Less => {
                report.under_replicated += 1;
                if copies == 0 {
                    report.zero_copies += 1;
                }
            }
            std::cmp::Ordering::Equal => report.exact_replicas += 1,
            std::cmp::Ordering::Greater => report.over_replicated += 1,
        }

        if verbose {
            let ports = holders
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {key}  {copies:>6}  {ports}");
        }
    }

    if report.records == 0 {
        report.min_copies = 0;
    }

    let mut distribution = distribution.into_iter().collect::<Vec<_>>();
    distribution.sort_unstable_by_key(|(copies, _)| *copies);
    println!("  Records inspected     : {}", report.records);
    println!(
        "  Replica target        : k={ksize} (extra retained copies may exist after topology changes)"
    );
    println!(
        "  Replica count range   : {}..={}",
        report.min_copies, report.max_copies
    );
    println!(
        "  Below / exact / above : {} / {} / {}",
        report.under_replicated, report.exact_replicas, report.over_replicated
    );
    println!("  Copy-count distribution:");
    for (copies, count) in distribution {
        println!(
            "    {copies} cop{}: {count} record{}",
            if copies == 1 { "y" } else { "ies" },
            if count == 1 { "" } else { "s" }
        );
    }
    println!();

    report
}

/// Compare physical replica placement with the globally closest nodes.
///
/// This is an end-to-end placement check. It deliberately does not call GET,
/// so what a read returns cannot change its result.
fn verify_global_replica_placement(
    nodes: &[(Arc<Server>, u16)],
    published: &[(String, String, Vec<u8>)],
    key_holders: &HashMap<String, Vec<u16>>,
    ksize: usize,
    verbose: bool,
) -> PlacementReport {
    println!("━━━ Global XOR Replica Placement (Kademlia §2.3) ━━━━━━━━━━━━━\n");
    println!("  Compares physical storage with the globally closest nodes.");
    println!("  This check is independent of GET.\n");

    let node_ids = nodes
        .iter()
        .map(|(server, port)| (server.node.id, *port))
        .collect::<Vec<_>>();
    let mut report = PlacementReport {
        records: published.len(),
        ..PlacementReport::default()
    };

    for (_did, key, _) in published {
        let dkey = dht_key(key);
        let target = Node::from_id(dkey);
        let dkey_hex = hex::encode(dkey);
        let holders = key_holders.get(&dkey_hex).map(Vec::as_slice).unwrap_or(&[]);

        let mut by_distance = node_ids
            .iter()
            .map(|(id, port)| (Node::from_id(*id).distance_to(&target), *port))
            .collect::<Vec<_>>();
        by_distance.sort_unstable_by_key(|(distance, _)| *distance);
        let closest = by_distance
            .iter()
            .take(ksize)
            .map(|(_, port)| *port)
            .collect::<Vec<_>>();

        let holding = closest
            .iter()
            .copied()
            .filter(|port| holders.contains(port))
            .collect::<Vec<_>>();
        let missing = closest
            .iter()
            .copied()
            .filter(|port| !holders.contains(port))
            .collect::<Vec<_>>();
        let extras = holders
            .iter()
            .copied()
            .filter(|port| !closest.contains(port))
            .collect::<Vec<_>>();

        if missing.is_empty() {
            report.full += 1;
        } else if holding.is_empty() {
            report.none += 1;
        } else {
            report.partial += 1;
        }
        if !extras.is_empty() {
            report.with_extras += 1;
        }

        if verbose || !missing.is_empty() {
            let status = if missing.is_empty() {
                "PASS"
            } else if holding.is_empty() {
                "FAIL"
            } else {
                "WARN"
            };
            println!(
                "  [{status}] key={}…  closest={closest:?}  holders={holders:?}",
                &dkey_hex[..8]
            );
            if !missing.is_empty() {
                println!("         missing closest nodes: {missing:?}");
            }
            if verbose && !extras.is_empty() {
                println!("         extra holders: {extras:?}");
            }
        }
    }

    println!("\n  Records inspected          : {}", report.records);
    println!("  All k closest hold a copy  : {}", report.full);
    println!("  Some k closest hold a copy : {}", report.partial);
    println!("  No k closest holds a copy  : {}", report.none);
    println!("  Records with extra holders : {}", report.with_extras);
    println!();

    report
}

/// Validate the bucket partition and optionally print the complete tree.
///
/// Hard invariants: inclusive ranges cover the 256-bit keyspace without gaps
/// or overlaps, every primary contact belongs to its bucket, no contact is
/// duplicated, and no bucket exceeds k primary contacts.
async fn inspect_bucket_structure(
    nodes: &[(Arc<Server>, u16)],
    ksize: usize,
    verbose: bool,
) -> BucketReport {
    println!("━━━ Bucket Partition and Convergence ━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    if verbose {
        println!("  Ranges are inclusive 256-bit bounds: [lo..=hi].\n");
    }

    let keyspace_max = U256::MAX;
    let mut report = BucketReport::default();

    for (server, port) in nodes {
        let proto = match &server.protocol {
            Some(protocol) => protocol,
            None => {
                report.violations += 1;
                println!("  [FAIL] Node :{port} is not started");
                continue;
            }
        };

        report.nodes += 1;
        let router = proto.router.read().await;
        let buckets = router.buckets();
        let peer_count = buckets.iter().map(|bucket| bucket.len()).sum::<usize>();
        report.buckets += buckets.len();
        report.peers += peer_count;

        if verbose {
            println!(
                "  Node :{port}  id={}…  ({} buckets, {} primary peers)",
                hex::encode(&router.node.id[..4]),
                buckets.len(),
                peer_count
            );
        }

        if buckets.is_empty() {
            report.violations += 1;
            println!("  [FAIL] Node :{port} has no buckets");
            continue;
        }

        let mut expected_start = U256::zero();
        let mut seen = HashSet::new();

        for (index, bucket) in buckets.iter().enumerate() {
            let lo = *bucket.range.start();
            let hi = *bucket.range.end();

            if lo != expected_start {
                report.violations += 1;
                println!(
                    "  [FAIL] Node :{port} bucket {index} starts at {lo:064x}, expected {expected_start:064x}"
                );
            }
            if hi < lo {
                report.violations += 1;
                println!(
                    "  [FAIL] Node :{port} bucket {index} has an inverted range [{lo:064x}..={hi:064x}]"
                );
            }
            if bucket.len() > ksize {
                report.violations += 1;
                println!(
                    "  [FAIL] Node :{port} bucket {index} has {} primary contacts, above k={ksize}",
                    bucket.len()
                );
            }

            for peer in bucket.nodes() {
                if !bucket.covers(peer.long_id) {
                    report.violations += 1;
                    println!(
                        "  [FAIL] Node :{port} bucket {index} contains out-of-range peer {}",
                        hex::encode(&peer.id[..8])
                    );
                }
                if peer.id == router.node.id {
                    report.violations += 1;
                    println!("  [FAIL] Node :{port} contains itself in bucket {index}");
                }
                if !seen.insert(peer.id) {
                    report.violations += 1;
                    println!(
                        "  [FAIL] Node :{port} contains duplicate peer {}",
                        hex::encode(&peer.id[..8])
                    );
                }
            }

            if verbose {
                let freshness = if bucket.is_lonely() {
                    "lonely"
                } else {
                    "fresh"
                };
                println!(
                    "    [{index:>2}] primary={:>2} depth={:>3} {freshness:<6} range=[{lo:064x}..={hi:064x}]",
                    bucket.len(),
                    bucket.depth()
                );
                for peer in bucket.nodes() {
                    let peer_port = peer
                        .port
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".into());
                    println!("         ↳ {}…  :{peer_port}", hex::encode(&peer.id[..4]));
                }
            }

            if hi < keyspace_max {
                expected_start = hi + U256::one();
            }
        }

        if *buckets.last().expect("non-empty bucket list").range.end() != keyspace_max {
            report.violations += 1;
            println!("  [FAIL] Node :{port} bucket partition does not end at {keyspace_max:064x}");
        }

        if verbose {
            println!();
        }
    }

    let divisor = report.nodes.max(1) as f64;
    let avg_buckets = report.buckets as f64 / divisor;
    let avg_peers = report.peers as f64 / divisor;
    let expected_buckets = (nodes.len() as f64).log2();
    report.converged = !nodes.is_empty() && avg_buckets >= expected_buckets * 0.7;

    println!("  Nodes inspected       : {}", report.nodes);
    println!("  Buckets inspected     : {}", report.buckets);
    println!(
        "  Partition invariants  : {} ({} violations)",
        if report.violations == 0 {
            "PASS"
        } else {
            "FAIL"
        },
        report.violations
    );
    println!(
        "  Avg buckets / node    : {avg_buckets:.1} (heuristic reference log₂({}) ≈ {expected_buckets:.1})",
        nodes.len()
    );
    println!("  Avg primary peers/node: {avg_peers:.1}");
    println!(
        "  Convergence heuristic : {}",
        if report.converged { "PASS" } else { "WARN" }
    );
    println!();

    report
}

/// Verify the R03 invariant against an exhaustive oracle over each node's
/// actual primary routing contacts.
async fn verify_local_top_k(
    nodes: &[(Arc<Server>, u16)],
    published: &[(String, String, Vec<u8>)],
    ksize: usize,
) -> LocalTopKReport {
    println!("━━━ Local FIND_NODE Top-k Correctness ━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("  Each query is checked against every primary contact known locally.");
    println!("  Global discovery remains the responsibility of the iterative crawl.\n");

    let targets = published
        .iter()
        .map(|(_, key, _)| Node::from_id(dht_key(key)))
        .collect::<Vec<_>>();
    let mut report = LocalTopKReport::default();

    for (server, port) in nodes {
        let Some(proto) = &server.protocol else {
            continue;
        };
        let router = proto.router.read().await;

        for target in &targets {
            let mut expected = router
                .buckets()
                .iter()
                .flat_map(|bucket| bucket.nodes().iter())
                .filter(|peer| peer.id != target.id)
                .cloned()
                .collect::<Vec<_>>();
            expected.sort_unstable_by_key(|peer| peer.distance_to(target));
            expected.truncate(ksize);

            let actual = router.find_neighbors(target, None);
            report.queries += 1;

            let expected_ids = expected.iter().map(|peer| peer.id).collect::<Vec<_>>();
            let actual_ids = actual.iter().map(|peer| peer.id).collect::<Vec<_>>();
            if actual_ids != expected_ids {
                report.mismatches += 1;
                if report.mismatches <= 10 {
                    let expected_ports = expected
                        .iter()
                        .map(|peer| peer.port.unwrap_or_default())
                        .collect::<Vec<_>>();
                    let actual_ports = actual
                        .iter()
                        .map(|peer| peer.port.unwrap_or_default())
                        .collect::<Vec<_>>();
                    println!(
                        "  [FAIL] node=:{port} target={}… expected={expected_ports:?} actual={actual_ports:?}",
                        hex::encode(&target.id[..4])
                    );
                }
            }
        }
    }

    if report.mismatches > 10 {
        println!(
            "  ... {} additional mismatches omitted",
            report.mismatches - 10
        );
    }
    println!("  Queries checked : {}", report.queries);
    println!("  Mismatches      : {}", report.mismatches);
    println!(
        "  Result          : {}\n",
        if report.mismatches == 0 {
            "PASS"
        } else {
            "FAIL"
        }
    );

    report
}

/// Flat peer list per node (reference view).
async fn print_routing_tables(nodes: &[(Arc<Server>, u16)]) {
    println!("━━━ Routing Tables (flat peer list per node) ━━━━━━━━━━━━━━━━━━\n");

    for (server, port) in nodes {
        let proto = match &server.protocol {
            Some(p) => p,
            None => {
                println!("  Node :{port}  (not started)");
                continue;
            }
        };

        let router = proto.router.read().await;
        let mut peers: Vec<_> = router
            .buckets()
            .iter()
            .flat_map(|b| b.nodes().iter().cloned())
            .collect();
        peers.sort_by_key(|n| n.port.unwrap_or(0));

        println!("  Node :{port}  ({} known peers)", peers.len());
        if peers.is_empty() {
            println!("    (no peers)");
        } else {
            println!(
                "    {:>44}  {:>5}  ip",
                "node-id (hex, first 8 bytes)", "port"
            );
            for peer in &peers {
                let id_hex: String = peer.id[..8].iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "    {}  {:>5}  {}",
                    id_hex,
                    peer.port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into()),
                    peer.ip.as_deref().unwrap_or("-"),
                );
            }
        }
        println!();
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn fmt_ns(ns: u64) -> String {
    if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    }
}

fn latency_stats(v: &mut [u64]) -> (f64, u64, u64, u64) {
    v.sort_unstable();
    let avg = if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<u64>() as f64 / v.len() as f64
    };
    let p50 = percentile(v, 50.0);
    let p95 = percentile(v, 95.0);
    let max = *v.last().unwrap_or(&0);
    (avg, p50, p95, max)
}

fn print_check(status: CheckStatus, name: &str, details: &str) {
    println!("  [{:<4}] {:<28} {details}", status.label(), name);
}

fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(run())
}

async fn run() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let verbose = args.iter().any(|arg| arg == "--verbose");
    let positional = args
        .iter()
        .filter(|arg| !arg.starts_with("--"))
        .collect::<Vec<_>>();
    let ksize = positional
        .first()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);
    let alpha = positional
        .get(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);

    if ksize == 0 || alpha == 0 {
        eprintln!("k and alpha must both be greater than zero");
        std::process::exit(2);
    }

    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Topology Test           ║");
    println!("╚══════════════════════════════════════════════╝");
    println!(
        "  Nodes    : {NUM_NODES}  (ports {BASE_PORT}–{})",
        BASE_PORT + NUM_NODES as u16 - 1
    );
    println!("  k (ksize)       : {ksize}  (replica-placement target)");
    println!("  alpha           : {alpha}");
    println!("  Remote GET      : first verified record");
    println!("  Records         : {NUM_RECORDS}");
    println!("  Timeout         : {}s/op", OP_TIMEOUT.as_secs());
    println!(
        "  Output          : {}\n",
        if verbose { "verbose" } else { "summary" }
    );

    print!("Starting {NUM_NODES} nodes... ");
    let mut nodes: Vec<(Arc<Server>, u16)> = Vec::with_capacity(NUM_NODES);
    for i in 0..NUM_NODES {
        let port = BASE_PORT + i as u16;
        nodes.push((start_node(port, ksize, alpha).await, port));
    }
    println!("ok");

    // Two passes: first wires everyone to the seed, second pass lets nodes
    // discover each other's neighbors and fill their routing tables.
    print!("Bootstrapping (2 passes)... ");
    let seed_port = BASE_PORT;
    for (server, _) in nodes.iter().skip(1) {
        server
            .bootstrap(vec![("127.0.0.1".to_string(), seed_port)])
            .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    for (server, _) in nodes.iter().skip(1) {
        server
            .bootstrap(vec![("127.0.0.1".to_string(), seed_port)])
            .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!("ok\n");

    println!("━━━ Phase 1: Publish {NUM_RECORDS} Records ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut published: Vec<(String, String, Vec<u8>)> = Vec::new();
    let mut set_ok = 0usize;
    let mut set_fail = 0usize;
    let mut set_latencies: Vec<u64> = Vec::new();

    for i in 0..NUM_RECORDS {
        let (did, key, record) = new_record();
        let (writer, writer_port) = &nodes[i % NUM_NODES];

        let t0 = Instant::now();
        let result = timeout(OP_TIMEOUT, writer.set(&key, record.clone())).await;
        let ns = t0.elapsed().as_nanos() as u64;

        match result {
            Ok(Some(true)) => {
                set_ok += 1;
                set_latencies.push(ns);
                if verbose {
                    println!(
                        "  [{i:>3}] writer={writer_port}  key={}  did={}…  SET ✓  ({:.1}ms)",
                        short(&key),
                        &did[..32],
                        ns as f64 / 1e6
                    );
                }
                published.push((did, key, record));
            }
            other => {
                set_fail += 1;
                println!(
                    "  [{i:>3}] writer={writer_port}  key={}  SET ✗  {other:?}",
                    short(&key)
                );
            }
        }
    }
    println!("\n  Published: {set_ok}/{NUM_RECORDS}  ({set_fail} failed)\n");

    println!("━━━ Phase 2: Retrieve Records ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("  reader is offset by NUM_NODES/2 from writer — forces a real DHT lookup\n");

    let mut get_ok = 0usize;
    let mut get_fail = 0usize;
    let mut get_corrupt = 0usize;
    let mut local_gets = 0usize;
    let mut remote_gets = 0usize;
    let mut get_latencies: Vec<u64> = Vec::new();

    for (i, (_did, key, original)) in published.iter().enumerate() {
        let reader_idx = (i + NUM_NODES / 2) % NUM_NODES;
        let (reader, reader_port) = &nodes[reader_idx];
        let local_fast_path = reader.storage.get(&dht_key(key)).is_some();
        let path = if local_fast_path {
            local_gets += 1;
            "local-fast-path"
        } else {
            remote_gets += 1;
            "remote"
        };

        let t0 = Instant::now();
        let result = timeout(OP_TIMEOUT, reader.get(key)).await;
        let ns = t0.elapsed().as_nanos() as u64;

        match result {
            Ok(Some(ref retrieved)) => {
                get_latencies.push(ns);
                if retrieved == original {
                    get_ok += 1;
                    if verbose {
                        println!(
                            "  [{i:>3}] reader={reader_port}  key={}  GET ✓  path={path}  ({:.1}ms)",
                            short(key),
                            ns as f64 / 1e6
                        );
                    }
                } else {
                    get_corrupt += 1;
                    println!(
                        "  [{i:>3}] reader={reader_port}  key={}  GET ✗  CORRUPTION  path={path}",
                        short(key)
                    );
                }
            }
            Ok(None) => {
                get_fail += 1;
                println!(
                    "  [{i:>3}] reader={reader_port}  key={}  GET ✗  no verified value  path={path}  ({:.1}ms)",
                    short(key),
                    ns as f64 / 1e6
                );
            }
            Err(_) => {
                get_fail += 1;
                println!(
                    "  [{i:>3}] reader={reader_port}  key={}  GET ✗  timeout  path={path}",
                    short(key)
                );
            }
        }
    }
    println!("\n  Retrieved: {get_ok}/{set_ok}  ({get_fail} unavailable, {get_corrupt} corrupted)");
    println!("  GET paths: {local_gets} local fast path, {remote_gets} remote\n");

    println!("━━━ Latency Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    let (sa, sp50, sp95, smax) = latency_stats(&mut set_latencies);
    let (ga, gp50, gp95, gmax) = latency_stats(&mut get_latencies);
    println!("  ┌───────┬──────────┬──────────┬──────────┬──────────┐");
    println!("  │       │   avg    │   p50    │   p95    │   max    │");
    println!("  ├───────┼──────────┼──────────┼──────────┼──────────┤");
    println!(
        "  │ SET   │ {:>8} │ {:>8} │ {:>8} │ {:>8} │",
        fmt_ns(sa as u64),
        fmt_ns(sp50),
        fmt_ns(sp95),
        fmt_ns(smax)
    );
    println!(
        "  │ GET   │ {:>8} │ {:>8} │ {:>8} │ {:>8} │",
        fmt_ns(ga as u64),
        fmt_ns(gp50),
        fmt_ns(gp95),
        fmt_ns(gmax)
    );
    println!("  └───────┴──────────┴──────────┴──────────┴──────────┘\n");

    let key_to_did: HashMap<String, String> = published
        .iter()
        .map(|(did, key_str, _)| {
            let dht_hex = hex::encode(dht_key(key_str));
            (dht_hex, did.clone())
        })
        .collect();

    if verbose {
        print_sample_docs(&published);
    }

    let expected_keys = key_to_did.keys().cloned().collect::<Vec<_>>();
    let key_holders = collect_storage_layout(&nodes, &key_to_did, verbose);
    let replication = print_replication_summary(&key_holders, &expected_keys, ksize, verbose);
    let placement =
        verify_global_replica_placement(&nodes, &published, &key_holders, ksize, verbose);
    let buckets = inspect_bucket_structure(&nodes, ksize, verbose).await;
    let local_top_k = verify_local_top_k(&nodes, &published, ksize).await;

    if verbose {
        print_routing_tables(&nodes).await;
    }

    let set_status = if set_fail == 0 {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let get_status = if get_fail == 0 && get_corrupt == 0 && get_ok == set_ok {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let replication_status = if replication.zero_copies > 0 {
        CheckStatus::Fail
    } else if replication.under_replicated > 0 || replication.over_replicated > 0 {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    let placement_status = if placement.none > 0 {
        CheckStatus::Fail
    } else if placement.partial > 0 || placement.with_extras > 0 {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    let bucket_status = if buckets.violations == 0 {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let local_top_k_status = if local_top_k.mismatches == 0 {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let convergence_status = if buckets.converged {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };

    println!("━━━ Final Diagnostic Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    print_check(
        set_status,
        "SET completion",
        &format!("{set_ok}/{NUM_RECORDS} complete"),
    );
    print_check(
        get_status,
        "GET retrieval",
        &format!("{get_ok}/{set_ok} verified; paths local={local_gets}, remote={remote_gets}"),
    );
    print_check(
        replication_status,
        "Replica counts",
        &format!(
            "below/exact/above k = {}/{}/{}",
            replication.under_replicated, replication.exact_replicas, replication.over_replicated
        ),
    );
    print_check(
        placement_status,
        "Global XOR placement",
        &format!(
            "full/partial/none = {}/{}/{}; extras={}",
            placement.full, placement.partial, placement.none, placement.with_extras
        ),
    );
    print_check(
        bucket_status,
        "Bucket partition",
        &format!(
            "{} buckets across {} nodes; violations={}",
            buckets.buckets, buckets.nodes, buckets.violations
        ),
    );
    print_check(
        local_top_k_status,
        "Local FIND_NODE top-k",
        &format!(
            "{}/{} exhaustive comparisons matched",
            local_top_k.queries - local_top_k.mismatches,
            local_top_k.queries
        ),
    );
    print_check(
        convergence_status,
        "Convergence heuristic",
        &format!("{} primary peers across the cluster", buckets.peers),
    );

    let statuses = [
        set_status,
        get_status,
        replication_status,
        placement_status,
        bucket_status,
        local_top_k_status,
        convergence_status,
    ];
    let has_failures = statuses.contains(&CheckStatus::Fail);
    let has_warnings = statuses.contains(&CheckStatus::Warn);

    if has_failures {
        println!("\n  OVERALL RESULT: FAILED ✗\n");
        std::process::exit(1);
    } else if has_warnings {
        println!("\n  OVERALL RESULT: PASSED WITH WARNINGS ~\n");
    } else {
        println!("\n  OVERALL RESULT: PASSED ✓\n");
    }
}
