//! Topology test for AuthKademlia-RS.
//!
//! Launches NUM_NODES nodes and exercises:
//!   - Phase 1: publish NUM_RECORDS authenticated DID records from rotating writers
//!   - Phase 2: retrieve every record from a node offset by half the cluster size
//!     (forces a real multi-hop DHT lookup, not a local cache hit)
//!
//! Diagnostic output:
//!   1. Latency table  (SET / GET avg, p50, p95, max)
//!   2. Sample DID Documents
//!   3. Storage tables (which DHT keys live on which node)
//!   4. Replication summary (copy-count per key)
//!   5. XOR-distance correctness  ← NEW: verifies each record is on the k-closest nodes
//!   6. Bucket structure           ← NEW: per-node bucket tree with range / depth / nodes
//!   7. Routing convergence        ← NEW: avg buckets, avg peers across the cluster
//!   8. Routing tables (flat peer list, for reference)
//!
//! Run:
//!   cargo run --release --example topology_analysis                # k=20 alpha=3
//!   cargo run --release --example topology_analysis -- 3 3         # k=3  alpha=3
//!   cargo run --release --example topology_analysis -- 5 2         # k=5  alpha=2
//!   RUST_LOG=info cargo run --release --example topology_analysis -- 3

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::digest;
use primitive_types::U256;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::PublicKey;
use serde_json::{json, Value};
use tokio::time::timeout;
use uuid::Uuid;

const BASE_PORT: u16 = 15810;
const NUM_NODES: usize = 30;
const NUM_RECORDS: usize = 100;
const OP_TIMEOUT: Duration = Duration::from_secs(10);

// ─── record helpers ──────────────────────────────────────────────────────────

fn base64url(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

fn sort_json_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

fn encode_did_document(doc: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_json_keys(doc)).expect("serialization failed")
}

fn build_signed_record(doc: &Value, sk: &dilithium2::SecretKey) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);
    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");
    let sig = dilithium2::detached_sign(&doc_bytes, sk);
    let sig_bytes =
        <dilithium2::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(&sig);
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

fn build_did_document(did: &str, dpk: &dilithium2::PublicKey, kpk: &kyber512::PublicKey) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2", "x": base64url(dpk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512", "x": base64url(kpk.as_bytes()) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "keyAgreement": [format!("{}#k1", did)],
        "service": [{ "id": format!("{}#device", did), "type": "DeviceAgent",
                      "serviceEndpoint": "http://example.com/device" }]
    })
}

/// Returns (did_uri, dht_key_uuid, record_bytes).
fn new_record() -> (String, String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &dpk, &kpk);
    let record = build_signed_record(&doc, &dsk);
    (did, key, record)
}

/// Extract the DID Document JSON from a raw wire record (skip alg + sig header).
fn extract_doc(record: &[u8]) -> Option<serde_json::Value> {
    const SIG_LEN: usize = 2420;
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
        let dkey_hex = hex::encode(digest(key_str.as_str()));
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

/// Print how many records each node stores and which keys they are.
async fn print_storage_tables(
    nodes: &[(Arc<Server>, u16)],
    key_to_did: &HashMap<String, String>,
) -> HashMap<String, Vec<u16>> {
    println!("━━━ Storage Tables (records per node) ━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut key_holders: HashMap<String, Vec<u16>> = HashMap::new();

    for (server, port) in nodes {
        let entries = server.storage.iter_all();
        let keys: Vec<String> = entries.iter().map(|(k, _)| hex::encode(k)).collect();
        println!("  Node :{port}  ({} records)", keys.len());
        if keys.is_empty() {
            println!("    (empty)");
        } else {
            for k in &keys {
                let did_hint = key_to_did
                    .get(k)
                    .map(|d| format!("  →  {}", &d[..d.len().min(50)]))
                    .unwrap_or_default();
                println!("    {k}{did_hint}");
                key_holders.entry(k.clone()).or_default().push(*port);
            }
        }
        println!();
    }

    key_holders
}

/// Print per-key replication count and which nodes hold each copy.
fn print_replication_summary(key_holders: &HashMap<String, Vec<u16>>) {
    println!("━━━ Replication Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("  {:>64}  copies  holders", "DHT key (hex)");
    println!("  {}  ------  -------", "-".repeat(64));
    let mut sorted: Vec<_> = key_holders.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());
    for (key, holders) in &sorted {
        let ports: Vec<String> = holders.iter().map(|p| p.to_string()).collect();
        println!("  {key}  {:>6}  {}", holders.len(), ports.join(", "));
    }

    // Copy-count distribution
    let mut dist: HashMap<usize, usize> = HashMap::new();
    for holders in key_holders.values() {
        *dist.entry(holders.len()).or_insert(0) += 1;
    }
    let mut dist_sorted: Vec<_> = dist.iter().collect();
    dist_sorted.sort_by_key(|(c, _)| **c);
    println!("\n  Copy-count distribution:");
    for (copies, count) in &dist_sorted {
        println!(
            "    {copies} cop{}: {count} records",
            if **copies == 1 { "y" } else { "ies" }
        );
    }
    println!();
}

/// XOR-distance correctness check.
///
/// For each record, compute the k globally-closest nodes (ground truth) and
/// verify which of those actually store the record.  Also report any nodes
/// outside the k-closest that hold a copy (tolerated for k > replicas, but
/// should be rare with small k).
async fn verify_xor_correctness(
    nodes: &[(Arc<Server>, u16)],
    published: &[(String, String, Vec<u8>)],
    ksize: usize,
) {
    println!("━━━ XOR-Distance Correctness (Kademlia §2.3) ━━━━━━━━━━━━━━━━━━\n");
    println!("  For each record: computes the {ksize} globally-closest nodes (XOR metric),");
    println!("  then checks whether those nodes actually hold the record.\n");
    println!("  Legend:  [✓] all k-closest hold it  [~] partial  [✗] none of k-closest hold it\n");

    let check_n = published.len().min(20);
    let mut full_ok = 0usize;
    let mut partial_ok = 0usize;
    let mut none_ok = 0usize;

    // Collect (node_id, port) once for efficiency
    let node_ids: Vec<([u8; 20], u16)> = nodes.iter().map(|(s, p)| (s.node.id, *p)).collect();

    for (_did, key_str, _) in published.iter().take(check_n) {
        let dkey = digest(key_str.as_str());
        let key_node = Node::from_id(dkey);

        // Sort all nodes by XOR distance to this key
        let mut by_dist: Vec<(U256, u16)> = node_ids
            .iter()
            .map(|(id, port)| (Node::from_id(*id).distance_to(&key_node), *port))
            .collect();
        by_dist.sort_by_key(|(d, _)| *d);

        let k_closest: Vec<u16> = by_dist.iter().take(ksize).map(|(_, p)| *p).collect();

        // Check which k-closest nodes actually hold the record
        let mut holding: Vec<u16> = vec![];
        let mut missing: Vec<u16> = vec![];
        for &port in &k_closest {
            let server = nodes
                .iter()
                .find(|(_, p)| *p == port)
                .map(|(s, _)| s)
                .unwrap();
            if server.storage.get(&dkey).is_some() {
                holding.push(port);
            } else {
                missing.push(port);
            }
        }

        // Any nodes outside k-closest that hold it (extra replicas)
        let mut extras: Vec<u16> = vec![];
        for (server, port) in nodes {
            if !k_closest.contains(port) && server.storage.get(&dkey).is_some() {
                extras.push(*port);
            }
        }

        let status = if missing.is_empty() {
            full_ok += 1;
            "✓"
        } else if !holding.is_empty() {
            partial_ok += 1;
            "~"
        } else {
            none_ok += 1;
            "✗"
        };

        // Abbreviated display
        let uuid_short = &key_str[..8.min(key_str.len())];
        let k_str: Vec<String> = k_closest.iter().map(|p| p.to_string()).collect();
        println!(
            "  [{status}] key={uuid_short}…  k-closest=[{}]",
            k_str.join(",")
        );
        if !holding.is_empty() {
            println!(
                "       holding : {:?}  ({}/{} k-closest)",
                holding,
                holding.len(),
                ksize
            );
        }
        if !missing.is_empty() {
            println!(
                "       missing : {:?}  (k-closest without the record)",
                missing
            );
        }
        if !extras.is_empty() {
            println!(
                "       extras  : {:?}  (outside k-closest but hold a copy)",
                extras
            );
        }
    }

    println!(
        "\n  Result on {} sampled records:  ✓ full={full_ok}  ~ partial={partial_ok}  ✗ none={none_ok}",
        check_n
    );
    if none_ok == 0 {
        println!("  → All checked records are held by at least one k-closest node ✓");
    } else {
        println!("  → {none_ok} records not found on ANY k-closest node — possible routing inconsistency");
    }
    println!();
}

/// Per-node bucket tree: shows range boundaries, node count, depth, freshness.
/// This is the primary view for verifying correct bucket splitting (§4.2).
async fn print_bucket_structure(nodes: &[(Arc<Server>, u16)]) {
    println!("━━━ Bucket Structure (k-bucket tree per node) ━━━━━━━━━━━━━━━━━\n");
    println!("  Each line: [bucket-idx]  nodes-in-bucket  depth  fresh/lonely  [lo_hex..hi_hex]\n");

    let mut total_buckets = 0usize;
    let mut total_peers = 0usize;

    for (server, port) in nodes {
        let proto = match &server.protocol {
            Some(p) => p,
            None => {
                println!("  Node :{port}  (not started)");
                continue;
            }
        };

        let router = proto.router.read().await;
        let buckets = router.buckets();
        let peer_count: usize = buckets.iter().map(|b| b.len()).sum();
        total_buckets += buckets.len();
        total_peers += peer_count;

        // Local node ID prefix for context
        let local_id_hex: String = router.node.id[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        println!(
            "  Node :{port}  id={}…  ({} buckets, {} peers)",
            local_id_hex,
            buckets.len(),
            peer_count
        );

        for (i, bucket) in buckets.iter().enumerate() {
            let lo = *bucket.range.start();
            let hi = *bucket.range.end();
            let lo_s = format!("{:032x}", lo);
            let _hi_s = format!("{:032x}", hi);
            let freshness = if bucket.is_lonely() {
                "lonely"
            } else {
                "fresh "
            };

            println!(
                "    [{:>2}]  nodes={:>2}  depth={:>3}  {}  [{}..]",
                i,
                bucket.len(),
                bucket.depth(),
                freshness,
                &lo_s[..16],
            );

            // List nodes inside this bucket
            for n in bucket.nodes().iter() {
                let nid: String = n.id[..4].iter().map(|b| format!("{b:02x}")).collect();
                let nport = n.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                println!("           ↳ {}…  :{}", nid, nport);
            }
        }
        println!();
    }

    // Convergence summary across all nodes
    let n = nodes.len();
    if n > 0 {
        let avg_buckets = total_buckets as f64 / n as f64;
        let avg_peers = total_peers as f64 / n as f64;
        // In a balanced N-node DHT, each node should know ~log2(N) buckets
        // and up to k*log2(N) peers
        let expected_buckets = (n as f64).log2();
        println!("━━━ Routing Convergence Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        println!("  Cluster size         : {n} nodes");
        println!("  Avg buckets / node   : {avg_buckets:.1}  (expected ≥ log₂({n}) ≈ {expected_buckets:.1})");
        println!("  Avg peers   / node   : {avg_peers:.1}");
        println!(
            "  {}",
            if avg_buckets >= expected_buckets * 0.7 {
                "→ Routing table appears well-converged ✓"
            } else {
                "→ Fewer buckets than expected — routing table may not be fully converged"
            }
        );
        println!();
    }
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

fn latency_stats(v: &mut Vec<u64>) -> (f64, u64, u64, u64) {
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
    let args: Vec<String> = std::env::args().collect();
    let ksize: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let alpha: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Topology Test           ║");
    println!("╚══════════════════════════════════════════════╝");
    println!(
        "  Nodes    : {NUM_NODES}  (ports {BASE_PORT}–{})",
        BASE_PORT + NUM_NODES as u16 - 1
    );
    println!("  k (ksize): {ksize}  → records replicated on ≤{ksize} closest nodes");
    println!("  alpha    : {alpha}");
    println!("  Records  : {NUM_RECORDS}");
    println!("  Timeout  : {}s/op\n", OP_TIMEOUT.as_secs());

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
                println!(
                    "  [{i:>3}] writer={writer_port}  key={}  did={}…  SET ✓  ({:.1}ms)",
                    &key[..8],
                    &did[..32],
                    ns as f64 / 1e6
                );
                published.push((did, key, record));
            }
            other => {
                set_fail += 1;
                println!(
                    "  [{i:>3}] writer={writer_port}  key={}  SET ✗  {other:?}",
                    &key[..8]
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
    let mut get_latencies: Vec<u64> = Vec::new();

    for (i, (_did, key, original)) in published.iter().enumerate() {
        let reader_idx = (i + NUM_NODES / 2) % NUM_NODES;
        let (reader, reader_port) = &nodes[reader_idx];

        let t0 = Instant::now();
        let result = timeout(OP_TIMEOUT, reader.get(key)).await;
        let ns = t0.elapsed().as_nanos() as u64;

        match result {
            Ok(Some(ref retrieved)) => {
                get_latencies.push(ns);
                if retrieved == original {
                    get_ok += 1;
                    println!(
                        "  [{i:>3}] reader={reader_port}  key={}  GET ✓  ({:.1}ms)",
                        &key[..8],
                        ns as f64 / 1e6
                    );
                } else {
                    get_corrupt += 1;
                    println!(
                        "  [{i:>3}] reader={reader_port}  key={}  GET ✗  CORRUPTION",
                        &key[..8]
                    );
                }
            }
            Ok(None) => {
                get_fail += 1;
                println!(
                    "  [{i:>3}] reader={reader_port}  key={}  GET ✗  not found  ({:.1}ms)",
                    &key[..8],
                    ns as f64 / 1e6
                );
            }
            Err(_) => {
                get_fail += 1;
                println!(
                    "  [{i:>3}] reader={reader_port}  key={}  GET ✗  timeout",
                    &key[..8]
                );
            }
        }
    }
    println!("\n  Retrieved: {get_ok}/{set_ok}  ({get_fail} not found, {get_corrupt} corrupted)\n");

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
            let dht_hex = hex::encode(digest(key_str.as_str()));
            (dht_hex, did.clone())
        })
        .collect();

    print_sample_docs(&published);
    let key_holders = print_storage_tables(&nodes, &key_to_did).await;
    print_replication_summary(&key_holders);
    verify_xor_correctness(&nodes, &published, ksize).await;
    print_bucket_structure(&nodes).await;
    print_routing_tables(&nodes).await;

    println!("━━━ Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    if get_fail == 0 && get_corrupt == 0 && set_fail == 0 {
        println!("  ALL CHECKS PASSED ✓\n");
    } else {
        println!("  SET fail: {set_fail}  GET fail: {get_fail}  Corruptions: {get_corrupt}\n");
        std::process::exit(1);
    }
}
