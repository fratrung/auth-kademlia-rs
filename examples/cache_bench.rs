//! Signature cache benchmark for AuthKademlia-RS.
//!
//! Two distinct measurement phases:
//!
//! **Phase 1 — DHT SET throughput** (real network, both clusters run sequentially)
//!   Measures end-to-end write performance with and without the signature cache.
//!
//! **Phase 2 — Signature verification micro-benchmark** (no network)
//!   Calls `DIDSignatureVerifierHandler::handle_signature_verification` directly
//!   via `spawn_blocking`, mirroring the exact branching in `verify_for_key`:
//!
//!   - Cold: SHA-256 key computed, cache miss → full Dilithium-2 via spawn_blocking
//!           → result inserted into SignatureCache.
//!   - Warm: SHA-256 key computed, cache hit → result returned directly, no spawn_blocking.
//!   - Uncached: always pays full Dilithium-2, no cache involved.
//!
//!   This is faithful to the production code path and eliminates network variance.
//!
//! Run:
//!   cargo run --release --example cache_bench

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::digest;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::PublicKey as SignPublicKey;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use uuid::Uuid;

// Clusters run sequentially so ports can be reused between phases,
// but we keep them distinct from stress_test (15800-15804).
const CACHED_SEED: u16 = 15810;
const CACHED_PEER1: u16 = 15811;
const CACHED_PEER2: u16 = 15812;
const UNCACHED_SEED: u16 = 15813;
const UNCACHED_PEER1: u16 = 15814;
const UNCACHED_PEER2: u16 = 15815;
// Isolated single-node clusters for Phase 2 micro-benchmark.
// Must be fresh (empty cache) so TinyLFU eviction from Phase 1 does not
// interfere with cache hit measurements.
const MICRO_CACHED_PORT: u16 = 15816;
const MICRO_UNCACHED_PORT: u16 = 15817;

const DEFAULT_OPS: usize = 10000;
const DEFAULT_CONCURRENCY: usize = 30;
// Micro-bench uses fewer ops: each op is sequential (~100 µs each), so 500
// gives a stable average in < 0.1 s total per cluster.
const MICRO_OPS: usize = 500;

const OP_TIMEOUT: Duration = Duration::from_secs(15);

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn avg_ns(v: &[u64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<u64>() as f64 / v.len() as f64
}

fn stddev_ns(v: &[u64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let mean = avg_ns(v);
    let var = v
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / v.len() as f64;
    var.sqrt()
}

fn fmt_dur(ns: u64) -> String {
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    }
}

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

fn new_record() -> (String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did), "type": "JsonWebKey2020", "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2", "x": base64url(dpk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did), "type": "JsonWebKey2020", "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512", "x": base64url(kpk.as_bytes()) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "keyAgreement":   [format!("{}#k1", did)],
        "service": [{ "id": format!("{}#device", did), "type": "DeviceAgent",
                      "serviceEndpoint": "http://example.com/device" }]
    });
    let doc_bytes = serde_json::to_vec(&sort_json_keys(&doc)).expect("serialize");
    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");
    let sig = dilithium2::detached_sign(&doc_bytes, &dsk);
    let sig_bytes =
        <dilithium2::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(&sig);
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    (key, record)
}

async fn start_cluster(seed: u16, peer1: u16, peer2: u16, use_cache: bool) -> Vec<Arc<Server>> {
    let make = |port: u16| async move {
        let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
            "issuer.bin",
        )));
        let mut srv = Server::new(handler, 20, 3, None, None, use_cache);
        srv.listen(port, "127.0.0.1").await.expect("listen failed");
        Arc::new(srv)
    };
    let s = make(seed).await;
    let p1 = make(peer1).await;
    let p2 = make(peer2).await;
    p1.bootstrap(vec![("127.0.0.1".to_string(), seed)]).await;
    p2.bootstrap(vec![("127.0.0.1".to_string(), seed)]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    vec![s, p1, p2]
}

struct SetResults {
    set_ns: Vec<u64>,
    ok: usize,
    failures: usize,
    wall_secs: f64,
}

async fn run_set_workload(nodes: &[Arc<Server>], num_ops: usize, concurrency: usize) -> SetResults {
    let set_ns = Arc::new(Mutex::new(Vec::<u64>::with_capacity(num_ops)));
    let ok = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let sem = Arc::new(Semaphore::new(concurrency));

    let wall = Instant::now();
    let mut handles = Vec::with_capacity(num_ops);

    for i in 0..num_ops {
        let writer = Arc::clone(&nodes[i % nodes.len()]);
        let sem = Arc::clone(&sem);
        let set_ns = Arc::clone(&set_ns);
        let ok = Arc::clone(&ok);
        let fail = Arc::clone(&failures);
        let done = Arc::clone(&done);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let (key, record) = new_record();
            let t0 = Instant::now();
            let r = timeout(OP_TIMEOUT, writer.set(&key, record)).await;
            let elapsed = t0.elapsed().as_nanos() as u64;
            if r == Ok(Some(true)) {
                ok.fetch_add(1, Ordering::Relaxed);
                set_ns.lock().await.push(elapsed);
            } else {
                fail.fetch_add(1, Ordering::Relaxed);
            }
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % ((num_ops / 10).max(1)) == 0 || n == num_ops {
                print!("\r    {n}/{num_ops}");
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    let wall_secs = wall.elapsed().as_secs_f64();
    println!("\r    {num_ops}/{num_ops}  ✓        ");

    let mut v = set_ns.lock().await.clone();
    v.sort_unstable();
    SetResults {
        set_ns: v,
        ok: ok.load(Ordering::Relaxed),
        failures: failures.load(Ordering::Relaxed),
        wall_secs,
    }
}

struct VerifyResults {
    cold_ns: Vec<u64>,
    warm_ns: Vec<u64>,
}

/// Spins up a fresh single-node server (no DHT bootstrap needed — Phase 2
/// uses only local storage reads) and measures cold vs warm GET latency.
///
/// The node must be fresh (empty cache) so that TinyLFU entries from Phase 1
/// do not evict Phase 2 entries before the warm pass runs.
async fn run_verify_micro(port: u16, use_cache: bool, n: usize) -> VerifyResults {
    // Fresh node — cache is empty, no Phase 1 pollution.
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, None, None, use_cache);
    srv.listen(port, "127.0.0.1")
        .await
        .expect("micro-bench listen failed");
    let node = Arc::new(srv);

    // Pre-generate records outside the timed section.
    let records: Vec<(String, Vec<u8>)> = (0..n).map(|_| new_record()).collect();

    // Inject records directly into local storage, bypassing the DHT.
    for (key, record) in &records {
        let dkey = digest(key);
        node.storage.set(dkey.to_vec(), record.clone());
    }

    // Cold pass: cache is empty → full Dilithium-2 for both variants.
    let mut cold_ns = Vec::with_capacity(n);
    for (key, _) in &records {
        let t = Instant::now();
        let _ = node.get(key).await;
        cold_ns.push(t.elapsed().as_nanos() as u64);
    }

    // Warm pass: cached → SHA-256 lookup; uncached → full Dilithium again.
    let mut warm_ns = Vec::with_capacity(n);
    for (key, _) in &records {
        let t = Instant::now();
        let _ = node.get(key).await;
        warm_ns.push(t.elapsed().as_nanos() as u64);
    }

    cold_ns.sort_unstable();
    warm_ns.sort_unstable();
    VerifyResults { cold_ns, warm_ns }
}

fn print_set_table(label: &str, r: &SetResults, num_ops: usize) {
    let tp = num_ops as f64 / r.wall_secs;
    println!(
        "  [{label}]  {:.1} ops/s  (wall {:.2}s)  ok/fail {}/{}",
        tp, r.wall_secs, r.ok, r.failures
    );
    if r.set_ns.is_empty() {
        return;
    }
    println!(
        "    SET  avg {:>8}  p50 {:>8}  p95 {:>8}  p99 {:>8}  max {:>8}",
        fmt_dur(avg_ns(&r.set_ns) as u64),
        fmt_dur(percentile(&r.set_ns, 50.0)),
        fmt_dur(percentile(&r.set_ns, 95.0)),
        fmt_dur(percentile(&r.set_ns, 99.0)),
        fmt_dur(*r.set_ns.last().unwrap_or(&0)),
    );
}

fn print_verify_table(label: &str, r: &VerifyResults) {
    println!("  [{label}]  n={}", r.cold_ns.len());
    for (name, v) in [("cold", &r.cold_ns), ("warm", &r.warm_ns)] {
        println!(
            "    {name}  avg {:>8} ±{:>8}  p50 {:>8}  p95 {:>8}  p99 {:>8}",
            fmt_dur(avg_ns(v) as u64),
            fmt_dur(stddev_ns(v) as u64),
            fmt_dur(percentile(v, 50.0)),
            fmt_dur(percentile(v, 95.0)),
            fmt_dur(percentile(v, 99.0)),
        );
    }
}

fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(run());
}

async fn run() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║       AuthKademlia-RS  Signature Cache Benchmark          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("  DHT SET : {DEFAULT_OPS} ops  c={DEFAULT_CONCURRENCY}");
    println!("  Verify  : {MICRO_OPS} ops  sequential  (local storage, no network)");
    println!("  Record  : ~6 KB  (Dilithium-2 + Kyber-512 DID Document)\n");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: DHT SET throughput — clusters run sequentially to avoid
    // CPU contention between the cached and uncached measurements.
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━ Phase 1: DHT SET throughput ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    print!("  Starting cluster A (cached, ports {CACHED_SEED}-{CACHED_PEER2})... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let cached_nodes = start_cluster(CACHED_SEED, CACHED_PEER1, CACHED_PEER2, true).await;
    println!("ok");
    let cached_set = run_set_workload(&cached_nodes, DEFAULT_OPS, DEFAULT_CONCURRENCY).await;
    print_set_table("cached  ", &cached_set, DEFAULT_OPS);

    // Brief pause so OS reclaims sockets / CPU before next cluster starts.
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!();

    print!("  Starting cluster B (uncached, ports {UNCACHED_SEED}-{UNCACHED_PEER2})... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let uncached_nodes = start_cluster(UNCACHED_SEED, UNCACHED_PEER1, UNCACHED_PEER2, false).await;
    println!("ok");
    let uncached_set = run_set_workload(&uncached_nodes, DEFAULT_OPS, DEFAULT_CONCURRENCY).await;
    print_set_table("uncached", &uncached_set, DEFAULT_OPS);

    // SET comparison
    let set_c = avg_ns(&cached_set.set_ns);
    let set_u = avg_ns(&uncached_set.set_ns);
    if set_c > 0.0 && set_u > 0.0 {
        println!(
            "\n  SET speedup: {:.1}×  ({} cached  vs  {} uncached)",
            set_u / set_c,
            fmt_dur(set_c as u64),
            fmt_dur(set_u as u64)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Signature verification micro-benchmark.
    // Records are written directly to local storage — no network noise.
    // This gives a stable, reproducible signal for the cache benefit.
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n━━━ Phase 2: Signature verification micro-benchmark ━━━━━━━━━\n");
    println!("  (fresh nodes, empty cache, local storage only, sequential GETs)\n");

    // Fresh nodes on isolated ports — no TinyLFU pollution from Phase 1.
    let cached_v = run_verify_micro(MICRO_CACHED_PORT, true, MICRO_OPS).await;
    print_verify_table("cached  ", &cached_v);
    println!();
    let uncached_v = run_verify_micro(MICRO_UNCACHED_PORT, false, MICRO_OPS).await;
    print_verify_table("uncached", &uncached_v);

    // Summary comparison
    let cold_c = avg_ns(&cached_v.cold_ns);
    let cold_u = avg_ns(&uncached_v.cold_ns);
    let warm_c = avg_ns(&cached_v.warm_ns);
    let warm_u = avg_ns(&uncached_v.warm_ns);

    println!("\n━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("  ┌─────────────┬─────────────────┬─────────────────┬────────────┐");
    println!("  │             │  cached (avg)   │ uncached (avg)  │  speedup   │");
    println!("  ├─────────────┼─────────────────┼─────────────────┼────────────┤");
    println!(
        "  │ DHT SET     │ {:>15} │ {:>15} │ {:>9.1}× │",
        fmt_dur(set_c as u64),
        fmt_dur(set_u as u64),
        if set_c > 0.0 { set_u / set_c } else { 0.0 }
    );
    println!(
        "  │ GET cold    │ {:>15} │ {:>15} │ {:>9.1}× │",
        fmt_dur(cold_c as u64),
        fmt_dur(cold_u as u64),
        if cold_c > 0.0 { cold_u / cold_c } else { 0.0 }
    );
    println!(
        "  │ GET warm    │ {:>15} │ {:>15} │ {:>9.1}× │",
        fmt_dur(warm_c as u64),
        fmt_dur(warm_u as u64),
        if warm_c > 0.0 { warm_u / warm_c } else { 0.0 }
    );
    println!("  └─────────────┴─────────────────┴─────────────────┴────────────┘");
    println!();
    println!("  Cold GET: first read — full Dilithium-2 for both (cache miss).");
    println!("  Warm GET: second read of same record.");
    println!("    Cached  → SHA-256 key lookup only  (~1 µs expected)");
    println!("    Uncached → full Dilithium-2 re-verify  (~100 µs expected)");
}
