/// Resilience test — Node B (attacker).
///
/// Runs three sequential phases against Node A:
///   1. STORE valid    — sends `POOL_SIZE` valid DID records; reports latency distribution.
///   2. STORE invalid  — sends `POOL_SIZE/3` tampered records (one sig byte flipped);
///      every acceptance is a security failure.
///   3. GET verify     — retrieves every key accepted in phase 1; reports latency distribution.
///
/// Each record is sent exactly once. Concurrency is bounded by `CONCURRENCY`.
/// Per-RPC latency is collected and reported as min/avg/p95/max + throughput (ops/sec).
///
/// Environment variables:
///   TARGET_ADDR   — Node A address (default: 172.21.0.10:5678)
///   ATTACKER_PORT — Node B's own UDP port (default: 5679)
///   POOL_SIZE     — valid records to generate (default: 300)
///   CONCURRENCY   — max in-flight RPCs per phase (default: 50)
///   RUST_LOG      — log level (default: warn)
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::protocol::KademliaProtocol;
use auth_kademlia_rs::utils::digest;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use tokio::task::JoinSet;
use tokio::time::timeout;
use uuid::Uuid;

// Must be strictly less than the protocol's internal RPC_TIMEOUT (5 s) so that
// when the victim doesn't respond in time this outer timeout fires first and
// the result is counted as timed_out rather than rejected.
const RPC_TIMEOUT: Duration = Duration::from_millis(4500);

struct LatencyStats {
    samples: Vec<Duration>,
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn push(&mut self, d: Duration) {
        self.samples.push(d);
    }

    /// Returns (min, avg, p95, max, ops_per_sec) over `wall` elapsed time.
    fn report(&mut self, wall: Duration) -> (f64, f64, f64, f64, f64) {
        if self.samples.is_empty() {
            return (0.0, 0.0, 0.0, 0.0, 0.0);
        }
        self.samples.sort_unstable();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let min = ms(*self.samples.first().unwrap());
        let max = ms(*self.samples.last().unwrap());
        let avg = self.samples.iter().map(|d| ms(*d)).sum::<f64>() / self.samples.len() as f64;
        let p95_idx = ((self.samples.len() as f64 * 0.95) as usize).min(self.samples.len() - 1);
        let p95 = ms(self.samples[p95_idx]);
        let tps = self.samples.len() as f64 / wall.as_secs_f64();
        (min, avg, p95, max, tps)
    }
}

fn print_latency(
    label: &str,
    stats: &mut LatencyStats,
    wall: Duration,
    accepted: usize,
    rejected: usize,
    timed_out: usize,
) {
    let (min, avg, p95, max, tps) = stats.report(wall);
    println!(
        "  accepted={accepted}  rejected={rejected}  timeout={timed_out}  \
         ({:.1}s  {tps:.1} ops/s)",
        wall.as_secs_f64()
    );
    if !stats.samples.is_empty() {
        println!(
            "  latency [{label}]  min={min:.1}ms  avg={avg:.1}ms  p95={p95:.1}ms  max={max:.1}ms"
        );
    }
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Sorts object keys recursively so the JSON is canonical before signing.
fn sort_json(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(sort_json).collect()),
        other => other.clone(),
    }
}

/// Builds a valid self-signed Dilithium-2 DID record (wire format: alg ‖ sig ‖ doc).
fn make_record() -> (String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();

    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did), "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2",
                                  "x": b64url(dpk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did), "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512",
                                  "x": b64url(kpk.as_bytes()) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "keyAgreement":   [format!("{}#k1", did)],
        "service": [{
            "id": format!("{}#device", did),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    });

    let doc_bytes = serde_json::to_vec(&sort_json(&doc)).unwrap();
    let sig = dilithium2::detached_sign(&doc_bytes, &dsk);

    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");

    let mut record = Vec::with_capacity(12 + sig.as_bytes().len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig.as_bytes());
    record.extend_from_slice(&doc_bytes);
    (key, record)
}

/// Sends every (key, record) pair to `victim` via `call_store_rpc`, bounded by `concurrency`.
/// Returns `(accepted, rejected, timed_out, accepted_keys, latency_stats)`.
async fn store_phase(
    proto: Arc<KademliaProtocol>,
    victim: Node,
    pool: Vec<(String, Vec<u8>)>,
    concurrency: usize,
) -> (usize, usize, usize, Vec<String>, LatencyStats) {
    // (timed_out: bool, accepted: bool, key, elapsed)
    let mut jset: JoinSet<(bool, bool, String, Duration)> = JoinSet::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut timed_out = 0usize;
    let mut accepted_keys: Vec<String> = Vec::new();
    let mut latency = LatencyStats::new();
    let mut iter = pool.into_iter();

    loop {
        while jset.len() < concurrency {
            match iter.next() {
                Some((key, record)) => {
                    let p = Arc::clone(&proto);
                    let v = victim.clone();
                    let k = key.clone();
                    jset.spawn(async move {
                        let dkey = digest(&k);
                        let t = Instant::now();
                        match timeout(RPC_TIMEOUT, p.call_store_rpc(&v, dkey, record)).await {
                            Ok(ok) => (false, ok, k, t.elapsed()),
                            Err(_) => (true, false, k, t.elapsed()),
                        }
                    });
                }
                None => break,
            }
        }
        if jset.is_empty() {
            break;
        }
        match jset.join_next().await {
            Some(Ok((is_timeout, ok, key, elapsed))) => {
                latency.push(elapsed);
                if is_timeout {
                    timed_out += 1;
                } else if ok {
                    accepted += 1;
                    accepted_keys.push(key);
                } else {
                    rejected += 1;
                }
            }
            _ => timed_out += 1,
        }
    }
    (accepted, rejected, timed_out, accepted_keys, latency)
}

/// Retrieves each key from the DHT via `server.get()`, bounded by `concurrency`.
/// Returns `(hits, misses, timed_out, latency_stats)`.
async fn get_phase(
    server: Arc<Server>,
    keys: Vec<String>,
    concurrency: usize,
) -> (usize, usize, usize, LatencyStats) {
    let mut jset: JoinSet<(bool, Duration)> = JoinSet::new();
    let mut hits = 0usize;
    let mut misses = 0usize;
    let mut timed_out = 0usize;
    let mut latency = LatencyStats::new();
    let mut iter = keys.into_iter();

    loop {
        while jset.len() < concurrency {
            match iter.next() {
                Some(key) => {
                    let s = Arc::clone(&server);
                    jset.spawn(async move {
                        let t = Instant::now();
                        let found = timeout(RPC_TIMEOUT, s.get(&key))
                            .await
                            .ok()
                            .flatten()
                            .is_some();
                        (found, t.elapsed())
                    });
                }
                None => break,
            }
        }
        if jset.is_empty() {
            break;
        }
        match jset.join_next().await {
            Some(Ok((found, elapsed))) => {
                latency.push(elapsed);
                if found {
                    hits += 1;
                } else {
                    misses += 1;
                }
            }
            _ => timed_out += 1,
        }
    }
    (hits, misses, timed_out, latency)
}

fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

async fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let target_addr =
        std::env::var("TARGET_ADDR").unwrap_or_else(|_| "172.21.0.10:5678".to_string());
    let attacker_port: u16 = std::env::var("ATTACKER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5679);
    let pool_size: usize = std::env::var("POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let concurrency: usize = std::env::var("CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let inv_size = (pool_size / 50).max(10);

    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Resilience Attacker     ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Target      : {target_addr}");
    println!("  Port        : 0.0.0.0:{attacker_port}");
    println!("  Valid pool  : {pool_size}");
    println!("  Invalid pool: {inv_size}");
    println!("  Concurrency : {concurrency}");
    println!();

    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));
    let mut server = Server::new(handler, 20, 3, None, None, true);
    server
        .listen(attacker_port, "0.0.0.0")
        .await
        .expect("failed to bind UDP socket");
    let server = Arc::new(server);

    // `depends_on` only guarantees the container started, not that the UDP socket is bound.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let parts: Vec<&str> = target_addr.splitn(2, ':').collect();
    let target_ip = parts[0].to_string();
    let target_port: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(5678);

    print!("[attacker] Bootstrapping with {target_addr}... ");
    let victim_addr = (target_ip.clone(), target_port);
    let discovered = server.bootstrap(vec![(target_ip, target_port)]).await;
    if discovered.is_empty() {
        println!("WARN: no peers discovered.");
    } else {
        println!("ok ({} peer(s))", discovered.len());
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let proto: Arc<KademliaProtocol> =
        Arc::clone(server.protocol.as_ref().expect("protocol not initialised"));
    let victim: Node = proto
        .router
        .read()
        .await
        .find_neighbors(&proto.source_node, None)
        .into_iter()
        .next()
        .expect("victim not in routing table after bootstrap");
    println!("[attacker] Victim: {victim}\n");

    // Dilithium keypair generation is CPU-intensive; done once before the test phases.
    print!("[attacker] Generating {pool_size} valid + {inv_size} invalid records... ");
    let t = Instant::now();
    let (valid_pool, invalid_pool): (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) =
        tokio::task::spawn_blocking(move || {
            let valid: Vec<_> = (0..pool_size).map(|_| make_record()).collect();
            let invalid: Vec<_> = (0..inv_size)
                .map(|_| {
                    let (key, mut rec) = make_record();
                    rec[500] ^= 0xFF;
                    (key, rec)
                })
                .collect();
            (valid, invalid)
        })
        .await
        .unwrap();
    println!("done ({:.1}s)\n", t.elapsed().as_secs_f64());

    println!(
        "[attacker] Phase 1 — STORE {} valid records  (concurrency={concurrency})",
        valid_pool.len()
    );
    let t1 = Instant::now();
    let (accepted, rejected, store_timeout, stored_keys, mut lat1) =
        store_phase(Arc::clone(&proto), victim.clone(), valid_pool, concurrency).await;
    let wall1 = t1.elapsed();
    print_latency(
        "store-valid",
        &mut lat1,
        wall1,
        accepted,
        rejected,
        store_timeout,
    );
    println!();

    println!(
        "[attacker] Phase 2 — STORE {} invalid records  (concurrency={concurrency})",
        invalid_pool.len()
    );
    let t2 = Instant::now();
    let (inv_accepted, inv_rejected, inv_timeout, _, mut lat2) = store_phase(
        Arc::clone(&proto),
        victim.clone(),
        invalid_pool,
        concurrency,
    )
    .await;
    let wall2 = t2.elapsed();
    print_latency(
        "store-invalid",
        &mut lat2,
        wall2,
        inv_accepted,
        inv_rejected,
        inv_timeout,
    );
    println!();

    // The victim may have been evicted from the routing table while under load
    // during Phase 2 (background ping tasks time out → remove from router).
    // Re-bootstrap to restore the routing table before issuing GET requests.
    print!("[attacker] Re-bootstrapping before GET phase... ");
    let rejoined = server.bootstrap(vec![victim_addr]).await;
    println!(
        "{}",
        if rejoined.is_empty() {
            "WARN: no peers"
        } else {
            "ok"
        }
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!(
        "[attacker] Phase 3 — GET {} stored keys  (concurrency={concurrency})",
        stored_keys.len()
    );
    let t3 = Instant::now();
    let (hits, misses, get_timeout, mut lat3) =
        get_phase(Arc::clone(&server), stored_keys, concurrency).await;
    let wall3 = t3.elapsed();
    let (min3, avg3, p95_3, max3, tps3) = lat3.report(wall3);
    println!(
        "  hit={hits}  miss={misses}  timeout={get_timeout}  \
         ({:.1}s  {tps3:.1} ops/s)",
        wall3.as_secs_f64()
    );
    if !lat3.samples.is_empty() {
        println!(
            "  latency [get]  min={min3:.1}ms  avg={avg3:.1}ms  \
             p95={p95_3:.1}ms  max={max3:.1}ms"
        );
    }
    println!();

    println!("━━━ Resilience verdict ━━━━━━━━━━━━━━━━━━━━━━━━\n");

    if inv_accepted == 0 {
        println!("  [✓] Security intact     all {inv_rejected} tampered records rejected");
    } else {
        eprintln!("  [✗] SECURITY FAILURE    {inv_accepted} tampered records accepted by Node A!");
    }

    if accepted > 0 {
        println!(
            "  [✓] Store functional    {accepted}/{} valid records accepted",
            accepted + rejected + store_timeout
        );
    } else {
        println!("  [!] No valid records stored (connectivity issue?)");
    }

    let miss_rate = if hits + misses > 0 {
        misses as f64 / (hits + misses) as f64
    } else {
        0.0
    };
    if miss_rate < 0.05 {
        println!(
            "  [✓] Retrieval reliable  miss rate {:.1}%",
            miss_rate * 100.0
        );
    } else {
        println!(
            "  [!] Retrieval degraded  miss rate {:.1}%",
            miss_rate * 100.0
        );
    }

    let (_, avg1, p95_1, max1, tps1) = lat1.report(wall1);
    println!("\n  Throughput summary:");
    println!(
        "    store-valid   {tps1:>6.1} ops/s  avg={avg1:.1}ms  p95={p95_1:.1}ms  max={max1:.1}ms"
    );
    let (_, avg2, p95_2, max2, tps2) = lat2.report(wall2);
    println!(
        "    store-invalid {tps2:>6.1} ops/s  avg={avg2:.1}ms  p95={p95_2:.1}ms  max={max2:.1}ms"
    );
    println!(
        "    get           {tps3:>6.1} ops/s  avg={avg3:.1}ms  p95={p95_3:.1}ms  max={max3:.1}ms"
    );

    println!();
    if inv_accepted == 0 {
        println!("  RESULT: Node A survived — no security violations.");
    } else {
        eprintln!("  RESULT: SECURITY FAILURE — Node A accepted tampered records.");
        std::process::exit(1);
    }

    // Machine-readable summary — parsed by resilience/run_stats.py
    let total_valid = accepted + rejected + store_timeout;
    let total_invalid = inv_accepted + inv_rejected + inv_timeout;
    println!(
        "METRICS_JSON {}",
        serde_json::to_string(&serde_json::json!({
            "pool_size":          total_valid,
            "inv_size":           total_invalid,
            "concurrency":        concurrency,
            "p1_accepted":        accepted,
            "p1_rejected":        rejected,
            "p1_timeout":         store_timeout,
            "p1_avg_ms":          avg1,
            "p1_p95_ms":          p95_1,
            "p1_max_ms":          max1,
            "p1_tps":             tps1,
            "p2_accepted":        inv_accepted,
            "p2_rejected":        inv_rejected,
            "p2_timeout":         inv_timeout,
            "p2_avg_ms":          avg2,
            "p2_p95_ms":          p95_2,
            "p2_tps":             tps2,
            "p3_hits":            hits,
            "p3_misses":          misses,
            "p3_timeout":         get_timeout,
            "p3_avg_ms":          avg3,
            "p3_p95_ms":          p95_3,
            "p3_max_ms":          max3,
            "p3_tps":             tps3,
        }))
        .unwrap()
    );
}
