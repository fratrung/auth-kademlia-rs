//! One whole node in its own process, driven by commands on stdin, one JSON
//! line per answer on stdout. `cluster.py` starts one per node; `run.sh`
//! builds it with the feature `counters` from a copy of the repository at
//! each commit it measures.
//!
//!   probe_node <port> <seed port> <k> <alpha> <data dir or -> <threads>
//!
//! Commands: bootstrap | publish <n> | republish_since <unix ms> | stats | quit

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use auth_kademlia_rs::auth_handler::did::PLACEHOLDER;
use auth_kademlia_rs::auth_handler::owner::OwnerTree;
use auth_kademlia_rs::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::{
    ForgetfulStorage, IStorage, DEFAULT_MAX_STORAGE_BYTES, DEFAULT_TTL,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = CURRENT.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn status_field(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_millis() as u64
}

/// A new DID and its position 0, as the testbed builds them.
fn new_did() -> (String, Vec<u8>) {
    let owner = OwnerTree::generate().expect("a tree");
    let public = owner.public_key(0).expect("position 0");
    let did = PLACEHOLDER;
    let initial = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#k0"),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65", "pub": URL_SAFE_NO_PAD.encode(public) }
        }],
        "authentication": [format!("{did}#k0")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }],
        "seq": 0,
    });
    let genesis = owner.genesis(&initial).expect("a genesis");
    let record = owner.record(&genesis, &initial, 0).expect("position 0");
    (genesis.did(), record)
}

async fn run(port: u16, seed: u16, k: usize, alpha: usize, data_dir: String) {
    let storage = (data_dir != "-").then(|| {
        Arc::new(
            ForgetfulStorage::persistent(&data_dir, DEFAULT_TTL, DEFAULT_MAX_STORAGE_BYTES)
                .expect("a store"),
        )
    });
    let handler: Arc<dyn SignatureVerifierHandler> =
        Arc::new(DIDSignatureVerifierHandler::new("/nonexistent/issuer.bin"));
    let mut server = Server::new(handler, k, alpha, None, storage, false);
    server.listen(port, "127.0.0.1").await.expect("listen");
    println!("{}", json!({"ready": port}));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let words: Vec<&str> = line.split_whitespace().collect();
        let answer = match words.first().copied() {
            Some("bootstrap") => {
                let found = server
                    .bootstrap(vec![("127.0.0.1".to_string(), seed)])
                    .await;
                json!({"bootstrap": found.len()})
            }
            Some("publish") => {
                let n: usize = words[1].parse().expect("a count");
                let started = Instant::now();
                let mut ok = 0;
                for _ in 0..n {
                    let (did, record) = new_did();
                    if server.set(&did, record).await == Some(true) {
                        ok += 1;
                    }
                }
                json!({"published": ok, "of": n, "ms": started.elapsed().as_millis() as u64})
            }
            Some("republish_since") => {
                // As the daily republication does, for the records no
                // other node renewed since the round started.
                let since: u64 = words[1].parse().expect("unix ms");
                let seconds = (now_ms().saturating_sub(since)) / 1000 + 1;
                let started = Instant::now();
                let old = server.storage.iter_older_than(seconds);
                let protocol = server.protocol.clone().expect("listening");
                let mut sent = 0;
                for (key, value) in old {
                    let Ok(key) = <[u8; 32]>::try_from(key.as_slice()) else {
                        continue;
                    };
                    protocol.republish(key, value).await;
                    sent += 1;
                }
                json!({"republished": sent, "ms": started.elapsed().as_millis() as u64})
            }
            Some("stats") => {
                let status = std::fs::read_to_string("/proc/self/status").expect("status");
                let stats = server.stats().await;
                let counters = server.counters();
                let sent = counters.as_ref().map(|c| {
                    c.sent
                        .iter()
                        .map(|(kind, s)| (kind.to_string(), json!([s.datagrams, s.bytes])))
                        .collect::<serde_json::Map<_, _>>()
                });
                let answer = json!({
                    "rss_kb": status_field(&status, "VmRSS:"),
                    "hwm_kb": status_field(&status, "VmHWM:"),
                    "threads": status_field(&status, "Threads:"),
                    "heap": CURRENT.load(Relaxed),
                    "heap_peak": PEAK.load(Relaxed),
                    "routing": stats.routing_nodes,
                    "records": stats.storage_records,
                    "storage_bytes": stats.storage_bytes,
                    "sent": sent,
                });
                PEAK.store(CURRENT.load(Relaxed), Relaxed);
                answer
            }
            Some("quit") => {
                server.stop().await;
                println!("{}", json!({"quit": true}));
                break;
            }
            other => json!({"error": format!("unknown {other:?}")}),
        };
        println!("{answer}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args[1].parse().expect("port");
    let seed: u16 = args[2].parse().expect("seed port");
    let k: usize = args[3].parse().expect("k");
    let alpha: usize = args[4].parse().expect("alpha");
    let data_dir = args[5].clone();
    let threads: usize = args[6].parse().expect("threads");
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .max_blocking_threads(threads)
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(run(port, seed, k, alpha, data_dir));
}
