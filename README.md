# AuthKademlia-RS

A Rust reimplementation of [AuthKademlia](https://github.com/fratrung/AuthKademlia) — an extended Kademlia Distributed Hash Table with native support for **signed records** and **Verifiable Data Registry (VDR)** capabilities for Decentralized Identifiers (DIDs).

-----

## Overview

AuthKademlia-RS is a high-performance, asynchronous implementation of the [Kademlia DHT protocol](http://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) written in Rust. It extends the standard Kademlia specification with cryptographic record signing, making it suitable for use as a decentralized identity infrastructure layer.

Unlike conventional DHT implementations, AuthKademlia-RS treats stored values as **verifiable artifacts**: each record is cryptographically bound to its author and can be independently verified by any node in the network — without any central authority.

-----

## Why Rust for the DHT Core?

The original [AuthKademlia](https://github.com/fratrung/AuthKademlia) is written in Python, and the application-layer logic (provisioning, REST APIs, orchestration) intentionally remains in Python. The DHT node core, however, has been reimplemented in Rust to address a fundamental constraint: **post-quantum signature verification is CPU-bound, and the Python GIL serialises all CPU-bound work to a single thread regardless of how many cores are available**.

### The GIL bottleneck on CPU-bound workloads

Python's **Global Interpreter Lock (GIL)** permits only one thread to execute bytecode at a time. For I/O-bound tasks this is rarely a bottleneck, but Dilithium-2 signature verification is purely computational. In CPython, even with `threading` or `asyncio`, all verification calls are serialised to one core:

```
Python (N cores):  throughput ≈ 1 core × ops/s        (GIL ceiling)
Rust   (N cores):  throughput ≈ N cores × ops/s        (true parallelism)
```

This gap widens on hardware with slower per-core performance, which is common in embedded and edge deployments where power and cost constraints favour multi-core low-frequency processors over single-core speed. The Python implementation would leave most available compute idle; the Rust implementation uses every core.

### Layered architecture via PyO3

The Python binding (built with [maturin](https://github.com/PyO3/maturin) via PyO3) releases the GIL before entering Rust code. This means:

- The **application layer stays in Python** — no rewrite required for existing tooling.
- The **DHT hot path (store, get, signature verification)** runs in Rust across all available cores with zero GIL contention.
- The performance gap between the two implementations grows proportionally with the number of cores and with the cost of the cryptographic primitive — both of which favour Rust in production deployments.

-----

## Key Differentiators

|Feature                  |Standard Kademlia|AuthKademlia-RS                     |
|-------------------------|-----------------|------------------------------------|
|Record integrity         |None             |Cryptographic signature verification|
|Identity support         |None             |Native DID Document storage         |
|Post-quantum cryptography|None             |Dilithium & Kyber key support       |
|Verifiable Data Registry |None             |Built-in VDR semantics              |
|Language                 |Various          |Rust (memory-safe, high-performance)|

-----

## Signed Records and Verifiable Data Registry

Each value stored in the DHT is a **structured signed record** with the following layout:

```
algorithm (12 bytes) | signature | DID Document (canonical JSON)
```

This structure allows any peer to:

- Verify the **authenticity** of stored data using the public key embedded in the DID Document
- Verify the **integrity** of the record against its signature
- Operate without trusting any single node or coordinator

Signature validation is handled automatically by the integrated verifier at insertion and retrieval time.

-----

## Network Layer & Application-Level Fragmentation

Since Post-Quantum Cryptography (PQC) records—containing Dilithium signatures and Kyber keys—often exceed the standard UDP MTU, **AuthKademlia-RS** implements a custom application-level fragmentation and reassembly system.

This ensures that messages remain within safe network limits, avoiding unreliable IP-level fragmentation and improving delivery rates across different network topologies.

### The Message Pipeline

When a node publishes or retrieves a record, the data passes through a structured lifecycle:

1.  **Serialize**: The record is serialized using `bincode` for high-performance binary encoding.
2.  **Split**: The payload is split into chunks of up to **1400 bytes** each, every chunk prefixed with a `KADF` header. A typical Dilithium-2 record (~6 KB) produces 5 fragments.
3.  **Send**: Fragments are transmitted independently from sender to receiver.
4.  **Recv**: The receiver populates a `ReassemblyMap` keyed by `(peer_addr, frag_id)`; slots fill as fragments arrive.
5.  **Assemble**: Once all fragments are received, they are concatenated in index order.
6.  **Dispatch**: The reassembled payload is deserialized and dispatched (e.g. `rpc_store()`), followed by cryptographic signature verification.
7.  **Response**: A result message is sent back to the sender to acknowledge the operation.

### Wire Format

Each UDP datagram sent by this layer has the following layout (all multi-byte integers big-endian):

```
[magic: 4 B "KADF"][frag_id: 4 B u32][index: 2 B u16][total: 2 B u16][payload: variable]
```

Total header: **12 bytes**. `frag_id` is unique per logical message per sender. `index` is 0-based; `total` is the number of fragments (≥ 1). When `total == 1` the datagram carries the entire frame.

By inspecting fragments you can identify the internal composition of a PQC record:
* **Dilithium-2 signature** (2420 B): spans roughly the first two fragments.
* **DID Document JSON** (with base64-encoded Kyber/Dilithium public keys): in the remaining fragments.

-----

## Record Consistency and Lifetime

AuthKademlia-RS uses a bounded consistency group without adding versions,
timestamps, or new fields to the wire protocol. With the default
`alpha = 3`, consistency decisions require a strict **2-of-3 majority** of
byte-identical records. The Dilithium signature is verified once, after a
winner has been selected; a split with no strict majority returns no value.

- **Local DID Document GET:** a valid local record is returned immediately.
  This preserves the low-latency Kademlia fast path and does not trigger a
  network quorum.
- **Remote DID Document GET:** when there is no local record, the node follows
  the normal iterative Kademlia lookup, querying the closest uncontacted peers
  in rounds and incorporating closer peers returned by misses. At most three
  record-bearing responses become votes; only a strict majority is returned.
- **Status List GET:** because the issuer Status List changes more frequently,
  it always uses the consistency group. A local copy contributes one vote and
  at most two remote records become additional votes. Discovery remains
  iterative; the local copy never causes an immediate return by itself.
- **UPDATE:** updates are propagated best-effort to the nodes discovered by the
  Kademlia crawl. Success is determined by a strict majority of the primary
  consistency group, capped at `alpha`. When the local node is a responsible
  replica, its verified prospective value participates in that group, but the
  local write is committed only after quorum is reached.
- **TTL:** records written to the default storage expire lazily after 14 days.
  Applications that need continued availability must refresh them through a
  legitimate publish or update before expiry.

This design deliberately keeps the existing RPC and record formats unchanged.
It reduces the risk of selecting a stale remote replica while avoiding version
metadata and the associated per-candidate signature verification cost.

-----

## Performance & Concurrency

| Mechanism | Detail |
|---|---|
| **Concurrent storage** | `DashMap` replaces `IndexMap + RwLock`. Storage operations on different keys are fully parallel with no single global lock. |
| **Lazy TTL expiry** | Records expire after 14 days by default. Expired entries are filtered at read time instead of an O(n) scan on every write. |
| **Signature cache** | `SignatureCache` (moka, SHA-256 keyed, TTL 1 h, 4096 entries). Repeated reads of the same record pay full Dilithium cost only once; subsequent reads are O(1). Any byte-level change forces full re-verification. |
| **Worker pool** | UDP receive loop dispatches via round-robin into `available_parallelism()` workers, each with a dedicated `mpsc::channel(256)`. `try_send` is attempted on each worker in turn; if all are full the loop awaits the base worker, providing backpressure without drops. |
| **Fire-and-forget routing** | Routing table updates (`welcome_if_new`) are spawned as background tasks in all RPC handlers. RPC responses are sent immediately without waiting for routing convergence. |
| **Replication filter** | On node join, only nodes XOR-closer to a key than the new node replicate it (Kademlia §2.5). Prevents redundant store RPCs from far-away nodes. |
| **Atomic insert** | `rpc_store` uses a DashMap `Entry`-based `insert_if_absent` — eliminates the TOCTOU race window that existed with the old read-then-write pattern. |

-----

## Concurrency Architecture

AuthKademlia-RS uses a two-layer concurrency model that separates
**async I/O** (Tokio tasks) from **CPU-bound work** (OS blocking threads).
Understanding the distinction matters on embedded hardware where both
cores and memory are scarce.

### Thread types

| Type | Created by | Scheduled by | Count | Used for |
|---|---|---|---|---|
| **Worker thread** (OS) | Tokio runtime at startup | Kernel | `available_parallelism()` | Executing async tasks |
| **Blocking thread** (OS) | Tokio on-demand | Kernel | ≤ `available_parallelism()` | Dilithium verification |
| **Task** (coroutine) | `tokio::spawn` | Tokio scheduler | Many | All async logic |

Worker threads and blocking threads are real OS threads visible to the
kernel. Tasks are lightweight state machines allocated on the heap —
they have no dedicated OS thread and consume no CPU when suspended on
`.await`.

### Runtime layout

```
Hardware proxy (N cores)
│
├─ Tokio worker threads  [OS threads, N = available_parallelism()]
│   Each runs a loop:  pick next ready task → poll it → repeat
│   Tasks yield at every .await, freeing the thread immediately.
│
└─ Tokio blocking pool  [OS threads, max = available_parallelism()]
    Created on-demand for spawn_blocking (Dilithium verify/sign).
    Capped via max_blocking_threads() — see runtime configuration.
```

### UDP receive pipeline

```
Network
  │  UDP datagram arrives
  ▼
Kernel  ──epoll──►  Tokio wakes {recv loop task}
                        │
                        │  recv_from() → (bytes, peer)
                        │  copy bytes into owned Vec
                        │  try_send round-robin to worker channel
                        │
                        ▼
              ┌─────────────────────────────────────────┐
              │  mpsc channels  (256-slot each)         │
              │  tx0 ──► [ ] [ ] [ ] ──► rx0            │
              │  tx1 ──► [ ] [ ] [ ] ──► rx1            │
              │  tx2 ──► [ ] [ ] [ ] ──► rx2            │
              │  tx3 ──► [ ] [ ] [ ] ──► rx3            │
              └─────────────────────────────────────────┘
                        │
                        ▼
              {worker task 0..N}  (one per channel)
                  rx.recv().await  — suspended when channel empty
                        │
                        ▼
                  handle_datagram()
                        │
                        ├─ response / ping / find_node
                        │   O(µs), no blocking work
                        │   task completes, returns to rx.recv()
                        │
                        └─ store / update / delete
                            verify_for_key()
                              spawn_blocking(Dilithium)
                              .await  ← task suspended, worker thread FREE
                                          │
                                          ▼
                                    Blocking OS thread
                                    Dilithium verify  (~5–50 ms on ARM)
                                          │
                                          ▼
                              task resumes on any free worker thread
                              storage.insert_if_absent()
                              send_frame(response)
```

**Key property:** when a worker task suspends on `.await` — waiting for
a channel, a lock, a network reply, or a blocking thread — the OS thread
that was executing it is immediately reused for another task. At any
given instant, the number of OS threads in use never exceeds
`worker_threads + max_blocking_threads = 2 × available_parallelism()`.

### Backpressure

When all worker channels are full (all workers busy, all queues at 256
entries) the recv loop suspends on `channel.send().await` instead of
dropping the datagram or spawning an unbounded number of tasks. The
system slows down gracefully under burst load without packet loss or
memory growth.

```
Normal load:   recv_from → try_send → Ok  (O(1), no allocation)
Burst load:    recv_from → try_send → Err (all full)
                         → send().await   (recv loop suspended)
                         ← worker drains one slot
                         → resumes, inserts datagram
```

### Signature cache interaction

The `SignatureCache` (moka, SHA-256 keyed, TTL 1 h) lifts most GET
operations entirely out of the blocking pool:

```
GET cold:  SHA-256(record) → cache miss → spawn_blocking(Dilithium) → cache.insert
GET warm:  SHA-256(record) → cache hit  → return immediately  (no blocking thread)
```

On a proxy that authenticates the same devices repeatedly, the warm
path dominates and the blocking pool stays nearly idle.

-----

## Throughput & Benchmarks

### Throughput limits

Each `set` → `get` round-trip includes a full Dilithium-2 signature verification
(~5 ms CPU time on a modern x86 core). Peak verification throughput scales linearly
with core count — approximately `N_cores / 5 ms` unique verifications per second.

The `SignatureCache` substantially raises the practical ceiling: once a record has
been verified once, subsequent reads return the cached result in O(1) time with no
blocking work.

### Signature cache benchmark

`examples/cache_bench.rs` measures two isolated phases:

- **Phase 1 — DHT SET throughput**: two sequential clusters (cached vs uncached) running real network operations with no CPU contention between them.
- **Phase 2 — Signature verification micro-benchmark**: records injected directly into local storage, sequential `get()` calls, zero network variance. Isolates the exact Dilithium-2 vs cache-hit cost.

The expected behaviour:
- *GET cold*: cache miss → SHA-256(record) + `moka.get()` miss + `spawn_blocking(Dilithium-2)` + `moka.insert()`. The SHA-256 overhead is small relative to Dilithium (~5 ms); on first read the cached node pays a marginal extra cost.
- *GET warm*: cache hit → SHA-256(record) + `moka.get()` → result returned immediately. No blocking work. Speedup is proportional to the Dilithium-2 cost on the target hardware.
- *DHT SET*: dominated by network round-trip; cache has negligible effect on write throughput.

Run `cargo run --release --example cache_bench` to collect measurements on your
own hardware (fixed at 10 000 ops, c=30 for DHT SET; 500 ops sequential for the
micro-benchmark). The cache can be disabled per-node by passing `use_cache: false`
to `Server::new` for benchmarking or security auditing.

### Routing topology diagnostic

`examples/topology_analysis.rs` builds an in-process cluster of N nodes, stores M records, then emits eight diagnostic sections that verify Kademlia routing correctness without any mocks:

| Section | What it checks |
|---|---|
| **Node discovery** | Each node lists the peers it found after bootstrapping |
| **Routing table size** | Peer count per node — confirms convergence |
| **Sample DID Documents** | 3 raw records stored in the DHT |
| **Storage per node** | Which keys each node holds |
| **Replication summary** | Copy-count distribution across the cluster |
| **XOR correctness** | For each sampled record: are the k XOR-closest nodes the ones actually storing it? |
| **Bucket structure** | Per-node bucket tree — index, node count, depth, fresh/lonely, range start |
| **Flat routing tables** | Full peer list per node with IP:port |

The XOR-correctness check is the key invariant: it sorts all nodes by XOR distance to each record's key and verifies that the k-closest nodes are the holders. Each record is labelled `[✓]` (all k-closest hold it), `[~]` (partial), or `[✗]` (none of the k-closest hold it).

```bash
# k=3 replication factor, 30 nodes, 100 records (default)
cargo run --release --example topology_analysis -- 3 30

# smaller cluster for quick inspection
cargo run --release --example topology_analysis -- 3 10
```

The bucket-structure section also reports convergence quality: average buckets per node should approach log₂(N) for a well-converged cluster.

### Resilience &amp; robustness tests (Docker)

`resilience/` contains three Docker-based scenarios that measure crash resistance,
security invariants, and performance degradation under adversarial load.
Node A is capped at **2 CPU cores / 256 MB RAM** to simulate a constrained
embedded edge device; Node B is unconstrained so it can fully saturate Node A's
CPU budget.

| Scenario | Tool | Purpose |
|----------|------|---------|
| Single adversarial run | `docker compose up --build` | Verify security invariants and basic survivability |
| Statistical benchmark | `run_stats.py` | N runs with mean, std, and Student-t confidence intervals |
| Degradation sweep | `degradation_sweep.py` | Acceptance rate, p95 latency and throughput vs attacker concurrency |

```bash
cd resilience

# single run
docker compose up --build

# 10-run statistical analysis (95 % CI)
python3 run_stats.py --no-build

# degradation curve across concurrency levels
python3 degradation_sweep.py --no-build
```

See **[`resilience/README.md`](resilience/README.md)** for full documentation:
test methodology, metric definitions, expected degradation behaviour, environment
variables, and output format.

**Why Docker and not a single-process benchmark:** attacker and victim running in the
same process share a Tokio runtime, so the attacker's CPU load directly degrades the
victim's async executor — not a realistic model. Separate containers give each node
its own runtime and let the OS scheduler arbitrate CPU time fairly, while
`deploy.resources.limits.cpus` constrains Node A independently of Node B.

-----

## DID:IIoT Integration

This implementation is designed to interoperate with the [`did:iiot` method](https://github.com/fratrung/did-iiot), an open DID method targeting **Industrial IoT** environments.

DID Documents stored in the DHT embed **post-quantum public keys** (Dilithium for authentication, Kyber for key exchange), enabling:

- Secure device authentication
- Post-quantum key exchange
- Verifiable credential issuance and resolution

A complete end-to-end integration example is available at [fratrung/did-iiot-dht](https://github.com/fratrung/did-iiot-dht).

-----

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
authkademlia-rs = { git = "https://github.com/fratrung/auth-kademlia-rs" }
```

-----

## Example

```rust
use std::sync::Arc;
use std::path::PathBuf;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use pqcrypto_traits::kem::PublicKey as KemPublicKey;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

/// Encode a raw public key as base64url (no padding).
fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// Serialize a DID Document to canonical JSON bytes (sorted keys, no spaces).
fn encode_did_document(doc: &Value) -> Vec<u8> {
    // serde_json does not guarantee key order on serialization of arbitrary
    // Value objects, so we convert to a BTreeMap-backed Value first.
    let canonical = sort_json_keys(doc);
    serde_json::to_vec(&canonical).expect("DID Document serialization failed")
}

/// Recursively sort all object keys so serialization is deterministic.
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

/// Build the signed record:
///
/// ```text
/// | algorithm (12 bytes, null-padded) | Dilithium signature | DID Document (JSON) |
/// ```
fn build_signed_record(
    doc: &Value,
    secret_key: &dilithium2::SecretKey,
    algorithm: &str,
) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    // Pack algorithm into exactly 12 bytes (UTF-8, null-padded on the right).
    let mut alg_field = [0u8; 12];
    let alg_bytes = algorithm.as_bytes();
    let copy_len = alg_bytes.len().min(12);
    alg_field[..copy_len].copy_from_slice(&alg_bytes[..copy_len]);

    // Sign using the detached API — returns only the signature bytes.
    let detached_sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let signature = detached_sig.as_bytes();

    // Concatenate: alg_field || signature || doc_bytes
    let mut record = Vec::with_capacity(12 + signature.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(signature);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Generate a `did:iiot` URI using a random UUID v4.
fn generate_did_iiot() -> String {
    format!("did:iiot:{}", Uuid::new_v4())
}

/// Build a minimal `did:iiot` DID Document with one Dilithium and one Kyber key.
fn build_did_document(
    did: &str,
    dilithium_pk: &dilithium2::PublicKey,
    kyber_pk: &kyber512::PublicKey,
) -> Value {
    let dilithium_x = base64url_encode(dilithium_pk.as_bytes());
    let kyber_x = base64url_encode(kyber_pk.as_bytes());

    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Dilithium2",
                    "x": dilithium_x
                }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Kyber512",
                    "x": kyber_x
                }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "keyAgreement":   [ format!("{}#k1", did) ],
        "service": [
            {
                "id": format!("{}#device", did),
                "type": "DeviceAgent",
                "serviceEndpoint": "http://example.com/device"
            }
        ]
    })
}

async fn start_node(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer.bin")));
    // use_cache=false: signature cache disabled for this example.
    // Pass true to enable the SignatureCache (recommended in production).
    let mut server = Server::new(handler, 20, 3, None, None, false);
    server.listen(port, "127.0.0.1").await.expect("failed to bind");
    server
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let node_1 = start_node(5678).await;
    let node_2 = start_node(5679).await;

    node_2.bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;

    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let (kyber_pk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let did_doc = build_did_document(&did, &dilithium_pk, &kyber_pk);
    let dht_key = did.split(':').next_back().expect("invalid DID").to_string();
    let signed_record = build_signed_record(&did_doc, &dilithium_sk, "Dilithium-2");

    match node_2.set(&dht_key, signed_record).await {
        Some(true) => println!("Record published under key {}", dht_key),
        _ => { eprintln!("Failed to publish record"); return Ok(()); }
    }

    match node_1.get(&dht_key).await {
        Some(record) => {
            let doc_start = 12 + dilithium2::signature_bytes();
            if let Ok(doc) = serde_json::from_slice::<Value>(&record[doc_start..]) {
                println!("Retrieved DID: {}", doc["id"]);
            }
        }
        None => eprintln!("Record not found"),
    }

    Ok(())
}

```

## Tokio runtime configuration

`auth_kademlia_rs` does not create a Tokio runtime — the caller owns it. Dilithium-2
verification is CPU-bound and runs on Tokio's blocking thread pool via `spawn_blocking`.
On embedded hardware (2–4 core ARM SoCs) the default pool cap of 512 threads causes
unnecessary context-switching overhead. Cap it to the number of physical cores:

```rust
fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)  // bounds concurrent Dilithium verifications
        .enable_all()
        .build()
        .unwrap()
        .block_on(run())
}
```

This setting is already applied in `scripts/dht_node.rs` (the Docker entry point) and
in all examples under `examples/`. If you embed the library in your own binary, apply
the same builder pattern instead of `#[tokio::main]`.

## Logging

AuthKademlia-RS uses the [`log`](https://docs.rs/log) crate with [`env_logger`](https://docs.rs/env_logger) as the backend. To enable debug output in your application:

```rust
env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
```

When running tests or the binary directly, use the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug cargo test -- --nocapture
RUST_LOG=auth_kademlia_rs=trace cargo run --bin dht_node
```

-----

## Python Bindings (experimental)

An optional Python extension can be built with [maturin](https://github.com/PyO3/maturin):

```bash
maturin develop --features python
```

> **Note:** The `python` feature builds a `cdylib` target via PyO3. Do **not** enable it in Rust-only deployments — the `cdylib` crate type changes linking behaviour and is unnecessary outside of Python extension builds. The Python bindings are experimental and not covered by the same stability guarantees as the Rust API.

-----

## Related Projects

- [AuthKademlia](https://github.com/fratrung/AuthKademlia) — original Python implementation
- [did:iiot](https://github.com/fratrung/did-iiot) — DID method for Industrial IoT
- [did-iiot-dht](https://github.com/fratrung/did-iiot-dht) — end-to-end integration example

-----

## AI-Assisted Development Disclosure

This project was developed with technical support from **GPT-5.6 SOL** and
**FABLE 5**. These AI agents supported design discussions, implementation, and
test development; they were not the originators or generators of the project's
ideas, goals, or core architectural direction. Those originated with the human
maintainer. Architectural and protocol alternatives were discussed with AI,
but every design decision was made and accepted by the human maintainer, who
retains full responsibility for the result.

The resulting code was reviewed at the functional and architectural level.
Line-by-line human review was focused on critical paths, including protocol
consistency, cryptographic verification, authenticated mutations, and storage
behaviour. AI assistance and automated tests support the review process but do
not constitute a guarantee of correctness or security.
