# AGENTS.md — auth-kademlia-rs

## What this is
Kademlia DHT in Rust with **authenticated records**: every stored value is a
self-signed DID Document (post-quantum: Dilithium-2 signature + Kyber-512 key
agreement). Nodes accept a record only if the embedded signature is valid;
updates and deletes require a second auth-signature produced with the owner's
private key.

**Target platform**: edge/embedded nodes (ARM multi-core, low per-core frequency)
for the `did:iiot` method. The Rust core is the performance-critical layer:
Dilithium-2 verification is CPU-bound (~5 ms on x86) and Python's GIL would
serialise it to a single core. The PyO3 binding releases the GIL before
entering Rust so all available cores can verify signatures in parallel.
Application-layer logic (provisioning, REST APIs, orchestration) remains in Python.

## Build & test
```
cargo build                          # library + dht_node binary
cargo build --bin dht_node           # only the Docker entry point
cargo test                           # all 194 tests
cargo test <name>                    # single test, e.g. test_delete_did_record
RUST_LOG=debug cargo test -- --nocapture   # verbose output
```

Python extension (maturin, optional — do not use in Rust-only deployments):
```
maturin develop --features python
```

### Python binding usage notes (`src/py_bindings.rs`)

- The module configures its Tokio runtime automatically at import, with
  `max_blocking_threads = available_parallelism()`. `init_runtime()` remains an
  idempotent compatibility hook; callers no longer need to invoke it.
- All methods returning binary data (`get_public_key`, `get_private_key`, `sign`,
  `generate_keypair`) return `PyBytes` / `(PyBytes, PyBytes)` — Python callers
  receive native `bytes` objects directly, no implicit list conversion.
- Key generation, signing, verification, and key-file I/O release the Python
  GIL. Async `Server` methods execute on Tokio and do not hold the GIL while the
  Rust future is running.
- `Server.get()` returns `bytes | None` (not `list | None`).
- `Server.set_detailed()` returns the publication status/reason and replica
  counters as a Python `dict`; `Server.stats()` exposes routing, storage-budget,
  and signature-cache counters.
- `Server(sig_cache=True/False)` controls the Dilithium signature cache (default
  `False`). Pass `sig_cache=True` to enable it in production for repeated-record
  workloads.

## Tokio runtime — caller responsibility

`auth_kademlia_rs` does **not** create a Tokio runtime. The caller must build one and
pass execution into it. To cap the blocking thread pool (used for Dilithium
`spawn_blocking` calls) to the number of physical cores — critical on embedded nodes:

```rust
fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run())
}
```

**Never use `#[tokio::main]`** in entry points that host `Server` — it uses the
default cap of 512 blocking threads, which thrashes the CPU on low-core SoCs.
`scripts/dht_node.rs` and all `examples/` already apply this pattern.

## Module map
| File | Role |
|---|---|
| `src/protocol.rs` | UDP transport, fragmentation, RPC dispatch (`rpc_store`, `rpc_update`, `rpc_delete`, `rpc_find_node`, `rpc_find_value`) |
| `src/network.rs` | Public `Server` API: `set/get/update/delete`, bootstrap, refresh loop |
| `src/crawling.rs` | Iterative lookup — `NodeSpiderCrawl` (find nodes) + `ValueSpiderCrawl` (find value) |
| `src/routing.rs` | Kademlia routing table + k-buckets (XOR distance, bucket splits); `KBucket` holds a primary LRU list + `replacement_nodes` overflow (§4.1); `TableTraverser` visits buckets in XOR-proximity order (mirrors Python AuthKademlia exactly); `touch_last_updated()` is called **only** by `TableTraverser` — bucket staleness reflects lookup activity, not node additions |
| `src/storage.rs` | `ForgetfulStorage` — sharded concurrent TTL KV store (`DashMap`); 14-day TTL and configurable byte budget (default 512 MiB), with lazy expiry on read |
| `src/signature_cache.rs` | `SignatureCache` — moka bounded cache (SHA-256 key, TTL 1 h, 4096 entries) for Dilithium verification results |
| `src/fragmentation.rs` | KADF fragmentation + reassembly (`encode_fragments`, `parse_fragment`, `ReassemblyMap`) |
| `src/auth_handler.rs` | `SignatureVerifierHandler` trait + `DIDSignatureVerifierHandler` (DID record verification) |
| `src/crypto/signature_verifier.rs` | `SignatureVerifier` trait, `resolve_alg_and_length()`, algorithm registry |
| `src/crypto/factory.rs` | `SignatureVerifierFactory` + `SignerFactory` — dispatch by algorithm string |
| `src/crypto/dilithium.rs` | Dilithium-2/3/5 verifier + signer |
| `src/crypto/ed25519.rs` | Ed25519 verifier + signer |
| `src/crypto/rsa.rs` | RSA verifier + signer |
| `src/crypto/key_manager.rs` | `KeyManager` — keypair generation, storage, sign/verify helpers |
| `src/node.rs` | `Node` struct, full **160-bit** XOR distance (`long_id: U256`, no folding), `from_id`; `NodeHeap` shortlist backed by a distance-sorted `Vec`; `Display` shows `ip:port` for real peers, `<key:hex8>` for key-space targets |
| `src/utils.rs` | `digest()` (SHA-1 → `[u8; 20]`), `digest_bytes()`, `ID_LEN = 20`, `STATUS_LIST_KEY` |
| `scripts/dht_node.rs` | Docker container entry point (`publisher` / `retriever` roles) |
| `tests/common/mod.rs` | Shared test helpers: `start_node`, `build_did_document`, `build_signed_record`, `generate_did_iiot` |

## Wire record format
```
| algorithm  (12 B, null-padded UTF-8) |
| signature  (2420 B for Dilithium-2)  |
| DID Document (JSON, canonical/sorted keys) |
```
The algorithm field drives `resolve_alg_and_length()` in
`src/crypto/signature_verifier.rs` to pick the right verifier and signature
length. Supported: `Dilithium-2/3/5` (2420/3293/4595 B), `Ed25519` (64 B), `RSA` (256 B).

## Application-level fragmentation (`src/fragmentation.rs`)
Large PQ records (~6 KB) are split into 1400-byte chunks before sending.
Wire format per UDP datagram (all integers big-endian):
```
[magic: 4 B "KADF"][frag_id: u32 4 B][index: u16 2 B][total: u16 2 B][payload]
```
Total header: **12 bytes**. `frag_id` is unique per logical message per sender.
`index` is 0-based; `total` is the number of fragments (≥ 1).
Constants: `FRAG_CHUNK_SIZE=1400`, `FRAG_HEADER_LEN=12`,
`MAX_MESSAGE_SIZE=256 KB`, `REASSEMBLY_TTL=10 s`.
`handle_datagram()` in `protocol.rs` reassembles transparently before deserialising.
Oversized messages (projected size > `MAX_MESSAGE_SIZE`) are discarded before
entering the reassembly buffer to bound memory usage.

## RPC message types (`src/protocol.rs`)
| Variant | Direction | Purpose |
|---|---|---|
| `Ping` / `Pong` | req/resp | Liveness check + node discovery |
| `Store` / `StoreResult` | req/resp | Store an authenticated record; result is `Stored`, `AlreadyStored`, `Conflict`, `CapacityExceeded`, or `InvalidRecord` |
| `Update` / `UpdateResult` | req/resp | Key-rotation update (requires `auth_signature`) |
| `UpdateStatusList` / `UpdateStatusListResult` | req/resp | Issuer-signed status-list update |
| `Delete` / `DeleteResult` | req/resp | Authenticated record deletion |
| `FindNode` / `FindNodeResult` | req/resp | Kademlia FIND_NODE |
| `FindValue` / `FindValueHit` / `FindValueNodes` | req/resp | Kademlia FIND_VALUE |
| `Leave` | fire-and-forget | Graceful departure, removes node from routing table |

All RPCs are serialised with `bincode` and framed with a `(msg_id: u32, is_request: bool, message)` envelope. Responses are correlated via `msg_id` through a `PendingMap`.

## Concurrency model
- `ForgetfulStorage` is `Arc<ForgetfulStorage>` (no outer `RwLock`). All `IStorage` methods take `&self`; internal synchronization via `DashMap` shards.
- `rpc_store` uses `insert_if_absent` (DashMap `Entry` API) with atomic global byte reservation. Identical bytes are idempotent; different bytes conflict; active records are never evicted for capacity.
- All RPC handlers use `self: &Arc<Self>` receiver to enable `tokio::spawn` without cloning the full struct. `welcome_if_new` is always fire-and-forget.
- UDP receive loop dispatches via round-robin to `available_parallelism()` fixed workers, each with a dedicated `mpsc::channel(256)`. `try_send` is attempted on each worker in order; if all channels are full the receive loop awaits the base worker (backpressure without drops). Zero allocations per datagram beyond the payload copy.
- Blocking thread pool (`spawn_blocking`) is bounded at the runtime level via `max_blocking_threads(available_parallelism())` in `scripts/dht_node.rs`. This caps concurrent Dilithium verifications to the number of physical cores, covering all call sites uniformly (`verify_for_key`, `verify_value`, `update`, `delete`). `KademliaProtocol` carries no application-level semaphore.
- `SignatureCache` is keyed on `SHA-256(record_bytes)`. TTL 1 h, capacity 4096 (moka TinyLFU). Eviction = cache miss = full re-verification (never a security bypass). On a cache miss the SHA-256 key is computed once via `compute_key()` and reused for both `get_by_key` and `insert_by_key` — never twice.
- `welcome_if_new` replication uses two conditions (Kademlia §2.5, matches Python AuthKademlia): `new_node_close` (new node is XOR-closer than the farthest k-neighbor) AND `this_closest` (this node is closer than the nearest k-neighbor). Both must be true to replicate. Neighbors are computed before `add_contact` so the new node is excluded from comparisons.
- `schedule_stats_log()` emits a `[stats]` log line every 60 s: routing table size, storage record count, used/max storage bytes, and (when enabled) signature cache entries.
- **Routing table internals** (`src/routing.rs`): `KBucket.add_node()` does **not** update `last_updated` — matches Python AuthKademlia behaviour where only lookups reset the timer. `touch_last_updated()` (called by `TableTraverser` on the central bucket during every `find_neighbors`) is the sole update point. `find_neighbors` uses `TableTraverser` with early-stop at k and excludes `target.id` — identical logic to Python's `find_neighbors + heapq.nsmallest`. Split condition §4.2: `covers(local_node) OR depth % 5 != 0`.

## Key invariants
- Records are **immutable after creation**: byte-identical STORE retries return `AlreadyStored`; different bytes for the same key return `Conflict`.
- A new `set()` reuses the nodes from one `ValueSpiderCrawl`. An identical retry performs node discovery so missing replicas can be completed. Remote candidates plus the local node are XOR-sorted and truncated to `k`, preventing `k+1` copies.
- Remote DID GET quorum is derived from `alpha` and is not independently
  configurable. With `alpha = 3`, two byte-identical record responses are
  required. In the diagnostic `k = 3, alpha = 3` topology, reaching only one
  holder therefore returns `None` even when that copy is valid; occasional
  randomized GET misses can reflect this narrow quorum plus transient routing
  convergence rather than an XOR-distance defect.
- Updates require `auth_signature = sign(new_record_bytes, old_private_key)`.
  `verify_key_rotation()` checks: (1) auth_sig valid under old public key, (2) new record self-signed.
  **Downgrade attacks are impossible**: to submit `record_v1` as "new" when `record_v2`
  is stored, an attacker would need to sign with `sk_v2` — which they do not possess.
- Deletes require `auth_signature = sign(delete_msg, owner_private_key)`.
- DHT key = `digest(did_uuid_string)` where `digest` is SHA-1 → `[u8; 20]`.
- XOR distance is computed over the **full 160-bit id** (`Node.long_id: U256`,
  `primitive-types`) — **no folding**. Distinct ids never collide and the
  distance order is total/canonical, matching Python's arbitrary-precision
  `int(node_id.hex(), 16)`. Bucket ranges (`routing.rs`) are `U256` over
  `[0, 2^160)`. Never reintroduce a `u128` projection — it inverts ordering
  and collides ids.
- `STATUS_LIST_KEY = digest("did:iiot:status-list")` uses issuer-node
  verification instead of DID-owner verification.
- `issuer.bin` is read lazily; if absent, a `log::warn!` is emitted at startup
  and only `STATUS_LIST_KEY` operations are affected (normal DID records are not).

## Test suite structure
| File | Count | Notes |
|---|---|---|
| `tests/network_tests.rs` | 11 | Full multi-node integration tests (real UDP) |
| `tests/crypto_tests.rs` | 27 | Crypto layer unit + DID handler unit tests |
| `tests/routing_tests.rs` | 20 | Routing table unit tests |
| `tests/storage_tests.rs` | 17 | `ForgetfulStorage` unit tests (includes `insert_if_absent` cases) |
| `tests/dht_integration.rs` | 1 | Legacy 3-node end-to-end scenario |
| `tests/scenarios/replication.rs` | 1 | welcome_if_new replication (3-node join) |
| `tests/scenarios/cache.rs` | 2 | SignatureCache hit-rate + false caching |
| `tests/scenarios/churn.rs` | 1 | Publisher leaves, record survives for new joiner |
| `tests/scenarios/worker_pool.rs` | 1 | 40-client burst, all responses delivered |
| `tests/scenarios/crypto.rs` | 4 | End-to-end crypto invariants (tamper, injection, downgrade, revocation) |
| `tests/quorum_tests.rs` | 7 | Real-UDP quorum, multi-hop lookup, local fast-path, Status List, and delayed UPDATE commit scenarios |
| `src/**` (inline) | 102 | Module-level `#[test]` blocks (incl. Kademlia convergence, strict-quorum selection, 160-bit XOR-metric regression, and fragmentation tests) |

All tests are network-clean (loopback only) and run in parallel without interference when port ranges are respected.

## Test port allocation (run in parallel — do not reuse)
| Range | Test |
|---|---|
| 15700–15701 | two-node bootstrap |
| 15710–15711 | cross-node set/get |
| 15720–15721 | idempotent SET retry + conflicting value rejection |
| 15730–15732 | key-rotation update |
| 15740–15741 | authenticated delete |
| 15750 | invalid signature rejection |
| 15760 | unreachable peer |
| 15780–15781, 15885 | update rejected on invalid new-record self-signature (three replicas) |
| 15782–15784 | update rejected when auth_sig uses wrong key |
| 15785–15786, 15884 | delete rejected when signature uses wrong key (three replicas) |
| 15787–15789 | scenario: welcome_if_new replication (A, B, C) |
| 15790 | scenario: signature cache hit rate |
| 15792–15795 | scenario: churn survivability (A seed, B publisher, C stays, D new joiner) |
| 15800–15840 | scenario: worker pool burst (target + 40 clients) |
| 15810–15817 | cache_bench example (Phase 1 + Phase 2 clusters) |
| 15810–15839 | topology_analysis example (30-node cluster) — **do not run simultaneously with cache_bench** |
| 15860–15861 | scenario: tampered payload / algorithm injection rejected |
| 15862–15863, 15886 | scenario: downgrade attack after rotation rejected (three replicas) |
| 15864–15865, 15887 | scenario: revoked key cannot authorise further rotation (three replicas) |
| 15866–15883 | quorum consistency: DID GET, Status List GET, and UPDATE commit |
| 15888–15894 | quorum consistency: iterative multi-hop DID GET |
| 15895–15896 | degraded SET report when one responsible node is at capacity |

When adding a new integration test use ports **15897+** and document them here (15900 is reserved below).

| 15900 | resilience test: Node A victim (host-exposed UDP, Docker only) |

## Examples

### `examples/cache_bench.rs`
Signature-cache benchmark in two isolated phases:
- **Phase 1** — DHT SET throughput (cached vs uncached clusters, no CPU contention).
- **Phase 2** — Dilithium-2 verification micro-benchmark (records injected directly into local storage, sequential `get()` calls, zero network variance).

```bash
cargo run --release --example cache_bench
```

### `examples/topology_analysis.rs`
30-node DHT topology analyser. Publishes 100 authenticated DID records from rotating writers, retrieves each from a node offset by half the cluster size (forcing real multi-hop lookups), then prints:

1. **Latency table** — SET/GET avg, p50, p95, max.
2. **Sample DID Documents** — full JSON of 3 published records.
3. **Storage tables** — which DHT keys live on which node (with DID URI cross-reference).
4. **Replication summary** — copy-count distribution per key.
5. **XOR-distance correctness** — for each sampled record, identifies the k globally-closest nodes (XOR metric) and verifies they actually hold the record (Kademlia §2.3).
6. **Bucket structure** — per-node k-bucket tree: bucket index, range boundaries, node count, depth, fresh/lonely status, and the nodes inside each bucket. Verifies correct binary splitting (§4.2).
7. **Routing convergence** — avg buckets per node vs expected log₂(N); avg peers per node.
8. **Flat routing tables** — full peer list per node for reference.

```bash
# default k=20 alpha=3
cargo run --release --example topology_analysis

# k=3: records replicated only on 3 closest nodes — best for observing XOR correctness
cargo run --release --example topology_analysis -- 3 3

# k=5 with DHT logs
RUST_LOG=info cargo run --release --example topology_analysis -- 5 2
```

Use this example to verify:
- **Routing**: bucket splits occur at the right depth (§4.2), avg buckets ≈ log₂(N).
- **Replication**: records land on the k globally-closest nodes, not arbitrary ones.
- **Convergence**: after 2 bootstrap passes, every node knows ≈ k × log₂(N) peers.

## Docker

### Demo (root `docker-compose.yaml`)
```
docker compose up --build            # 4 containers: seed, peer1, peer2, peer3
docker compose logs -f dht_peer_2   # follow a single container
```
`DEMO_DID_UUID` in `.env` is the shared key for the publisher→retriever demo.
Environment variables per container: `NODE_PORT`, `IS_SEED`, `BOOTSTRAP_ADDR`,
`ROLE` (`publisher`|`retriever`), `FIXED_DID_UUID`, `RETRIEVE_KEY`, `RUST_LOG`.

### Resilience / attack test (`resilience/docker-compose.yaml`)
```
cd resilience
docker compose up --build                         # 120 s attack, Node A capped at 2 cores
DURATION_SECS=300 CONCURRENCY=40 docker compose up --build   # custom intensity
```
Node A (victim) pre-seeds 5 records; Node B (attacker) floods with valid/invalid
SETs and GETs. Final report shows timeout rate and security verdict.
See `resilience/README.md` for full details.

## Adding a new crypto algorithm
1. Implement `SignatureVerifier` (and optionally `Signer`) in `src/crypto/<alg>.rs`.
2. Register in `src/crypto/factory.rs` → `SignatureVerifierFactory::create()` and `SignerFactory::create()`.
3. Add the algorithm string + signature length to `resolve_alg_and_length()` in
   `src/crypto/signature_verifier.rs`.
4. Add tests in `tests/crypto_tests.rs`.

## Session continuity — RESUME_BEFORE_COMPACT.md

When the conversation is approaching context limits and a `/compact` is imminent,
write a file `RESUME_BEFORE_COMPACT.md` in the project root **before** the compact
happens. This file lets the next context window pick up exactly where the session
left off.

The file must contain:
1. **Current task** — what the user is working on right now, in one sentence.
2. **Pending actions** — any commits not yet created, PRs not yet opened, commands
   not yet run, open questions awaiting an answer.
3. **Key decisions made this session** — non-obvious choices and why they were made
   (architecture, algorithm, workaround). Skip anything obvious from the code.
4. **Files changed** — list of modified files with one-line summaries of what changed.
5. **Known issues / blockers** — anything broken, half-finished, or needing follow-up.

Keep it concise (≤ 60 lines). The file is ephemeral: delete it once the first
message of the new session confirms the context has been picked up.

## What NOT to do
- Do not reduce `Node.long_id` below the full 160 bits (e.g. a `u128` fold):
  it silently inverts XOR distance ordering and collides distinct ids. Keep it
  `U256`.
- Do not hold a `Mutex` lock across an `.await` — deadlock risk.
- Do not increase `MAX_MESSAGE_SIZE` without a matching memory-budget review.
- Do not add `unwrap()` in protocol/network paths — use `?` or log + return.
- Do not add new integration tests on already-used port ranges.
- Do not enable the `python` feature in Rust-only deployments (`cdylib` changes linking).
- Do not add an `"updated"` timestamp field to DID Documents for ordering: downgrade
  attacks are already prevented by the auth-signature chain; the field would be
  redundant and would break compatibility with existing records without a migration.
