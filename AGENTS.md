# AGENTS.md — auth-kademlia-rs

## What this is
Kademlia DHT in Rust with **authenticated records**: every stored value is a
self-signed DID Document (post-quantum: an ML-DSA-65 signature, FIPS 204;
ADR 0003). Nodes accept a record only if the embedded signature is valid.
A DID is the hash of its first document, and each version of a DID Document
names the hash of the only key that may sign the next one (ADR 0005): a
replica checks an update against the version before it, with no second
signature. Records have no explicit delete operation and are removed only by
TTL expiry.

**Target platform**: edge/embedded nodes (ARM multi-core, low per-core frequency)
for the `did:iiot` method. The Rust core is the performance-critical layer:
ML-DSA-65 verification is CPU-bound and Python's GIL would
serialise it to a single core. The PyO3 binding releases the GIL before
entering Rust so all available cores can verify signatures in parallel.
Application-layer logic (provisioning, REST APIs, orchestration) remains in Python.

## Build & test
```
cargo build                          # library + dht_node binary
cargo build --bin dht_node           # only the Docker entry point
cargo test                           # all 335 tests
cargo test --features counters       # 339: also the counters' own tests
cargo test --features testbed        # 340: also the testbed's FindHash lie switch
cargo test <name>                    # single test, e.g. test_update_did_record_key_rotation
RUST_LOG=debug cargo test -- --nocapture   # verbose output
```
ML-DSA and ML-KEM come from `aws-lc-rs` (ADR 0003): its C code is built by
the `cc` crate, so a C compiler is needed (no cmake on Linux x86-64/AArch64).

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
- Keys are DIDs (`did:iiot:` and the base64url of the SHA-256 of the first
  document, ADR 0005), not UUIDs.
- `Server.set()` and `Server.set_detailed()` publish only a version 0.
  `set_detailed()` returns the publication status/reason and replica counters
  as a Python `dict`: `stale_rejections` and `newer_claimed` are the replicas
  that hold or were told of a later version (reason `newer_version`); a later
  version passed to them is refused locally (reason `use_update`).
- `Server.update(key, value, earlier)` publishes a version N >= 1: `earlier`
  are the owner's saved versions 0 to N-1, used only to replay the chain to
  replicas that miss versions. Retries resend the same saved bytes; the owner
  calls it again with them at least once every 24 hours.
- `MlDsaKeyManager.keypair_from_seed(seed)` returns the ML-DSA-65 key pair of a
  32-byte seed, the same pair for the same seed: the application keeps only the
  seed of the next key, and `nextKeyHash` is the SHA-256 of its public key.
- `Server.stats()` exposes routing, storage-budget, and signature-cache
  counters.
- `MlKemKeyManager(max_age_secs=30, max_outstanding=64)` gives one ML-KEM-768
  key pair per handshake: `ephemeral_public_key()` returns `(key_id, bytes)`,
  `decapsulate(key_id, ciphertext)` returns the shared secret and destroys the
  pair, and the static `MlKemKeyManager.encapsulate(public_key)` returns
  `(shared_secret, ciphertext)`. It has no method that returns, stores or reads
  a private key; do not add one (ADR 0003).
- `Server(sig_cache=True/False)` controls the ML-DSA signature cache (default
  `False`). Pass `sig_cache=True` to enable it in production for repeated-record
  workloads.

## Tokio runtime — caller responsibility

`auth_kademlia_rs` does **not** create a Tokio runtime. The caller must build one and
pass execution into it. To cap the blocking thread pool (used for ML-DSA
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
| `src/protocol/mod.rs` | `KademliaProtocol`: the struct, its constructor and its tasks; the other files of `protocol/` each hold one part of its methods |
| `src/protocol/messages.rs` | `RpcMessage` (the wire format: variants are encoded by position, so new ones go at the end), `Frame`, `ExpectedResponse` |
| `src/protocol/transport.rs` | Sending and receiving: KADF fragments and reassembly, `call` with its resends, `handle_datagram`, `InProgress` |
| `src/protocol/handlers.rs` | `dispatch_request` and the handlers of every request except STORE (`rpc_update`, `rpc_find_node`, `rpc_find_value`, `rpc_find_hash`, ...); verification of a record for a key |
| `src/protocol/store_check.rs` | `rpc_store` and the network check of an empty replica (`network_check`: R2 for a version 0, R5 with the fetch of the version before for a later one) |
| `src/protocol/acceptance_tests.rs` | Tests of the STORE and UPDATE rules against neighbours that hold, claim, serve or keep silent |
| `src/protocol/client.rs` | Outgoing calls (`call_*`) and `SpiderProtocol`, the requests of the lookups |
| `src/protocol/contacts.rs` | Failing and returning contacts, pings of failing contacts, refresh ids |
| `src/protocol/welcome.rs` | Nodes met through a message: inline routing insert, bounded replication queue |
| `src/protocol/test_support.rs` | Helpers shared by the protocol tests |
| `src/network/mod.rs` | Public `Server` API: the struct, `new`, `listen`, `stop`, `bootstrap`; the other files of `network/` each hold one operation |
| `src/network/publish.rs` | SET of a version 0 (`set`, `set_detailed`) and its report (`SetReport`, `SetOutcome`) |
| `src/network/read.rs` | GET |
| `src/network/update.rs` | UPDATE of a version N >= 1 (`update`, `update_digest`): the owner's chain (`OwnerChain`), the local vote, and the replay to replicas that miss versions (`replay`, `fill_empty_replica`) |
| `src/network/maintenance.rs` | Refresh and republication, recovery tick, stats (`ServerStats`), saved state |
| `src/crawling.rs` | Iterative lookup — `NodeSpiderCrawl` (find nodes) + `ValueSpiderCrawl` (find value; `search` with a deadline tells `NotFound` from `Incomplete`) |
| `src/routing.rs` | Kademlia routing table + k-buckets (XOR distance, bucket splits); `KBucket` holds a primary LRU list + `replacement_nodes` overflow (§4.1); `find_neighbors` returns the exact local top-k across known primary contacts, skipping failing ones (see Concurrency model); `touch_last_updated()` is called only for the bucket containing the lookup target — bucket staleness reflects lookup activity, not node additions |
| `src/storage.rs` | `ForgetfulStorage` — sharded concurrent TTL KV store (`DashMap`); 14-day TTL and configurable byte budget (default 512 MiB), with lazy expiry on read; `insert_if_absent` and `replace_if` (compare and swap under the entry) |
| `src/signature_cache.rs` | `SignatureCache` — moka bounded cache (SHA-256 key, TTL 1 h, 4096 entries) for ML-DSA-65 verification results |
| `src/fragmentation.rs` | KADF fragmentation + reassembly (`encode_fragments`, `parse_fragment`, `accept_fragment`, `ReassemblyMap`) |
| `src/retransmit.rs` | When to send a request again: per-peer round-trip estimate (`RoundTrips`, RFC 6298), `MAX_RESENDS`, bounds of the wait |
| `src/counters.rs` | Datagrams, bytes, resends and STORE checks counted for measurements (feature `counters`, off by default; empty without it) |
| `src/auth_handler/mod.rs` | `SignatureVerifierHandler` trait + `DIDSignatureVerifierHandler` (DID record verification); `verify_record`, `verify_issuer_signed`: how a node runs it (binding first, signature cache, blocking thread), shared by protocol and network |
| `src/auth_handler/did.rs` | The `did:iiot` DID (ADR 0005): canonical suffix, `key_of_did`, canonical JSON, the hashed form of version 0 (`derive_did`), and step 1 of the rules, the form of a record for a key (`record_form`: `seq`, `prev`, `nextKeyHash`) |
| `src/auth_handler/rules.rs` | The STORE and UPDATE rules as pure functions: `decide_locally` against the stored copy (R1, R3, R4), `decide_version_zero` (R2), `decide_successor` and `check_fetched` (R5), `store_quorum` |
| `src/auth_handler/test_chain.rs` | Chains of versions for the unit tests, the DID computed as the Python application computes it |
| `src/crypto/signature_verifier.rs` | `SignatureVerifier` trait, `resolve_alg_and_length()`, algorithm registry |
| `src/crypto/factory.rs` | `SignatureVerifierFactory` + `SignerFactory` — dispatch by algorithm string |
| `src/crypto/mldsa.rs` | ML-DSA-65 from `aws-lc-rs`: `MlDsa65KeyPair` (generate, from a 32-byte seed, sign, raw public key, expanded private key), verifier + signer (pure ML-DSA, empty context), `signature_len()`/`public_key_len()`, `ML_DSA_65` name |
| `src/crypto/ed25519.rs` | Ed25519 verifier + signer |
| `src/crypto/rsa.rs` | RSA verifier + signer |
| `src/crypto/key_manager.rs` | `KeyManager` — keypair generation, storage, sign/verify helpers (`MlDsaKeyManager`, with `keypair_from_seed`; `Ed25519KeyManager`); `MlKemKeyManager` — ephemeral ML-KEM-768 pairs, one per handshake, in memory only, expiring after 30 s, at most 64 given out (ADR 0003) |
| `src/node.rs` | `Node` struct, full **256-bit** XOR distance (`long_id: U256`, no folding), `from_id`; `NodeHeap` shortlist backed by a distance-sorted `Vec`, which keeps every node a lookup met so that one beyond `k` replaces a peer that did not answer (reads see the closest `k`), while `add_reported` takes at most `k` nodes per answer; `Display` shows `ip:port` for real peers, `<key:hex8>` for key-space targets |
| `src/utils.rs` | `digest()` (SHA-256 → `[u8; 32]`), `digest_bytes()`, `ID_LEN = 32`, `STATUS_LIST_KEY` (ADR 0004) |
| `scripts/dht_node.rs` | Docker container entry point (`publisher` / `retriever` roles, the DID passed through `/shared/did`) |
| `tests/common/mod.rs` | Shared test helpers: `start_node`, `build_did_document`, `build_signed_record`, `version0`, `new_did_record`, `key_of`, and `Chain`, the versions of one DID with their keys |
| `testbed/node.rs` | Testbed node (`testbed_node` binary): one DHT node per container, driven through a control socket inside the container; keeps its DID's chain of versions |
| `testbed/testbed.py` | Testbed driver: generates the Docker network, applies `tc netem` profiles, sends commands to nodes |
| `testbed/attack.py` | Testbed attack mode: starts the attacker (`race`, `burst`, `successor`, `spoof`, `persist`) and runs the `race` and `restart` scenarios on a running network |
| `testbed/measure.py` | Testbed measurement mode: publication time and availability (`publish`), rotations with restarted replicas and liars (`update`), copies over time under churn (`churn`) |
| `testbed/attacker.rs` | Testbed attacker (`testbed_attacker` binary): sniffs the host's packets, sends forged versions as STOREs and spoofed `FindHash` answers |
| `testbed/did.rs` | DID records shared by the two testbed binaries: version 0, the versions after it, forged versions |

## Wire record format
```
| algorithm  (12 B, null-padded UTF-8) |
| signature  (3309 B for ML-DSA-65)    |
| DID Document (JSON, canonical/sorted keys) |
```
A node accepts only `ML-DSA-65` records (ADR 0003): `record_algorithm()` in
`src/auth_handler/mod.rs` refuses any other algorithm field, for DID Documents,
key rotations and the Status List. `resolve_alg_and_length()` in
`src/crypto/signature_verifier.rs` gives the signature length, from
`aws-lc-rs` (`mldsa::signature_len()`), never from a literal; it also knows `Ed25519`
(64 B) and `RSA` (256 B), which no record may use. The DID Document holds one
key, an RFC 9964 JWK in `verificationMethod[0]`:
`{"kty": "AKP", "alg": "ML-DSA-65", "pub": <base64url>}`, the raw key: the
verifier refuses a key of another length, such as the DER `SubjectPublicKeyInfo`
that `aws-lc-rs` would also take. A `kty` other than
`AKP` or an `alg` other than the record's algorithm field is `KeyMismatch`
(`InvalidRecord`). There is no `keyAgreement` key: key agreement is ephemeral
ML-KEM, outside the DHT.

Every DID Document (ADR 0005) has `seq`, `prev` (the base64url SHA-256 of the
whole record before it, not in version 0) and `nextKeyHash` (the base64url
SHA-256 of the raw public key that alone may sign the next version), and is in
canonical form: printable ASCII only, integers within ±(2^53 − 1) without
fraction or exponent, and bytes equal to their `serde_json` re-serialization
(sorted keys, no whitespace). A version that commits to its own key is
refused. The DID is `did:iiot:` and the base64url, without padding, of the
SHA-256 of version 0 in hashed form: without `id`, its own DID written as the
placeholder `did:iiot:self` in string values (`derive_did`, `hashed_form` in
`src/auth_handler/did.rs`).

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
`handle_datagram()` in `src/protocol/transport.rs` reassembles transparently before deserialising (`accept_fragment`).
Oversized messages (projected size > `MAX_MESSAGE_SIZE`) are discarded before
entering the reassembly buffer to bound memory usage.

## RPC message types (`src/protocol/messages.rs`)
| Variant | Direction | Purpose |
|---|---|---|
| `Ping` / `Pong` | req/resp | Liveness check + node discovery |
| `Store` / `StoreResult` | req/resp | Store an authenticated record; result is `Stored`, `AlreadyStored`, `Conflict`, `Stale` (a later version is held), `NewerClaimed` (the check was told of a later one), `MissingPrevious`, `CapacityExceeded`, or `InvalidRecord` |
| `Update` / `UpdateResult` | req/resp | Version N >= 1 of a DID, the record only (ADR 0005); result is an `UpdateStatus`: `Updated`, `AlreadyStored`, `MissingPrevious` (the `seq` held, or none), `Stale`, `Conflict`, `CapacityExceeded`, `InvalidRecord` |
| `UpdateStatusList` / `UpdateStatusListResult` | req/resp | Issuer-signed status-list update |
| `FindNode` / `FindNodeResult` | req/resp | Kademlia FIND_NODE |
| `FindValue` / `FindValueHit` / `FindValueNodes` | req/resp | Kademlia FIND_VALUE |
| `FindHash` / `FindHashHit` / `FindValueNodes` | req/resp | `seq` and SHA-256 of the stored record (`record_hash`), asked by an empty replica before a STORE; one datagram. Added after `Leave`, so older nodes cannot decode it |
| `Received` | resp | Receipt for a request carrying a record (`Store`, `Update`, `UpdateStatusList`), sent before the answer and again for each copy that arrives while the request is handled. Added after `FindHashHit` |
| `Leave` | fire-and-forget | Graceful departure, removes node from routing table |

All RPCs are serialised with `bincode` and framed with a `(msg_id: u32, is_request: bool, message)` envelope. Responses are correlated via `msg_id` through a `PendingMap`.

## Concurrency model
- `ForgetfulStorage` is `Arc<ForgetfulStorage>` (no outer `RwLock`). All `IStorage` methods take `&self`; internal synchronization via `DashMap` shards.
- `rpc_store` uses `insert_if_absent` (DashMap `Entry` API) with atomic global byte reservation. Identical bytes are idempotent; active records are never evicted for capacity. A verified successor (R3) replaces the stored record with `replace_if`, a compare and swap under the entry: if the record changed since the rules read it, the handler decides once more, and after a second change it sends no answer. `rpc_update` writes the same way.
- A STORE for a key the node does not hold waits for a lookup (see Key invariants), whose answers arrive through the receive workers. `handle_datagram` therefore runs it in its own task (`spawn_task`) instead of on the worker, and answers when it is done; at most `MAX_STORE_LOOKUPS` (256) wait at once, beyond that the STORE is dropped. Handled on the worker, 8 such STOREs at once left the lookups without their answers and forged records were stored 5/5.
- **Message ids** (ADR 0005, open point 25): each request draws its msg_id at random (`rand`), never one a pending request holds (`fresh_id`, under the lock of the pending map); an answer counts only if its id is pending for the address it comes from. An attacker who does not read the traffic cannot guess one; one who reads it still sees every id.
- **Lost datagrams** (`call`, `src/retransmit.rs`): a request with no sign of its peer after `resend_after` is sent again, same msg_id and fragment id, up to `MAX_RESENDS` (2) times, doubling the wait; the call still ends at `RPC_TIMEOUT`. The wait is 3 round trips of that peer, or smoothed + 4 × variation if larger (RFC 6298), within 20 ms–1 s, and 500 ms for a peer never measured. Only requests sent once are measured (Karn). A request carrying a record gets a receipt (`Received`) before it is handled, so the sender does not resend a 6 KB record while an empty replica runs its network check; after a receipt a copy only asks again for an answer that may have been lost (a stored record then answers `AlreadyStored` at once). The receiver recognises a copy of a request it is still handling by sender address and SHA-256 of the whole request (`InProgress`) and answers it with the receipt only, so a copy never starts a second check; another request under the same msg_id is not a copy. Measured before this (0.5% loss, 30 nodes, k=5): the check refused on a single lost datagram and left 15/40 publications degraded, against 7/40 without the check.
- All RPC handlers use `self: &Arc<Self>` receiver to enable `tokio::spawn` without cloning the full struct.
- **Futurelock** (Oxide RFD 609): the router is a fair `tokio::sync::RwLock`, so a waiting writer blocks later readers. Never keep futures that may wait for the router in a set the task stops polling while it awaits something else that takes the router (a `FuturesUnordered` pulled with `next()` and an await in the loop body, a `&mut future` in `select!`). `ValueSpiderCrawl::search` reads the router between answers (`failing_among`) and writes it at its deadline (`note_no_answer`), while its requests may wait to write it (`schedule_welcome_if_new` adds a node met in an answer): it therefore spawns them in a `JoinSet`. With a `FuturesUnordered` a node of the 127-node testbed stopped answering two seconds after the first publication, and `a_lookup_keeps_polling_a_request_that_waits_for_the_routing_table` hung. `join_all` (`find_round`) keeps polling every future and is safe.
- **Nodes met through a message** (`schedule_welcome_if_new`): the sender enters the routing table inline, before the handler answers (Kademlia §2.2); only sending it its records is deferred. That replication scans the whole storage, so it runs one node at a time (`WELCOME_CONCURRENCY`), at most `MAX_WELCOME_QUEUE` (256) nodes wait for it, deduplicated by id, and a node beyond that gets its records from the hourly republication. The scan takes the routing table's read lock per `WELCOME_SCAN_CHUNK` (256) records, because the inline insert needs the write lock. A full bucket's oldest contact is pinged at most once at a time (`oldest_pings_in_flight`). Do not put the insert back behind the replication bound: with one permit and new nodes dropped on contention, 30 nodes after one bootstrap pass knew a median of 20-22 of the 29 others (26-27 now), and quorum GET tests failed about 1 run in 16 because a reader never learned the node holding the valid copy.
- UDP receive loop dispatches via round-robin to `available_parallelism()` fixed workers, each with a dedicated `mpsc::channel(256)`. `try_send` is attempted on each worker in order; if all channels are full the receive loop awaits the base worker (backpressure without drops). Zero allocations per datagram beyond the payload copy.
- Blocking thread pool (`spawn_blocking`) is bounded at the runtime level via `max_blocking_threads(available_parallelism())` in `scripts/dht_node.rs`. This caps concurrent ML-DSA verifications to the number of physical cores, covering all call sites uniformly (`verify_for_key`, `verify_value`, `update`). `KademliaProtocol` carries no application-level semaphore.
- `SignatureCache` is keyed on `SHA-256(record_bytes)`. TTL 1 h, capacity 4096 (moka TinyLFU). Eviction = cache miss = full re-verification (never a security bypass). On a cache miss the SHA-256 key is computed once via `compute_key()` and reused for both `get_by_key` and `insert_by_key` — never twice.
- The replication to a new node (`replicate_to`) uses two conditions (Kademlia §2.5, matches Python AuthKademlia): `new_node_close` (new node is XOR-closer than the farthest k-neighbor) AND `this_closest` (this node is closer than the nearest k-neighbor). Both must be true to replicate. The new node is already in the routing table when the scan runs, so `find_neighbors` excludes it from the comparisons.
- `schedule_stats_log()` emits a `[stats]` log line every 60 s: routing table size and live contacts, storage record count, used/max storage bytes, and (when enabled) signature cache entries.
- Every task that holds the protocol (receive loop, workers, refresh, maintenance, stats, save-state, the replication to new nodes, LRU pings) must start through `KademliaProtocol::spawn_task`, never `tokio::spawn`; otherwise it keeps the socket bound after shutdown. The one exception is the requests of a value lookup (`ValueSpiderCrawl::search`), which run in a `JoinSet` owned by the lookup and are aborted when it returns or is dropped. `Server::stop` sends `Leave` without waiting for a reply, cancels those tasks, and returns once the socket is released, so `listen` can be called again. Dropping a `Server` cancels them too, without sending `Leave`.
- **Unresponsive contacts** (Kademlia §4.1, unlike Python): a timeout calls `record_failure`, it does not remove the contact. Each failure sets a `retry_after` with exponential backoff (5 s to 300 s, plus jitter), and failures inside that window are not counted, so a burst of concurrent timeouts counts once. After `STALE_AFTER_FAILURES` (5) in a row a contact is stale: it is removed only if a replacement exists, otherwise it stays flagged, is not advertised (`find_neighbors_to_advertise`), and gives way to a new contact when its bucket is full. Any response clears the failures; a failing contact is cleared only from its registered endpoint, while a stale one also accepts a new endpoint. `find_neighbors` skips failing contacts while at least `read_quorum(alpha)` healthy ones remain, and uses stale ones last. `Leave` still removes the contact immediately.
- **Recovery** (`schedule_maintenance`): a 1 s tick pings failing contacts whose backoff has elapsed, so user lookups do not pay for them. While no contact is live it also retries the addresses given to `bootstrap` (`seeds`), with backoff up to 60 s, and runs a self-lookup once reconnected. It does no network work while the table is healthy. A contact silent for at least `RETURNED_AFTER` goes through `welcome` when it comes back, so it receives the records it missed.
- **Lookups and dead contacts** (Kademlia §2.3, §4.1): a lookup with a deadline (the STORE check) stops waiting at the deadline and marks the peers silent for at least `SILENT_AFTER` (1 s) as failing (`note_no_answer`), since their requests never reached a timeout; the STORE check also leaves failing contacts out entirely. A crawl never re-admits a peer that failed during it, and does not query a reported contact this node knows is failing (`SpiderProtocol::failing_among`), because other nodes that have not tried it keep reporting it. Initial peers are exempt, so `find_neighbors` can still use failing contacts as a last resort. The result holds only peers that responded, so no STORE goes to a dead peer. `set_detailed` counts the others in `unavailable_nodes`, not in `expected_replicas`: `Complete` means every node that responded holds the record. The first lookup after a peer dies still waits `RPC_TIMEOUT` (2.5 s) per round that contains a dead peer, because rounds wait for all their RPCs.
- **Publication while cut off**: if no remote replica is reachable but the node has known contacts or seeds, `set_detailed` counts one unavailable replica and reports `Degraded`. A node that never had contacts or seeds still reports `Complete 1/1`.
- **Routing table internals** (`src/routing.rs`): `KBucket.add_node()` does **not** update `last_updated`; only lookups reset the timer. `find_neighbors` touches the bucket containing the lookup target, evaluates every known primary contact with the full 256-bit XOR metric, excludes `target.id` and the optional caller-supplied peer, then returns the exact local top-k. Split condition §4.2: `covers(local_node) OR depth % 5 != 0`.

## Key invariants
- **One record per key, replaced only by a verified successor** (ADR 0005, `decide_locally`): byte-identical bytes return `AlreadyStored` (R1); a version N+1 whose `prev` is the hash of the stored record and whose signing key hashes to the stored `nextKeyHash` replaces it once its signature verifies (R3); an older version is `Stale`; another version with the stored `seq` is `Conflict` (R4: signed twice, proven duplicity by the same key, or another key); a version further ahead is `MissingPrevious` and nothing is asked. The network check fills only a replica that holds nothing.
- A new `set()` reuses the nodes from one `ValueSpiderCrawl`. An identical retry performs node discovery so missing replicas can be completed. Remote candidates plus the local node are XOR-sorted and truncated to `k`, preventing `k+1` copies.
- A remote DID GET takes no vote: `find_first_valid` returns the first record
  that passes DID binding and signature verification (Kademlia §2.3), discards
  any that fail, and cancels the requests still in flight. This does not prove
  the record is current or authentic: a stale replica or a forged, correctly
  self-signed record passes too. Authenticity comes from the caller comparing
  the public key with the hash in the VC, so do not treat `get` as an identity
  check. Do not bring the vote back as a defence: two colluding nodes win it.
- The Status List GET keeps a quorum derived from `alpha`, not independently
  configurable: with `alpha = 3`, two byte-identical record responses, or `None`.
- **An update is authorized by the chain** (ADR 0005, section 2): version N-1
  names the only key that may sign version N (`nextKeyHash`), and a version that
  commits to its own key is refused. There is no `auth_signature`. A replay of an
  old version is refused by `seq` and `prev` at a holder (`Stale`, `Conflict`),
  and at an empty replica by R2 and R5 at or above the quorum; it does not rest
  on the key changing. A stolen current key cannot rotate: the next key is kept
  as a seed until the rotation that reveals it.
- **UPDATE** (`Server::update`, `update_digest`): the owner sends version N with
  its earlier versions; it reads no copy first. `rpc_update` answers an
  `UpdateStatus`. A replica holding N-1 replaces it (R3); one behind or empty
  answers `MissingPrevious`, and only that answer makes the owner replay its
  chain to it, stop-and-wait: version 0 by STORE (R2), the next ones by UPDATE,
  the replicas behind first and the empty ones after. If version 0 of a replay
  is refused with `NewerClaimed` (a sibling replica was just repaired), the
  owner sends its current version once by STORE (R5), a departure from the
  ADR. Success is a strict majority of the consistency group, capped at
  `alpha`: the local copy, voted by the same rules against what it holds, and
  the closest remote replicas that answered `Updated` or `AlreadyStored` (or
  were filled by the replay); the others are updated best-effort. The local
  copy is written after the majority, with `replace_if`. `update` validates the earlier
  versions it gets (consecutive, linked by `prev`, the last committing to the
  key of version N) and refuses locally otherwise.
- Retrying an applied UPDATE is safe: a replica holding the same bytes answers
  `AlreadyStored`. Retries must resend the saved bytes: another version N signed
  by the same key is proven duplicity, refused and logged, and the owner signs
  each version once.
- `rpc_update` never accepts a version without the one before it: with nothing
  stored it has no key to check, and answers `MissingPrevious`. Never make it
  accept without a stored record.
- An empty replica checks the network before a STORE (`rpc_store`,
  `network_check`), for every DID record (`store_needs_lookup`): the Status List
  is exempt. It asks the nodes closest to the key for the `seq` and SHA-256 of
  their record (`FindHash`, through `ValueSpiderCrawl::search`), asking all of
  them, leaving no cached copy, giving up after `STORE_LOOKUP_TIMEOUT` (2 s,
  below `RPC_TIMEOUT`). The rules decide once every node asked has answered or
  the deadline has passed, refusals first.
  - A replica asks them all at once (`asking_everyone`), and in a later round all the
    nodes that answers added, instead of `alpha` per round: one round, sometimes two,
    instead of several, and a node it knows cannot be pushed out of the lookup before it
    is asked by made-up nodes closer to the key in an earlier answer (with `alpha` per
    round, such an answer hid the only holder and a forged record was stored:
    `a_neighbour_cannot_push_a_known_holder_out_of_the_store_check`). It still waits for every
    node it asked, including one pushed out since. A node that knows `k` nodes closer to
    the key than itself is not a replica by its own table and keeps `alpha` per round:
    asking all would ask `k` nodes per hop, most replaced at the next.
  - Before asking, it checks the form of the record for the key (step 1,
    `record_form`, no signature): a record that does not bind to the key is
    `InvalidRecord` and starts no lookup.
  - **Version 0 (R2):** refused with `NewerClaimed` only when a quorum claims a
    later version, so that one holder of a later version cannot stop the owner's
    replay; refused with `Conflict` on another version 0; accepted, after its
    signature, when every node asked answered.
  - **Version N >= 1 (R5):** one answer is enough to refuse: a `seq` above N
    (`NewerClaimed`), another version N, a version N-1 that is not its `prev`
    (`Conflict`), or a `seq` below N-1, a holder behind (open point 26). Without
    a refusal it fetches version N-1 from the nodes that answered `(N-1, prev)`
    (`FindValue`, one record), checks that it is the `prev` and commits to the
    key of version N, and accepts when the holders of version N and the fetched
    versions reach `store_quorum` of the nodes asked; for N = 1 one fetched,
    verified version 0 is enough. "No node holds the key" gives no votes: no
    answer.
  - A node did not answer, even after the resends, or there was nobody to ask (a
    node that has just restarted knows no contacts yet): `rpc_store` returns
    `None` and the replica sends no answer, so the sender counts it as
    unavailable. Nobody to ask is not "nobody holds it": in the testbed a
    persistent attacker got forged records onto 6/20 restarted replicas through
    that window.

  **Never make the check accept when a node did not answer** (fail-safe default, Saltzer
  and Schroeder 1975; accepting on silence is the soft-fail revocation flaw, Langley 2012).
  With whole records as answers, a burst of forged STOREs made the replica drop the
  holders' fragmented answers (`MAX_REASSEMBLY_ENTRIES_PER_PEER`), and accepting on
  timeout stored up to 86/128 forged records. Do not switch the check back to `FindValue`
  either: a hash answer fits in one datagram, a whole record takes about 6 KB in 5
  fragments per holder; R5 fetches one record only after the hashes allow it. Cost: the
  first STORE after a node dies is refused by each replica that still asks it.
  Limits (ADR 0005, Consequences): one node that claims a later version, or does not
  answer, blocks the repair of an empty replica by a later version (the single liar's
  veto); below the quorum the owner's replay restores copies only where the check
  allows it; a forgery accepted at an empty replica stays there until it expires.
- There is no DELETE API or RPC. Active records are never removed explicitly;
  TTL expiry is the only record-removal mechanism.
- DHT key = the decoded suffix of the DID (ADR 0005, `key_of_did`): `did:iiot:`
  then 43 characters of base64url without padding, in canonical form (the text
  encodes back to itself, so one DID is one key), the SHA-256 of version 0 in
  hashed form. Version 0 binds to a key only if its hashed form hashes to that
  key; a later version binds by the suffix of its `id`, and its place in the
  chain is checked by the rules. A UUID DID binds to no key. This check runs
  before the signature cache and on SET, GET, and UPDATE paths.
  `STATUS_LIST_KEY` is exempt.
- Invalid STORE requests return `InvalidRecord` and never add, replace, remove,
  or otherwise mutate routing contacts based on the unauthenticated `sender_id`.
- XOR distance is computed over the **full 256-bit id** (`Node.long_id: U256`,
  `primitive-types`) — **no folding**. Distinct ids never collide and the
  distance order is total/canonical, matching Python's arbitrary-precision
  `int(node_id.hex(), 16)`. Bucket ranges (`routing.rs`) are inclusive `U256`
  ranges over `[0, 2^256 - 1]`: the last value is `U256::MAX`, and 2^256, the
  width of the whole space, is not a `U256`. Compute a midpoint as
  `lo + (hi - lo) / 2`, and the width `hi - lo + 1` with `checked_add`: for the
  whole space it overflows (`random_id_in`). Never reintroduce a `u128`
  projection — it inverts ordering and collides ids.
- `STATUS_LIST_KEY = digest("status-list")` uses issuer-node
  verification instead of DID-owner verification.
- `issuer.bin` holds the issuer's raw ML-DSA-65 public key (1952 B); an old
  Dilithium-2 key (1312 B) is refused by its length. It is read lazily, on
  each issuer verification; if absent, only
  `STATUS_LIST_KEY` operations fail (normal DID records are not affected).
  `scripts/dht_node.rs` logs a warning at startup when the file is missing.

## Test suite structure
| File | Count | Notes |
|---|---|---|
| `tests/network_tests.rs` | 17 | Full multi-node integration tests (real UDP) |
| `tests/crypto_tests.rs` | 24 | Crypto layer unit + DID handler unit tests |
| `tests/routing_tests.rs` | 22 | Routing table unit tests |
| `tests/storage_tests.rs` | 20 | `ForgetfulStorage` unit tests (includes `insert_if_absent` and `replace_if` cases) |
| `tests/dht_integration.rs` | 1 | Legacy 3-node end-to-end scenario |
| `tests/scenarios/replication.rs` | 1 | replication to a joining node (3-node join) |
| `tests/scenarios/cache.rs` | 2 | SignatureCache hit-rate + false caching |
| `tests/scenarios/churn.rs` | 1 | Publisher leaves, record survives for new joiner |
| `tests/scenarios/worker_pool.rs` | 1 | 40-client burst, all responses delivered |
| `tests/scenarios/crypto.rs` | 4 | End-to-end crypto invariants (tamper, injection, downgrade, revocation) |
| `tests/quorum_tests.rs` | 19 | Real-UDP DID GET without a vote, multi-hop lookup, local fast-path, Status List quorum, delayed UPDATE commit, retry of an applied UPDATE, UPDATE to replicas without the record, and the network check of a STORE to an empty replica |
| `tests/chain_tests.rs` | 11 | Chains of versions over real UDP (ADR 0005): `set` refuses a later version, forged versions at empty replicas, the replay below the quorum and to replicas behind, the closed gap, no cache STORE |
| `src/**` (inline) | 212 | Module-level `#[test]` blocks (incl. Kademlia convergence, strict-quorum selection, XOR-metric regression, the 256-bit key space, fragmentation, the DID derivation with a Python test vector, the STORE and UPDATE rules, random message ids, and the protocol tests of `acceptance_tests.rs`); with `--features counters` 4 more, with `--features testbed` 1 more (the `FindHash` lie switch) |

All tests are network-clean (loopback only) and run in parallel without interference when port ranges are respected.

## Test port allocation (run in parallel — do not reuse)
| Range | Test |
|---|---|
| 5678–5680 | legacy 3-node scenario (`tests/dht_integration.rs`) |
| 15700–15701 | two-node bootstrap |
| 15710–15711 | cross-node set/get |
| 15720–15721 | idempotent SET retry + conflicting value rejection |
| 15730–15732 | key-rotation update |
| 15750 | invalid signature rejection |
| 15760 | unreachable peer |
| 15780–15781, 15885 | update rejected on invalid new-record self-signature (three replicas) |
| 15782–15784 | update rejected when auth_sig uses wrong key |
| 15787–15789 | scenario: replication to a joining node (A, B, C) |
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
| 15897 | valid DID record rejected under the key of another DID |
| 15898–15899, 15901–15903 | shutdown: `stop`, server drop, and cancellation of in-flight replication |
| 15904–15905 | Status List publication under the Python issuer's key |
| 15906–15912 | recovery: outage, late seed, lone node |
| 15913–15923 | DID GET without a vote: single copy, invalid record, dead peer |
| 15924–15927 | publication with a dead peer that others keep reporting |
| 15928–15932 | retry of an already applied UPDATE |
| 15933–15937 | UPDATE to replicas without the record |
| 15938–15953 | STORE to an empty replica: network check |
| 15954–16017 | chains of versions (`tests/chain_tests.rs`) |

When adding a new integration test use ports **16018+** and document them here (15900 is reserved below).

| 15900 | resilience test: Node A victim (host-exposed UDP, Docker only) |

## Examples

### `examples/cache_bench.rs`
Signature-cache benchmark in two isolated phases:
- **Phase 1** — DHT SET throughput (cached vs uncached clusters, no CPU contention).
- **Phase 2** — ML-DSA-65 verification micro-benchmark (records injected directly into local storage, sequential `get()` calls, zero network variance).

```bash
cargo run --release --example cache_bench
```

### `examples/topology_analysis.rs`
30-node DHT topology analyser. It publishes 100 authenticated DID records,
retrieves them from offset readers, and prints a concise diagnostic by default:

1. **Operation summary** — SET/GET success, latency, and local vs remote GET paths.
2. **Replication summary** — below/exact/above-`k` copy distribution.
3. **Global XOR placement** — physical holders vs globally closest nodes, explicitly independent of GET.
4. **Local FIND_NODE top-k** — exhaustive oracle comparison for every node and published target.
5. **Bucket invariants** — full 256-bit contiguous coverage, membership, uniqueness, and capacity.
6. **Routing convergence** — average buckets and primary peers per node.
7. **Final verdict** — `PASS`/`WARN`/`FAIL` per check with a non-zero exit for hard failures.

Pass `--verbose` to include full DID samples, storage tables, per-key placement,
complete inclusive bucket ranges and contents, and flat routing tables.

```bash
# default k=20 alpha=3, summary output
cargo run --release --example topology_analysis

# k=3 alpha=3, strict routing profile
cargo run --release --example topology_analysis -- 3 3

# full diagnostic output
cargo run --release --example topology_analysis -- 3 3 --verbose

# k=5 with DHT logs
RUST_LOG=info cargo run --release --example topology_analysis -- 5 2
```

Use this example to distinguish:
- **Local routing correctness**: each node returns its exact known primary top-k.
- **Global convergence and placement**: iterative crawls approach globally closest nodes.
- **Read availability**: a remote DID GET returns the first verified copy; local DID hits use the verified fast path.
- **Extra replicas**: retained copies are warnings, not evidence of a local XOR-ordering failure.

## Docker

### Demo (root `docker-compose.yaml`)
```
docker compose up --build            # 4 containers: seed, peer1, peer2, peer3
docker compose logs -f dht_peer_2   # follow a single container
```
The publisher builds version 0 of a new DID, publishes it, and writes the DID to
`/shared/did` (a temporary file, then a rename) on a volume it shares with the
retriever, which waits for the file and reads the record. The DID changes on
every run, since it is the hash of a document with a new key; the volume is a
tmpfs, emptied once no container uses it, so a retriever never reads the DID of
an earlier run. No key or seed is in `.env` or the compose file (ADR 0005, open
point 17). Environment variables per container: `NODE_PORT`, `IS_SEED`,
`BOOTSTRAP_ADDR`, `ROLE` (`publisher`|`retriever`), `RETRIEVE_KEY` (a DID to
read instead of the file), `RUST_LOG`.

Every Dockerfile builds on the Debian release it runs on (`bookworm`): the C
code of AWS-LC links against the builder's glibc, and a binary built on a newer
one (`__isoc23_strtol`, glibc 2.38) does not start on `debian:bookworm-slim`.

### Testbed (`testbed/`)
N nodes in Docker with configurable `k`, `alpha`, seeds and `tc netem` profiles
(LAN, WAN Europe, WAN Trans-Atlantic, from Verizon's published latencies).
```
testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu
testbed/testbed.py ctl node-3 publish        # also: update, republish, get, lie on|off, storage, routing
testbed/testbed.py get node-3 --from node-5
testbed/testbed.py pause node-10             # also: netem, stop, start, logs
testbed/testbed.py down
```
The binaries are built only with `--features testbed` (the image enables it).
Beyond about 30 nodes the host's neighbour table limit (`gc_thresh3`, 1024 by
default, shared by all containers) must be raised first, or nodes cannot send,
and so must the per-CPU receive backlog (`net.core.netdev_max_backlog`, 1000 by
default), or the host drops datagrams silently even without emulated loss: see
"More than about 30 nodes on one machine" in `testbed/README.md`.
A node keeps its DID's chain of versions: `publish` sends version 0,
`update` signs the next version with the committed key and sends it with the
earlier ones, `republish` sends the current version again with the saved
bytes. `lie on` (testbed builds only, `KademliaProtocol::set_lying`) makes it
answer every `FindHash` with a made-up version far ahead.
`testbed/attack.py` adds an attacker that reads the traffic and sends forged
versions (the owner's DID and `prev`, its own key): `start --mode
race|burst|successor|spoof|persist`, then the `race` or `restart` scenario.
`successor` answers each STORE of a version 0 with a forged version 1;
`spoof` answers each `FindHash` with answers claiming a later version from the
address of the node asked, under random ids (`--spoof-ids observed`, the
control, under the ids read on the wire). `testbed/measure.py publish`
measures publication time and when other nodes can read the record (`ctl
<node> new`, `ctl <node> watch`); `update` measures rotations, with replicas
restarted empty (`--restart`) and liars near the key (`--liars`); `churn`
counts the copies of a record over time while nodes crash, with liars. See
`testbed/README.md`. With `--counters` they also read every node's counters
(`ctl <node> counters`) before and after each operation.

`EXPERIMENTS.md` holds the experiments that validate the current code
(latency, traffic, check, rotation, attacks, liars, churn) with their setup
and results, and `experiments/<date>-<topic>/` the raw data of each campaign
with the script that ran it; rerun and update them when a change affects
them. `testbed/README.md` keeps the commands and the measurements that led to
fixes.

### Counters (`src/counters.rs`, feature `counters`)
Off by default; the `testbed` feature turns them on. Without the feature
`Counters` is an empty struct and its methods do nothing. They count, per node:
datagrams and bytes sent by message type (in `send_datagrams`, so first copies
and resends together, KADF header included); resends, split by whether the
peer's round trip was measured when the request was first sent; and the STORE
checks of empty replicas, by outcome (`invalid`, `nobody_to_ask`, `accepted`,
`newer_claimed`, `other_version`, `not_following`, `holder_behind`,
`fetch_refused`, `too_few_votes`, `no_answer`: the rows of R2 and R5), lookup
rounds and duration, and the checks that fetched the version before with
their whole duration (`fetches`, `fetch_duration_ms`).
`KademliaProtocol::counters` and `Server::counters` return a
`CounterSnapshot`; counters only grow, so a measurement is the difference of
two snapshots. Keep `MESSAGE_TYPES` in step with `rpc_message_name` when adding
a message type: an unknown name is not counted. The test
`every_message_type_is_counted` fails until they match, and every `match` on
`RpcMessage` lists all variants, so a new one does not compile until each
place handles it.

### Resilience / attack test (`resilience/docker-compose.yaml`)
```
cd resilience
docker compose up --build                         # 120 s attack, Node A capped at 2 cores
DURATION_SECS=300 CONCURRENCY=40 docker compose up --build   # custom intensity
```
Node A (victim) pre-seeds 5 records; Node B (attacker) floods with valid/invalid
SETs and GETs. Final report shows timeout rate and security verdict.
See `resilience/README.md` for full details.

## Diagrams (`docs/design/`)
`DESIGN.md` shows each diagram as a PNG next to its Mermaid source (`*.mmd`),
because the GitHub mobile app does not draw Mermaid blocks. Edit the `.mmd`,
then draw it again with mermaid-cli and commit both:
```
cd docs/design && mmdc -i store-check.mmd -o store-check.png -b white -s 2 -w 1000
```
On Ubuntu 23.10+ headless Chrome needs `-p` with a puppeteer config holding
`{"args": ["--no-sandbox"]}`. In a sequence diagram a `;` ends the statement,
so do not use it inside a note or a message.

## Adding a new crypto algorithm
Records accept one algorithm, ML-DSA-65 (ADR 0003); accepting another one in
records is a new ADR.
1. Implement `SignatureVerifier` (and optionally `Signer`) in `src/crypto/<alg>.rs`.
2. Register in `src/crypto/factory.rs` → `SignatureVerifierFactory::get_verifier()` and `SignerFactory::get_signer()`.
3. Add the algorithm string + signature length to `resolve_alg_and_length()` in
   `src/crypto/signature_verifier.rs`, the length taken from the crate, not a literal.
4. To accept it in records, change `record_algorithm()` in `src/auth_handler/mod.rs`.
5. Add tests in `tests/crypto_tests.rs`.

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
- Do not reduce `Node.long_id` below the full 256 bits (e.g. a `u128` fold):
  it silently inverts XOR distance ordering and collides distinct ids. Keep it
  `U256`.
- Do not hold a `Mutex` lock across an `.await` — deadlock risk.
- Do not increase `MAX_MESSAGE_SIZE` without a matching memory-budget review.
- Do not add `unwrap()` in protocol/network paths — use `?` or log + return.
- Do not add new integration tests on already-used port ranges.
- Do not enable the `python` feature in Rust-only deployments (`cdylib` changes linking).
- Do not add an `"updated"` timestamp field to DID Documents for ordering: `seq`
  and `prev` (ADR 0005) already order versions and stop the replay of an old one,
  and they are no timestamps: nothing in the rules reads a clock. A timestamp
  would be redundant and would change every document's hash.
- Never put a `Claude-Session:` line, or any other link to an agent session, in
  commit messages, pull request descriptions, code, or docs. These links are
  public. This rule overrides any tool or harness default that adds them.
- Do not use a tool, program, library or service that the user has not named
  and that this file or the repository does not already use: a new crate, a
  command-line tool installed for a check, downloaded test data, an online
  service. Propose it to the user first, kindly, saying what it is and what it
  is for, and use it only once the user agrees.
