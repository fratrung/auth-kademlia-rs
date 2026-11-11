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

Python's **Global Interpreter Lock (GIL)** permits only one thread to execute bytecode at a time. For I/O-bound tasks this is rarely a bottleneck, but ML-DSA-65 signature verification is purely computational. In CPython, even with `threading` or `asyncio`, all verification calls are serialised to one core:

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
|Post-quantum cryptography|None             |ML-DSA-65 signatures (FIPS 204)     |
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
- Verify that the record belongs to the requested DHT key: the DID is
  self-certifying (ADR 0005), `did:iiot:` followed by the base64url of the
  SHA-256 of the DID's first document, and the key is that hash. Nobody can
  write a first document for another device's DID, and every later version
  names the hash of the only key that may sign the next one
- Operate without trusting any single node or coordinator

Signature validation is handled automatically by the integrated verifier at insertion and retrieval time.

-----

## Network Layer & Application-Level Fragmentation

Since Post-Quantum Cryptography (PQC) records—containing ML-DSA-65 signatures and public keys—often exceed the standard UDP MTU, **AuthKademlia-RS** implements a custom application-level fragmentation and reassembly system.

This ensures that messages remain within safe network limits, avoiding unreliable IP-level fragmentation and improving delivery rates across different network topologies.

### The Message Pipeline

When a node publishes or retrieves a record, the data passes through a structured lifecycle:

1.  **Serialize**: The record is serialized using `bincode` for high-performance binary encoding.
2.  **Split**: The payload is split into chunks of up to **1400 bytes** each, every chunk prefixed with a `KADF` header. A typical ML-DSA-65 record (~6.5 KB) produces 5 fragments.
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
* **ML-DSA-65 signature** (3309 B): spans roughly the first three fragments.
* **DID Document JSON** (with the base64url-encoded ML-DSA-65 public key): in the remaining fragments.

-----

## Record Consistency and Lifetime

A DID has a chain of versions (ADR 0005). Every DID Document carries `seq`,
`prev`, the SHA-256 of the record before it, and `nextKeyHash`, the SHA-256 of
the public key that alone may sign the next version. Version 0 fixes the DID;
each later version is signed by the key the one before committed to, so every
update rotates the key and needs no second signature. A node holds one version
per DID, the latest it could verify. A remote DID Document read takes the
first record that passes verification. The Status List and UPDATE use a
bounded consistency group: with the default `alpha = 3`, a strict **2-of-3
majority**.

- **Local DID Document GET:** a valid local record is returned immediately.
  This preserves the low-latency Kademlia fast path and does not use the
  network.
- **Remote DID Document GET:** when there is no local record, the node follows
  the normal iterative Kademlia lookup, querying the closest uncontacted peers
  in rounds and incorporating closer peers returned by misses. As in Kademlia
  §2.3, the lookup halts at the first record that passes DID binding and
  signature verification; a record that fails is discarded and the lookup
  continues. No vote is taken. This read does not prove the record is current or
  authentic: a replica that missed an update, or a forged but correctly
  self-signed record, passes too. The application must compare the public key
  with the hash in the Verifiable Credential.
- **Status List GET:** because the issuer Status List changes more frequently,
  it always uses the consistency group. A local copy contributes one vote and
  at most two remote records become additional votes. Discovery remains
  iterative; the local copy never causes an immediate return by itself. The
  signature is verified once, after a winner has been selected, and a split with
  no strict majority returns no value.
- **Publication:** `set` publishes version 0 only, and refuses a later
  version locally. A replica that holds a later version answers that its copy
  is newer (`stale_rejections` in the report of `set_detailed`).
- **UPDATE:** `update` publishes version N ≥ 1 with the owner's earlier
  versions, and reads no copy first. A replica holding version N−1 checks the
  new one on its own: its `prev` is the hash of the stored record, the hash of
  its signing key is the stored `nextKeyHash`, and its signature verifies. A
  replica that is behind or holds nothing answers that the version before is
  missing, and the owner replays its chain to it, one version at a time.
  Success is a strict majority of the consistency group: the local copy, when
  this node is a replica, and the closest remote replicas, `alpha` members in
  all; the other replicas are updated too but do not count. The local copy is
  written only after that majority. An older version is refused as stale, and
  a different version with the same `seq` as a conflict.
- **Retrying an update:** repeating the same update is safe, and the owner
  must resend the same saved bytes: a second, different version signed by the
  same key is refused as duplicity. The owner keeps every version it published
  and calls `update` again with them at least once every 24 hours, so that
  copies lost to churn come back.
- **STORE to an empty replica:** a replica cannot tell a forged record from the
  owner's by its signature alone. Before storing a record it does not hold, it
  asks the nodes closest to the DID for the `seq` and SHA-256 of the record
  they hold (`FindHash`), not for the record itself. It asks all of them at
  once, and leaves no cached copy. A record that is malformed or does not
  belong to the DID's key is refused as `InvalidRecord` before anyone is
  asked. Then:
  - for a version 0, it refuses when a quorum of the nodes asked holds a later
    version, or one holds another version 0, and otherwise stores it once
    every node asked has answered and the signature verifies;
  - for a later version N, one answer that names a later version, another
    version N, a version N−1 that is not its `prev`, or a version older than
    N−1 is enough to refuse. Otherwise it fetches version N−1 from a node that
    holds it, checks that it is the `prev` and commits to the new version's
    key, and stores the new version when enough nodes hold it or its
    predecessor (`store_quorum`, 13 of 19 at `k = 20`);
  - if one of them does not answer within 2 s, even after its question is
    sent again, or it knows nobody to ask, as right after a restart, it
    refuses and does not answer, so the sender counts it as unavailable.

  A hash answer takes one datagram, against about 6 KB and 5 fragments for a
  whole record, so the check costs little bandwidth, and a burst of requests
  cannot make the replica drop answers that arrive in pieces. A hash cannot be
  verified, so a node can block a STORE by claiming a later version, as it
  can by not answering; to get a forged record accepted it needs a quorum of
  the nodes asked. Nodes that do not know `FindHash` do not answer it, so every
  node of a network must run a version that does.

  Refusing on silence is the fail-safe default of Saltzer and Schroeder (1975),
  "base access decisions on permission rather than exclusion". Accepting on
  silence would repeat the flaw of soft-fail certificate revocation checks: an
  attacker who can make the answer fail to arrive makes the check pass
  ([Langley, 2012](https://www.imperialviolet.org/2012/02/05/crlsets.html): "a
  seat-belt that snaps when you crash"). An earlier version that accepted on
  silence and received whole records stored up to 86 of 128 forged records
  under a burst, because the replica dropped the fragmented answers. The price
  is availability: the first STORE after a node dies is refused by every
  replica that still asks it, and a retry succeeds. The check is a read before
  write without consensus. Databases that need a strict "insert if absent"
  across replicas run a consensus round instead, such as Cassandra's
  lightweight transactions (`INSERT ... IF NOT EXISTS`, Paxos). It does not
  help against an attacker who controls a quorum of the nodes close to the DID,
  and one node that claims a later version can keep an empty replica from
  being repaired (`EXPERIMENTS.md`, A4).
- **Lost datagrams:** every request carries a message id drawn at random, so
  an answer under a guessed id is discarded. A request with no answer after a
  few round trips of its peer is sent again, with the same id, at most twice, doubling the wait (round trips estimated
  per peer as in RFC 6298, measured only on requests sent once). A request
  that carries a record gets a receipt as soon as it arrives, so the sender
  does not resend a 6 KB record while an empty replica runs its check; a copy
  of a request still being handled gets the receipt again and starts nothing.
  Without this, refusing on silence turned one lost datagram of the check into
  a missing replica: with 0.5% loss, 30 nodes and k=5, 26 of 80 publications
  lost a replica, against 7 of 40 without the check; with it, none of 80
  did, and no publication waited for a timeout.
- **TTL:** records written to the default storage expire lazily after 14 days.
  Applications that need continued availability must refresh them through a
  legitimate publish or update before expiry.
- **Lifecycle:** DID records have no explicit delete operation. Expiry through
  the configured TTL is the only removal mechanism exposed by the DHT API.

The Status List read quorum is derived from `alpha`; it is not an independent
configuration parameter. With the default `alpha = 3`, a read needs two
byte-identical record responses out of at most three record-bearing responses, so
a single valid copy returns `None` by design.

The diagnostic `k = 3, alpha = 3` configuration limits the replication set to
three nodes, leaving very little tolerance for a routing table that is still
converging. An occasional GET miss in the randomized topology example can be
caused by this deliberately narrow configuration; it does not by itself
demonstrate a routing or distance-ordering defect.

### Bounded storage and publication outcomes

Each node has a storage budget of **512 MiB** by default. The budget counts key
and value bytes and never evicts active records: expired records are reclaimed
by the periodic TTL pass, while a write that would exceed the budget returns an
explicit `CapacityExceeded` result.

STORE responses distinguish `Stored`, `AlreadyStored`, `Conflict`,
`CapacityExceeded`, and `InvalidRecord`. Byte-identical retries are
idempotent. `Server::set_detailed()` reports the expected and acknowledged
replicas and classifies publication as `Complete`, `Degraded`, or
`Rejected`; the existing `set()` API remains as a compatibility wrapper.

The replica target set is formed from the crawl result plus the local node,
ordered by the full 256-bit XOR distance and truncated to `k`. A node that is
full does not evict an active record and the publisher does not substitute a
farther node, so routing and responsible-node selection remain unchanged.

A node that has known contacts or bootstrap addresses but cannot reach any of
them reports `Degraded`, not `Complete`: it holds one copy of a wider replica
set. It keeps its contacts through an outage and rejoins on its own, handing
over what it published in the meantime. Only a node that has never had a
contact or a bootstrap address reports `Complete` with a single copy.

A node that does not respond during a lookup is not a replica. It stays out of
that lookup even if other peers keep reporting it, receives no STORE, and is
counted in `unavailable_nodes` without preventing a `Complete` outcome, so
`Complete` means that every node that responded holds the record. Check that
counter to tell how many known nodes were unreachable.

Configure the budget per process:

```bash
MAX_STORAGE_BYTES=536870912 cargo run --bin dht_node
```

Rust callers can supply a bounded storage instance to `Server::new`:

```rust
let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
    DEFAULT_TTL,
    512 * 1024 * 1024,
));
let server = Server::new(handler, 20, 3, None, Some(storage), false);
```

The Python constructor accepts `max_storage_bytes` with the same default.

This release changes the bincode representation of `StoreResult` and removes
the application-level `Delete` RPC variants. Nodes in a cluster must therefore
be upgraded together. The signed record format and the Kademlia routing
algorithm are unchanged.

-----

## Performance & Concurrency

| Mechanism | Detail |
|---|---|
| **Concurrent storage** | `DashMap` keeps per-key operations parallel; an atomic byte reservation enforces the per-node budget without a global async lock. |
| **Lazy TTL expiry** | Records expire after 14 days by default. Expired entries are filtered at read time instead of an O(n) scan on every write. |
| **Signature cache** | `SignatureCache` (moka, SHA-256 keyed, TTL 1 h, 4096 entries). Repeated reads of the same record pay the full ML-DSA cost only once; subsequent reads are O(1). DID-to-DHT-key binding is checked before every cache lookup, and any byte-level change forces full signature re-verification. |
| **Worker pool** | UDP receive loop dispatches via round-robin into `available_parallelism()` workers, each with a dedicated `mpsc::channel(256)`. `try_send` is attempted on each worker in turn; if all are full the loop awaits the base worker, providing backpressure without drops. |
| **Fire-and-forget replication** | A node met through a message enters the routing table at once. Sending it the records it should hold scans the whole storage, so it runs in the background, one node at a time, with at most 256 nodes waiting. RPC responses are sent without waiting for it. |
| **Replication filter** | On node join, only nodes XOR-closer to a key than the new node replicate it (Kademlia §2.5). Prevents redundant store RPCs from far-away nodes. |
| **Atomic insert** | `rpc_store` uses a DashMap `Entry`-based `insert_if_absent`; identical retries return `AlreadyStored`, different bytes return `Conflict`, and capacity is reserved before insertion. |

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
| **Blocking thread** (OS) | Tokio on-demand | Kernel | ≤ `available_parallelism()` | ML-DSA verification |
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
    Created on-demand for spawn_blocking (ML-DSA verify/sign).
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
                        └─ store / update
                            verify_for_key()
                              spawn_blocking(ML-DSA)
                              .await  ← task suspended, worker thread FREE
                                          │
                                          ▼
                                    Blocking OS thread
                                    ML-DSA-65 verify
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
GET cold:  SHA-256(record) → cache miss → spawn_blocking(ML-DSA)   → cache.insert
GET warm:  SHA-256(record) → cache hit  → return immediately  (no blocking thread)
```

On a proxy that authenticates the same devices repeatedly, the warm
path dominates and the blocking pool stays nearly idle.

-----

## Throughput & Benchmarks

### Throughput limits

Each `set` → `get` round-trip includes a full ML-DSA-65 signature verification.
Peak verification throughput scales linearly with core count — approximately
`N_cores / t_verify` unique verifications per second, where `t_verify` is the
time of one verification on the target core (measure it with `cache_bench`).

The `SignatureCache` substantially raises the practical ceiling: once a record has
been verified once, subsequent reads return the cached result in O(1) time with no
blocking work.

### Signature cache benchmark

`examples/cache_bench.rs` measures two isolated phases:

- **Phase 1 — DHT SET throughput**: two sequential clusters (cached vs uncached) running real network operations with no CPU contention between them.
- **Phase 2 — Signature verification micro-benchmark**: records injected directly into local storage, sequential `get()` calls, zero network variance. Isolates the exact ML-DSA-65 vs cache-hit cost.

The expected behaviour:
- *GET cold*: cache miss → SHA-256(record) + `moka.get()` miss + `spawn_blocking(ML-DSA-65)` + `moka.insert()`. The SHA-256 overhead is small relative to ML-DSA; on first read the cached node pays a marginal extra cost.
- *GET warm*: cache hit → SHA-256(record) + `moka.get()` → result returned immediately. No blocking work. Speedup is proportional to the ML-DSA-65 cost on the target hardware.
- *DHT SET*: dominated by network round-trip; cache has negligible effect on write throughput.

Run `cargo run --release --example cache_bench` to collect measurements on your
own hardware (fixed at 10 000 ops, c=30 for DHT SET; 500 ops sequential for the
micro-benchmark). The cache can be disabled per-node by passing `use_cache: false`
to `Server::new` for benchmarking or security auditing.

### Routing topology diagnostic

`examples/topology_analysis.rs` builds a 30-node in-process cluster, publishes
100 authenticated records, retrieves them through readers offset from their
writers, and emits an actionable routing verdict.

The default output is a concise summary:

| Check | What it validates |
|---|---|
| **SET/GET** | Publication success, verified reads, latency, and local-fast-path vs remote counts |
| **Replica counts** | Below/exact/above-`k` copy distribution |
| **Global XOR placement** | Physical holders compared with the globally closest nodes; independent of GET |
| **Local FIND_NODE top-k** | Every node response compared with an exhaustive oracle over its known primary contacts |
| **Bucket partition** | Full 256-bit coverage without gaps/overlaps, contact membership, uniqueness, and bucket capacity |
| **Convergence** | Average bucket and primary-peer counts as a heuristic |
| **Final result** | Per-check `PASS`/`WARN`/`FAIL`; hard failures produce a non-zero exit status |

Use `--verbose` to additionally print three complete DID Documents, per-key
storage and replica placement, inclusive 256-bit bucket ranges and contents,
and flat routing tables.

```bash
# default: k=20, alpha=3, summary output
cargo run --release --example topology_analysis

# k=3, alpha=3: strict routing profile
cargo run --release --example topology_analysis -- 3 3

# full diagnostic details
cargo run --release --example topology_analysis -- 3 3 --verbose

# k=5, alpha=2
cargo run --release --example topology_analysis -- 5 2
```

Local DID hits use the verified fast path, and a remote DID GET returns the
first verified copy. The separate physical-placement and local top-k checks
prevent a GET miss from being misreported as an XOR-routing failure. Extra
retained replicas are reported as warnings rather than local top-k failures.

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

DID Documents stored in the DHT embed a **post-quantum public key** (ML-DSA-65, as an RFC 9964 JWK), enabling:

- Secure device authentication
- Verifiable credential issuance and resolution

Key exchange between devices uses ephemeral ML-KEM keys outside the DHT, signed with the device's ML-DSA-65 key (ADR 0003), so DID Documents carry no key agreement key.

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

Version 0 of a new DID: the device generates its current key pair and the
next one, from a 32-byte seed it keeps (ADR 0005), builds the draft of the
first document with its own DID written as `did:iiot:self`, and lets
`derive_did` compute the DID and put it in place. `examples/publish_did.rs`
is the complete program.

```rust
use std::path::PathBuf;
use std::sync::Arc;

use auth_kademlia_rs::auth_handler::did::{canonical_bytes, derive_did, PLACEHOLDER};
use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::crypto::mldsa::{self, MlDsa65KeyPair};
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::utils::digest_bytes;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

/// The draft of version 0: an ML-DSA-65 key as an RFC 9964 JWK, no key
/// agreement key (ADR 0003), its own DID written as the placeholder, no `id`,
/// `seq` 0 and the hash of the next public key.
fn version_zero_draft(signing_pk: &[u8], next_pk: &[u8]) -> Value {
    let did = PLACEHOLDER;
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#k0"),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": {
                "kty": "AKP",
                "alg": "ML-DSA-65",
                "pub": URL_SAFE_NO_PAD.encode(signing_pk)
            }
        }],
        "authentication": [format!("{did}#k0")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }],
        "seq": 0,
        "nextKeyHash": URL_SAFE_NO_PAD.encode(digest_bytes(next_pk)),
    })
}

/// `| algorithm (12 bytes, null-padded) | ML-DSA-65 signature | DID Document |`,
/// the document in canonical JSON.
fn build_signed_record(doc: &Value, key_pair: &MlDsa65KeyPair) -> Vec<u8> {
    let doc_bytes = canonical_bytes(doc).expect("a DID Document in canonical form");
    let mut record = vec![0u8; 12];
    record[..9].copy_from_slice(b"ML-DSA-65");
    record.extend_from_slice(&key_pair.sign(&doc_bytes).expect("ML-DSA-65 signing"));
    record.extend_from_slice(&doc_bytes);
    record
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

    // The current key signs version 0; the next one, kept as its seed, alone
    // may sign version 1.
    let key_pair = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
    let next_seed: [u8; MlDsa65KeyPair::SEED_LEN] = rand::random();
    let next_key = MlDsa65KeyPair::from_seed(&next_seed).expect("ML-DSA-65 key from seed");

    let draft = version_zero_draft(key_pair.public_key(), next_key.public_key());
    let (did, did_doc) = derive_did(&draft).expect("version 0 gives its DID");
    let signed_record = build_signed_record(&did_doc, &key_pair);

    match node_2.set(&did, signed_record).await {
        Some(true) => println!("Record published under {did}"),
        _ => {
            eprintln!("Failed to publish record");
            return Ok(());
        }
    }

    match node_1.get(&did).await {
        Some(record) => {
            let doc_start = 12 + mldsa::signature_len();
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

`auth_kademlia_rs` does not create a Tokio runtime — the caller owns it. ML-DSA-65
verification is CPU-bound and runs on Tokio's blocking thread pool via `spawn_blocking`.
On embedded hardware (2–4 core ARM SoCs) the default pool cap of 512 threads causes
unnecessary context-switching overhead. Cap it to the number of physical cores:

```rust
fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)  // bounds concurrent ML-DSA verifications
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

The module configures a Tokio runtime automatically, limiting CPU-bound
`spawn_blocking` work to `available_parallelism()`. Cryptographic key
generation, signing, verification, and key-file I/O release the GIL, allowing
independent Python threads and async node operations to execute through the
Rust core without Python-side serialisation. The legacy `init_runtime()`
function is still available but is no longer required.

```python
import asyncio
import authkademlia_py

async def run_node(did: str, version_0: bytes, version_1: bytes, next_seed: bytes) -> None:
    node = authkademlia_py.Server(
        ksize=20,
        alpha=3,
        sig_cache=True,
        max_storage_bytes=512 * 1024 * 1024,
    )
    await node.listen(5678, "127.0.0.1")

    # Version 0 under its DID: did:iiot: and the base64url of the SHA-256 of
    # the first document, with its own DID written as did:iiot:self.
    outcome = await node.set_detailed(did, version_0)
    if outcome["status"] != "complete":
        print(outcome)  # report: stale_rejections, newer_claimed, ...

    # Version 1, signed by the key whose hash version 0 committed to, rebuilt
    # from the seed the device kept. Resend the same saved bytes on a retry.
    keys = authkademlia_py.MlDsaKeyManager("keys")
    public_key, private_key = keys.keypair_from_seed(next_seed)
    confirmed = await node.update(did, version_1, [version_0])

    stats = await node.stats()
    print(stats["storage_bytes"], stats["available_storage_bytes"])
    await node.stop()

asyncio.run(run_node(did, version_0, version_1, next_seed))
```

`set()` remains available for compatibility and returns `True` for a complete
publication, `False` for a degraded or unavailable publication, and `None` for
an invalid or conflicting record. Prefer `set_detailed()` when replication and
capacity outcomes affect application behaviour. Both publish only a version 0;
`update(did, version, earlier)` publishes a later one, with the owner's saved
earlier versions, which it uses only to replay the chain to replicas that miss
versions. The application keeps every version it published, and calls
`update` again with the saved bytes at least once every 24 hours.

`MlKemKeyManager` gives one ephemeral ML-KEM-768 key pair per handshake
between devices (ADR 0003). Private keys never leave the extension: a pair
is destroyed when it is used, and expires after 30 s if it is not.

```python
from authkademlia_py import MlKemKeyManager

# Device A: a new pair, whose public key it sends signed with its ML-DSA-65 key
kem = MlKemKeyManager()
key_id, public_key = kem.ephemeral_public_key()

# Device B, after verifying that signature
secret_b, ciphertext = MlKemKeyManager.encapsulate(public_key)

# Device A
secret_a = kem.decapsulate(key_id, ciphertext)
```

A modified ciphertext gives a different secret, not an error (implicit
rejection, FIPS 203): confirm the key before using it.

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
