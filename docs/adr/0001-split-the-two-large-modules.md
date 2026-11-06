# 0001. Split the two large modules, keep the others

Status: Accepted, 2026-11-06.

## Context

`src/` has about 10 000 lines, and two files hold almost half of them.

- `src/protocol.rs`, 3386 lines (about 1890 of code, 1500 of tests), holds the
  wire messages, the UDP transport with fragments and resends, every RPC
  handler, the network check of an empty replica, the outgoing calls, contact
  upkeep and the replication to new nodes.
- `src/network.rs`, 1167 lines, holds `Server` and every operation on it: SET,
  GET, UPDATE, bootstrap, refresh, republication, stats, saved state.

Reading one part means scrolling past all the others. The other modules are
under 1000 lines and each holds one thing.

Some code is written twice or hides mistakes the compiler could catch:

- The verification of a record for a key (DID binding, signature cache,
  `spawn_blocking`) is written twice, almost line for line: `verify_for_key`
  in `protocol.rs` and `verify_value` in `network.rs`. The key-rotation check
  is also called from both files.
- Three `match` on `RpcMessage` end with `_ =>` (`ExpectedResponse::for_request`,
  `carried_record`, `dispatch_request`). A new message, such as the reservation
  of ADR 0002, compiles and is treated as needing no answer: its call discards
  the answer and times out. `MESSAGE_TYPES` in `counters.rs` is a copy of
  `rpc_message_name` kept by hand.
- `FindHash` is answered through `rpc_find_value`, which copies the 6 KB record
  and reads its JSON on every question, only to hash it.
- `handle_datagram` is 232 lines, with the reassembly of fragments inline.

The reservation (ADR 0002) adds a message, a table, a handler and a phase of
SET. Without a split it lands in the middle of the two large files.

## Decision

Only `protocol.rs` and `network.rs` are split. At the top level the crate stays
split by layer, as today; inside `protocol/` and `network/` it is split by
operation. The other files stay where they are, cleaned inside.

```
src/
  lib.rs
  utils.rs              digest, ID_LEN, STATUS_LIST_KEY
  node.rs               unchanged
  routing.rs            unchanged
  storage.rs            unchanged
  crawling.rs           unchanged
  fragmentation.rs      KADF, and the reassembly now inside handle_datagram
  retransmit.rs         unchanged
  counters.rs           message names taken from protocol/messages.rs
  signature_cache.rs    unchanged
  auth_handler.rs       SignatureVerifierHandler and DIDSignatureVerifierHandler
                        as today, and the verification of a record for a key,
                        written once, used by protocol and network
  crypto/               unchanged: algorithms only, no knowledge of DIDs
  protocol/
    mod.rs              KademliaProtocol, new, tasks, shutdown, seeds
    messages.rs         RpcMessage, StoreStatus, WireNode, record_hash, Frame,
                        ExpectedResponse, rpc_message_name, carried_record
    transport.rs        message and fragment ids, encoding, sending, call
                        with its resends, handle_datagram, answer,
                        InProgress, PendingCall
    handlers.rs         dispatch_request; Ping, Update, UpdateStatusList,
                        FindNode, FindValue, FindHash, Leave
    store_check.rs      rpc_store, network_copy, StoreLookupSlot
    reservation.rs      the reservation (ADR 0002)
    client.rs           outgoing calls (call_*), SpiderProtocol
    contacts.rs         note_failure, note_alive, add_contact, probes,
                        refresh ids
    welcome.rs          schedule_welcome_if_new, replicate_to, their bounds
    test_support.rs     helpers shared by the tests of protocol (cfg(test))
  network/
    mod.rs              Server, new, listen, stop, bootstrap, Drop
    publish.rs          set, set_detailed, their lookups, SetReport,
                        SetOutcome
    read.rs             get
    update.rs           update, update_digest
    maintenance.rs      refresh, republication, maintenance tick, stats
                        (ServerStats), saved state
  py_bindings.rs        unchanged
```

`auth_handler.rs` keeps the DID rule and gains the way the node runs it, in one
place: binding first, then the signature cache, then `spawn_blocking`, then
the cache again. There is no separate record module: `crypto/` holds the
algorithms, `auth_handler.rs` everything about verifying a DID record.

Rules for the split:

- **Behaviour.** A move changes no behaviour, no name, no wire format and
  nothing visible outside the module.
- **Public paths.** They stay, through `pub use`: `protocol::{KademliaProtocol,
  RpcMessage, StoreStatus, WireNode, record_hash}`, `network::{Server,
  SetOutcome, SetRejection, SetReport, ServerStats}`, `auth_handler::*`. The
  Python API does not change.
- **One impl block per file.** `KademliaProtocol` and `Server` keep their struct
  and constructor in `mod.rs`; each other file has its own `impl` block with
  the methods of its part.
- **Visibility.** The narrowest that compiles. Child modules see the private
  fields of the parent's structs, so no field becomes public. A method used by
  a sibling file becomes `pub(super)`, no more. No new `pub`.
- **Module comments.** Each new file starts with a `//!` comment that says what
  it holds, and where the closest related code is.
- **Comments and tests.** Comments move with their code. Each test moves next
  to the code it tests, with the same name. Test helpers used by more than one
  file go to `test_support.rs`.
- **Moves apart from changes.** A move commit changes no line except `use`,
  `mod`, visibility and the module comment. This is checked by comparing the
  sorted lines before and after, and the list of test names
  (`cargo test -- --list`).
- **Exhaustive matches.** Every `match` on `RpcMessage` lists all variants.
- **Checks after every commit.**
  - `cargo test` and `cargo test --features counters` pass (253 and 256 tests
    when this was decided).
  - `cargo clippy --all-targets`: no new warning.
  - `cargo fmt --check`.
  - `cargo build --features testbed` and `cargo check --features python`.

## Steps

Six commits, each about one thing. A large move is checked as well as a small
one: same code lines, same test names, all the checks.

1. `protocol.rs` split into the files of `protocol/` (after a first commit that
   only renames it to `protocol/mod.rs`, so that git follows the history).
2. `network.rs` split into the files of `network/`.
3. Messages: every `match` on `RpcMessage` lists all variants; a test ties
   `MESSAGE_TYPES` to `rpc_message_name`; `FindHash` gets its own handler,
   `rpc_find_hash`, which the reservation and O3 will change. It answers as
   today: what it costs (a copy of the record and a JSON parse per question)
   is measured and changed with O3 and O5, not here.
4. The verification of a record for a key, written once in `auth_handler.rs`.
   It is security code, so its commit does nothing else; `crypto_tests`,
   `quorum_tests` and the cache tests check it.
5. Repeated code: the reassembly moves from `handle_datagram` to
   `fragmentation.rs`; the address parse (`format!("{}:{}").parse()`, seven
   times) and the set-up of a lookup (nine times) get one helper each.
6. Dead code and documents: unused public items are removed (`gather_dict`,
   `shared_prefix`, `bytes_to_bit_string` in `utils.rs`, `Node::random`,
   `KademliaProtocol::welcome_if_new`; the crate is not on crates.io, checked
   2026-11-06); comments and documents that name code that no longer exists.

Then ADR 0002.

After ADR 0002, each with a test that fails before the change, because they
change behaviour:
- `Server::listen` called twice replaces the protocol without stopping the old
  one, which keeps the socket bound.
- A SET lookup that meets two different records in one round sends `k` STOREs
  and reports `ReplicaConflict` instead of `ExistingRecord`.
- A replica that already holds a record runs the Dilithium verification before
  comparing bytes; comparing first would answer `Conflict` instead of
  `InvalidRecord` to an invalid record.
- `info` logs on every lookup and every round.
- One builder of DID records for tests, testbed, scripts and examples (eleven
  copies today), one runtime builder (nine), one record parser (three).
- Optional: `params.rs` for the times and limits that depend on each other,
  with compile-time checks such as `STORE_LOOKUP_TIMEOUT < RPC_TIMEOUT`.

## Consequences

- The reservation gets its own file, `protocol/reservation.rs`, next to
  `store_check.rs`, and its SET phase goes in `network/publish.rs`.
- `git blame` on moved lines shows the move commit; `git blame -C -C` follows
  the lines to where they came from.
- Line references in `AGENTS.md`, `DESIGN.md` and the working notes change.

## Alternatives rejected

- **Several crates.** `crawling` and `protocol` depend on each other, and
  `Server` reaches into the protocol's state: many internals would become
  public, and the maturin and Docker builds would change.
- **Split by layer everywhere, or by operation everywhere.** `RpcMessage` stays
  one enum, because the order of its variants is the wire format; a split by
  layer separates each handler from its caller.
- **A new record module next to `auth_handler.rs`.** Two verifiers of DID
  records in two places.
- **Tests moved to `tests/`.** They use private internals.
- **One large commit.** It cannot be checked as a pure move.
