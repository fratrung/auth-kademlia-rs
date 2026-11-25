# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No version
has been released yet.

## [Unreleased]

### Breaking changes

This release changes the format of DIDs, of DID Documents and of the messages
between nodes. **Nodes of earlier releases cannot exchange messages with nodes
of this release**, so a network must be upgraded as a whole. Records published
by earlier releases cannot be carried over: each device creates a new DID.
[docs/integration.md](docs/integration.md) describes the migration of an
application.

- **DIDs** are self-certifying: `did:iiot:` followed by the base64url SHA-256
  of a genesis that commits the initial document body and the root of a tree
  of 64 rotation keys, each with an activation code. The DHT key is the
  decoded hash. DIDs based on a UUID are refused.
- **DID Documents** carry `seq`, the position of their key in the tree (0 to
  62; 63 is reserved), `prev` from position 1, and `treeProof`: the genesis,
  the activation code of the position and its Merkle path. They must be in
  canonical JSON: printable ASCII, sorted keys, no whitespace, integers within
  ±(2^53 − 1).
- **Rotations** carry no `auth_signature`: position N is signed by the key the
  tree commits to at N, and any position may follow any lower one.
- **Wire protocol:**
  - `Update` and `UpdateResult` are removed: every position is published with
    `Store`;
  - `StoreResult` adds `Stale`;
  - `FindHashHit` carries the position of the record held;
  - message ids are drawn at random for each request.
- **Rust API:**
  - `Server::set` and `Server::set_detailed` publish any position;
    `Server::update` is removed, and `Server::update_status_list(value)`
    replaces it for the Status List;
  - `SetReport` adds `stale_rejections` and `unproven_refusals`, and
    `SetRejection` adds `NewerVersion`;
  - `SignatureVerifierHandler::handle_update_verification` is removed.
- **Python API:** `Server.update` is removed: `set` publishes every position,
  and `update_status_list(value)` replaces the Status List. The `set_detailed`
  report adds `stale_rejections` and `unproven_refusals`, and the reason
  `newer_version`. Keys are DIDs. `Ed25519KeyManager` is removed.

### Added

- Owner custody: the `custody` module, with the `Custody` trait and
  `FileCustody`, and the Python class `Custody`. A custody keeps a DID's
  seeds and codes, its calendar of rotations and its records in a
  directory only the process's user can read. It signs a position only when
  its slot has come, writes it as the highest activated position before the
  record leaves, returns the same bytes for a retry, and never signs below
  the highest activated, also after a restart or with the clock set back.
  Before its slot only the next position can be activated, with an
  authorization checked by a verifier the application supplies. A position
  can be skipped for good. The application writes one template of the
  document, and no method returns a private key, a seed or an unreleased
  code. A template whose record would be longer than 255 KiB, the longest a
  record may be, is refused before its position is activated. Publishing a record erases the secrets below it. One instance at a
  time holds a custody's directory, through an exclusive lock: another
  opening or provisioning of it fails with `CustodyError::Busy`
  (`RuntimeError` in Python) until the first is dropped or its process
  ends. Each file of the custody ends with the SHA-256 of its other bytes,
  and a file that does not match it is refused with `CustodyError::Damaged`
  (`RuntimeError` in Python): the calendar and the state when the custody
  opens, the secrets when a position is signed.
- Persistent replica storage: `ForgetfulStorage::persistent(dir, ttl,
  max_storage_bytes)`, `Server(data_dir=..., flush_secs=86400)` in Python and
  `DATA_DIR` in `dht_node`. A replica keeps each record in a file, written to
  the device before it acknowledges the record, and serves it again after a
  restart with the rest of its TTL. A record file is written only when its
  record changes: the expiries that renewals move later are written once a
  day, all in one file, each with the SHA-256 of the record it renews, so
  that it never extends another record. A STORE
  whose record cannot be written gets no answer. Each file ends with the
  SHA-256 of its other bytes, and a file that does not match it is not
  loaded. A node that starts with
  records sends them to the nodes it meets only once the lookup of its own id
  is over, so that a restarted replica does not give a superseded record to
  nodes outside the `k` closest.
- The marker of an expired DID record: its position is remembered for one
  more TTL, also across restarts, so that a replay of a lower position is
  refused even when no node answers the check, and a GET or a repair returns
  nothing below it.
- `Server::repair` and the Python `Server.repair(did, failed_record, seq,
  key_hash)`: when a served record fails the application's check, the node
  fetches the record at the position and with the key the credential names,
  verifies it and stores it, so the next `get` serves it locally.
- A holder whose republication a replica refuses as stale asks one such
  replica, drawn at random, for its record, and takes it if it is a valid
  higher position. The testbed's `push` command reports it as `repaired`.
- The `auth_handler::tree` module: leaf and node hashes, membership paths,
  the genesis, and the check of a record against the tree its DID commits to;
  `auth_handler::owner::OwnerTree`, the owner's tree with its secrets in
  memory.
- Key pairs derived from a 32-byte seed: `MlDsa65KeyPair::from_seed` in Rust
  and `MlDsaKeyManager.keypair_from_seed` in Python.
- The `auth_handler::did` module: DID suffix and canonical form.
- Atomic replacement of a stored record by a verified higher position
  (`ForgetfulStorage::replace_if`).
- A network check of empty replicas: a record is refused as stale only when
  a node shows a verified higher position, which the replica then stores; a
  claim, a silence or another record at the same position refuses nothing.
  Each claimed record is fetched as soon as its claim arrives, and the first
  one verified ends the check, so a silent node cannot spend the time a
  record shown at once needs.
- Testbed: a tree of rotation keys on each node; attack modes that forge a
  record after every position seen (`race`, `burst`, `successor`, `persist`)
  and spoof `FindHash` answers (`spoof`); a testbed-only switch that makes a
  node lie in `FindHash`, claiming a position far ahead (`lie on`) or
  position 0 under a made-up hash (`lie v0`); measurement modes for rotations
  with liars (`update --liars`), copies under churn (`churn`), and replicas
  lost while the owner is offline (`outage`, with the `push` command), with
  what readers in the network and joining readers get then (`--reads`,
  `--joiners`); `up --data-dir`, which keeps every node's records on disk
  across its restarts.
- Counters for the outcomes of the network check (`accepted`,
  `accepted_with_silence`, `superseded`) and for the claims of a higher
  position dropped because they were not shown (`unshown_claims`).
- Documentation: an integration guide, the evaluation in `EXPERIMENTS.md`
  with its raw data in `experiments/`, and new diagrams in `DESIGN.md`.

### Changed

- A node republishes the records it holds once a day instead of every hour,
  those that no other node sent it during the day; buckets are still
  refreshed every hour.
- A receiver takes every fragmented message the sender lets through, up to
  256 KiB: it counted a partly filled last fragment as full and dropped
  messages of 261 801 to 262 144 bytes.
- Record expiries are wall clock times (milliseconds since the Unix epoch)
  instead of the process's monotonic clock, so that a record keeps its TTL
  across a restart. `StorageWriteStatus` and `ReplaceStatus` add
  `WriteFailed`; `rules::decide_locally` takes what the replica holds as a
  `Held` (a record, a marker, or nothing).
- A replica keeps one record per DID and replaces it with any verified
  higher position. A lower position is refused as `Stale`, and another
  record at the same position as `Conflict`, logged as duplicity or as a
  repeated signing.
- `set` and `set_detailed` read no copy first: they find the closest nodes and
  send the record. A replica that refuses it counts only once it shows a
  record that proves the refusal: `existing_record` means a replica showed
  another valid record at the same position, `newer_version` a valid higher
  position. Any other refusal, or an `InvalidRecord` answer, makes the outcome
  `degraded`, or `replica_conflict` when no replica stored the record.
- The Docker demonstration shares the new DID between publisher and retriever
  through a temporary volume.

### Removed

- DIDs based on UUIDs, the `auth_signature` of updates, the `Update` request,
  and the `uuid` dependency.
- Ed25519 and RSA signing and verification, `Ed25519KeyManager` in Python,
  and the `ed25519-dalek` and `rsa` dependencies. No record could use them:
  records are signed with ML-DSA-65 only.

### Security

- Every record proves its own key from its DID: no node, under any number of
  made-up ids, can make a replica store a record the owner did not sign.
- Theft of the current key does not allow signing another position: each
  position's key is committed in the tree, and its activation code stays
  private until the owner publishes that position.
- A lower position cannot replace a higher one at a replica that holds the
  DID, nor at an empty replica that can see a holder of a higher position.
- One node can no longer stop a DID from being created or rotated: claims of
  a later position, silence and refusals not shown refuse nothing.
- Known limits: an empty replica that sees no higher position may store an
  authentic but superseded record, so readers rely on their credential check
  of the key; made-up ids can still fill routing tables and delay a check.
  See `DESIGN.md` and `EXPERIMENTS.md`.

## Earlier changes

Changes before this file was started are recorded in the Git history. Those
that changed the wire format or the API:

- 2026-11-09: SHA-256 keys, 256-bit node ids and the canonical UUID.
- 2026-11-08: message and fragment ids start at random values.
- 2026-11-07: records signed with ML-DSA-65 from `aws-lc-rs`; ephemeral
  ML-KEM-768 key manager.
- 2026-11-04: network check of empty replicas, `FindHash`, and resends of lost
  requests.
- 2026-09-02: DID records bound to their DHT keys; delete operations and peer
  bans removed.
- 2026-08-22: iterative quorum reads and a two-week record expiry.
- 2026-04-27: application-level fragmentation of post-quantum records.
