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
  of the first version of the DID Document, with its own DID written as the
  placeholder `did:iiot:self`. The DHT key is the decoded hash. DIDs based on
  a UUID are refused.
- **DID Documents** carry `seq`, `prev` (the hash of the previous record) and
  `nextKeyHash` (the hash of the key that signs the next version), and must be
  in canonical JSON: printable ASCII, sorted keys, no whitespace, integers
  within ±(2^53 − 1).
- **Updates** carry no `auth_signature`. Version N must be signed by the key
  that version N−1 committed to, so every update is a key rotation.
- **Wire protocol:**
  - `Update` carries the record only, and `UpdateResult` returns a status:
    `Updated`, `AlreadyStored`, `MissingPrevious` (with the version held),
    `Stale`, `Conflict`, `CapacityExceeded` or `InvalidRecord`;
  - `StoreResult` adds `Stale`, `NewerClaimed` and `MissingPrevious`;
  - `FindHashHit` carries the version number of the record held;
  - message ids are drawn at random for each request.
- **Rust API:**
  - `Server::set` and `Server::set_detailed` publish only a version 0; a
    later version is refused with `SetRejection::UseUpdate`;
  - `Server::update(key, value, earlier)` replaces
    `Server::update(key, value, auth_signature)`: `earlier` holds the owner's
    previous versions;
  - `SetReport` adds `stale_rejections` and `newer_claimed`, and
    `SetRejection` adds `NewerVersion` and `UseUpdate`;
  - `SignatureVerifierHandler::handle_update_verification` is removed.
- **Python API:** `Server.update(key, value, earlier)`; the `set_detailed`
  report adds `stale_rejections` and `newer_claimed`, and the reasons
  `newer_version` and `use_update`; keys are DIDs. The Status List is
  updated with `update("status-list", value, [])`.

### Added

- Key pairs derived from a 32-byte seed: `MlDsa65KeyPair::from_seed` in Rust
  and `MlDsaKeyManager.keypair_from_seed` in Python, so that an application
  keeps only the seed of its next key.
- The `auth_handler::did` module: DID derivation, canonical form, DHT key of
  a DID.
- Validation of a successor by a replica that holds the previous version, and
  its atomic replacement (`ForgetfulStorage::replace_if`).
- A network check of empty replicas for every version: a first version is
  refused when a quorum of the closest nodes reports a later one; a later
  version is refused on any contradicting answer, and is otherwise accepted
  once the previous version has been fetched and verified and a quorum
  agrees.
- Replay of the owner's chain to replicas that are behind or empty.
- Testbed: chains of versions on each node; attack modes that forge a
  successor of every first version (`successor`) and spoof `FindHash` answers
  (`spoof`); a testbed-only switch that makes a node lie in `FindHash`;
  measurement modes for rotations with liars (`update --liars`), copies under
  churn (`churn`), and replicas lost while the owner is offline (`outage`,
  with the `push` command), with what readers in the network and joining
  readers get then (`--reads`, `--joiners`).
- Counters for the new outcomes of the network check.
- Documentation: an integration guide, the evaluation of this release in
  `EXPERIMENTS.md` with its raw data in `experiments/`, and new diagrams in
  `DESIGN.md`.

### Changed

- A replica keeps one version per DID and replaces it only with its verified
  successor. An older version is refused as `Stale`, and another version with
  the same number as `Conflict`, logged as duplicity.
- A rotation sends about 6.5 KB in 5 fragments to each replica, instead of
  about 9.8 KB in 8: 31% less traffic, as measured on 127 nodes.
- The Docker demonstration shares the new DID between publisher and retriever
  through a temporary volume.

### Removed

- DIDs based on UUIDs, the `auth_signature` of updates, and the `uuid`
  dependency.

### Security

- Nobody but the device can publish a first version under its DID.
- Theft of the current key does not allow a rotation: the next key is kept
  as a seed until the rotation that reveals it.
- An earlier version cannot be replayed as the current one at a replica that
  holds the DID, nor at an empty replica while at least a quorum of the nodes
  it asks hold the DID.
- Known limits: one node that claims a later version, or does not answer,
  keeps an empty replica empty; below a quorum of holders only the owner can
  restore copies; a quorum of colluding nodes near a DID controls what it
  resolves to. See `DESIGN.md`, section 13, and `EXPERIMENTS.md`.

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
