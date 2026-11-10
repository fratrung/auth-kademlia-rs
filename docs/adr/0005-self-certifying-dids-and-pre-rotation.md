# 0005. Self-certifying DIDs and a pre-rotated chain of versions

Status: Accepted, 2026-11-11 (proposed 2026-11-09). It supersedes ADR 0002,
and amends ADR 0004: the part that makes the DID a canonical UUID. The rest
of ADR 0004 (SHA-256, 256-bit ids and keys) stays.

## Context

- **A record does not prove its DID.** The DID is a random version 4 UUID and
  its key is the SHA-256 of the UUID text (ADR 0004). Anyone can sign a
  document for any DID with their own key (`DESIGN.md` section 2). An empty
  replica therefore asks the network before a STORE (`FindHash`, `DESIGN.md`
  section 7) and answers `Conflict` at the first other hash, without
  verifying anything. One node can block a STORE that way.
- **The first publication is not protected.** Whoever learns the DID from the
  owner's first STOREs can publish a forged record on the replicas the owner
  has not reached yet. ADR 0002 proposed a reservation against it.
- **Known gap** (`AGENTS.md`, key invariants). While the old version of a
  rotated record is anywhere in the network, an empty replica refuses the new
  version by STORE, so the `update_digest` fallback fails.
- **Records carry no order.** An update that keeps the signing key can be
  replayed (`DESIGN.md` section 9), and a replica cannot tell an old version
  from a new one.
- **An update carries a second signature, and the current key can rotate.**
  `auth_signature = sign(new record, old private key)` adds 3309 bytes to
  every UPDATE (about 9.8 KB, 8 fragments, instead of 6.5 KB and 5), costs a
  second ML-DSA verification, and is discarded once checked, so a replica
  that missed the update cannot check it later. Whoever steals the current
  private key, the one the device uses every day, can sign an update to a key
  of their own.

The DID document already holds the device's public key. If the DID is the
hash of the first document, the first record proves its own binding, with no
question to the network. Later versions keep the same DID and form a chain:
each names its predecessor, its number in the chain, and the hash of the key
that will sign the next version (pre-rotation, as in KERI).

## Decision

### 1. The DID

The owner computes the DID from the first document (version 0):

1. Build the DID document with every field except the top-level `id`: the
   ML-DSA-65 key (ADR 0003), the services, `"seq": 0`, no `prev`, and the
   `nextKeyHash` of the key that will sign version 1 (section 2). Every
   place where the document refers to its own DID (`verificationMethod[].id`,
   `controller`, `authentication`, `service[].id`) uses the placeholder
   `P = "did:iiot:self"` in place of the DID, followed by its fragment as
   usual (`"did:iiot:self#k0"`).
2. Serialize it in canonical form (open point 3) and compute
   `S = SHA-256(bytes)`, all 32 bytes.
3. The DID is `did:iiot:` followed by `base64url(S)`, without padding: 43
   characters (open point 1).
4. Replace the placeholder with the DID everywhere, add `"id": DID`, and sign
   the document with ML-DSA-65. The record format of ADR 0003 does not change.

**Key in the DHT.** The key of a DID is `S`, the 32 bytes of its suffix,
decoded. It is not hashed again.

**Hashed form**, as any node computes it from a document `doc` whose `id` is
`D = "did:iiot:" + s`:

1. `s` must be canonical base64url: 43 characters from the URL-safe alphabet,
   no padding, decoding to 32 bytes that encode back to `s`. Otherwise the
   record is `InvalidRecord`.
2. If any string value in `doc` equals `P`, or starts with `P` followed by
   `#`, `?` or `/`, the record is `InvalidRecord`. Otherwise a document could
   hold the placeholder in a place where another holds the DID, and both would
   hash alike.
3. Remove the top-level `id`. Replace every string value equal to `D`, or
   starting with `D` followed by `#`, `?` or `/`, by the same value with `P`
   in place of `D`. Object keys are not changed.
4. Serialize in canonical form, and compute SHA-256.

**Binding of version 0.** A record with `"seq": 0` binds to key `K` only if:
- the hashed form gives `K`;
- it has no `prev`;
- it has a valid `nextKeyHash` (section 2);
- the decoded suffix of its `id` is `K`;
- its self-signature verifies.

The binding needs nothing else: since the DID is the hash of version 0, it
fixes both the first key and the hash of the second. Whether a replica that
holds nothing takes a version 0 is a separate question, of freshness, which
R2 answers by asking the network whether the DID has moved on (section 3,
open point 23).

Sources: the DID as the hash of the first operation comes from [PLC]
("Operation Serialization, Signing, and Validation"); the placeholder for
the identifier inside the hashed bytes from KERI's SAID ([CESR], Annex A).
SHA-256 is [FIPS180].

### 2. Versions: `seq`, `prev` and `nextKeyHash`

- Every document carries `seq`, an integer from 0 to 2^53 − 1 (open point
  3).
- Version 0 has `seq` 0 and no `prev`. Version N ≥ 1 has `seq` N and
  `prev = base64url(record_hash(record of version N−1))`. `record_hash` is
  the function `FindHash` already uses: the SHA-256 of the whole record.
- Every document, version 0 included, carries
  `nextKeyHash = base64url(SHA-256(pk))`, where `pk` is the raw public key
  that will sign the next version: the 1952 bytes of the `pub` of its JWK,
  decoded, not the JWK. It has the encoding of the suffix (open point 1), 43
  characters, decoded as strictly. A document without it, or with `null`, an
  empty string, a non-canonical value, or the SHA-256 of its own key, is
  `InvalidRecord`: a commitment to the current key would let the current key
  sign the next version.
- `id` never changes.
- **An update** builds version N+1 with the same `id`, `seq + 1`, `prev`,
  the key whose hash is the `nextKeyHash` of version N, and a new
  `nextKeyHash` for the key after it. It is self-signed with its own key, and
  that is its only signature: there is no `auth_signature`. Every update
  therefore changes the key (ADR 0003), by construction.
- **The authorization is in the chain.** Version N−1 names the only key that
  may sign version N. A replica that holds version N−1 checks version N on its
  own, with one ML-DSA verification and one SHA-256. A STORE or an UPDATE of a
  version N ≥ 1 carries the record only, and a replica stores the record only,
  as today: in a publication, the `update_digest` fallback, replication to a
  new node and republication alike.
- **Custody of the next key.** The device holds two private keys: the current
  one, which signs the current version and the device's authentications, and
  the next one, which only signs the next version. The next key is kept as its
  ML-DSA-65 seed (32 bytes, FIPS 204; `aws-lc-rs` builds the key pair from it,
  `PqdsaKeyPair::from_seed`) in a secure element (or TPM, TEE or HSM), not in
  RAM, and is used only at the rotation that reveals it. The old private key
  is erased after the rotation. Pre-rotation protects the DID only as far as
  the next key is better guarded than the current one: a theft of the whole
  device memory takes both, and then it is no weaker than an `auth_signature`,
  but no stronger. Where to keep it is the Python application's and the
  device's choice, not the node's.
- **The owner keeps its chain** (open point 20). It saves every version it
  published, from version 0 to the current one, about 6.5 KB each. Holders
  keep only the current version. The owner is the one who can restore copies
  once fewer than the quorum remain: version 0 by R2 at a replica that holds
  nothing, then each later version by R3, and a replica behind gets the
  versions it misses, one at a time. At or above the quorum, an empty replica
  takes the current version by R5 and refuses to start again from version 0
  (R2, open point 23).
- **Binding of version N ≥ 1.** The decoded suffix of `id` is the key,
  `seq ≥ 1`, `prev` and `nextKeyHash` are present and valid, and the
  self-signature verifies. The hash of the document does not bind a later
  version: only the chain does, through the rules below.

Sources:
- `seq`: BEP 44 ([BEP44], "Mutable Items"), where a node rejects a `seq`
  lower than or equal to the stored one.
- `prev`: did:plc ([PLC]), "a CID hash pointer to a previous operation".
- `nextKeyHash`, the pre-rotation: KERI ([KERI], "Pre-rotation", "Tetrad
  bindings", "Next key digest list field"); did:webvh ([WEBVH], "Pre-Rotation
  Key Hash Generation and Verification" and "Read (Resolve)", step 7: "A key
  not in the previous entry's nextKeyHashes MUST cause resolution to
  terminate"); Sidetree ([SIDETREE], "Commitment Schemes", "Update").
- Custody of the seed: [FIPS204], Algorithm 6 (`ML-DSA.KeyGen_internal(ξ)`
  from a 32-byte seed); section 4, "one can store only the 32-byte seed";
  section 3.6.3, the seed "shall be treated with the same safeguards as a
  private key". [SP800-57], section 6.1.1, Table 5: a private signature key
  needs confidentiality and integrity from generation to the end of its
  cryptoperiod; section 6.2.2.3 for its protection in storage. [AWSLC],
  `PqdsaKeyPair::from_seed`.

### 3. Accepting a record at a replica

These rules decide what a replica does with a DID record. A STORE can be
accepted by R2, R3 or R5; an UPDATE only by R3 (open point 12): it takes the
same steps, but where a STORE would run R2 or R5 it refuses, and the other
rules only choose which refusal it gets (the UPDATE table below). The Status
List keeps its own rules (see "Not in this ADR"). The replica takes these
steps in this order (open point 20):

1. **Form.** It parses the document and checks, without verifying any
   signature:
   - for an UPDATE, a `seq` of at least 1: version 0 follows no version, so
     an UPDATE of it has nothing to replace;
   - the canonical form (open point 3) and the placeholder rule (section 1);
   - `id`: a canonical suffix whose decoded bytes are the key;
   - `seq` from 0 to 2^53 − 1; `prev` absent when `seq` is 0, present and
     canonical otherwise; `nextKeyHash` present and canonical, and not the
     SHA-256 of the document's own key, which would let the current key sign
     the next version;
   - for `seq` 0, the hashed form gives the key.

   Any failure is `InvalidRecord`.
2. **R1**, same bytes as stored: `AlreadyStored`. A STORE refreshes the
   expiry of the stored record, as `insert_if_absent` does today, so that
   republication keeps a record alive. Nothing is verified: the bytes are
   those of a record the replica verified when it stored it.
3. **By what the replica holds** for the key:
   - nothing, version 0: R2 (a STORE; an UPDATE of version 0 failed step 1);
   - nothing, version N ≥ 1: R5 for a STORE, `MissingPrevious` for an UPDATE;
   - version N−1: R3;
   - version N or a later one: R4;
   - a version below N−1: `MissingPrevious` with the stored `seq`. The stored
     record is not touched and the network is not asked (open point 20).
4. **The signature** is verified only where a rule needs it: R2, R3, the
   accepting rows of R5, and the proven duplicity of R4. Where it is needed
   and does not verify, the outcome is `InvalidRecord`.
5. **The write.** R2 and R5 write with `insert_if_absent`, R3 with
   `replace_if` (open point 14). If the stored record changed since step 3,
   the replica runs steps 2 and 3 once more against the new one, locally. If
   that would need R2 or R5 again, or the record changes a second time, it
   gives no answer. A record that does not fit in the storage budget is
   `CapacityExceeded`, and nothing is replaced. A STORE accepted by R2, R3 or
   R5 answers `Stored`; an UPDATE accepted by R3 answers `Updated`.

The sender enters the routing table, as today, after a STORE that was
accepted or answered by R1 (the bytes are those of a verified record), never
after `InvalidRecord` or another refusal; an UPDATE answered by R1 leaves
routing untouched, as today (`AGENTS.md`, `src/protocol/store_check.rs`).

- **R2, version 0 at a replica that holds nothing** (open point 23).
  Version 0 proves its binding, not that it is current. Anyone holds every
  published version, so anyone could send an empty replica version 0 and
  then each later version by R3, up to an old one, or up to a version forked
  with a key it stole once that key was revealed, and the network would never
  be asked. R2 therefore asks the same nodes as R5, with `FindHash`, and
  decides when every node asked has answered or the deadline passes,
  refusals first:

  | Answers | Outcome |
  |---|---|
  | at least `store_quorum(n)` answers with `seq ≥ 1` | `NewerClaimed`: the DID has moved on; the replica takes the current version by R5 |
  | any `(0, h)` with `h ≠ record_hash(v0)` | `Conflict`: another record of version 0, signed again; logged with both hashes |
  | every node asked has answered, no row above | verify the self-signature, then accept |
  | no refusal, and silence or nobody to ask | no answer, as R5: never accept on silence |

  The first refusal needs the quorum, not one answer. Below the quorum R5
  cannot accept the current version at an empty replica, so the owner's
  replay from version 0 is the only way to bring copies back, and a single
  holder of a later version must not stop it. The owner's own node does not
  ask about its own version 0: `set` writes it locally, as today
  (`src/network/publish.rs`). A first publication pays one round of
  `FindHash` per empty replica, as every STORE does today.
- **R3, successor of the stored version N−1:** check that:
  - `prev = record_hash(stored)`;
  - SHA-256 of its raw public key is the stored `nextKeyHash`;
  - the self-signature verifies.

  If all pass, replace the stored record. This is today's `rpc_update`, with
  `seq` and `prev` added and the `auth_signature` replaced by the
  `nextKeyHash` check: one ML-DSA verification instead of two. The same `id`
  and `seq = stored.seq + 1` follow from steps 1 and 3. A replica that holds
  version N−1 decides on its own and never asks the network (open point 9):
  a wrong `prev`, or a key that is not the committed one, is `Conflict`,
  logged as a fork.
- **R4, the replica holds version N or a later one, different bytes:**
  - a later version is stored: `Stale`, without verifying anything, since the
    replica holds a newer, verified version (open points 13 and 21);
  - version N is stored: `Conflict`, logged (open points 6 and 11):
    - the same document with another signature: signed twice, at info level,
      without verifying the signature, so a copy whose signature was
      corrupted is logged the same way; it is refused either way;
    - the stored public key, another document and a valid self-signature:
      proven duplicity, two versions of one place in the chain signed by one
      key, as a warning;
    - another public key: a plain conflict, without verifying anything.
- **R5, network check, version N ≥ 1 at a replica that holds nothing**
  (open points 5, 9, 19, 20 and 26). `FindHash` answers now carry
  `(seq, hash)`.
  The replica asks the nodes closest to the key, as today, and decides when
  every node asked has answered or the deadline passes, refusals first. A
  refusal wins even when another node is still silent at the deadline: no
  row can accept then, and the sender learns why. Without a refusal, a row
  accepts only once every node asked has answered:

  | Answers | Outcome |
  |---|---|
  | any `seq > N` | `NewerClaimed`: a node claims a newer version, which it does not prove (open point 21) |
  | any `(N, h)` with `h ≠ record_hash(vN)` | `Conflict`; log it as a conflict, with both hashes (a hash proves nothing about the key) |
  | any `(N−1, h)` with `h ≠ prev` | `Conflict`: vN does not follow the version N−1 that node holds |
  | any `seq < N−1` | `Conflict`: a holder is behind, or vN skips versions; logged as a holder behind, with both `seq` (open point 26) |
  | any `(N−1, prev)` | fetch version N−1 and check it (below). With N = 1 accept if the check holds; with N ≥ 2 each such answer is a vote for the next row (open point 19) |
  | at least `store_quorum(n)` votes: answers `(N, record_hash(vN))`, plus answers `(N−1, prev)` when N ≥ 2 | verify the self-signature, then accept |
  | no refusal, and silence, fewer than `store_quorum(n)` votes, or nobody to ask | no answer, as today: never accept on silence |

  **The fetch.** The replica asks one node that answered `(N−1, prev)` for
  its record with `FindValue`: the one closest to the key first, then the
  next one if it gives no record, within the deadline of the whole check
  (`STORE_LOOKUP_TIMEOUT`, counted from the start of the lookup). The record
  must:
  - hash to `prev`;
  - pass step 1 with `seq = N−1` and the same key, and for N = 1 the whole
    binding of version 0, self-signature included (section 1);
  - commit to vN's key: SHA-256 of vN's raw public key is its `nextKeyHash`.

  A record that does not hash to `prev` proves nothing about vN: that
  node's answer is dropped, it is no vote, and the replica asks the next
  one. A record that hashes to `prev` is the very record every voter
  `(N−1, prev)` claims, so if it fails the other two checks the outcome is
  `Conflict`. vN's self-signature must verify too, or the outcome is
  `InvalidRecord` (step 4). No record within the deadline gives no answer.
  It is one record from one node, after the round of hashes, not a record
  from every holder, so the reason why `FindHash` replaced `FindValue` in
  the check still holds (`AGENTS.md`). Whether the round of hashes and a
  fetch of 5 fragments fit in `STORE_LOOKUP_TIMEOUT` (2 s) on the WAN
  profiles is measured in the testbed (Validation).

  An answer with `seq < N−1` refuses (open point 26). Either a holder is
  behind, or vN claims a `seq` beyond what the network holds. So one honest
  node holding the genuine current version vC refuses every forged vN that
  is not its signed successor:
  - a `seq` below C gets `NewerClaimed`;
  - C itself gets `Conflict` by the second row;
  - C + 1 with another `prev` gets `Conflict` by the third row;
  - anything beyond C + 1 gets `Conflict` by this row.

  What gets past it is only a version C + 1 whose `prev` names vC, and the
  fetch then requires its key to be the one vC commits to, which only the
  next key can sign. This is the veto one honest holder has today ("Another
  hash: `Conflict`"). The price is that holders cannot fill an empty replica
  while an honest replica two or more versions behind is asked. The owner
  repairs those first ("The replay", order), at least once every 24 hours.
  Without the owner the stale record stays until it expires, and replicas
  holding the same old version can refresh each other's expiry by
  republication (R1).

  With N = 1 the fetch is fully cryptographic, because version 0 proves its
  own binding, and one answer is enough. With N ≥ 2 nothing the replica
  holds proves that version N−1 is genuine, so every way to accept needs the
  quorum, and no honest node asked may hold the record.
- **UPDATE** (open point 12) is a conditional write on `prev`. It applies
  R1, answering `AlreadyStored`, and R3, answering `Updated`. It never asks
  the network and never accepts without version N−1. Otherwise it refuses
  and says why:

  | The replica holds | Answer | `update_digest` then |
  |---|---|---|
  | nothing | `MissingPrevious` | sends the record by STORE (R5); if it is not stored, the replay below, from version 0 (open point 20) |
  | a `seq` `s` below N−1 | `MissingPrevious` with `s` | the replay below, from version s+1 (open point 20) |
  | a `seq` above N | `Stale` | sends nothing |
  | `seq` N with other bytes (R4), or version N−1 with a wrong `prev` or key (a fork) | `Conflict` | sends nothing |
  | a record that fails step 1, or a signature that does not verify | `InvalidRecord` | sends nothing |
  | no room for it | `CapacityExceeded` | sends nothing |
  | no answer | — | sends nothing, as today |

  **The replay** (open points 20 and 24). `update_digest` sends the owner's
  versions to one replica in order, each one after the answer to the one
  before: version 0 by STORE, since R2 runs only on a STORE, and every later
  version by UPDATE, checked by R3.
  - It starts after `MissingPrevious` with `s`, from version s+1. After a
    fallback STORE that ends in no answer, `Conflict` or `NewerClaimed`, it
    starts from version 0, or from s+1 if that STORE answered
    `MissingPrevious` with `s`. A fallback STORE that ends in `Stale`,
    `InvalidRecord` or `CapacityExceeded` starts none: the replica holds a
    newer version, or the replay would fail the same way.
  - `Updated`, `Stored` or `AlreadyStored` sends the next version. Any other
    answer, or none, stops the replay to that replica until the next call,
    so one call sends a replica at most N + 1 records.
  - **Order** (open point 23): the replicas behind first, the empty ones
    after. `update_digest` replays to the replicas that answered
    `MissingPrevious` with `s`, and only once those replays end sends the
    fallback STORE to the replicas that hold nothing. Their R5 then counts
    the replicas just repaired: honest holders spread over several versions
    (with `k = 20`, 7 at N and 6 at N−2) give 13 answers with `seq ≥ 1`,
    enough for R2 to refuse version 0, but only 7 votes for R5.
  - **When:** the owner calls `update` after each rotation, and again with
    the saved bytes at least once every 24 hours, as Kademlia asks of the
    original publisher ([KAD], section 2.3), well within the 14-day expiry.
    The cadence is the Python application's (section 5).
  - **Cost:** a replica that holds nothing gets up to N + 1 records of about
    6.5 KB and verifies each one. With a rotation a week, a year's chain is
    53 versions, about 345 KB to each such replica. A node among the `k`
    closest that answers `MissingPrevious` falsely gets the whole chain once
    per call: an amplification bounded by the length of the chain and by
    the owner's cadence. Unlike a key event log in the record (see
    "Alternatives rejected"), the chain goes only to the replicas that miss
    versions, not with every STORE and every republication.

  `update_digest` counts toward its quorum each replica's answer to vN,
  whichever message carried it (the UPDATE, the fallback STORE, or the last
  step of a replay): `Updated`, `Stored` and `AlreadyStored` count for it,
  any other outcome or none against. The owner's own node checks its local
  copy as any replica does: its vote is the outcome of R1 or R3 against that
  copy. When it lacks version N−1, it first writes the owner's versions up to
  N−1 locally, by R2 and R3, without asking the network, since the chain is
  the owner's own. It writes vN with `replace_if` only once the quorum is
  met, as today (`update_commits_locally_after_quorum` in
  `tests/quorum_tests.rs`). This closes the known gap.

Sources:
- R2 asks the network because an empty replica has seen nothing first:
  [KERI], "Security Properties of Pre-rotation", "Dead-Attacks" ("The
  attacker, therefore, must get ahead of the propagation of a past rotation
  event. Otherwise, the Validator would have already First-seen the original
  event"). It refuses only on a quorum, as KAWA decides on a threshold of
  witnesses ([KERI], "KERI's Algorithm for Witness Agreement (KAWA)",
  "Immunity and Availability": it "guarantees that at most one sufficient
  agreement occurs or none at all"), and as Byzantine quorum systems keep a
  value that is not self-verifying only when reported by a set of servers
  that cannot all be faulty ([BQS], section 4). The attacks it stops are
  TUF's rollback and indefinite freeze ([TUF], section 1.5.2: "An attacker
  cannot trick clients into installing software that is older than that
  which the client previously knew to be available").
- R3 checks the successor against the commitment of the stored version, as
  did:webvh checks each log entry against the previous one ([WEBVH], "Read
  (Resolve)") and TUF each root version N+1 against version N ([TUF],
  section 5.3.4).
- R4: the duplicity of KERI ([KERI], Annex A, "Duplicity": "a verified but
  different version of an event at the same location") and its "First Seen
  Policy" ("first seen, always seen, never unseen"), which a replica follows
  by keeping the version it holds. A `seq` equal to the stored one with other
  bytes is refused, as in [BEP44].
- R5 never accepts on silence: fail-safe defaults ([SALTZER], I-A-3 b,
  "Base access decisions on permission rather than exclusion"), and the
  soft-fail of revocation checks ([LANGLEY]: checks "which result in a network
  error are effectively ignored").
- R5 never replaces a stored record, and a replica behind is repaired only by
  verified successors, one at a time: [KERI], "First Seen Policy"; [TUF],
  section 5.3.4, where a client checks each root version N+1 against version
  N; the owner republishing its own record follows [KAD], section 2.3 ("we also
  require the original publisher of a ⟨key,value⟩ pair to republish it every
  24 hours").

### 4. Reads

`get` keeps its semantics: the first record that binds and verifies. It now
uses the bindings of sections 1 and 2. Choosing the highest `seq` among
answers is not decided here: a self-signed record with a made-up higher `seq`
would win a plain highest-`seq` rule. Reads stay non-authoritative, and the
caller still compares the public key with the hash in the VC.

### 5. Python

The Python application builds documents and computes the DID as in section 1,
and keys as the decoded suffix. A test vector is computed with Python's
`json` and `hashlib` and checked by the Rust tests (as in ADR 0004). It
generates the next key pair before each version, writes its `nextKeyHash`,
keeps its seed as section 2 says, and no longer computes an `auth_signature`.
It signs each version once, saves the record, and sends the saved bytes on
every retry (open point 11). It reads `stale_rejections` from
`set_detailed` apart from `conflict_rejections` (open point 13). It
publishes version 0 with `set` and every later version with `update`, with
no `auth_signature` (open point 16). It keeps every version it published and
passes the earlier ones to `update`, which uses them only to replay the chain
to replicas that miss versions; it calls `update` again with the saved bytes
at least once every 24 hours, so that copies lost to churn come back (open
point 20, section 3, "The replay"). It
generates and keeps the next key as a seed, through the seed API of open
point 22.

## Consequences

- **ADR 0002 is superseded:** no reservation.
- **ADR 0004:** the canonical UUID gives way to the canonical base64url suffix.
  Collision resistance now matters: an owner who found two first documents with
  the same hash could show one or the other. Full SHA-256 gives about 2^128.
- **Wire:**
  - `FindHashHit` gains `seq`;
  - `Update` loses `auth_signature`: an UPDATE of a rotated record goes from
    about 9.8 KB in 8 fragments to about 6.5 KB in 5;
  - `UpdateResult { ok: bool }` becomes a status: `Updated`,
    `AlreadyStored`, `MissingPrevious` (with the stored `seq`, if any),
    `Stale`, `Conflict`, `CapacityExceeded`, `InvalidRecord` (open points 12
    and 20);
  - `StoreStatus` gains `Stale`, `NewerClaimed` and `MissingPrevious` (open
    points 13, 20 and 21), and `SetReport` counts `Stale` in
    `stale_rejections`, apart from `conflict_rejections`. `set` publishes
    only version 0, which never meets R5, so `NewerClaimed` reaches only
    `update`, which logs it and replays (section 3), and the STOREs of
    republication and `replicate_to`, which ignore every answer as today;
  - every document grows by its `nextKeyHash`, about 60 bytes.

  Nodes before and after this change cannot talk. No network runs these
  records yet.
- **Saved records:** unchanged, the record only.
- **Theft of a revealed key** no longer lets an attacker rotate: the next
  key never left the secure element. It still lets them sign another version
  M, with a `nextKeyHash` of their own, where M is the version that revealed
  the stolen key: the current one, or an older one if the key was copied
  while it was in use. A replica holding the genuine version M or a later
  one refuses it (R4, logged as duplicity, or `Stale`). The other replicas
  are where the fork can land (open point 23):
  - a replica holding version M−1 that missed the update, until the genuine
    version M reaches it: a first-seen race;
  - a replica that holds nothing, walked up the genuine chain to M−1 and
    then given the fork. R2 stops this while at least `store_quorum(n)`
    nodes near the key answer with `seq ≥ 1`, and a version 0 signed again
    with a stolen `k0` whenever one node answers with the genuine version 0.
    Below the quorum it stays possible.

  A fork that lands stays until it expires, and the thief can keep it alive
  by sending it again (R1); the owner's replay cannot repair it, since R3
  refuses the genuine chain there. KERI names this duplicity and answers it
  with "first seen" and witnesses ([KERI], Annex A, "Duplicity", "First Seen
  Policy"; "Security Properties of Pre-rotation", "Dead-Attacks"; "KERI's
  Algorithm for Witness Agreement (KAWA)").
- **An old version pinned at an empty replica.** Below the quorum, anyone
  can walk an empty replica up the genuine chain to an old version and leave
  it there, perhaps with a key the owner rotated away from. Holders cannot
  move it (their STORE of the current version gets `MissingPrevious`), the
  owner's replay does. At or above the quorum R2 and R5 refuse it, as
  today's check refuses an old record at an empty replica.
- **A lost next key** means no further rotation, as a lost key does today:
  the device needs a new DID.
- **Holders alone cannot bring back a record below the quorum** (open point
  20). R5 needs `store_quorum(n)` holders that answer, so once fewer copies
  remain, republication and `replicate_to` add none, and with `k = 3` that is
  one holder left. The owner restores them by replaying its chain, which
  needs no quorum there: it calls `update` again with its saved versions, as
  Kademlia asks the original publisher to republish ([KAD], section 2.3). At
  or above the quorum the replay from version 0 is refused (R2) and is not
  needed, since R5 fills the replica.
- **One node can keep new replicas empty**, at any number of holders, by a
  refusing answer or by silence, as today. Below the quorum too: one answer
  `(0, h)` with a made-up `h`, or one silent node, stops the owner's replay
  at its first step (R2), so the replay needs no votes but does need every
  node asked to answer truthfully. With one persistent liar near a DID the
  number of copies can only fall. `store_quorum(n)` liars that claim
  `seq ≥ 1` block the owner's replay to every empty replica; the same number
  already gets a forgery through R5. A refusal that must show its evidence
  would remove the single liar's veto, and is item 4 of "Not in this ADR".
- **What the check at an empty replica assumes.** R2 and R5 count answers,
  so their safety holds only while:
  - an answer comes from the node it names. Malkhi and Reiter assume "an
    authenticated, reliable channel" ([BQS], section 3.1), while S/Kademlia
    presumes that "nodes can spoof IP addresses and there is no
    authentication of data packets in the underlay" ([SKAD], section 3.1).
    Here an answer is matched by message id and source address
    (`src/protocol/transport.rs`), so a node that reads the traffic and
    sends datagrams under another node's address casts that node's vote.
    Message ids counted up from a random start, so a node asked in a round
    could predict the ids of the other requests of that round; they are now
    drawn at random for each request (open point 25), and only a node that
    reads the traffic can answer for another;
  - node ids cannot be chosen: admission bounds how many identities an
    attacker has, not where they sit, so `store_quorum(n)` admitted nodes
    can place themselves next to one DID until ids come from admitted keys
    (item 2 of "Not in this ADR"; [SKAD], section 3.2, "Eclipse attack": it
    "can be prevented, first, if a node can not choose its nodeId freely");
  - the replica's own routing table sets `n`: a restarted replica that knows
    few contacts asks few nodes, and needs few votes (open point 5).
- **A next seed suspected of having leaked** has one answer: rotate with it
  at once. There is no way to commit to another next key without signing
  the next version with the one committed.
- **A forgery accepted at an empty replica stays there.** A forged vN
  accepted by R5 needs `store_quorum(n)` colluders among the nodes asked
  and, with open point 26, no honest node among them that holds the record.
  R3 then refuses the genuine chain there as a fork, until the forged record
  expires; a forged `seq` near 2^53 − 1 makes every genuine later version
  `Stale` there. The defence is the quorum and one honest holder's refusal,
  and later node ids from public keys and disjoint paths (items 2 and 3 of
  "Not in this ADR").
- **`AGENTS.md` changes:**
  - "Records are immutable after creation" becomes: one record per key,
    replaced only by a verified successor (R3); the network check (R5) only
    fills a replica that holds nothing (open point 20);
  - the STORE check of an empty replica covers version 0 too (R2, open
    point 23), with its own rows, and the replay of the genuine chain below
    the quorum is stated as a limit; for a version N ≥ 1, "no node holds the
    key" is no longer an accept but no answer, since it gives no votes; the
    fetch of one record in R5 is noted beside the rule that the check uses
    `FindHash` and not `FindValue`. The
    STORE still runs in its own task when the key is not held
    (`store_needs_lookup`), which with open points 20 and 23 covers every
    case that runs R2 or R5;
  - the DHT key invariant follows section 1;
  - "Updates require `auth_signature`" becomes the `nextKeyHash` check, and
    the downgrade argument rests on `seq` and `prev` at a holder, and on R2
    and R5 at an empty replica, at or above the quorum; not on the key
    change;
  - the "What NOT to do" item about an `"updated"` field gets a note: `seq`
    and `prev` are no timestamps, they order versions and stop the replay of
    an update that keeps the key;
  - "UPDATE does not converge on its own" and "Retrying an applied UPDATE
    is safe" follow open points 12 and 16: `Server::update` reads no copy,
    `rpc_update` answers with a status, and only `MissingPrevious` sends the
    STORE or the replay;
  - in the STORE check, "Another hash: `Conflict`" becomes the rows of R5:
    a `seq` below N−1 refuses as a holder behind (open point 26), a higher
    one is `NewerClaimed`;
  - the outcomes of the check counted by `src/counters.rs` (`unbound`,
    `nobody_to_ask`, `none_or_same`, `other`, `no_answer`) follow the rows
    of R5, and the experiment on the check in `EXPERIMENTS.md` is run again;
  - the local vote of `update_digest` is the outcome of the rules against the
    local copy, no longer a vote counted before any check;
  - the concurrency-model bullet on `rpc_store` ("different bytes
    conflict") gains the replacement by R3 with `replace_if`;
  - the "Lost datagrams" bullet: message ids are drawn at random for each
    request, and a resend keeps its id (open point 25);
  - the wire record format: every document has `seq`, `prev` (not in
    version 0) and `nextKeyHash`, in the canonical form of open point 3,
    printable ASCII only;
  - the test table and its counts, and the ports of the new tests, from
    15954;
  - the known gap goes away.
- **ADR 0003:** every update changes the signing key, now by construction: a
  version that keeps the key cannot match the `nextKeyHash` before it.
  Updates without rotation would need versions signed by the current key
  (KERI's interaction events), a later ADR.
- **API:** functions that take a DID UUID take the DID, or its suffix, instead
  (`py_bindings` included). `set` and `set_detailed` publish only a version
  0; `update` takes a version N ≥ 1 and the owner's earlier versions, used
  only to replay, and reads no copy first (open points 16 and 20). On
  `STATUS_LIST_KEY`, `update` keeps today's path: the issuer's signature, no
  `seq` and no earlier versions (item 1 of "Not in this ADR").
  `MlDsa65KeyPair` gains `from_seed`, and `py_bindings` a way to build a key
  pair from a seed (open point 22). `SignatureVerifierHandler::
  handle_update_verification` goes away with the `auth_signature`.
- **Dependencies:** none new. SHA-256 and base64url are already in use.

## Alternatives rejected

- **A random UUID with a reservation (ADR 0002).** It hides the DID for one
  round trip only, does not stop whoever knows the UUID first, and a
  reservation with a random hash blocks the owner.
- **XOR of SHA-256(document) and SHA-256(public key).** The key is already in
  the document, so the XOR adds nothing, and it makes the security harder to
  argue.
- **A key event log in the record (KERI).** The record grows with every
  rotation, without bound with weekly rotations. Its pre-rotation is adopted
  (section 2), without the log.
- **The `auth_signature` stored and sent with the record** (the first draft
  of this ADR). A replica that missed an update could check it, but every
  STORE of a rotated record carried 3309 more bytes, a replica holding
  nothing could not check it either, and the current key could still rotate.
- **The `auth_signature` discarded after the UPDATE** (today). A replica that
  missed the update can only trust the network (R5).
- **A separate controller key (did:plc).** A second key to protect.
- **Signed receipts from replicas with a threshold.** Constant size, but it
  needs signatures from others on every rotation. To be weighed later.
- **Recursive proofs of the chain (SNARK, STARK).** Constant size and no
  trust, but research work, too heavy for the boards.
- **A truncated hash.** did:plc truncates the base32 hash to 24 characters
  ([PLC]), 120 bits: about 2^60 against collisions, less against a quantum
  computer.
- **A DID from a device attribute (IP, MAC, serial number).** Predictable:
  anyone can derive it.

## Not in this ADR

Separate ADRs, in this order of urgency:
1. **Version and expiry of the Status List.** `rpc_update_status_list` accepts
   any list the issuer signed, so an old list can be sent again.
2. **Node ids derived from public keys, and admission.**
3. **Lookups over disjoint paths** ([SKAD], section 4.4, "Lookup over
   disjoint paths"), then the condition "answers from at least two paths" in
   R5.
4. **Signed `FindHash` answers, proof requests for a claimed higher `seq`, and
   disputes settled by walking back `prev` through an archive.**
5. **Reads that choose the highest verifiable `seq`.**
6. **Deterministic CBOR** (RFC 8949, section 4.2) for documents, to explore
   and possibly adopt if they leave JSON, for example on very constrained
   devices: a change of DID Core representation, and of how the DID is
   derived.
7. **The JSON-LD context of the documents.** They declare
   `"@context": ["https://www.w3.org/ns/did/v1"]`, which defines 11 terms
   and not `publicKeyJwk`, `JsonWebKey2020` or `DeviceAgent`, already used
   today, nor `seq` and `prev`: a strict JSON-LD processor drops them. Nodes
   and the Python application read documents as plain JSON, so nothing
   breaks today. A `did:iiot` context, or plain JSON without `@context`,
   is a separate decision.
8. **More than one next key, a threshold, and closing a DID** (KERI,
   did:webvh `nextKeyHashes`): an empty commitment that ends the chain, or
   several devices or operators who must agree on a rotation.
9. **Keeping the evidence of duplicity**: both records of a proven
   duplicity, kept and served to whoever must stop trusting the DID, as
   KERI's juror keeps a duplicitous event log ([KERI], "Witnessing Policy";
   keripy's `.dels`, [KERIPY-DB]).

## Open points (decided with the user before any code)

1. **Encoding of the suffix:** base64url without padding, 43 characters
   (proposed); hex, 64 characters; or multibase with an algorithm code.

   **Decided (2026-11-10):** base64url without padding, 43 characters. Hex
   is 21 characters longer at every place the DID appears and needs a rule
   for letter case; a multibase prefix names the hash, which no node can use
   today, since changing the hash needs a new ADR and every node anyway. A
   prefix can come with that ADR: today's DIDs stay apart by their exact
   length. The decoder is strict: `URL_SAFE_NO_PAD` of `base64` 0.22 refuses
   padding and non-zero trailing bits, and the node also checks that the 32
   bytes encode back to `s`. Python's `base64.urlsafe_b64decode` accepts
   trailing bits, so the Python application must make the same check.

   Sources: base64url is [RFC4648], section 5; section 3.5 lets a decoder
   "reject an encoding if the pad bits have not been set to zero", which
   makes the encoding of 32 bytes unique. `base64` 0.22.1,
   `src/engine/general_purpose/mod.rs` (`URL_SAFE_NO_PAD`, read in the crate
   source). Python 3: `base64.urlsafe_b64decode` decoded 42 `A` followed by
   `B` into 32 bytes that encode back to another string (checked on
   2026-11-10).
2. **The placeholder:** `did:iiot:self` (proposed).

   **Decided (2026-11-10):** `did:iiot:self`. DID Core leaves to the method
   how the method-specific id is generated (DID Core 1.0, 8.1 and 8.2), and
   sets rules only on the document as published and resolved: `id` expresses
   the DID (5.1.1) and "MUST match the DID that was resolved" (7.1), a
   verification method's `id` is a DID URL and its `controller` a DID (5.2).
   The published document holds the DID everywhere, and rule 2 of the hashed
   form refuses one that holds the placeholder. `did:iiot:self` fits the DID
   syntax (`idchar`, 3.1) but is no `did:iiot` DID: the method specifies how
   its method-specific-id is generated (8.1), here a suffix of exactly 43
   characters. KERI does the same with a placeholder of `#` characters
   (SAID); did:peer method 4 leaves `id` out of its input document instead,
   and its resolver adds `id` and every missing `controller`, so the signed
   document is not the one read.
   As the method specification, this ADR also gives what DID Core 8.1 asks
   of it: the suffix is case-sensitive and has one form, the canonical
   base64url of open point 1, with no normalization; it is unique as long as
   SHA-256 resists collisions.

   The owner replaces the placeholder with the same rule the node uses (a
   string value equal to `P`, or starting with `P` followed by `#`, `?` or
   `/`), never by text substitution: otherwise a placeholder inside a URL
   would be replaced by the owner and not put back by the node, and the
   owner's own record would not bind. A document of any version that holds
   the placeholder by that rule is `InvalidRecord`, not only version 0, so
   the placeholder never reaches a reader.

   Sources: [DIDCORE] sections 3.1, 5.1.1, 5.2, 7.1, 8.1 ("MUST specify how
   to generate the method-specific-id", "MUST define sensitivity and
   normalization", "MUST be unique within a DID method") and 8.2. The
   placeholder: [CESR], Annex A, "Self-addressing identifier (SAID)",
   "Generation and Verification Protocols" ("a dummy string of #
   characters"). did:peer: [PEER], "Method 4", "Creating a DID" and
   "Resolving a DID".
3. **Canonical serialization:** today's serialization (`serde_json`, sorted
   keys, compact), or RFC 8785 (JCS), which needs a crate or our own code
   (`AGENTS.md`: ask before adding a crate). Until then, documents are ASCII
   only?

   **Decided (2026-11-10):** today's serialization, restricted so that it is
   RFC 8785 byte for byte, with no new crate:
   - keys and strings hold printable ASCII only (0x20 to 0x7E): keys sort
     alike by bytes (`serde_json`, built without `preserve_order`) and by
     UTF-16 code units (JCS), and both escape only `"` and `\`;
   - no number with a fraction or an exponent: JCS writes them as ECMAScript
     does, `serde_json` does not;
   - integers within ±(2^53 − 1), which both write as plain decimals;
   - the node requires the document bytes to be canonical already:
     serializing the parsed document gives the same bytes. This refuses
     whitespace, keys out of order, needless escapes and duplicate keys,
     which parsers resolve differently (`serde_json` keeps the last), so a
     reader in another language cannot see another key than the node.

   Any other document is `InvalidRecord`. A JCS library adopted later gives
   the same bytes, so no DID changes. SSZ was weighed and rejected: it gives
   the same uniqueness of bytes with a fixed schema, but DID documents are
   JSON for every reader, the services are open, and it needs a crate in
   Rust and a library in Python. Deterministic CBOR (RFC 8949, section 4.2,
   as did:plc uses) is the format to explore if documents ever leave JSON
   (see "Not in this ADR").

   Sources: [RFC8785] sections 3.2.3 (property names sorted "as arrays of
   UTF-16 code units"), 3.2.2.3 (numbers as ECMA-262) and 3.2.2.2 (only `\\`
   and `\"` escaped among printable characters). Duplicate keys: [RFC8259]
   section 4 ("the behavior of software that receives such an object is
   unpredictable") and [BISHOPFOX], "Inconsistent Duplicate Key Precedence",
   a survey of 49 parsers. SSZ: [SSZ]. Deterministic CBOR: [RFC8949] section
   4.2.1; did:plc encodes its operations in DAG-CBOR ([PLC]).
4. **Field names:** `seq` and `prev` at the top level (proposed); DID Core
   allows extension properties.

   **Decided (2026-11-10):** `seq` and `prev` at the top level. `seq` is a
   JSON integer; `prev` has the encoding of the suffix (open point 1), 43
   characters. Version 0 has no `prev` key at all: `"prev": null` or an
   empty string is `InvalidRecord`, so that "no predecessor" has one form.
   `prev` is the name did:plc uses. `versionId` was rejected: DID Core uses
   it in the metadata of a resolution (`didDocumentMetadata.versionId`), not
   in the document; a resolver may report `seq` there. A nested object would
   avoid a clash with a future DID Core term that is not in sight.

   Sources: extension properties, [DIDCORE] section 4.1; `versionId`,
   [DIDCORE] section 7.1.3 ("DID document metadata SHOULD include a
   versionId property"); `prev`, [PLC]; `seq`, [BEP44].
5. **`STORE_QUORUM`:** proposed 2, until lookups over disjoint paths exist.

   **Decided (2026-11-10):** not a constant but a function of the nodes that
   can vouch for the record. The replica asks the nodes closest to the key;
   since it is one of the `k` replicas, at most `n = min(k − 1, nodes asked)`
   of them hold the record. Then:

   ```
   f               = max(1, ⌊(n − 1) / 3⌋)
   store_quorum(n) = max(2, min(n, ⌈(n + f + 1) / 2⌉))
   ```

   and with fewer than `store_quorum(n)` matching answers R5 gives no
   answer, so with `n < 2` the quorum row never accepts (the fetch row with
   N = 1 still can, open point 19). With `k = 3` (the testbed) it
   is 2, with `k = 5` 3, with `k = 10` 6, with `k = 20` (the default) 13.

   Why this formula:
   - `f` is the number of nodes that may lie, the largest that keeps
     `n > 3f`, the condition under which a dissemination quorum system
     exists. For `n ≤ 3` no such `f ≥ 1` exists; `f` is set to 1 anyway, as
     keripy does, and the quorum becomes all of the `n` nodes.
   - Any two sets of `⌈(n + f + 1)/2⌉` nodes among `n` share at least `f + 1`,
     so at least one honest node. An honest replica holds one version for a
     place in the chain (R4), so two versions N, for instance a genuine one
     and one signed with a stolen current key, cannot both be accepted by
     empty replicas that ask the same nodes. (Revised after the reviews:
     this does not follow from the intersection alone, since an honest node
     at N−1 votes `(N−1, prev)` for any successor that names its hash, and
     two forks of version N share their `prev`. What stops the second fork
     is the refusal row `(N, h)` of R5 from an honest holder of the first,
     and first seen at holders (R4). And with open point 23 it holds only
     because R2 asks the network too: with R2 asking nobody, a replay of the
     genuine chain from version 0 reached the fork without meeting R5.
     Below the quorum it still can.)
   - It is also at least `f + 1`, so the liars alone never reach it. For
     N ≥ 2 a version N is not self-verifying at an empty replica, which
     cannot check the chain behind it, and Byzantine quorum systems accept
     such a value only when at least `f + 1` servers report it.
   - The minimum of 2 departs from KERI, whose threshold for one witness is
     1: no replica accepts on the word of one node. A network smaller than
     `k` gets a quorum it can reach, since `n` follows the nodes asked. The
     other side of it: a restarted replica that knows few contacts has a
     small `n`, so its bar drops to 2 whatever `k` is, and a routing table
     filled by an attacker lowers it the same way; nobody to ask still gives
     no answer.
   - The silence rule stays: every node asked must answer. KERI tolerates up
     to `n − M` silent witnesses (`M ≤ n − f`); this ADR does not, by
     `AGENTS.md` (never accept on silence). Liveness pays: with `k = 20` an
     empty replica needs 13 of the 19 others holding the version, and all 19
     answering, or it stays empty until the next republication.
   - The quorum is no defence when an attacker can place many nodes near a
     key: that needs node ids derived from public keys and lookups over
     disjoint paths (items 2 and 3 of "Not in this ADR").

   In the code the rows of R5 that trust answers sit in one function, so
   that disjoint paths can be added there later.

   Sources: [BQS], section 5.1, Definition 5.1 (dissemination quorum
   systems, for self-verifying data), Corollary 5.5 (one exists for `f`
   faults "iff n > 3f") and Example 5.7 (Threshold: quorums of size
   `⌈(n + f + 1)/2⌉`); section 4, the read of masking quorum systems, for
   data that is not self-verifying, which keeps only a value reported by a
   set of servers that cannot all be faulty. Note, after the reviews: for
   data that is not self-verifying, as vN is for N ≥ 2 at an empty
   replica, the paper builds masking quorums, of size `⌈(n + 2f + 1)/2⌉`
   with `n > 4f` (Example 4.7), not the dissemination size taken here. The
   rule is still safe against forgery for another reason: the replica asks
   every node, needs `store_quorum(n) ≥ f + 1` matching votes, and so the
   liars alone never reach it (the read rule of section 4). The size is a
   policy chosen above `f + 1`, not the dissemination construction, and `f`
   is not the number of liars the check tolerates: a forgery needs
   `store_quorum(n)` of them and, with open point 26, no honest holder among
   the nodes asked; a block needs one. [KERI], Annex A, "KERI's Algorithm
   for Witness Agreement (KAWA)", "Immunity and Availability" ("a threshold
   M < N that guarantees that at most one sufficient agreement occurs or none
   at all"; "at most F* = N-M of the witnesses are potentially unavailable").
   [KERIPY], `ample()`, the same threshold in KERI's reference
   implementation: `f` from `n >= 3*f+1`, at least 1, and
   `(n+f+1)/2 <= m <= n-f`. Compared and not taken: [LIBP2P]
   `Quorum::Majority`, `total / 2 + 1`, and [CASSANDRA] `QUORUM`, `n/2 + 1`
   with `W + R > RF`: majorities designed for nodes that fail, not for nodes
   that lie. With `k = 20` the majority is 11, and two sets of 11 among the
   19 other replicas share only 3 nodes, which 6 liars can cover.
6. **Duplicity at equal `seq` (R4, R5):** only logged for now, or both records
   kept as evidence?

   **Decided (2026-11-10):** logged only; the replica keeps the version it
   holds and answers `Conflict`, and nothing else is stored. Two cases are
   told apart:
   - **proven duplicity** (R4): the incoming version N has the public key of
     the stored version N, another document, and its self-signature
     verifies. Two documents at one place in the chain signed by one key
     prove that the key revealed by version N was stolen, or that its owner
     signed two versions. Logged as a warning with the key, `seq` and both
     record hashes. It costs one ML-DSA verification, only in this case. The
     same document with another signature is no duplicity but a version
     signed twice (open point 11);
   - **plain conflict**: another public key (any forged record), or an
     answer `(N, h)` in R5, where a hash proves nothing about the key.
     Logged without verifying anything.

   Keeping both records would need a second entry per key (about 6.5 KB), a
   format, and a bound against whoever fills it, for evidence that nobody
   reads yet: item 9 of "Not in this ADR".

   Sources: [KERI], Annex A, "Duplicity" ("A validator SHOULD choose not to
   trust when there is evidence of duplicity") and "Witnessing Policy" (by
   default "inconsistent receipts, i.e., for different event versions at the
   same location, are discarded (not kept in the log)"; a controller may run
   a juror that "keeps a duplicitous event log (DEL)"). [KERIPY-DB], `.dels`,
   "duplicitous event log tables", kept apart from the event log.
7. **ADR 0004 in the README table:** Accepted with a note, since only its
   UUID part changes?

   **Decided (2026-11-10):** when this ADR is accepted, ADR 0004 becomes
   "Accepted, amended by 0005", in the table of `docs/adr/README.md` and in
   its own Status line, and nothing else in it changes; ADR 0002 becomes
   "Superseded by 0005". `docs/adr/README.md` adds "Amended by NNNN" to the
   statuses: part of the decision is changed by a later ADR, the rest still
   holds. "Superseded" would say that all of ADR 0004 is replaced, while its
   SHA-256 keys and 256-bit ids stay.

   Sources: [NYGARD] ("If a later ADR changes or reverses a decision, it may
   be marked as "deprecated" or "superseded" with a reference to its
   replacement"); [ADRTOOLS], `adr new -l "5:Amends:Amended by"`, a new ADR
   that amends an earlier one without replacing it.
8. **The entry for record and authorization:** a `bincode` struct, or the two
   concatenated with a length.

   **Closed (2026-11-10)** by open point 18: there is no authorization to
   store, and a stored entry is the record only.

Raised while reviewing this ADR against the code:

9. **R5 against a current replica.** R5 also runs when the stored record
   does not match `prev`, and the table has no row for an answer `(N−1, h)`
   with `h ≠ prev`. A replica holding the genuine version 5 gets a forged
   version 6 with a made-up `prev`: R3 fails, R4 does not apply, R5 runs. The
   honest answers `(5, H(v5))` match no row, two colluders answer
   `(6, H(forged v6))`, the quorum row holds and the forgery replaces version
   5. Proposed:
   - a stored `seq = N−1` whose `record_hash` is not `prev` is a local
     `Conflict`, logged as a fork; R5 runs only when nothing is stored or the
     stored `seq` is below N−1;
   - an answer `(N−1, h)` with `h ≠ prev` refuses;
   - the rows are applied once every node asked has answered, refusals first.

   **Decided (2026-11-10):** as proposed, written into R3 and R5 (section
   3). A replica that holds version N−1 never asks the network about a
   version N: R3 alone decides, and a `prev` that does not match is a fork,
   logged. R5 gains the row `(N−1, h ≠ prev)`, which refuses, and its rows
   are applied after the last answer, refusals first, so that no accepting
   row can win over an answer that refuses. One node can still block a STORE
   by answering `(N−1, h)` with a made-up `h`, as it can today by answering
   another hash or by not answering.

   Revised by open point 20 after the review: a replica that holds a version
   below N−1 no longer runs R5, since a forged vN with a skipped `seq` made
   the honest answers neutral and replaced a verified record; R5 runs only
   at a replica that holds nothing.

   Sources: [KERI], Annex A, "First Seen Policy" ("first seen, always seen,
   never unseen"): a validator holding a version of the chain does not take
   another branch from the network. [BEP44], "Mutable Items", `cas` ("If it
   mismatches, the store fails and an error MUST be returned"): `prev` plays
   the part of `cas`, naming the record being replaced, by its hash instead
   of its sequence number. [WEBVH], "Read (Resolve)", step 3: the version
   number "MUST equal the previous entry's version number + 1", "Gaps MUST
   terminate resolution", and the entry hash is verified "for every entry".
   [SALTZER], I-A-3 b, fail-safe defaults, for refusals before acceptance.
10. **A version 0 sent again after a rotation.** R2 asks nobody, so an empty
    replica accepts version 0 long after the DID was rotated, where today's
    check would refuse it. A late republication is repaired by R3 or R5 when
    the current version arrives. With the old key `k0` compromised, an
    attacker sends version 0 and then a version 1 authorized by `k0`, which R3
    accepts: the replica refuses the genuine version 1 (R4), and its answer
    `(1, h)` makes other empty replicas refuse it too. Options:
    - (a) state it as a known limit: readers stay protected by the VC;
    - (b) R2 asks the network and refuses on `store_quorum(n)` matching answers
      with `seq ≥ 1`, which brings back the cost of the check at a first
      publication;
    - (c) pre-rotation (KERI: each document commits to the hash of the next
      key), in a later ADR.

    Proposed: (a) now, (c) as a later ADR.

    **Decided (2026-11-10):** (c), in this ADR (open point 18). With `k0`
    compromised the attack fails: version 0 fixes the hash of the key of
    version 1, so a version 1 under another key is refused by R3. A version 0
    sent late is still accepted by an empty replica (R2) and repaired when the
    current version arrives (R3, R5). What is left is the theft of the key a
    version revealed, described under Consequences. Revised by open point 20:
    a replica holding a late version 0 moves on by R3 when the next version
    comes, and when it is two or more versions behind it answers
    `MissingPrevious`, and the owner's replay repairs it. Revised by open
    point 23: pre-rotation alone did not close this, since a replay of the
    genuine chain from version 0 walked an empty replica to an old version
    or to a fork without asking the network. Option (b) is adopted beside
    (c): R2 asks the network, and refuses version 0 on `store_quorum(n)`
    answers with `seq ≥ 1`.

    Sources: [KERI], "Pre-rotation" and "Tetrad bindings" ("the Inception
    event MUST include a list of digests of the set of pre-rotated public
    keys").
11. **Two versions 0 of one DID.** ML-DSA-65 signing in AWS-LC is randomized,
    so the owner who signs the same document twice gets two records of one
    DID. R2 as written ("unless the replica holds a record with a higher
    `seq`") comes before R4 and would replace the first with the second.
    Proposed: R2 applies only when nothing is stored; another version 0 at an
    equal `seq` is R4. The owner signs version 0 once and resends the saved
    bytes on every retry, the Python application included.

    **Decided (2026-11-10):** as proposed. A replica keeps the first copy it
    stored and answers `Conflict` to the other, so every copy of the chain
    goes on from the record whose hash the owner puts in `prev`. A version 0
    can conflict at its key only with the same document signed again, since
    another document gives another DID and another key: R4 logs that case
    as signed twice, at info level, for every version, and keeps proven
    duplicity for two documents (open point 6). The owner signs each version
    once and resends the saved bytes, as `AGENTS.md` already requires of
    UPDATE retries; the Python application included.

    Deterministic ML-DSA, which would give the same bytes on every signing,
    was rejected: FIPS 204 allows it but advises against it where side
    channels are a concern, as on a device an attacker can hold. A `prev`
    over the document instead of the record was rejected too: replicas
    store and compare records (R1, `FindHash`, storage), so every check
    would have to parse the document, and `prev` is decided (open point 4).

    Sources: [FIPS204], section 3.4, "Hedged and Deterministic Signing": the
    hedged variant is the default, and the deterministic one "should not be
    used on platforms where side-channel attacks are a concern and where they
    cannot be otherwise mitigated". [BEP44], "Mutable Items": a `seq` "lower
    than or equal to" the stored one is rejected, and an equal `seq` with the
    same value only resets the timeout. `AGENTS.md`, key invariants: "Retries
    must resend the saved bytes".
12. **UPDATE to an empty replica.** The rules apply "by STORE or UPDATE", and
    `AGENTS.md` forbids `rpc_update` to accept without a stored record.
    Proposed: an UPDATE still refuses when nothing is stored; R2 and R5 run
    only on a STORE, which the `update_digest` fallback sends.

    **Decided (2026-11-10):** as proposed, and the refusal says why (section
    3, the UPDATE table). An UPDATE is a write conditioned on the stored
    version N−1: it applies only R1 (same bytes: `AlreadyStored`, an update
    already applied) and R3 (a verified successor: `Updated`), never creates
    a record and never asks the network. A replica that lacks version N−1
    answers `MissingPrevious`, and only that answer makes `update_digest`
    send the STORE, where R2 and R5 decide. One that holds version N with
    other bytes, or a fork of N−1, answers `Conflict`, and one that holds a
    newer version answers `Stale` (open point 13); no STORE follows either,
    since it would be refused again, about 6.5 KB for nothing. The same
    bytes are `AlreadyStored` (R1). An UPDATE whose version N−1 is missing is
    not kept to wait for it either. Revised by open point 20: a replica that
    holds a version below N−1 answers `MissingPrevious` with its `seq`, and
    the owner replays the versions it misses.

    Sources: [RFC9110], section 13.1.1, `If-Match`: a conditional write is
    false when the current state does not match, and then the server "MUST
    NOT perform the requested method"; it may answer with a 2xx status when
    the change was already applied; section 13.1.2,
    `If-None-Match: *`, creation only when nothing exists, which is R2.
    [K8S], "Concurrency Control and Consistency" (a stale `resourceVersion`
    "fails with a StatusConflict (HTTP status code 409)"), "HTTP Status codes"
    (404 NotFound apart from 409 Conflict) and "Verbs on Resources" (create on
    update off for "Most built-in types"). [BEP44], errors 301 ("the CAS hash
    mismatched, re-read value and try again") and 302, told apart. [KERI],
    "Receipt Signatures": an escrow for events not seen yet "could be
    vulnerable to a DDoS attack due to spurious event references".
    `AGENTS.md`, key invariants: "Never make `rpc_update` accept an update
    without a stored record" and "Only a refusal triggers the STORE, not a
    missing answer".
13. **Status of a stale record** (first row of R5): `Conflict` (proposed), or
    a new `StoreStatus` variant.

    **Decided (2026-11-10):** a new status, `Stale`, in `StoreStatus` and in
    the status of UPDATE, for a newer version than the one sent: R4 with a
    lower `seq`, where the replica holds the newer version, verified; and
    the first row of R5, where a node only claims it (a claim one node can
    use to block a STORE, as it can by not answering; proofs of a claimed
    higher `seq` are item 4 of "Not in this ADR"). `Conflict` stays for
    another version at the same place in the chain: R4 with an equal `seq`,
    the rows `(N, h)` and `(N−1, h ≠ prev)` of R5, a fork refused by
    UPDATE. A late version 0 at a replica holding a later version is
    `Stale`. The sender can then tell "its copy is old" from "another
    version competes with it", which may be an attack. `SetReport` gains
    `stale_rejections`, and so does the `dict` of `set_detailed` in Python.
    Revised by open point 21: `Stale` is kept for R4, where it is proven, and
    the first row of R5 answers `NewerClaimed`; no status stops a
    republication.

    Sources: [BEP44], error codes 302 ("sequence number less than current")
    and 301 ("the CAS hash mismatched, re-read value and try again"), kept
    apart. [K8S], "Concurrency Control and Consistency": on a stale
    `resourceVersion` "the correct client action at this point is to GET the
    resource again, apply the changes afresh, and try submitting again";
    "Response Status Kind", where `Conflict` and `AlreadyExists` share 409
    and the `reason` tells them apart.
14. **Replacing atomically.** R3 and R5 replace a stored record, so storage
    needs a compare-and-swap: replace only if the stored record is still the
    one the rule checked. Today `rpc_update` verifies and then calls
    `storage.set`, and two concurrent updates can both pass. Proposed: in this
    ADR.

    **Decided (2026-11-10):** in this ADR, with optimistic concurrency. The
    replica reads the stored record and keeps its bytes, checks the rules
    without a lock (the ML-DSA verification runs on a blocking thread, and
    no lock may be held across an `.await`), then writes with a new storage
    operation, `replace_if(key, expected, new)`. Under the lock of that one
    DashMap entry, with no `.await`, as `insert_if_absent` does, it compares
    the stored bytes with `expected`, replaces them if they are equal and not
    expired, keeps the byte accounting, and otherwise writes nothing and
    reports the change. The replica then applies the rules once more to the
    new stored record, locally and with the signature cache: two versions 3
    in parallel end with the second one refused by R4 as proven duplicity.
    The same recheck follows an `insert_if_absent` that finds a record
    stored meanwhile: a version 1 checked by R5 at an empty replica while
    version 0 arrives by R2 then passes R3, and a recheck that would need R5
    again gives no answer. If the record changed again, the replica gives no
    answer, so that it never loops; the sender retries or the republication
    brings it. Every replacement of a DID record goes through `replace_if`:
    R3 by UPDATE and by STORE, and the local write of `update_digest`. A
    creation stays `insert_if_absent` (R2, R5); `set` stays for the Status
    List, outside this ADR.

    Sources: [RFC9110], section 13.1.1: `If-Match` is "most often used with
    state-changing methods (e.g., POST, PUT, DELETE) to prevent accidental
    overwrites" by user agents acting in parallel. [K8S], "Concurrency Control
    and Consistency": "When a record is about to be updated, its version is
    checked against a pre-saved value, and if it doesn't match, the update
    fails with a StatusConflict". [BEP44], `cas` ("If it mismatches, the store
    fails"). `AGENTS.md`, "Concurrency model" (`insert_if_absent` with the
    DashMap `Entry` API and atomic byte reservation) and "What NOT to do" (no
    lock held across an `.await`).
15. **The cache STORE of `ValueSpiderCrawl::find`.** A lookup sends the value
    it found to the nearest node without it (used by `update`,
    `check_publish_state` and maintenance): the copy it found first, which
    may be stale, and a version 0 sent so is accepted by R2 at an empty node.
    Proposed: drop it.

    Correction (2026-11-10): only `check_publish_state` uses
    `ValueSpiderCrawl::find`, the lookup with which `set` and `set_detailed`
    check whether the key is already published. `get` uses
    `find_first_valid`, the STORE check `search`, and neither writes;
    `update` and maintenance run node lookups.

    **Decided (2026-11-10):** dropped. `find` only reads. The STORE sent a
    record the publisher neither chose nor verified (the first one found: a
    retry of its own, a stale version or a forgery) with the full 14-day
    TTL, and at the node that got it started R2, which takes a stale version
    0 with no question, or R5, a network check of `k` `FindHash` requests on
    every `set`. Missing copies come through the paths that verify: an
    identical `set` retry, which already finds the nodes and completes the
    replicas; `replicate_to` for a node that joins; the hourly republication;
    and the `update_digest` STORE after `MissingPrevious`. No cache for
    popular keys: DID records of devices are not the hot spots it was made
    for, and `get` never used it. One would be a separate decision, with the
    short expiry of the paper.

    Sources: [KAD], section 2.3: "For caching purposes, once a lookup
    succeeds, the requesting node stores the ⟨key,value⟩ pair at the closest
    node it observed to the key that did not return the value", with an
    expiry "exponentially inversely proportional to the number of nodes
    between the current node and the node whose ID is closest to the key ID"
    against "over-caching". [LIBP2P], `Caching`: the write-back "must be
    performed explicitly, if desired and after choosing a record from the
    results, via `put_record_to`", and `Caching::Disabled` turns it off.
16. **Publishing a version N ≥ 1.** With pre-rotation a version N ≥ 1 is a
    plain record, so `set` and `set_detailed` could send it, and R3 or R5
    decides at each replica; `update` publishes a copy that already is the new
    record again. Left open: whether `set` takes a version N ≥ 1, or only
    `update` does.

    **Decided (2026-11-10):** two operations, as the DID method operations.
    - `set` and `set_detailed` create: they publish only a version 0, and
      refuse a record with `seq ≥ 1` locally, before sending anything, with
      an outcome that names `update`.
    - `update(key, record)` updates: only a version N ≥ 1, with no
      `auth_signature`. It no longer reads a copy first. A copy read from the
      network proves nothing for N ≥ 1, since anyone can build a self-signed
      version N−1, and a replica serving one first would make a local check
      fail and block the owner. `update` checks the record alone (suffix of
      `id` equal to the key, `seq ≥ 1`, valid `prev` and `nextKeyHash`, valid
      self-signature), finds the `k` closest nodes and sends the UPDATE; the
      replicas decide with their own state (R3, or `MissingPrevious` and the
      STORE that goes to R5). This saves a value lookup, about 6.5 KB.
    - A retry is the same call with the saved bytes: a replica holding it
      answers `AlreadyStored` (R1), one missing version N−1 answers
      `MissingPrevious` and gets the STORE. The special case "the copy read
      already is the new record" goes away.
    - The owner's own copy goes through the rules of any replica: R3 against
      it, and `replace_if` (open point 14).
    - Internal STOREs (`replicate_to`, republication, the fallback) carry any
      version, and the rules at the replica decide. The Status List keeps its
      own path.

    Sources: [DIDCORE], section 8.2: a method "MUST specify how a DID
    controller creates a DID and its associated DID document" and "MUST
    specify what constitutes an update to a DID document", two operations.
    [K8S], "Verbs on Resources": POST creates, PUT updates, and create on
    update is off for "Most built-in types". [RFC9110], sections 13.1.2
    (`If-None-Match: *`, create) and 13.1.1 (`If-Match`, update). [BEP44],
    compared: one `put` with `seq`, where the key never rotates.

    Revised by open point 20: `update` also takes the owner's earlier saved
    versions, used only to replay the chain to replicas that miss versions.
17. **Scope.** Every DID document builder changes (tests, examples, scripts,
    the testbed), and the Docker demo cannot fix the DID in `.env`
    (`DEMO_DID_UUID`, `FIXED_DID_UUID`, `RETRIEVE_KEY`): the DID now depends on
    a random key, so the retriever must learn it from the publisher.

    **Decided (2026-11-10):** the change covers every place that builds or
    names a DID:
    - tests: `tests/common/mod.rs` (`build_did_document`,
      `build_signed_record`, `generate_did_iiot`), `tests/scenarios/common.rs`,
      and the tests that build DIDs (`crypto_tests`, `network_tests`,
      `quorum_tests`, `storage_tests`, `dht_integration`, `scenarios/cache`,
      `scenarios/crypto`);
    - examples: `cache_bench`, `publish_did`, `topology_analysis`;
    - scripts: `dht_node.rs`, `resilience_victim.rs`, `resilience_attacker.rs`;
    - testbed: `did.rs`, `node.rs` (update without `auth_signature`),
      `attacker.rs`;
    - `src/auth_handler.rs` (the binding; `handle_update_verification` goes
      away), `src/crypto/mldsa.rs` and `src/crypto/key_manager.rs`
      (`from_seed`, open point 22) and `src/py_bindings.rs`;
    - `AGENTS.md`, `DESIGN.md`, `README.md`, the diagrams,
      `docker-compose.yaml` and `.env`; ADR 0002 and 0004 only in their
      Status line (open point 7).

    The `uuid` crate is removed from `Cargo.toml` if nothing uses it after
    the change: one dependency less, none added.

    The Docker demo passes the DID from the publisher to the retriever
    through a shared volume. The publisher generates its two keys, builds
    version 0, computes the DID, publishes, and writes the DID to a file of
    the volume (`/shared/did`), first to a temporary file and then by a
    rename, so the retriever never reads half a file. The retriever waits for
    the file, with a time limit, reads the DID and runs the GET.
    `DEMO_DID_UUID` and `FIXED_DID_UUID` go away; `RETRIEVE_KEY` stays as an
    optional DID to look up instead of the file. As in the real system, the
    verifier learns the DID from outside (a VC, the device), not from a
    shared configuration.

    Fixed key seeds in `.env`, which would give a fixed DID, were rejected:
    they put a private seed in `.env` and `docker-compose.yaml`, against the
    custody of section 2.

    Sources: [OWASP-SECRETS], section 5.1, "Injection of Secrets": "secrets
    themselves should never be hardcoded using docker ENV or docker ARG
    commands", since "environment variables are generally accessible to all
    processes and may be included in logs or system dumps". Sections 1 and 2
    of this ADR.
18. **The authorization of an update** (raised by open point 8): the
    `auth_signature` stored and sent with the record, discarded as today, or
    pre-rotation.

    **Decided (2026-11-10):** pre-rotation, `nextKeyHash` in every document
    (section 2), as KERI (pre-rotated key digests in each establishment
    event), did:webvh (`nextKeyHashes`) and Sidetree (update commitments) do.
    It removes the second signature from the wire and from verification, lets
    a replica that missed an update verify it locally, closes open point 10,
    and stops whoever holds the current key from rotating. The next key's
    seed stays in a secure element, not in RAM. A replica holding nothing
    still depends on R5: the systems above solve that by replaying the whole
    history (did:webvh, Sidetree, TUF) or with witnesses (KERI), both outside
    this ADR (item 4 of "Not in this ADR"). The name `nextKeyHash` was chosen
    over `next`: beside `prev`, a hash of the previous record, `next` would
    read as the hash of the next record.

    Revised by open point 20: the owner keeps its whole chain and replays it
    to the replicas that miss versions (section 3, "The replay"). What stays
    out, as item 4 of "Not in this ADR", is a replica or a reader that
    fetches and walks the chain from data the network serves.

    Sources: [KERI] "Pre-rotation" ("Each public key in the set of next
    (ensuing) pre-rotated public keys is hidden in or blinded by a digest of
    that key"); [WEBVH] "Pre-Rotation Key Hash Generation and Verification",
    "Read (Resolve)" step 7, and "DID Witnesses"; [SIDETREE] "Commitment
    Schemes" and "Update" ("Retrieve the Update Reveal Value that matches the
    previously anchored Update Commitment"); [TUF] section 5.3.4, root
    version N+1 signed by a threshold of version N and of N+1, the model of
    the rejected `auth_signature`; [BEP44], `seq` without key rotation. The
    seed in a secure element: [FIPS204] sections 3.6.3 and 4, [SP800-57]
    sections 6.1.1 and 6.2.2.3.
19. **The third row of R5 for N ≥ 2.** The record fetched from the node that
    answered `(N−1, prev)` is checked against `prev` and against vN's key,
    but for N ≥ 2 nothing proves it is the genuine version N−1: one node can
    serve a made-up version N−1 that commits to its own key, with a forged vN
    after it. Only for N = 1 is the row fully cryptographic. Proposed: the
    row is sufficient for N = 1; for N ≥ 2 such an answer, once checked,
    counts as one vote toward `store_quorum(n)`.

    **Decided (2026-11-10):** as proposed, written into R5 (section 3). With
    N = 1 one answer `(0, prev)` is enough, since version 0 proves its own
    binding. With N ≥ 2 an answer `(N−1, prev)` counts as one vote, beside
    the answers `(N, record_hash(vN))`, and the replica accepts only with
    `store_quorum(n)` votes. When such answers exist it fetches version N−1
    once and checks `prev`, the committed key and the self-signature of vN,
    and refuses if one fails: since the record fetched hashes to `prev`, it
    is the very record those voters claim to hold, and the check of the
    committed key holds for all of them. Without this, one colluder serving
    a made-up version N−1 would get a forged vN accepted, where the quorum
    row needs `store_quorum(n)` of them (13 with `k = 20`). The honest
    replicas still at version N−1 while an update spreads help an empty
    replica accept the genuine vN.

    This is no full answer for N ≥ 2: `store_quorum(n)` colluders near the
    key still get a forgery accepted, as through the quorum row. The full
    answer verifies the chain from version 0, as did:plc and did:webvh
    resolvers do, and needs the old versions kept somewhere (item 4 of "Not
    in this ADR"); against many colluders near a key, node ids derived from
    public keys and lookups over disjoint paths (items 2 and 3). Removing the
    row for N ≥ 2 was rejected: simpler, but the replicas still at version
    N−1 would no longer count, and an empty replica would stay empty more
    often while an update spreads.

    Revised by open points 20 and 23: the old versions are now kept by the
    owner, who replays them, so below the quorum a replica that holds
    nothing can reach vN by R2 and R3 without trusting the network. R5 and
    this row still serve the
    STOREs of holders (republication, `replicate_to`), which have only the
    current version.

    Sources: [BQS], section 5.1 (self-verifying data, as version 0 is, where
    one correct answer is enough) and section 4 (data that is not
    self-verifying, as version N−1 is for N ≥ 2 at an empty replica, kept
    only when reported by a set of servers that cannot all be faulty).
    [PLC], "Operation Serialization, Signing, and Validation", and [WEBVH],
    "Read (Resolve)" step 3 ("Verification MUST be performed for every
    entry"): a later version is fully verified only from the first one.

Raised by the review of this ADR before its acceptance (2026-11-10):

20. **R5 at a replica that already holds a verified record, and copies below
    the quorum.** Two findings. A replica holding the genuine version 5 that
    gets a forged version 7 skipped R3 (5 is not 6) and R4, and ran R5 since
    5 < N−1; the honest answers `(5, H(v5))` have `seq < N−1` and counted
    neither for nor against, so `store_quorum(n)` colluders replaced a
    verified record. And since R5 needs `store_quorum(n)` holders, once fewer
    copies remain (one, with `k = 3`) neither republication nor
    `replicate_to` adds any, and the record dies at its expiry.

    **Decided (2026-11-10):** R5 runs only at a replica that holds nothing.
    A replica holding a verified record moves only by R3, one verified
    successor at a time. One that holds a version below N−1 answers
    `MissingPrevious` with its `seq`, by STORE or UPDATE, and its record is
    not touched. The owner keeps its whole chain (section 2) and repairs: to
    a replica behind it replays the versions it misses by UPDATE, each one
    R3; to a replica that holds nothing and does not store vN by R5, it
    replays from version 0, by R2 and then R3, which needs no quorum and no
    trust in the network. `update` takes the earlier versions for this, and
    the owner calls it again with the saved bytes to bring back copies lost
    to churn. Holders alone still cannot restore a record below the quorum,
    as Consequences says.

    Revised by open point 23: the replay from version 0 needs no trust in
    the network only below the quorum, and there only no votes: every node
    asked must still answer, and none may refuse (Consequences). At or above
    the quorum R2 refuses version 0, and the empty replica takes the current
    version by R5.

    Sources: [KERI], Annex A, "First Seen Policy" ("first seen, always seen,
    never unseen"); [TUF], section 5.3.4, root version N+1 checked against
    version N; [KAD], section 2.3, the original publisher republishes its
    pair.
21. **One `Stale` for a proof and for a claim.** `Stale` came from R4, where
    the replica holds a newer, verified version, and from the first row of
    R5, where any node may claim one. Open point 13 also said the sender
    "stops republishing that copy", so one node answering `(N+1, h)` would
    have stopped honest holders from republishing the current version.

    **Decided (2026-11-10):** `Stale` stays for R4 only, and the first row
    of R5 answers `NewerClaimed`. No status stops a republication:
    republication and `replicate_to` ignore every answer, as they do today
    (`src/network/maintenance.rs`, `src/protocol/welcome.rs`), and only the
    owner's reports tell the two apart.

    Sources: `AGENTS.md`, key invariants: an unverified request does not
    change state ("Invalid STORE requests ... never add, replace, remove, or
    otherwise mutate routing contacts based on the unauthenticated
    `sender_id`"); [BEP44], errors 301 and 302 told apart.
22. **The seed of the next key.** Section 2 keeps the next key as its
    32-byte seed, but `MlDsa65KeyPair` has only `generate` and
    `from_private_key`, and `py_bindings` hands out the expanded key.

    **Decided (2026-11-10):** `MlDsa65KeyPair::from_seed`, on
    `PqdsaKeyPair::from_seed` of `aws-lc-rs` (already a dependency), and a
    binding in `py_bindings` that builds a key pair from a seed the
    application generated. No new crate.

    Sources: [FIPS204], Algorithm 6 and sections 3.6.3 and 4; [AWSLC],
    `PqdsaKeyPair::from_seed`.

Raised by the second review before acceptance (2026-11-10):

23. **A replay of the genuine chain at an empty replica.** Every version was
    public, so anyone may hold all of them. R2 asked nobody and R3 asks
    nobody, so a chain sent from version 0 never met R5:
    - anyone, with no key, walked an empty replica up to an old version and
      left it there; holders could not move it, and today's check refuses
      such an old record;
    - a thief of a key some version M revealed, the current one or an older
      one copied while in use, sent versions 0 to M−1 and then a version M
      of its own: R3 accepted it, the replica followed the fork, refused the
      owner's chain, and the thief kept the fork alive through R1. Rotation
      did not recover from the theft there;
    - a thief of `k0` signed version 0 again; the replica then refused the
      genuine version 0 (R4) and version 1 (R3), even from the owner.

    Options: (a) keep R2 asking nobody and state these as limits; (b) R2
    asks the network, as option (b) of open point 10.

    **Decided (2026-11-10):** (b), with two additions, written into R2 and
    "The replay" (section 3).
    - R2 asks the nodes R5 asks, and refuses version 0 with `NewerClaimed`
      when at least `store_quorum(n)` answers carry `seq ≥ 1`; it gives no
      answer on silence or with nobody to ask.
    - One answer `(0, h)` with another hash is `Conflict`, as one answer of
      another hash is today and in R5: otherwise a version 0 signed again
      with a stolen `k0` passes for a DID that never rotated, whose holders
      all answer `seq` 0.
    - The owner replays first to the replicas behind, then to the empty
      ones, so that their R5 counts the replicas just repaired.

    At or above the quorum the chain cannot start at an empty replica, and
    the three attacks fail. The refusal needs the quorum, not one answer:
    with one holder enough, an empty replica could be filled neither by R5
    nor by the owner's replay while 1 to `store_quorum(n)` − 1 holders
    remain, and the record would die at its expiry. Below the quorum the
    attacks stay possible, as Consequences says. A first publication again
    pays one round of `FindHash` per empty replica, as every STORE does
    today, so nothing is lost against the current code. Rejected: a refusal
    on one answer (the deadlock above); a quorum of identical `(seq, hash)`
    (honest holders spread over versions would let version 0 in again);
    checking the end of a replayed chain instead of version 0 (a pending
    state or a chain message, for no gain); closing the gap below the quorum
    too (signed `FindHash` answers or receipts, item 4 of "Not in this ADR"
    and "Alternatives rejected").

    Sources: [KERI], "Security Properties of Pre-rotation", "Dead-Attacks"
    ("The attacker, therefore, must get ahead of the propagation of a past
    rotation event. Otherwise, the Validator would have already First-seen
    the original event"), and "KERI's Algorithm for Witness Agreement
    (KAWA)", "Immunity and Availability" ("guarantees that at most one
    sufficient agreement occurs or none at all"); [BQS], section 4, a value
    that is not self-verifying, kept only when reported by a set of servers
    that cannot all be faulty; [TUF], section 1.5.2, rollback and
    indefinite freeze attacks; [SALTZER], I-A-3 b, no answer on silence.
24. **The cost of the replay.** A replica that holds nothing gets up to
    N + 1 records and verifies each one, and a node near the key that
    answers `MissingPrevious` falsely gets the whole chain.

    **Decided (2026-11-10):** no cap on the length of the chain, with the
    bounds of "The replay" (section 3): stop-and-wait, so each record leaves
    only after the answer to the one before, matched by its message id, and
    a spoofed address gets one record and its resends, not the chain; one
    replay per replica per call; and, with open point 23, a replay from
    version 0 only below the quorum. A cap would leave an old DID
    unrepairable once its chain passed it. The cost is measured in the
    testbed; a real bound needs checkpoints signed by replicas, a later ADR.

    Sources: [KAD], section 2.3, the original publisher republishes its
    pair; "Alternatives rejected", the key event log in the record, which
    grows every STORE where the replay grows only the repair.

Raised by the analysis of the design after the reviews (2026-11-11):

25. **Message ids that can be predicted.** R2 and R5 count answers, and an
    answer is matched by message id and source address. Message ids count up
    by one from a random start (`next_id` in `src/protocol/transport.rs`),
    so a node asked in a `FindHash` round learns one id and knows the ids of
    the other requests of the round. Where it can send datagrams under
    another node's address, which S/Kademlia presumes ([SKAD], section 3.1),
    it answers for the other nodes before they do, and casts their votes.
    Today's check has the same weakness, but the ADR's argument is now a
    count of liars. Proposed: every request takes an unpredictable message
    id, drawn from the random generator already in use (`rand`, seeded by
    the operating system) and drawn again if a pending request holds it;
    resends keep their id, as today. Nothing changes on the wire. It does
    not stop a node that reads the traffic: that needs signed answers (item
    4 of "Not in this ADR").

    **Decided (2026-11-11):** as proposed. `next_id` draws each message id
    from `rand::random`, the thread-local generator of `rand` 0.8, already a
    dependency, which "uses the same PRNG as `StdRng` for security and
    performance and is automatically seeded from `OsRng`" (its
    documentation, `rngs/thread.rs`). An id that a pending request already
    holds is drawn again. Resends keep their id, as today. Fragment ids stay
    as they are: a forged fragment can only spoil a reassembly, which the
    decoding or the hash of a fetched record catches, and one node can
    already block a STORE. Nothing changes on the wire. What stays open is
    a node on the path that reads the traffic: it sees every id, and only
    signed answers stop it (item 4 of "Not in this ADR").

    Sources: [RFC5452], section 9.1 (responses matched on the query ID) and
    section 9.2 ("Use an unpredictable query ID for outgoing queries";
    "Proper unpredictability can be achieved by employing a high quality
    (pseudo-)random generator"); [BQS], section 3.1, the authenticated
    channel the quorum assumes; [SKAD], section 3.1, nodes that "can spoof
    IP addresses".
26. **An honest holder that cannot stop a forgery.** In R5 an answer with
    `seq < N−1` counts neither way. An attacker who sends a forged vN with a
    far `seq` therefore makes the honest holders of the current version
    neutral, and `store_quorum(n)` colluders among the nodes asked get it
    stored: 13 of 19 with `k = 20`, while today one honest holder answering
    another hash refuses it. Proposed: an answer with `seq < N−1` refuses,
    as `Conflict`, logged as a holder behind. A liar gains nothing, since it
    can already refuse. The price is that holders cannot fill an empty
    replica while an honest replica two or more versions behind is asked;
    the owner repairs those first ("The replay", order).

    **Decided (2026-11-11):** as proposed, written into R5 (section 3). One
    honest node that holds the genuine current version vC now refuses every
    forged vN except a version C + 1 that names vC and is signed by the key
    vC commits to, that is, by the next key. Safety at an empty replica goes
    back to today's "one honest holder is enough", while the known gap stays
    closed, because the owner repairs the replicas behind before it fills
    the empty ones, at least once every 24 hours. Without the owner, a
    record two or more versions old stays until it expires, and replicas
    holding the same old version can refresh each other's expiry by
    republication (R1). Rejected: keeping these answers neutral, which left
    safety to `store_quorum(n)` colluders alone (13 of 19 with `k = 20`).

    Sources: [WEBVH], "Read (Resolve)", step 3 ("Gaps MUST terminate
    resolution"); [TUF], section 5.3.5 (the new version "MUST be exactly
    the version in the trusted root metadata (version N) incremented by
    one"); [SALTZER], I-A-3 b, fail-safe defaults; `AGENTS.md`, today's
    check ("Another hash: `Conflict`").

## Validation


Tests written before the code, failing on the current one:

- **Derivation:**
  - a version 0 binds;
  - changing any field (the key, a service, `seq`) breaks the binding;
  - an `id` with another suffix does not bind;
  - a non-canonical suffix does not bind (padding, wrong length, an encoding
    that does not round-trip);
  - a document that holds the placeholder literally does not bind;
  - a version 0 with `prev` does not bind;
  - a document without `nextKeyHash`, with a non-canonical one, or with the
    hash of its own key, does not bind;
  - a version N ≥ 1 with `prev: null` or `prev: ""` does not bind;
  - the canonical form refuses whitespace, keys out of order, a duplicate
    key, a needless escape, a non-ASCII or control character, a number with
    a fraction or an exponent, and an integer beyond 2^53 − 1;
  - rule 3 of the hashed form: values equal to the DID or starting with it
    followed by `#`, `?` or `/` take the placeholder, and the DID inside a
    longer URL does not;
  - the Python test vector gives the same DID.
- **Order of checks** (section 3): a record that fails step 1 is
  `InvalidRecord` before any signature is verified and leaves routing
  untouched; an UPDATE of a version 0 is `InvalidRecord`; R1 on a STORE
  refreshes the expiry of the stored record and adds the sender to routing,
  R1 on an UPDATE does neither; a successor that does not fit in the budget
  is `CapacityExceeded` and the stored record stays.
- **R2** (open point 23): one test per row of its table, with mock
  neighbours. `store_quorum(n)` answers with `seq ≥ 1` give `NewerClaimed`,
  one fewer lets version 0 in; one answer `(0, h)` with another hash gives
  `Conflict`; silence or nobody to ask gives no answer; the owner's `set`
  writes its own version 0 locally with no `FindHash`. The same document
  signed a second time, sent to a replica holding the first copy, is
  `Conflict`, logged as signed twice, and the first copy stays.
- **Replay of the genuine chain** (open point 23), at an empty replica with
  holders at or above the quorum: versions 0 to M sent one after the other
  leave it empty (version 0 is `NewerClaimed`); versions 0 to M−1 and then a
  version M signed with the key version M revealed, with the attacker's
  `nextKeyHash`, get nothing stored; a version 0 signed again with `k0`, for
  a DID that never rotated, is `Conflict`. Below the quorum the same chain
  is accepted, as Consequences states, and the owner's replay repairs a
  replica pinned at an old version. Honest holders spread over versions (7
  at N, 6 at N−2, `k = 20`) do not leave an empty replica empty after one
  owner's call, since the replicas behind are repaired first.
- **R3:** an update is refused when:
  - its `seq` is not `stored + 1`;
  - its `prev` does not match, at a replica holding version N−1, which
    sends no `FindHash` and logs a fork (open point 9);
  - its `id` changes;
  - the hash of its key is not the stored `nextKeyHash`: a key of the
    attacker, or the stored key kept.

  A valid one is accepted, and an UPDATE carries no `auth_signature`.
- **R4:** an older `seq` is `Stale`, a late version 0 included; an equal
  `seq` with other bytes is `Conflict`, and logged. A version N signed by
  the key it reveals with another `nextKeyHash` (the stolen current key),
  sent to a replica holding the genuine version N, is logged as proven
  duplicity; one under another key as a plain conflict, without a signature
  verification; in both cases the stored record is unchanged.
- **Replacing atomically:** `replace_if` replaces only the expected bytes,
  and not an expired record. Two valid versions 3 sent at once to a replica
  holding version 2 leave exactly one of them stored, and the other is
  `Conflict`, logged as proven duplicity. A version 1 checked by R5 at an
  empty replica while version 0 arrives by R2 is then checked by R3 and
  stored.
- **No cache STORE:** a `set` whose lookup finds a record already stored
  sends no STORE to the nearest node without it (open point 15).
- **Create and update** (open point 16): `set` refuses a version N ≥ 1
  without sending anything; `update` refuses a version 0, sends no value
  lookup, and completes even when the first replica asked serves a forged
  version N−1.
- **UPDATE:** one test per row of its table. A replica with nothing answers
  `MissingPrevious` and gets the STORE, and the chain from version 0 when
  that STORE is not stored; one two versions behind answers
  `MissingPrevious` with its `seq` and gets the versions it misses, one at a
  time; one holding a newer version answers `Stale`, one holding version N
  with other bytes or a fork answers `Conflict`, and neither gets a STORE;
  the same bytes are `AlreadyStored`; an UPDATE to an empty replica sends no
  `FindHash`.
- **Replay** (open point 20): with copies below the quorum (one holder,
  `k = 3`), the owner's `update` with its saved versions restores every
  replica; a replica holding the genuine version 5 that gets a forged
  version 7 answers `MissingPrevious` and keeps version 5, whatever its
  neighbours answer. The replay sends version 0 by STORE and the others by
  UPDATE, in order, one after the answer to the one before; it starts from
  s+1 after `MissingPrevious` with `s`; it stops for that replica at the
  first answer other than `Updated`, `Stored` or `AlreadyStored`; and the
  replica counts toward the quorum with its answer to vN. The owner's own
  node that lacks version N−1 writes its chain locally without a `FindHash`,
  and commits vN only once the quorum is met. An `update` on
  `STATUS_LIST_KEY` still takes the issuer's path.
- **R5:** one test per row of the table, with mock neighbours, as in
  `store_check.rs`. `store_quorum(n)` gives 2, 3, 3, 4, 4, 5, 6, 13 for
  `n` = 2, 3, 4, 5, 6, 7, 9, 19, and with `n = 1` the quorum row never
  accepts; one answer short of the quorum gives no answer. With N = 1 one
  answer `(0, prev)` is enough, but one node serving a made-up version 0′
  that commits to its own key, with a version 1′ after it, gets nothing
  accepted, since version 0′ does not bind to the key. With N ≥ 2 one node
  serving a made-up version N−1 that commits to the attacker's key gets no
  forged vN accepted, while answers `(N−1, prev)` and `(N, record_hash(vN))`
  reaching the quorum together accept the genuine one. A refusing answer
  that arrives after an accepting one still refuses, and a refusal with
  another node silent at the deadline is that refusal. The fetch tries the
  next voter when the first gives no record or one that does not hash to
  `prev` (and that voter's answer is no vote), and gives no answer past the
  deadline; a fetched record that hashes to `prev` but does not commit to
  vN's key is `Conflict`, and a vN whose self-signature fails is
  `InvalidRecord`. A claimed `seq > N` is `NewerClaimed`, and a
  republication that gets it goes on (open point 21). An answer with
  `seq < N−1` is `Conflict`, logged as a holder behind (open point 26):
  with `k = 20`, one honest holder of the current version among 19 nodes
  asked stops a forged vN with a far `seq` that the other 18 vote for; and
  an empty replica refused because a holder two versions behind was asked
  is filled once the owner's `update` has repaired that holder.
- **Message ids** (open point 25): a thousand requests in a row do not get
  consecutive ids, an id a pending request holds is never given out again,
  a resend keeps its id, and an answer under a guessed id from another
  node's address is discarded unless that id is pending for that address.
- **The key security case:** right after a version 0 is published, an empty
  replica gets a forged version 1 whose `prev` is the real hash of version 0,
  self-signed by the attacker with a key whose hash is not the `nextKeyHash`
  of version 0. It is refused, and so it is by a replica holding version 0,
  even when the attacker holds the private key of version 0.
- **Network:**
  - after a rotation, a restarted replica refuses a forged version N by STORE;
  - the genuine version N reaches it through replication, and
    `update_digest` succeeds while the old version is still on some
    replicas (the closed gap).
- `cargo test`, `cargo test --features counters`, `cargo clippy --all-targets
  --features testbed`, `cargo fmt --check`, `cargo build --features testbed`,
  `cargo check --features python`.
- **Testbed:**
  - `race` and `burst` against replicas restarted after an UPDATE;
  - a new mode that sends a forged version 1 right after the owner's
    version 0;
  - a new mode where some nodes lie in `FindHash`, to measure how many STOREs
    they block;
  - E1 and E2 measured again, the UPDATE in 5 fragments instead of 8;
  - the duration of the R5 check with its fetch, on the WAN profiles,
    against `STORE_LOOKUP_TIMEOUT` (2 s). If it does not fit, the
    implementation stops and asks before changing the timeout.
- **Docker demo** (open point 17): `docker compose up`, and the retriever
  reads the DID from the shared volume and gets the publisher's record.
- **Reports:** `stale_rejections` in `SetReport` and in the `dict` of
  `set_detailed`.
- **Seed** (open point 22): `MlDsa65KeyPair::from_seed` gives the same key
  pair for the same seed, and its public key is the one whose hash a
  `nextKeyHash` commits to.

## References

Checked on the sources on 2026-11-10. Specifications built with Spec-Up
(CESR, KERI, did:webvh, did:peer, Sidetree) have no section numbers, so they
are cited by heading.

- [ADRTOOLS] N. Pryce, adr-tools, `src/adr-new`, option `-l`.
  https://github.com/npryce/adr-tools/blob/master/src/adr-new
- [AWSLC] aws-lc-rs 1.19.0, `PqdsaKeyPair::from_seed`.
  https://docs.rs/aws-lc-rs/1.19.0/aws_lc_rs/signature/struct.PqdsaKeyPair.html
- [BEP44] A. Norberg, S. Siloti, "Storing arbitrary data in the DHT", BEP 44.
  https://www.bittorrent.org/beps/bep_0044.html
- [BISHOPFOX] J. Miller, "An Exploration & Remediation of JSON
  Interoperability Vulnerabilities", Bishop Fox, 25 February 2021.
  https://bishopfox.com/blog/json-interoperability-vulnerabilities
- [BQS] D. Malkhi, M. Reiter, "Byzantine Quorum Systems", Proc. 29th ACM
  Symposium on Theory of Computing (STOC '97), El Paso, 1997, pp. 569–578.
  Sections 4 and 5.1 read on the paper. A journal version appeared in
  Distributed Computing 11(4), 1998.
  https://people.cs.umass.edu/~arun/cs691ee/reading/BQS97.pdf
- [CASSANDRA] Apache Cassandra documentation, "Dynamo", "Tunable
  Consistency".
  https://cassandra.apache.org/doc/latest/cassandra/architecture/dynamo.html
- [CESR] Trust over IP, "Composable Event Streaming Representation (CESR)",
  v1.1, Annex A, "Self-addressing identifier (SAID)".
  https://trustoverip.github.io/kswg-cesr-specification/#self-addressing-identifier-said
- [DIDCORE] W3C, "Decentralized Identifiers (DIDs) v1.0", Recommendation, 19
  July 2022. https://www.w3.org/TR/2022/REC-did-core-20220719/
- [FIPS180] NIST FIPS 180-4, "Secure Hash Standard", 2015.
- [FIPS204] NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard",
  2024. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- [K8S] Kubernetes, "API Conventions", sig-architecture.
  https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- [KAD] P. Maymounkov, D. Mazières, "Kademlia: A Peer-to-peer Information
  System Based on the XOR Metric", IPTPS 2002, section 2.3.
  https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf
- [KERI] Trust over IP, "Key Event Receipt Infrastructure (KERI)", v1.1.
  https://trustoverip.github.io/kswg-keri-specification/
- [KERIPY] WebOfTrust keripy, `src/keri/core/eventing.py`, `ample()`.
  https://github.com/WebOfTrust/keripy/blob/main/src/keri/core/eventing.py
- [KERIPY-DB] WebOfTrust keripy, `src/keri/db/basing.py`, `Baser.dels`.
  https://github.com/WebOfTrust/keripy/blob/main/src/keri/db/basing.py
- [LANGLEY] A. Langley, "Revocation checking and Chrome's CRL", 5 February
  2012. https://www.imperialviolet.org/2012/02/05/crlsets.html
- [LIBP2P] rust-libp2p, `protocols/kad/src/behaviour.rs`, `Quorum::eval`,
  `Caching`, `Config::set_caching`.
  https://github.com/libp2p/rust-libp2p/blob/master/protocols/kad/src/behaviour.rs
- [NYGARD] M. Nygard, "Documenting Architecture Decisions", Cognitect,
  15 November 2011.
  https://www.cognitect.com/blog/2011/11/15/documenting-architecture-decisions
- [OWASP-SECRETS] OWASP Cheat Sheet Series, "Secrets Management Cheat
  Sheet", section 5.1.
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- [PEER] DIF, "Peer DID Method Specification", v1.0 draft, "Method 4".
  https://identity.foundation/peer-did-method-spec/#method-4-short-form-and-long-form
- [PLC] "did:plc Method Specification", v0.3.0, December 2025.
  https://web.plc.directory/spec/v0.1/did-plc
- [RFC4648] S. Josefsson, "The Base16, Base32, and Base64 Data Encodings",
  RFC 4648, 2006.
- [RFC5452] A. Hubert, R. van Mook, "Measures for Making DNS More Resilient
  against Forged Answers", RFC 5452, 2009.
  https://www.rfc-editor.org/rfc/rfc5452
- [RFC8259] T. Bray, "The JavaScript Object Notation (JSON) Data Interchange
  Format", RFC 8259, 2017.
- [RFC8785] A. Rundgren, B. Jordan, S. Erdtman, "JSON Canonicalization
  Scheme (JCS)", RFC 8785, 2020.
- [RFC8949] C. Bormann, P. Hoffman, "Concise Binary Object Representation
  (CBOR)", RFC 8949, 2020.
- [RFC9110] R. Fielding, M. Nottingham, J. Reschke, "HTTP Semantics", RFC
  9110, 2022, sections 13.1.1, 13.1.2 and 15.5.13.
  https://httpwg.org/specs/rfc9110.html
- [SALTZER] J. H. Saltzer, M. D. Schroeder, "The Protection of Information
  in Computer Systems", Proc. IEEE 63(9), 1975, section I-A-3.
  https://www.cs.virginia.edu/~evans/cs551/saltzer/
- [SIDETREE] DIF, "Sidetree", v1.0.1. https://identity.foundation/sidetree/spec/
- [SKAD] I. Baumgart, S. Mies, "S/Kademlia: A practicable approach towards
  secure key-based routing", ICPADS 2007, doi:10.1109/ICPADS.2007.4447808.
- [SP800-57] NIST SP 800-57 Part 1 Rev. 5, "Recommendation for Key
  Management", 2020.
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- [SSZ] Ethereum consensus-specs v1.5.0, "SimpleSerialize (SSZ)".
  https://github.com/ethereum/consensus-specs/blob/v1.5.0/ssz/simple-serialize.md
- [TUF] "The Update Framework Specification", v1.0.37, sections 1.5.2 and
  5.3.
  https://theupdateframework.github.io/specification/latest/
- [WEBVH] DIF, "The did:webvh DID Method", v1.0.
  https://identity.foundation/didwebvh/v1.0/
- In this repository: `DESIGN.md` sections 2, 3, 7, 9 and 11; ADR 0002,
  0003, 0004.
