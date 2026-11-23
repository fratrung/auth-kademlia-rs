# 0006. Commit a DID's rotation keys in a Merkle tree

Status: Accepted, 2026-11-23 (proposed 2026-11-23). It covers records within
the first tree; migration between trees is not in this ADR. It replaces the
record format of ADR 0005 (point 11).

## Context

Under ADR 0005 a replica at version 3 can verify version 4 using the
`nextKeyHash` it holds. To install version 5 it first needs version 4.
Each missed version can add a whole signed DID Document to the owner's
replay. We want the replica to be able to check the signing key at position
5 directly against a commitment made when the DID was created.

## Decision

The following points have been agreed for the first tree.

1. The genesis commits the SHA-256 digest of the initial document body in
   its hashed form (point 7), the Merkle root, tree height, hash and signature
   algorithm identifiers, and format version. The DID is
   `did:iiot:` followed by the unpadded base64url encoding of the SHA-256
   digest of its canonical JSON bytes (ADR 0005, open point 3). Those 32
   digest bytes are the DHT key. The genesis has no reference to its own
   DID. The owner substitutes the resulting DID into the initial draft
   before signing document 0.
2. Position `i` commits to its raw ML-DSA-65 public key and an independent
   uniformly random 32-byte activation code for that position.
   The leaf hash is SHA-256 over the concatenation of byte `0x00`, the
   encoded index, the public key and the raw code, in that order.
   An internal node hashes byte `0x01`
   followed by its left and right child hashes. The two prefixes keep a
   leaf from being read as a node: in Certificate Transparency "this domain
   separation is required to give second preimage resistance" ([RFC9162],
   section 2.1.1). The index is 4 bytes, big-endian, as LMS encodes its
   leaf number `q` ([RFC8554], section 5.4). The exact genesis and record
   formats are pending (point 12). The first tree has height 6 and
   64 positions. Positions 0 through 62 sign documents. Position 63 is
   reserved. Each membership path occupies 192 raw bytes. A record carries
   its index, key and path as an XMSS or LMS signature carries its leaf
   index and authentication path ([RFC8391], section 4.1.8; [RFC8554],
   section 5.4). Unlike them, each leaf holds a many-time ML-DSA-65 key,
   not a one-time key.
3. The signed document carries the code for its position. A replica checks
   its decoded length, the genesis against the requested DID, the leaf and
   its position against the root, and the document's signature against
   that leaf's key. For document 0 it also checks the initial body digest.
   A valid record at 5 can replace a record at 3 directly.
   An empty replica offered 5 stores it unless its bounded check verifies
   a higher record (point 2). Claims, silence and other records at 5 do not
   stop it (points 2 and 3). Neither case requires document 4. The
   document's `seq` is the index of its leaf (point 12).
4. The signed `prev` field after document 0 names the hash of the record the
   owner identifies as its previous publication. The replica checks the
   field's format. It can establish authorization without fetching that record.

### Owner custody

A Rust trait separates the owner's application from the storage and use of
leaf signing keys and activation codes. The first implementation uses local
files. A future implementation can keep the secrets and sign inside a
trusted execution environment (TEE). Both produce the same signed document.
Replicas use the public verifier and have no need for this trait.

Provisioning can obtain the public tree material needed to prepare the genesis
and membership proofs. For publication the application requests a signed
record for a given DID, position and document. The backend checks that the
position is active, inserts its code in the signed content and signs inside
the custody boundary. The application receives the signed bytes, including
the now public code. The Python interface for this path needs no private key,
seed, or operation to read an unreleased code. The existing `KeyManager`
trait requires private-key export and is unsuitable as the contract for
this operation. Retries publish the saved record bytes.

The file backend persists the leaf secrets, codes and activation state and
loads the selected leaf's secrets when needed. Its files and backups share
the trust placed in their reader. A copy of the full store exposes future
signing keys and their codes. A TEE backend can enforce a stronger boundary
if it also controls activation, including requests from the normal application.

## Consequences

The DID commits through the genesis to both the initial document body and
the tree. Changing the initial body in hashed form changes the DID under
the SHA-256 collision-resistance assumption. Signing the same body twice
can still yield two records with different signatures. If the owner has already released
a leaf's code, a replica with less history may still accept a record at
that position. A replica that has seen a higher position rejects it as stale.
The owner can skip a compromised future leaf and withhold its code permanently.
An unreleased position stays unusable, as KERI's unexposed next keys do.
They can be "held in reserve and not exposed at the next (immediately
subsequent) Establishment event" ([KERI], "Reserve Rotation"), and "later
exploit of the current authoritative signing key(s) may not capture key
rotation authority" ([KERI], "Security Properties of Pre-rotation").

No rule for DID records counts votes. A node answering under made-up ids
can still delay a check, hide a newer record from an empty replica or fill
routing tables (ADR 0005, "Not in this ADR", item 2). It cannot make a
replica store a record that the leaf key did not sign.

A reader's protection against an authentic but superseded record rests on
the application. The proxies check the signing key against the current
credential (point 6). That holds only if the credential of a superseded
key is revoked, or expires, at rotation. Otherwise a stolen key 3 with its
old credential still authenticates, whatever the DHT serves. The protocol
repository owns that rule.

## Alternatives rejected

Requiring the intermediate documents for a same-tree jump would reintroduce
the replay that this change is meant to remove.

## Not in this ADR

The current discussion defers migration between trees. The rules above apply
only under the root committed in the genesis.

This repository implements and tests DHT records, custody operations,
publication, resolution, repair and persistence. The protocol repository
owns session authentication and its integration tests.

## Open points

### 1. Owner custody and automatic rotation

**Decided, 2026-11-23.** The owner configures the schedule at provisioning.
The first implementation uses the Rust custody trait and local files described
in Decision. Rotation is automatic and the interval is configurable per
deployment. A week or a month is a deployment choice.

**Owner behavior within one tree.**

- Provision an independent random 32-byte activation code for each usable
  document position before computing the root. Keep each unreleased code
  private, including when exporting a public path or the genesis.
- Let the provisioned start be `T`, the positive interval be `D`, and the
  number of usable document positions be `U`, numbered from zero. Before
  `T` no position is due. At or after `T`, the due index is
  `floor((now - T) / D)`. The boundary itself belongs to the new interval.
  A request count or an index supplied by Python cannot advance this
  schedule. Only an authorized early activation can (below).
- When a new slot becomes due, prepare its document even when only the
  rotation fields change. Keep the prepared record private until the
  application explicitly requests publication as described in point 9.
  Persist pending and published state distinctly. A restart must not publish
  a pending record merely because its slot has arrived. While waiting, retain
  the last published bytes for republication. Retries use the same saved bytes.
- After an outage, prepare the currently due position directly and publish
  it on the caller's request. If the last
  publication was 2 and the device returns during slot 5, its signed
  `prev` names record 2. Keep codes 3 and 4 unreleased. Persist the greatest
  position activated so that a restart or a backward clock adjustment
  cannot reopen an earlier position during ordinary operation. Make that
  write durable before the signed record leaves the backend. A file write
  the operating system still caches is not enough. SP 800-208 requires this
  order for the leaf index of a stateful hash-based key ([SP800-208],
  sections 8.1 and 9.1). Here a reopened position does not break
  ML-DSA-65, a many-time signature, but it creates two records at one
  position (points 3 and 4).
- A position skipped because its private key is known to have leaked must
  stay disabled across restart. Its due date cannot override that decision.
  At the end of the usable range the tree is exhausted. Never wrap around,
  generate a new record at the final position, or use a reserved position.
  The disposition of an exhausted tree belongs to the migration discussion.
- Replicas verify genesis binding, the position, the code and membership
  proof, and the document signature on writes and reads. The owner's
  calendar is local. Crossing a date does not revoke a published record at
  a reader.

**Authorized early activation.** Decided, 2026-11-23. When the current
key is known to have leaked, revoking its credential stops the thief but
also leaves the device without a usable key until the next boundary, up to
`D`. The owner can then activate the next position that is neither
activated nor skipped before its slot, with an authorization bound to the
DID and that position and valid once. The backend persists the new
greatest activated position before releasing the record, as for a
scheduled one. The calendar keeps `T` and `D`: the due index becomes the
greater of the calendar index and the greatest activated position. The
early position therefore also covers its own slot, and the next one is due
at its normal boundary. An authorization never reopens a lower position, a
skipped one or the reserved 63. Revoking the leaked key's credential
remains the application's step (Status List). In the file backend the host
can read the secrets, so the authorization binds only an honest
application. A TEE backend can enforce it.

**Decided, 2026-11-23: the issuer signs the authorization.** The issuer
must issue the credential of the new key anyway, and its ML-DSA-65 key is
already provisioned for the Status List. The decision to rotate early, the
format of the authorization, the new credential and the revocation of the
old one belong to the protocol layer above the DHT. Replicas never see the
authorization. This repository only prepares the custody side. The
early-activation call of the custody trait takes the authorization and
checks it with a verifier the application supplies, before any signature
or release.

**Custody guarantees.** The file backend trusts local time and the files
holding its state. A party that can copy the entire store obtains future
keys and codes. To enforce the schedule against a compromised host, a TEE
backend needs an independently protected schedule and time source, rollback
protection, and internal enforcement of signing and release permissions.
A TEE backend is outside the first implementation. It produces the same
record format. Once a code is public, a holder of its stolen private key
can sign a competing document at that position.

**One instance at a time.** Decided, 2026-11-24. Each instance of the file
backend decides from its own copy of the activation state, so two
instances on one store would each sign the next position: two records at
one position, made by the owner. The backend takes an exclusive lock on
the store when it opens or provisions it, holds it while the instance
lives, and refuses a second instance at once. A signer must store the new
index "before exporting a signature value or accepting another request to
sign a message" ([SP800-208], section 8.1), which two signers sharing one
state cannot do. The lock does not stop a copy of the store, nor an older
state restored from a backup: for stateful schemes "simply copying the
private key would create a risk of OTS key reuse" ([SP800-208], section 7).

**Acceptance cases.** Use controlled time in the custody tests.

| Case | Expected result |
|---|---|
| Request 5 during slot 3 without an authorization, including repeated requests | No signature for 5 and no code for 5 |
| Just before and exactly at the boundary between 3 and 4 | Position 3 is due before the boundary and 4 at the boundary |
| Retry a publication in the same slot | Byte-identical record, including its signature |
| Restart in slot 5 after publishing 2 | Prepare 5 with the hash of 2 as `prev`, keep 2 published until an explicit publish call, and keep codes 3 and 4 unreleased |
| Move the clock back to slot 3 after activating 5 | No new signature or release at 3 |
| Reach the first slot beyond the usable range | Exhaustion, with no reuse or wraparound |
| Give a replica the real public key and path for 5, then sign a document containing the wrong code with the real key for 5 | Reject even though the signature verifies |
| Correct that code and sign again in the test fixture | Membership and signature verify for 5 |
| Request 6 during slot 5 with a valid authorization for 6 | Signature and code for 6, and 6 persisted as the greatest activated position before the record is returned |
| Reuse that authorization, or present one for another DID or position | No signature and no code |
| The calendar reaches slot 6 after the early activation of 6 | No new record. 7 is due at its normal boundary |
| An authorization for a skipped position, a lower one or 63 | No signature and no code |

The separation of an exposed signer from a protected helper is studied by
Dodis, Katz, Xu and Yung in [Key-Insulated Public Key
Cryptosystems](https://www.iacr.org/archive/eurocrypt2002/23320064/dodis-ec02.pdf).
The activation code in the Merkle leaf is a project proposal with a
narrower property. It has no security proof in this ADR.

### 2. Which evidence of a newer record should an empty replica accept?

**Decided, 2026-11-23, for evidence of a newer record.** An empty replica
checking a valid incoming record at N must refuse it as stale once it
verifies a record for the same DID at any higher position in the authorized
tree. One such record suffices regardless of how many peers report older
positions. A higher `FindHash` answer triggers a fetch. Before acting on the
returned record the replica checks its actual position, genesis binding,
activation code, Merkle path and signature. The peer's announced number
alone cannot establish staleness.

| Observation during the check | Consequence for the incoming 5 |
|---|---|
| A peer shows a valid 6 for this DID | A single verified newer record suffices to refuse 5 as stale |
| A peer only claims 6, times out on the fetch, or shows invalid bytes or another DID | The claim supplies neither proof of a newer record nor a vote to accept 5 |
| Every peer asked answers with 3 | The replica may take the verified 5, as agreed in Decision 3 |

One shown valid 6 proves that 5 has been superseded even if 7 exists
elsewhere. A failed fetch leaves the decision dependent on the remaining
evidence. Test the same check with all other peers reporting 3, first with
a genuine 6, then with a correctly signed 6 for a different DID. Only the
first establishes staleness.

**Decided, 2026-11-23, for the fetches.** The replica fetches one record
for each distinct claimed (position, hash), from the closest peer that
claimed it. It fetches at most `k - 1` records, all at once and within the
same deadline, as ADR 0005 does for a claimed other version 0
(`show_claims`). One verified higher record is enough to refuse. A claim
whose record is not shown in time is dropped. Made-up ids that answer with
many different hashes therefore cost at most `k - 1` fetches.

**Amended, 2026-11-24.** Each claim is fetched as soon as it arrives, from
the first peer that made it, while the lookup goes on, and the first
verified record ends the check. Fetched once the lookup was over, they
shared its deadline: a single silent peer spent it, and an empty replica
stored 5 although a peer had shown 6 at once (found in a review, reproduced
by `a_silent_neighbour_does_not_keep_a_shown_higher_record_out`). Taken in
the order they arrive rather than closest first, the claims of made-up
peers, asked only after the answer that names them, no longer use up the
`k - 1` fetches before the peers the replica knew
(`made_up_claims_cannot_use_up_the_fetches_before_a_known_holder`).

**Application requirement.** IoT peers need the DID Document version whose
signing key the issuer currently authorizes for the handshake. During a
partition a replica can identify the
highest version it has verified. It cannot establish whether a higher
version exists outside its view.

**Decided, 2026-11-23, for partial and zero replies.** An empty replica
with no retained history receives a valid 5. Run the
bounded network check. If a peer shows a valid 6, prefer 6 for local storage
and refuse the incoming 5 as stale. If the check finds no newer record or
verified same-position conflict, store 5 even if zero neighbors answer by
the deadline, subject to the normal storage budget and atomic write rules.
There is no minimum response count for this same-tree admission decision.
This decision concerns admission at one replica. The owner's publication
report still concerns confirmations from replicas. Under this rule a
partition can also reintroduce an authentic older record into empty storage.
A replica that already knows 6 must keep that lower bound when processing 5.

**Zero replies.** The sender supplied a complete signed 5. It is the
replica's subsequent queries to other peers that receive no response by
the deadline. If 5 is current, serving it makes the current key available
locally. If 6 exists across a partition, serving 5 returns an authentic
but superseded key. The replica observes the same inputs in both cases.
Replaying the public record requires no private key. Answering a fresh
handshake challenge under key 5 requires possession of its private key.

**Handshake consequence.** A device using 6 can fail authentication when a
reader uses its stale local 5. Point 9 describes a network-only DHT lookup
that can repair the local copy before retrying the handshake.

Acceptance test: start with empty storage, supply a fully verified 5, let
every query time out, and assert that the replica stores those exact bytes.
Repeat with a bad membership proof and assert that storage stays empty.
Repeat with a locally held 6 and assert that 6 remains stored. How long a
node retains a highest-seen position after losing the record is addressed in point 6.

**Decided, 2026-11-23, for the owner's publication report.** The report
applies the same evidence rule as a replica. A replica refuses a STORE as
`Stale` only when it holds a record at a higher position, or has fetched
and verified one during its check. It never refuses because a peer claimed
one, and the `NewerClaimed` result is removed. The owner counts a refusal
only once the refusing replica shows its record, and the owner verifies it
for the DID (genesis, leaf, code, path, signature) at a higher position or
at the same position with different content (point 3). Any other refusal
counts as a replica that did not store. No number of claims rejects a
publication. Under ADR 0005, `classify_set_report` rejected with
`NewerVersion` once claims reached `store_quorum`. One node answering under
made-up ids could reach that count ([DOUCEUR], abstract: "if a single
faulty entity can present multiple identities, it can control a
substantial fraction of the system").

Acceptance test: publish 5 where 13 of 19 replicas answer `Stale` and show
no record, or an invalid one. They count as replicas that did not store,
and the publication is not rejected. Repeat with one replica that shows a
valid 6: the publication is reported as superseded.

### 3. Two different signed documents at the same position

**Decided, 2026-11-23, for a replica holding a record.** At position 5 the leaf commits to one public
key and activation code. Two different canonical documents can nevertheless
both be signed by that key, for example with different service endpoints.
If a replica already holds a verified 5A and receives a verified 5B with
different document content, keep serving 5A and report a conflict to the
sender. Record both hashes for diagnosis. A later valid 6 can replace
either copy through the usual same-tree rule. Two replicas may serve
different documents until that happens.

Acceptance test: preload verified 5A, deliver 5B, and check both the
conflict response and the exact bytes retained. Repeat in reverse order.
Then deliver the same valid 6 in each run and check that both end with 6.
A byte-identical replay of the complete record is idempotent.

**Decided, 2026-11-23, for an empty replica, with no vote.** A STORE
supplies verified 5A. If the bounded check verifies a higher record, the
newer-record rule applies first. Otherwise the replica stores 5A, whatever
other peers report at 5. A report of another hash at 5 is not fetched and
does not count, because it cannot change the decision. A later STORE of 5B
meets the holding-replica rule above, which keeps 5A and records both
hashes. If another write won the race, apply the holding-replica rules to
the actual stored record.

An earlier draft chose 5B when `store_quorum(n)` of the closest `k - 1`
peers reported its hash and one copy verified. Votes are counted per node
id, and one node can answer under any number of made-up ids ([DOUCEUR],
abstract). With a stolen key 5 whose code is public, a single node could
therefore make empty replicas prefer its 5B even over the owner's first
STORE. The choice between two records signed by the same leaf key gives no
evidence of the owner's intent in any case. The replica keeps the first
record it verified, as a KERI validator does ([KERI], Annex A, "First Seen
Policy": "first seen, always seen, never unseen"), and a later valid 6
replaces either copy. No rule for DID records uses `store_quorum` any
more. The Status List keeps its own read quorum.

Acceptance tests:

| Evidence observed while handling a STORE of valid 5A | Stored record | Response |
|---|---|---|
| 13 of 19 peers report the hash of a 5B that would verify | 5A | `Stored` |
| Every peer is silent | 5A | `Stored` |
| A peer shows a valid higher record 6 | 6 | `Stale` |
| 5B arrives by STORE after 5A is stored | 5A | `Conflict`, both hashes recorded |

### 4. The same canonical document signed twice

**Decided, 2026-11-23.** The owner saves the exact signed record durably
before its first network send. A retry, including after a restart, sends
those same bytes and is idempotent. If the owner instead signs the same canonical document again,
two valid signatures can produce different complete record hashes, even
though the key, service endpoints and every other signed field agree.
Compare the canonical document bytes when classifying a verified mismatch.
Keep the same storage and exact-byte confirmation rules as in point 3.
Classify two valid signatures on the same bytes as a repeated signing event.
Reserve proven duplicity for two different signed contents. An invalid
second signature establishes neither event. The signed `prev` of a later
version can identify which exact record the owner used for audit.

Acceptance test: preload a signed document, send a second valid signature
on identical canonical bytes, and assert that the first exact record
remains stored, the response is `Conflict`, and the diagnostic identifies
repeated signing. Sending the original record bytes yields `AlreadyStored`.

### 5. What should a replica remember after a restart?

**Decided, 2026-11-23.** A replica that held an acknowledged, unexpired 6
before a restart must be able to serve 6 immediately, even if no other
node answers. Persist the selected record bytes with their expiry. Preserve
the remaining TTL across downtime. Recover the live record before answering
requests for the DID. A stale 5 cannot replace that 6. This storage belongs to the replica
and is separate from the owner's saved publication bytes in point 4.
Point 6 covers retention of version metadata after record expiry.

**Write policy.** Persist one current signed
record per local DID. For a first write or a change of version, make the
record and its expiry durable together before acknowledging storage. If
records are written only by a periodic task, a power cut between accepting
6 and the next flush can leave 5 as the recovered version.

For identical republications that extend only the TTL, keep the newest
expiry in memory and let a periodic task batch changed expiries. An idle
tick issues no writes. A metadata update must still match the exact record
it renews. A delayed flush for 5 must never overwrite any part of 6. If a
power cut loses a pending renewal, use the earlier durable expiry. Never
restart the TTL from boot time. The batching interval remains configurable.

**Amended, 2026-11-24: damaged files.** Each file ends with the SHA-256 of
its other bytes, and a file that does not match it is not loaded. Records
enter a replica's memory only verified, and the rules rely on it: a held
record is kept against another at its position, and a repair returns a held
record of the expected position and key without checking its signature. A
byte the device changed in the signature of 6 left its form intact, so the
restarted replica served it, refused the valid 6 as a conflict, and a
repair returned it (found in a review, reproduced by
`a_record_damaged_on_disk_is_not_returned_by_a_repair`). A changed marker
would refuse the lower positions of a DID for a TTL. The hash costs
microseconds per file, where verifying every record's signature at each
start would cost one ML-DSA verification per record and still not cover
markers. It does not stop a party that can write the files.

At the ADR 0005 estimate of 6.5 KB per record, 20 DIDs require about 130 KB
of record bytes before filesystem and ADR 0006 format overhead. A weekly
rotation at every DID would add about 130 KB of new record payload writes
per week. Neither number estimates physical writes to the storage medium.

**Acceptance cases.**

- Start with durable 5, store 6, observe a positive storage response, then
  simulate power loss without running shutdown hooks. Restart before expiry
  with all peers offline. GET must return the exact bytes of 6.
- Fail the durable write for 6 while 5 is still live. The STORE or UPDATE
  must not confirm 6. Recovery must still yield the complete 5.
- Renew identical 6 from expiry E1 to E2. After a crash before the flush,
  restart before E1 and check that 6 has the original durable expiry E1.
  Repeat with a completed flush and check that 6 survives until E2.
- Queue a renewal for 5, commit 6, then run the pending flush. The record
  and expiry of 6 must stay intact. A following idle tick issues no writes.

### 6. What should a replica retain after TTL expiry?

**Decided, 2026-11-23.** Reuse the persistent replica storage from point 5.
When an accepted document expires, drop its payload and retain only metadata
in the same store: the DID key, the highest accepted position for that DID
and the marker's expiry. Only accepting a verified document can establish
that position. A peer's claim or the owner's rotation schedule cannot advance
it. In the intended deployment the owner rotates weekly. Each replica
measures retention from the local record expiry.

The default retention interval is one additional record TTL (14 days in the
current configuration). Compute the marker deadline from the record's expiry,
including on recovery. If both deadlines passed while the replica was off,
discard the entry immediately. A read, rejected replay or restart cannot
extend retention. Include these entries in the storage budget and reuse the
existing expiry maintenance.

During this interval a replica that remembers 6 refuses 5 as stale even
when no neighbor answers. It can accept a verified 6 or higher through the
empty-replica check, subject to the same-position conflict rules. The
marker alone supplies no document to GET and cannot prove 6 to another
node. Replace it atomically when storing the new record. After its own
expiry discard the marker and apply the ordinary empty-replica rules.
Test a power cycle while only the marker exists, a replay of 5 on either
side of marker expiry, and restoration of a verified 6 while it is live.

**Application rationale.** During a new Modbus handshake the proxies check
the issuer's VC, the Status List and the hash of the signing public key.
If the current VC names key 6, returning key 5 cannot complete that
handshake. Established sessions do not perform a DHT lookup for each
message. During an overlay outage a new session can use qualifying cached
material within its validity window, otherwise it is deferred. Storage TTL
and application validity are separate. In the published application each
signing-key rotation also needs a matching VC. Automatic leaf activation
therefore needs credential coordination before a new key can be used in a
handshake. See sections 5.2, 5.3 and 6.4 of
[Trungadi et al. (2025)](https://doi.org/10.1016/j.jisa.2025.104199).

### 7. Which device properties belong in the genesis?

**Decided, 2026-11-23.** The genesis commits to the complete initial DID
Document body in hashed form. Device attributes included by the owner at
creation are covered by that digest. An attribute can change in a later
signed document under the same DID. The commitment preserves the original
declaration and supplies no independent attestation of its truth.

1. Build the initial body, including the first signing public key, services
   and any device attributes. Omit the top-level `id`. Follow ADR 0005's
   placeholder rules for self-references, including DID URLs. Hash the
   canonical JSON bytes with SHA-256. The input is the document body before
   signing. Genesis and the enclosing record are outside this input.
2. Hash the canonical genesis containing that digest and the tree commitment
   as specified in Decision 1. Insert the resulting DID as `id`, expand the
   placeholders in the document, and sign it with leaf 0.
3. On receipt of 0, reconstruct the hashed form from the canonical body:
   check its `id`, reject a literal placeholder in the published document,
   remove the top-level `id` and undo the substitution in string values by
   the ADR 0005 rules. Require the digest to equal the one in the genesis.
   On receipt of 5, verify the genesis against the DID and verify leaf 5
   and its signature. The replica can do so without fetching document 0.

Acceptance cases: hold the root fixed and change a serial number in the
initial body. The derived DID must change. A valid leaf-0 signature on
that altered body under the original DID must fail the digest check.
A later authorized version may update the same field under the original DID.

### 8. How many positions may sign documents?

**Decided, 2026-11-23.** Use a binary tree of height 6. Position 0 signs
the initial document. Positions 1 through 62 allow 62 subsequent rotations.
At a weekly cadence the last usable slot starts 62 weeks after creation.
Position 63 is reserved. Reject a document at 63 even if its signature and
six-hash path verify. Reject an out-of-range index and any path whose
decoded length differs from 192 bytes. Provisioning commits all 64 leaves.
The use of position 63 in a future migration remains a separate decision.

**Cost per owner DID.** In a seed-based implementation, 64 independent
32-byte ML-DSA seeds and 64 independent 32-byte codes occupy 4 KiB of raw
secret material. The 127 SHA-256 hashes of the complete public tree occupy
4,064 bytes. These figures exclude the signed record, storage metadata,
filesystem overhead and temporary crypto workspace. Provisioning can derive
one public key at a time and retain its leaf hash. Weekly rotation needs
only the selected key and its precomputed path. A replica only receives
the published record and proof.

### 9. Local-first DID lookup and network-only repair

**Decided, 2026-11-23.** Ordinary DID GET returns an unexpired, verified local
record immediately. On a local miss it uses the normal network lookup and
respects any live minimum position from point 6. The Status List retains
its existing DHT read policy.

Expose a separate repair call in Rust and Python. The caller supplies the
DID, the local record that failed, the expected position (the document's
`seq`) and the SHA-256 digest of the expected raw signing key. These are lookup inputs.
The DHT verifies fetched records itself.

1. Issue one bounded network lookup. Use the failed local record as a
   comparison baseline. Continue past remote copies of that record, older
   records, and unverifiable claims while candidates and time remain.
2. Check genesis binding, leaf position, activation code, Merkle path and
   signature. Require the expected DID, exact position and key digest, and
   a position higher than the failed record. Respect the highest position
   already verified during the lookup and the live local minimum.
3. Repair local storage using a conditional durable write against the failed
   record. If a concurrent writer already installed the matching record,
   return it. If local storage has advanced beyond it, preserve the newer
   bytes and return no match. Report success only for an installed match.
4. If no candidate qualifies by the deadline, return no match and leave
   the stored record intact. The caller decides how to handle that result.

A repaired record is an ordinary stored record. The same rules,
persistence (point 5), TTL and hourly republication apply to it as to any
other, including on a node outside the `k` closest to the key. An ordinary
GET that goes to the network stores nothing, as today. Only the repair
call writes locally, because the application has checked its result
against the credential.

**DHT acceptance cases.** Use signed record fixtures and controlled RPC
responses. Call the library operations directly.

| Operation and inputs | Expected result |
|---|---|
| Ordinary GET with local 5 | Return 5, with zero DID lookup RPCs |
| Explicit repair with local 5, target 6 and key digest for 6. First peer repeats 5, another supplies verified 6 | Return 6, persist it and serve it on the next ordinary GET without a remote call |
| Repair with only 5, a wrong DID or key digest, an invalid proof, or silence | Return no match and retain 5 |
| A concurrent writer installs 7 before repair of 5 with 6 commits | Preserve 7 and return no match for 6 |
| Only a live marker for 6 survives and normal GET finds remote 5 | Return no record |

**Integration context.** The application supplies the lookup criteria from
the credential it has validated and decides whether to retry authentication.
When rotation is due but the issuer is offline, the application may prepare
6, keep 5 published and use 5 while its VC authorizes it. Publication of 6
is an explicit call once its matching credential is available. Credential
issuance, Status List freshness for authentication, revocation decisions
and end-to-end Modbus handshakes are implemented and tested in the protocol
repository.

### 10. Holders repair themselves after `Stale`

**Decided, 2026-11-23.** The hourly republication
(`src/network/maintenance.rs`) ignores the answers today. When a replica
answers `Stale` to the republication of 5, the holder fetches that
replica's record (`FindValue`). It verifies the record as in point 2: DID,
genesis, leaf, code, path, signature, and a position above 5. It then
replaces its 5 with a conditional write. A replica that answers `Stale`
without showing a valid higher record costs one fetch and changes nothing.
There is at most one fetch per record per republication round. Replicas
left behind are repaired without waiting for the owner. Under ADR 0005 a
holder could take only the next version (R3).

Acceptance test: a holder of 5 republishes to a replica that holds 6, and
ends with 6. Repeat with a replica that answers `Stale` and shows nothing,
or an invalid record: the holder keeps 5.

### 11. Rollout: replace the ADR 0005 records

**Decided, 2026-11-23.** ADR 0005 has not been released. Its branch is not
merged into `main`, and the changelog lists it under "Unreleased". The
format of this ADR replaces the ADR 0005 record format. Nodes accept one
format, with no transition period.

This ADR replaces, in ADR 0005:

- the DID: the SHA-256 of the canonical genesis, not of the hashed form of
  version 0 (Decision 1, point 7);
- `nextKeyHash`, and the check of `prev` against the stored record: the key
  of a position is checked against the root (Decisions 2 to 4);
- R2, R3, R5 and the quorum of the network check. A holder takes any
  higher position (Decision 3). An empty replica stores a verified record
  unless it verifies a higher one (points 2 and 3);
- the `Update` request, `MissingPrevious` and the owner's replay of its
  chain: every position is published by STORE, and a replica behind takes
  it directly;
- the `NewerClaimed` result and the quorum of claims in the owner's report
  (point 2).

It keeps:

- canonical JSON and the placeholder rules (ADR 0005, section 1 and open
  point 3);
- the 43-character suffix and its key;
- R1: the same bytes are `AlreadyStored`;
- the `FindHash` answer `(seq, hash)` in one datagram;
- a holder's `Stale` for a lower position, and its `Conflict` for another
  record at its own (R4);
- refusals that count only once shown (ADR 0005, open point 27);
- random message ids, receipts and the futurelock rule.

The rule never to accept on silence (ADR 0005, R5; `AGENTS.md`) changes
meaning. Under ADR 0005 the answers of other nodes were the only evidence
that a record was authentic, so silence could not stand in for them. Here
the record proves its own authorization from the DID, so the permission to
store it is the record itself: "Base access decisions on permission rather
than exclusion" ([SALTZER], section I-A-3 b). The check only looks for
evidence that the record has been superseded. `AGENTS.md`, `DESIGN.md`,
the changelog and `docs/integration.md` change with the code that
implements this ADR, not before. Until then the ADR 0005 rule protects the
code in place.

### 12. Record format, and the handoff still to specify

**Decided, 2026-11-23: the record format.** The envelope stays that of
ADR 0005: the algorithm field (12 bytes), the ML-DSA-65 signature (3309
bytes) and the canonical JSON document. The document at position 5:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "authentication": ["did:iiot:X#k0"],
  "id": "did:iiot:X",
  "prev": "<base64url SHA-256 of the previous record>",
  "seq": 5,
  "service": ["..."],
  "treeProof": {
    "code": "<32 bytes in base64url, 43 characters>",
    "genesis": {
      "hashAlg": "SHA-256",
      "height": 6,
      "initialBodyHash": "<43 characters>",
      "root": "<43 characters>",
      "sigAlg": "ML-DSA-65",
      "version": 1
    },
    "path": "<192 bytes in base64url, 256 characters>"
  },
  "verificationMethod": [{"publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-65", "pub": "..."}}]
}
```

- `nextKeyHash` is removed. `seq` is the index of the leaf, from 0 to 62.
  63 is refused. The proof carries no separate index, so the two cannot
  disagree.
- `prev` is absent at 0 and present after it. Only its format is checked
  (Decision 4).
- The DID is `did:iiot:` and the base64url, without padding, of the
  SHA-256 of the canonical bytes of `genesis`.
- A leaf is SHA-256(0x00 ‖ u32 big-endian `seq` ‖ raw public key of 1952
  bytes ‖ code of 32 bytes). A node is SHA-256(0x01 ‖ left ‖ right).
  `path` holds six 32-byte siblings: the first is the leaf's sibling and
  the last the sibling just below the root, as LMS orders its path
  ([RFC8554], section 5.4). Bit `i` of `seq`, from the least significant,
  is 1 when the node at level `i` is a right child.
- `initialBodyHash` is the SHA-256 of the hashed body of document 0: the
  document without `id` and `treeProof`, with the DID written back as the
  placeholder (ADR 0005, section 1). The application builds the body. The
  custody backend adds `treeProof` and signs, so the code does not pass
  through the application before the signature.
- `treeProof` and `genesis` hold exactly these members. A replica refuses
  an unknown algorithm, a version other than 1, a height other than 6, a
  code that does not decode to 32 bytes and a path that does not decode to
  192.
- Shared test vectors use public keys from fixed seeds. The DID depends
  only on hashes, so a Python script with `hashlib` and `json` alone
  recomputes it.

The record grows by about 0.55 KB: about 7.0 KB in 6 KADF fragments,
against about 6.5 KB in 5 under ADR 0005. Measured on the testbed on
2026-11-23 (`EXPERIMENTS.md`, E2), a first publication at `k` = 20 sends
1.5% more, about 9 KiB, one more fragment in each of its 20 STOREs, and a
read 4 to 9% more. The latency of a publication does not change (E1).

**Decided, 2026-11-23: the handoff.**

- The Python recovery API is the repair call of point 9:
  `Server.repair(did, failed_record, seq, key_hash)` returns the record it
  installed, or `None`, and raises `ValueError` when `key_hash` is not 32
  bytes. The caller passes the record it was served, which keeps the call
  from going below what the caller already holds. The owner's side is the
  `Custody` class of point 1.
- The per-case tests are the acceptance cases of points 1, 5, 6 and 9 and
  the STORE rules of points 2 to 4, run against a clock the tests move and
  against neighbours whose answers the tests choose. `AGENTS.md`,
  `DESIGN.md`, the changelog and `docs/integration.md` describe the result.
- The threat table below names, for each threat inside the scope of the
  DHT, what stops it, the tests that check it, and the testbed experiment
  that measured it (`EXPERIMENTS.md`, 127 nodes, `k` = 20, unless the
  experiment says otherwise).

| Threat | What stops it | Tests | Testbed |
|---|---|---|---|
| A record signed by a key outside the tree | `tree_form` before any lookup or signature: the leaf of its key and code does not reach the root the DID commits to (`InvalidRecord`) | `a_forged_record_is_invalid_whatever_the_network_says`, `made_up_ids_cannot_get_a_forged_record_stored`, `test_rotation_rejected_when_signed_by_a_key_outside_the_tree` | A1, A2, A3: no forged record stored |
| A flood of forged STOREs | The same form check, so a forged record starts no lookup and costs no signature check | `a_record_that_fails_the_form_is_invalid_before_anything_else` | A2: every forged STORE but 146 answered |
| The replay of a superseded genuine record | A holder refuses a lower position (`Stale`); an empty replica stores it only if no node shows a higher one, which it fetches as soon as it is claimed; the marker of an expired record (point 6); the repair of a reader (point 9) | `a_holder_decides_alone_by_position`, `an_old_genuine_record_is_stored_only_where_nothing_higher_is_shown`, `a_remembered_position_refuses_a_lower_one_without_asking`, `downgrade_attack_after_rotation_rejected`, `a_silent_neighbour_does_not_keep_a_shown_higher_record_out` | E4, L2 |
| Nodes that claim a higher position they cannot show, under any number of ids | A claim refuses nothing; only a fetched, verified higher record does (point 2). Claims are fetched as they arrive, so those of made-up peers come after the peers a replica knew | `a_claim_that_is_not_shown_refuses_nothing`, `made_up_ids_at_one_address_cannot_block_a_record`, `one_shown_higher_position_refuses_and_is_stored`, `made_up_claims_cannot_use_up_the_fetches_before_a_known_holder` | A4, L1: up to 18 liars block nothing |
| Answers spoofed for the nodes asked | Message ids drawn at random; an answer spoofed under the ids read on the wire has the power of a liar only | `a_thousand_requests_in_a_row_do_not_get_consecutive_ids`, `an_id_a_pending_request_holds_is_not_given_out_again` | A5 |
| Two records at one position | A holder keeps the first (`Conflict`, point 3); the owner signs each position once and resends the same bytes (point 4) | `another_record_at_the_stored_position_leaves_the_stored_one`, `two_records_at_once_at_one_position_leave_exactly_one`, `a_retry_in_the_same_slot_gives_the_same_bytes` | |
| The theft of the current key | Each later position needs its own key and its own code, which stay secret until it is published | `revoked_key_cannot_authorise_further_rotation`, `a_record_with_another_code_fails_the_tree_though_its_signature_verifies` | |
| The owner reusing a position, after a restart or with the clock set back | The custody writes the highest activated position durably before it returns a record, and signs nothing below it (point 1) | `a_restart_in_slot_5_after_publishing_2_prepares_5_after_2`, `a_clock_set_back_reopens_no_position` | |
| Two instances of the custody on one store, each signing the next position | An exclusive lock on the store, held while an instance lives (point 1) | `one_instance_at_a_time_holds_a_custody` | |
| An early activation without authority | The application's verifier checks the issuer's authorization; it reaches only the next position that is not skipped | `a_position_is_never_signed_before_its_slot_without_an_authorization`, `an_authorization_holds_once_for_its_did_and_position`, `an_authorization_never_reaches_a_skipped_lower_or_reserved_position` | |
| Reading the custody's files | Files readable by the owner's user only; the secrets below a published position are erased | `only_the_owner_can_read_the_custody`, `publishing_erases_the_secrets_below_the_published_position` | |
| A replica losing its records in a crash or a power cut | A durable write before the replica acknowledges, no answer when the write fails (point 5) | `a_restarted_replica_serves_its_record_with_no_peer`, `a_replica_that_cannot_write_does_not_confirm_the_record` | D1: no copy lost |
| A record or a marker damaged on the replica's disk | The SHA-256 at the end of each file; a file that does not match it is not loaded (point 5) | `a_file_whose_bytes_changed_is_skipped_and_kept`, `a_record_damaged_on_disk_is_not_returned_by_a_repair` | |
| A restarted replica spreading a superseded record | It sends its records to the nodes it meets only once the lookup of its own id is over | `a_node_that_starts_with_records_sends_them_only_once_it_has_joined`, `a_restarted_replica_sends_its_records_only_once_it_has_joined` | D1: 2520 of 2520 reads current, 461 older before the fix |
| A reader served a superseded record | The application compares the key with its credential and calls the repair (point 9) | `a_reader_repairs_its_record_and_then_serves_the_new_one_locally`, `a_repair_without_the_expected_record_keeps_the_served_one`, `a_repair_below_a_remembered_position_finds_nothing` | L3: no forged record read |

Outside the DHT's scope, as `DESIGN.md` (section 2) states: an attacker that
controls every node close to a DID, which can choose which of the owner's
records that DID resolves to but cannot forge one; the binding between a DID
and a device, which the credential makes; and the authentication of a
session, in the protocol repository.

Tree migration is deferred as described in the scope above.

## References

Checked on the sources on 2026-11-23. The entries shared with ADR 0005 were
checked there. KERI's "Reserve Rotation" and "Security Properties of
Pre-rotation" were checked on 2026-11-23. KERI is built with Spec-Up and
has no section numbers, so it is cited by heading.

- [DOUCEUR] J. R. Douceur, "The Sybil Attack", IPTPS 2002,
  doi:10.1007/3-540-45748-8_24.
  https://courses.csail.mit.edu/6.895/fall02/papers/Douceur/iptps02-douceur.pdf
- [KERI] Trust over IP, "Key Event Receipt Infrastructure (KERI)", v1.1.
  https://trustoverip.github.io/kswg-keri-specification/
- [RFC8391] A. Huelsing, D. Butin, S. Gazdag, J. Rijneveld, A. Mohaisen,
  "XMSS: eXtended Merkle Signature Scheme", RFC 8391, May 2018.
  https://www.rfc-editor.org/rfc/rfc8391
- [RFC8554] D. McGrew, M. Curcio, S. Fluhrer, "Leighton-Micali Hash-Based
  Signatures", RFC 8554, April 2019.
  https://www.rfc-editor.org/rfc/rfc8554
- [RFC9162] B. Laurie, E. Messeri, R. Stradling, "Certificate Transparency
  Version 2.0", RFC 9162, December 2021.
  https://www.rfc-editor.org/rfc/rfc9162
- [SALTZER] J. H. Saltzer, M. D. Schroeder, "The Protection of Information
  in Computer Systems", Proc. IEEE 63(9), 1975, section I-A-3.
  https://www.cs.virginia.edu/~evans/cs551/saltzer/
- [SP800-208] D. A. Cooper, D. C. Apon, Q. H. Dang, M. S. Davidson,
  M. J. Dworkin, C. A. Miller, "Recommendation for Stateful Hash-Based
  Signature Schemes", NIST SP 800-208, October 2020.
  https://doi.org/10.6028/NIST.SP.800-208
