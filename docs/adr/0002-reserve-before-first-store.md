# 0002. Reserve the key before the first STORE

Status: Proposed, 2026-11-05. The open points below are decided before the
code is written.

## Context

At the first publication of a DID no replica holds the record, so the network
check of an empty replica (`DESIGN.md` section 7) finds nothing and the first
record to arrive is stored. The owner's first STORE carries the record, and
with it the DID. A node that reads the traffic learns the DID from that STORE
and can send its own self-signed record for the same DID to the nodes the
owner has not reached yet.

Testbed, 10 nodes, `k` = 3, attacker in `persist` mode (`EXPERIMENTS.md`
section 7): in 1 round of 20 the attacker learned the DID from the owner's
first STOREs and got forged records onto 6 of the 9 other nodes; the owner's
publication was rejected and 3 of 3 plain reads returned the forged record.
The check holds once the network holds a record: a restarted replica never
took a forged record of a DID already published.

## Decision

- Before the STOREs, the owner sends each replica chosen by its lookup a
  reservation: the key and the SHA-256 of the record (`record_hash`), in one
  datagram. The key is the SHA-1 of the DID's UUID, so the reservation does not
  reveal the DID, and without the DID nobody can build a record that binds to
  the key.
- The first reservation of a key wins. A replica holding a reservation accepts
  only the record with that hash; any other record gets `Conflict` at once,
  without a lookup or a signature verification.
- A reservation lasts about 3 round trips, between 10 ms and 1 s, and for as
  long as the STORE that matches it is being handled.
- Then the owner sends the STOREs. When the first one reveals the DID, every
  replica it reached is already reserved for the owner's hash.
- UPDATE, GET, the replication to new nodes and the hourly republication do
  not change: they move records that already exist, which the check protects.

Precondition: DID UUIDs are random (version 4, 122 random bits). If they are
derived from a serial number, a MAC address or a time, the key can be reversed
by trying the candidates, and the reservation hides nothing. The Rust code
uses `Uuid::new_v4`; the Python provisioning must do the same.

## Open points

1. **Where the check runs.**
   - (a) On the STORE, as today, after the DID binding check (`rpc_store`);
     the reservation only marks the key.
   - (b) On the reservation. It carries no record, so the binding cannot be
     checked first: a made-up reservation would cost a replica a lookup of
     about 20 `FindHash` and one of the 256 lookup slots (`MAX_STORE_LOOKUPS`).
   - Proposed: (a).
2. **Nodes that are not reserved.** In the testbed round above the forged
   records were on nodes the owner never contacted. They are empty and their
   check finds nothing.
   - (a) `FindHash` also answers with a reserved hash, so their check sees the
     owner's reservation on the replicas and refuses. It also lets an attacker
     that reserves some replicas first, with a random hash, make the others
     refuse the owner's STORE.
   - (b) A node that knows at least 2`k` live nodes closer to the key than
     itself refuses a STORE without a lookup (P13 O7). Its risk is refusing
     wrongly when views differ.
3. **A replica already reserved with another hash.** The owner retries after
   the expiry, or reports the publication as rejected.
4. **The expiry when the owner's round trip was never measured.** Today the
   default is 500 ms (`INITIAL_RESEND_AFTER`).

## Consequences

- A first publication costs one more round trip, of one datagram per replica.
- New message types go at the end of `RpcMessage`. Older nodes cannot decode
  them; no network runs them yet.
- What remains open:
  - Whoever knows the UUID before the owner publishes can reserve first. Only
    the reader comparing the key with the hash in the VC detects it.
  - An attacker on the path can stop a publication, by reserving first with a
    random hash or by dropping datagrams. It cannot get a forged record
    stored.
- The other optimizations of the check (P13) stay valid: the check does not go
  away. O3 changes `FindHash` too, so it comes after this ADR and the message
  changes once.

## Validation

- Unit tests written before the code: a replica reserved for hash H answers
  `Conflict` to a STORE with another record, with no lookup and no
  verification; a STORE with hash H goes through the check as today; a
  reservation expires; a second reservation with another hash is refused.
- Integration tests on ports 15954 and up.
- Testbed:
  - `persist`, 20 rounds: no forged record, today 1;
  - `race` and `burst`: still 0 of 80;
  - first-publication latency, expected to rise by about one round trip;
  - a new attacker mode that reserves first, to measure the blocking.
  Results go into `EXPERIMENTS.md`.
