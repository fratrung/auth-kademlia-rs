# 0004. SHA-256 keys, 256-bit ids, and the canonical UUID

Status: Accepted, 2026-11-08. Amended by ADR 0005, 2026-11-11: the DID is no
longer a canonical UUID.

## Context

The key of a DID in the DHT is the SHA-1 of the UUID text after `did:iiot:`,
the key of the Status List the SHA-1 of `status-list`. Node ids are 160 random
bits, and distances are the XOR of 160-bit ids.

**What the key hash must give here**, and what it need not:

- Keys spread evenly over the nodes. Any of the hashes below does.
- Nobody can build another DID whose key is the key of an existing one (a
  second preimage, among UUID texts). Whoever could would occupy that key, as
  in ADR 0002, but would not impersonate its owner: the document would carry
  another `id`, and the reader compares the public key with the hash in the VC.
- The key does not reveal the DID (a preimage), which the reservation of ADR
  0002 relies on. This is bounded by the randomness of the UUID, not by the
  hash: a version 4 UUID has 122 random bits.
- No collision resistance: two DIDs of the same attacker under one key harm
  nobody else.

**SHA-1.** It is broken for collisions (SHAttered, 2017; a chosen-prefix
collision, 2020), which this use does not depend on, and not for second
preimages. NIST retires it by 31 December 2030; after that date validated
modules may not use it, and an audit flags it before then.

**Quantum computers.** Grover's algorithm finds a second preimage of an
`n`-bit hash in about 2^(n/2) steps, which do not parallelise well: 2^80 at
160 bits, 2^128 at 256 bits. Among UUID texts the attack is harder still (at
most about 2^128 canonical texts, so at 160 bits another UUID with a given
key exists with a probability of about 2^-32), but an audit reads the generic
figure.

**Other Kademlia DHTs.** The Kademlia paper and the BitTorrent DHT (BEP 5) use
160-bit SHA-1 ids. BitTorrent v2 (BEP 52) hashes with SHA-256 and truncates
it to 20 bytes where the existing protocols expect 20 bytes, to stay
compatible with a DHT already running. Kademlia DHTs designed more recently
use 256-bit ids: libp2p (the XOR of SHA-256 hashes of the keys), Ethereum's
node discovery (the Keccak-256 of the node's public key), Hyperswarm (32-byte
ids). No network runs this DHT yet, so there is nothing to stay compatible
with.

**The UUID text.** The binding check accepts every text that parses as a UUID
(upper or mixed case, without hyphens, in braces, as `urn:uuid:`) and hashes
it as written. One UUID therefore gives many DIDs, each under another key:
`did:iiot:3f2b…` and `did:iiot:3F2B…` are different DIDs, and anyone can
publish such a variant of an existing DID with their own key. RFC 9562 writes
UUIDs in lower case and compares them without regard to case, so software
that follows it can take one variant for another.

## Decision

- **Keys.** The key of a DID is the SHA-256 of its UUID in canonical form, all
  32 bytes. The key of the Status List is the SHA-256 of `status-list`.
- **Node ids** are 256 random bits; distances are the XOR of 256-bit ids.
  Every id and key on the wire is 32 bytes.
- **Canonical UUID.** The canonical form is the one RFC 9562 writes: 36
  characters, lower-case hexadecimal, hyphenated
  (`3f2b1c4e-8a6d-4e2b-9c1a-5d7e8f9a0b1c`). A record whose DID holds the UUID
  in another form does not bind to any key and is `InvalidRecord`. One UUID is
  one DID and one key.
- **SHA-256, not SHA3-256.** Against classical and quantum attacks they are
  equivalent here, and the advantages of SHA-3 (a different construction, no
  length extension) do not matter for hashing a UUID. SHA-256 is accelerated
  in hardware on recent x86 processors, on ARMv8 cores with the cryptography
  extensions, and on many microcontrollers and secure elements; SHA-3 rarely
  is. It is already used here (the hash of a record, the signature cache) and
  in Python's standard library.
- **Python.** The Python application changes at the same time, wherever it
  computes a key itself. Python's `str(uuid.UUID(...))` and Rust's
  `Uuid::to_string` already write the canonical form.

## Consequences

- **Wire.** Every message carries 32-byte ids and keys instead of 20. Nodes
  before and after this change cannot decode each other's messages, and every
  key changes. No network runs these records yet (as in ADR 0002 and 0003).
- **Saved state.** The file `save_state` writes holds the node's own id, 20
  bytes, and the addresses of its neighbours, without their ids. Nothing in
  the crate reads it back. An application that passes the old id to `Server`
  gets an error (`node_id` must be 32 bytes), so it drops the id and the node
  takes a new random one; the addresses still serve to bootstrap.
- **Sizes**, derived from the message format, not measured:
  - 12 bytes more per id or key in every message;
  - an answer to FIND_NODE with `k` = 20 grows from about 0.9 to 1.1 KB, one
    datagram either way; with `k` = 25 from about 1.1 to 1.4 KB, at the edge
    of one fragment (1400 bytes), so it takes two when the addresses are long;
  - with IPv6 addresses, an answer with `k` = 25 already takes two.
- **Cost of the hash.** The canonical text is 36 bytes, one SHA-256 block,
  under a microsecond or so on the boards. Every key is checked next to an
  ML-DSA-65 verification, which costs hundreds of microseconds or more.
- **Code.** `ID_LEN` becomes 32. `long_id` stays a `U256`, now holding the
  whole id. The last value of the key space, 2^256 − 1, is the largest
  `U256`: bucket ranges keep it as an inclusive bound, and the middle of a
  range is computed as `low + (high − low) / 2`, which does not overflow.
  `AGENTS.md`, `DESIGN.md`, the testbed and the examples say 256 bits.
- **ADR 0002** still holds: its reservation carries the SHA-256 key, and
  finding the DID from it still costs about 2^122 tries.
- E1 and E2 of `EXPERIMENTS.md` (latency and traffic) are measured again,
  together with those of ADR 0003.

## Alternatives rejected

- **Keeping SHA-1.** Not exploitable in this use, but retired by NIST by 2030,
  and 2^80 against a quantum second preimage.
- **SHA-256 truncated to 160 bits.** No change to the wire, the choice of
  BitTorrent v2. It is a choice for compatibility with a running network,
  which this DHT does not have, and it keeps 2^80 against a quantum second
  preimage. Should keys ever become hashes of their content, 160 bits give
  only 2^80 against collisions.
- **SHA3-256.** The same security, rarely accelerated in hardware.
- **Hashing the UUID text as written.** One UUID, many DIDs (see Context).
- **Node ids derived from a public key** (S/Kademlia), against nodes that
  choose their id to sit next to a key. A different problem, which the length
  of the hash does not change; not decided here.

## Validation

- Tests written before the code, failing on the current one:
  - the key of a DID is the SHA-256 of its canonical UUID, checked against a
    value computed outside the crate (Python's `hashlib`);
  - a DID whose UUID is upper case, mixed case, without hyphens, in braces or
    a `urn:uuid:` is `InvalidRecord`, under the key of its text and under the
    key of its canonical form;
  - ids are 32 bytes on the wire;
  - the table splits the bucket that covers the whole key space into two
    halves that meet without a gap, and ids at the top of the space (all
    bytes `0xFF`) find their bucket and their distance without overflow.
- `cargo test`, `cargo test --features counters`, `cargo clippy
  --all-targets --features testbed`, `cargo fmt --check`, `cargo build
  --features testbed`, `cargo check --features python`; the bucket checks of
  `examples/topology_analysis.rs` over the 256-bit space.
- Testbed: E1 and E2 again.

## References

- P. Maymounkov, D. Mazières, "Kademlia: A Peer-to-peer Information System
  Based on the XOR Metric", IPTPS 2002.
- BitTorrent BEP 5, "DHT Protocol", and BEP 52, "The BitTorrent Protocol
  Specification v2".
- libp2p, Kademlia DHT specification.
- Ethereum devp2p, Node Discovery Protocol v5.
- NIST, "NIST Retires SHA-1 Cryptographic Algorithm", 15 December 2022.
- NIST FIPS 180-4, "Secure Hash Standard".
- RFC 9562, "Universally Unique IDentifiers (UUIDs)", May 2024.
- M. Stevens et al., "The first collision for full SHA-1", 2017; G. Leurent,
  T. Peyrin, "SHA-1 is a Shambles", 2020.
