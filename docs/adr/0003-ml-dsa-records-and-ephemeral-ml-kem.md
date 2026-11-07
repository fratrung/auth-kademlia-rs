# 0003. ML-DSA-65 for records, ephemeral ML-KEM-768 outside the DHT

Status: Accepted, 2026-11-07.

## Context

Records are signed with CRYSTALS-Dilithium as submitted to round 3 of the NIST
competition (`pqcrypto-dilithium` 0.5.0), and the DID Documents built in this
repository carry a Kyber-512 key for key agreement. Both predate the NIST
standards of August 2024: ML-DSA (FIPS 204) and ML-KEM (FIPS 203). The
standards changed the algorithms, not only their names: an ML-DSA signature
does not verify as a Dilithium one, and the reverse.

Other problems with the current code:

- **Signature lengths written by hand.** `resolve_alg_and_length` gives 3293
  and 4595 bytes for Dilithium-3 and 5; the crate in use produces 3309 and
  4627. A Dilithium-3 or 5 record is cut in the wrong place and refused (code
  review of 2026-11-07, finding A1). Only Dilithium-2 is right.
- **Not only post-quantum keys.** The record header also accepts `RSA` and
  `Ed25519`: a DID can be published with a key a quantum computer breaks.
- **A key format that is no standard.** The documents write the public key as
  `{"kty": "OKP", "crv": "Dilithium2", "x": ...}`. `OKP` (RFC 8037) is for
  Edwards and Montgomery curves. RFC 9964, "ML-DSA for JOSE and COSE" (May
  2026), defines the key type `AKP` with the parameters `alg` and `pub`.
- **A key the DHT does not use.** The Kyber key sits in the document, but only
  the handshake between devices uses it, outside the DHT. A static key
  agreement key also gives no forward secrecy: whoever records the handshakes
  and later obtains the device's key decrypts all of them.

The Python application moves to the standards at the same time.

## Decision

**Parameter sets: ML-DSA-65 and ML-KEM-768**, both NIST security category 3.

- FIPS 203 (section 8) recommends ML-KEM-768 as the default parameter set.
- FIPS 204 names no default. ML-DSA-65 is the set of the same category. It is
  the default of Java's `KeyPairGenerator` (JEP 497) and the smallest set of
  Apple CryptoKit; BSI TR-02102-1 recommends ML-DSA-65 and 87 (per a
  secondary source, the BSI text could not be reached).
- ML-DSA-44 (category 2) is post-quantum too, and smaller. Choosing it later,
  for instance if record size becomes a problem on the edge boards, is a new
  ADR.

**Records.**

```
| algorithm "ML-DSA-65" (12 B, null-padded) | signature (3309 B) | DID Document (JSON) |
```

- A node accepts only `ML-DSA-65`, for DID Documents and for the Status List.
  A record with any other algorithm field is `InvalidRecord`: Dilithium-2, 3
  and 5, Ed25519, RSA. The Ed25519 and RSA code stays in `crypto/`; no record
  reaches it.
- Lengths come from the crate (`mldsa::signature_len()`), never from
  literals.
- The signature is pure ML-DSA (not HashML-DSA) over the document, with an
  empty context string, as every ML-DSA library signs by default. The
  authorization of a key rotation (`auth_signature`) is an ML-DSA-65 signature
  of the new record by the old key, as today.

**The public key in the DID Document** follows RFC 9964:

```json
"publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65", "pub": "<base64url>" }
```

- A node reads it from `verificationMethod[0]`, as today, and refuses the
  record (`InvalidRecord`) unless `kty` is `AKP` and `alg` equals the record's
  algorithm field. A record cannot name one algorithm in its header and
  another in its key.
- The node reads nothing else of the document but `id` (the DID binding).

**No key agreement key in the DID Document.** The documents built in this
repository have one verification method, the ML-DSA-65 key, and no
`keyAgreement`. An UPDATE rotates the ML-DSA key; there is no other key to
rotate.

**Status List.** The issuer signs it with ML-DSA-65; `issuer.bin` holds the
issuer's raw ML-DSA-65 public key (1952 B).

**ML-KEM-768 is ephemeral, and lives in the key manager.** The handshake is
the application's, outside the DHT. The key manager (`MlKemKeyManager` in
`src/crypto/key_manager.rs`) gives it one key pair per handshake:

- `ephemeral_public_key()` returns `(id, public key)` of a pair that only that
  handshake gets, and generates the next pair at once, in another thread, so a
  handshake does not wait for key generation. The id is random, so an answer
  meant for a pair given out before a restart does not reach a new one.
- `decapsulate(id, ciphertext)` uses the pair once and destroys it, whatever
  the ciphertext. ML-KEM does not report a wrong ciphertext: it returns a
  pseudo-random secret instead (implicit rejection, FIPS 203), and the
  handshake finds out when it confirms the key. Any use consumes the pair.
- A pair given out and never used expires after 30 s, and at most a bounded
  number of pairs are given out at once, 64 by default. Both are parameters.
  Beyond the bound a new handshake is refused until a pair is used or
  expires; no pair given out is destroyed to make room.
- Private keys stay inside AWS-LC, which zeroes them when it frees them, when
  consumed or expired; they are never exported or written to a file. An
  expired pair is freed at the next call to the manager, or when the manager
  is dropped.
- `encapsulate(public key)` returns `(shared secret, ciphertext)`, without
  state, for the other side of the handshake.
- The ephemeral public key is not in the DID Document, so the handshake must
  sign it with the device's ML-DSA-65 key, whose hash the VC holds. Otherwise
  a node in the middle could replace it.

**Crate.** `aws-lc-rs` (1.19) replaces `pqcrypto-dilithium` and
`pqcrypto-kyber`, for ML-DSA-65 and for ML-KEM-768. It binds AWS-LC, whose
ML-DSA and ML-KEM are `mldsa-native` and `mlkem-native` of the PQ Code
Package: their C code is proved free of undefined behaviour (CBMC), their
AArch64 and x86-64 assembly correct and constant-time (HOL Light). AWS-LC's
ML-KEM is in a FIPS 140-3 validated module (certificate #5314); the module
that adds ML-DSA (FIPS 4.0) is submitted, not yet validated. Neither it nor
any alternative below has had an independent audit. AWS maintains it, and it
is the default provider of rustls.

- It signs and verifies with the empty context only.
- It takes a public key raw or as a DER `SubjectPublicKeyInfo`. A node takes
  only the raw key (1952 B), so a document holds its key in one form.
- It can derive a key pair from a 32-byte seed. The key manager still stores
  the expanded private key (4032 B for ML-DSA-65), as before; storing the seed
  that RFC 9964 uses for `priv` is a later change. The DHT needs only public
  keys.
- It builds its C code with the `cc` crate on Linux x86-64 and AArch64: a C
  compiler is enough, no cmake.

**Python.** `DilithiumKeyManager` becomes `MlDsaKeyManager` (ML-DSA-65).
`KyberKeyManager` becomes `MlKemKeyManager`, with the ephemeral API above and
no way to store or read a private key.

## Consequences

- **Wire.** A record signed with Dilithium no longer verifies, and the
  algorithm field changes. No network runs these records yet (as in ADR
  0002). The nodes and the Python application change together, and
  `issuer.bin` is generated again: an old Dilithium-2 key (1312 B) is refused
  by its length.
- **Sizes**, derived from the parameter sizes, not measured:

  | | Dilithium-2 + Kyber-512 key | ML-DSA-65, no KEM key |
  |---|---|---|
  | Record | about 6.0 KB, 5 fragments | about 6.5 KB, 5 fragments |
  | UPDATE (record and authorization) | about 8.5 KB, 7 fragments | about 9.9 KB, 8 fragments |
  | STOREs of a first publication, k = 20 | 120 KiB (measured) | about 128 KiB |

  Verification is slower than Dilithium-2, with larger parameters; not
  measured. E1 and E2 of `EXPERIMENTS.md` are measured again. The sizes in
  the paper (Dilithium-2, Kyber-512) no longer match the code.
- Finding A1 of the review goes away: no Dilithium-3 or 5, no hand-written
  length.
- The decision of 2026-11-02 that Dilithium and Kyber always rotate together
  becomes: every update rotates the ML-DSA key. An update must still change
  the signing key (P3 point e).
- Tests, testbed, scripts and examples build ML-DSA-65 documents without a KEM
  key. ADR 0001 keeps one builder for all of them as a later cleanup; this ADR
  does not do it.
- AWS-LC clears every allocation it frees, so the keys it holds are zeroed
  when they are dropped. A private key exported from it (the key manager's
  files) is a copy this crate must zero itself.

## Alternatives rejected

- **ML-DSA-44 and ML-KEM-512**, the counterparts of Dilithium-2 and Kyber-512
  (categories 2 and 1). Smaller, still post-quantum, but below the default
  NIST recommends for ML-KEM and the sets BSI recommends.
- **ML-DSA-87 and ML-KEM-1024.** Required by NSA's CNSA 2.0 for US national
  security systems, not by this deployment, and larger.
- **Accepting all three ML-DSA sets.** A DID could then be published at
  category 2. One set is one rule; adding one is one entry in a table.
- **Keeping Dilithium-2.** Not a standard, and its signatures are not ML-DSA
  signatures.
- **`pqcrypto-mldsa` 0.1.2 and `pqcrypto-mlkem` 0.1.1**, the PQClean crates
  first chosen here. PQClean was archived on 2026-08-04, and RustSec marks the
  crates unmaintained (RUSTSEC-2026-0161, RUSTSEC-2026-0166): no further
  security fixes.
- **RustCrypto `ml-dsa` and `ml-kem`.** Pure Rust, maintained, widely used,
  and the replacement RustSec suggests. Their README says they were never
  independently audited, and `ml-dsa` had advisories (a timing side channel,
  signatures with repeated hint indices accepted), since fixed. The fallback
  if `aws-lc-rs` does not fit, for instance if it does not build for a board.
- **`libcrux-ml-dsa` and `libcrux-ml-kem`.** Parts formally verified (hax,
  F*), and the ML-KEM is in OpenSSH. Still 0.0.x, and its ML-DSA verification
  had two bugs in 2026 (a norm check, an AVX2 edge case), fixed in 0.0.8 and
  0.0.9.
- **A static ML-KEM key in the DID Document.** No forward secrecy, and a
  second key to rotate with every update.
- **A context string per use**, for instance to keep a signature of a VC from
  passing as a Status List (P4 point 4). It changes what the Python side
  signs, and `aws-lc-rs` has no API for it; it is decided with P4.

## Validation

- Tests written before the code, failing on the current one:
  - a complete ML-DSA-65 record passes `handle_signature_verification`,
    `is_bound_to_key` and `verify_record`, and its signature is as long as
    the crate says;
  - a record is `InvalidRecord` when its header says `ML-DSA-65` and its key
    has another `alg`, or a `kty` other than `AKP`;
  - a record whose header is `Dilithium-2`, `Ed25519` or `RSA` is
    `InvalidRecord`;
  - the ML-KEM key manager: two calls give two different pairs; `encapsulate`
    and `decapsulate` agree; a second `decapsulate` with the same id fails; a
    pair expires; the number given out at once is bounded; `encapsulate`
    refuses a key with a coefficient out of range (FIPS 203, section 7.2).
    The manager has no key directory: in Python, `MlKemKeyManager` has no
    method that returns, stores or reads a private key.
- Before choosing the crate, outside the repository: `aws-lc-rs` signs and
  verifies with `fips204`, RustCrypto `ml-dsa` and `pqcrypto-mldsa`, in both
  directions and with each other's private keys; it encapsulates and
  decapsulates with `fips203` and RustCrypto `ml-kem`, and agrees with them on
  the implicit rejection of a modified ciphertext. It passes NIST's ACVP
  vectors for ML-DSA-65 key generation (25) and ML-KEM-768 decapsulation
  (35); of the signature verification vectors only one has an empty context,
  and it passes. The ARM code was not run.
- `cargo test`, `cargo test --features counters`, `cargo clippy
  --all-targets`, `cargo fmt --check`, `cargo build --features testbed`,
  `cargo check --features python`.
- Testbed: E1 and E2 again; A1 and A2 should not change.

## References

- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
  August 2024.
- NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard", August
  2024.
- RFC 9964, "ML-DSA for JOSE and COSE", May 2026.
- OpenJDK JEP 496 and JEP 497, ML-KEM and ML-DSA in Java 24.
- BSI TR-02102-1, "Cryptographic Mechanisms: Recommendations and Key
  Lengths", 2025.
- NIST CMVP certificate #5314, AWS-LC 3 Cryptographic Module, FIPS 140-3.
- PQ Code Package, `mldsa-native` and `mlkem-native`,
  https://github.com/pq-code-package.
- RustSec RUSTSEC-2026-0161 and RUSTSEC-2026-0166, `pqcrypto-mlkem` and
  `pqcrypto-mldsa` unmaintained, 2026-06-04; PQClean issue #604.
