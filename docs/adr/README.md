# Architecture Decision Records

An ADR records one decision about the design of AuthKademlia: the context
that called for it, what was decided, and what follows from it. One file per
decision, numbered. An accepted ADR is not rewritten: a later decision that
changes it gets a new ADR, and the old one is marked superseded.

Status is one of: Proposed, Accepted, Superseded by NNNN, Amended by NNNN.
Amended means that a later ADR changes part of the decision and the rest
still holds; superseded, that the later ADR replaces all of it.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-split-the-two-large-modules.md) | Split the two large modules, keep the others | Accepted |
| [0002](0002-reserve-before-first-store.md) | Reserve the key before the first STORE | Superseded by [0005](0005-self-certifying-dids-and-pre-rotation.md) |
| [0003](0003-ml-dsa-records-and-ephemeral-ml-kem.md) | ML-DSA-65 for records, ephemeral ML-KEM-768 outside the DHT | Accepted |
| [0004](0004-sha-256-ids-and-canonical-uuid.md) | SHA-256 keys, 256-bit ids, and the canonical UUID | Accepted, amended by [0005](0005-self-certifying-dids-and-pre-rotation.md) |
| [0005](0005-self-certifying-dids-and-pre-rotation.md) | Self-certifying DIDs and a pre-rotated chain of versions | Accepted |
