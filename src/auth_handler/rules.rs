//! Whether a replica takes a DID record: the rules R1 to R5 and the UPDATE
//! table of ADR 0005, section 3, as pure functions.
//!
//! They read records and answers, and decide; they verify no signature and
//! ask nobody. The node gathers what they need: the record it holds, the
//! answers `(seq, hash)` of the nodes it asked, a record it fetched. Where a
//! rule needs a signature, the decision says so, and the node verifies it.
//!
//! - `decide_locally`: steps 1 to 3, by what the replica holds.
//! - `decide_version_zero`: R2, a version 0 at a replica that holds nothing.
//! - `decide_successor`: R5, a version N ≥ 1 at a replica that holds nothing.
//!   Its rows that trust answers are all there (open point 5).
//! - `check_fetched`: the version N−1 R5 fetches from a node that voted for it.

use crate::utils::{digest_bytes, ID_LEN};

use super::did::{document_of, record_form, FormError, RecordForm};

/// A request that carries a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Store,
    Update,
}

/// Why a version N is refused at a replica holding another record, without
/// asking anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalConflict {
    /// R4: the same document as the stored version N, signed again.
    SignedTwice,
    /// R4: another public key at the place of the stored version N.
    OtherKey,
    /// R4: the stored key signed another document at the same place: proven
    /// duplicity, once its signature verifies.
    ProvenDuplicity,
    /// R3: a version N whose `prev` is not the stored version N−1.
    WrongPrev,
    /// R3: a version N whose key is not the one the stored version N−1
    /// commits to.
    UncommittedKey,
}

/// What a replica does with a record by what it holds (steps 1 to 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Local {
    /// Step 1 failed: `InvalidRecord`.
    Invalid(FormError),
    /// R1: the same bytes as stored.
    AlreadyStored,
    /// A STORE at a replica that holds nothing: R2 for version 0, R5 for a
    /// later one. Carries the form of the record sent.
    AskNetwork(RecordForm),
    /// R3: the record follows the stored version. Verify its signature, then
    /// replace the stored record.
    VerifyAndReplace,
    /// R4: the stored key, another document at the same place. Verify its
    /// signature: valid is proven duplicity (`Conflict`), invalid is
    /// `InvalidRecord`.
    VerifyDuplicity,
    /// R4: the replica holds a later version.
    Stale { stored: u64 },
    /// R3 or R4: refused, logged by kind.
    Conflict(LocalConflict),
    /// An UPDATE at a replica that holds nothing (`None`), or any request at
    /// one that holds a version below N−1 (its `seq`).
    MissingPrevious(Option<u64>),
}

/// A node's answer to `FindHash`: the version it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub seq: u64,
    pub hash: [u8; ID_LEN],
}

/// Why the network refuses a record at a replica that holds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A node claims a newer version (R5), or the quorum does (R2).
    NewerClaimed { seq: u64 },
    /// A node holds another record at the same place: `(N, h)` in R5,
    /// `(0, h)` in R2.
    OtherVersion { seq: u64, hash: [u8; ID_LEN] },
    /// A node holds a version N−1 that the record does not follow.
    NotFollowing { hash: [u8; ID_LEN] },
    /// A node holds a version below N−1 (open point 26).
    HolderBehind { seq: u64 },
    /// The fetched version N−1 hashes to `prev` but fails its checks.
    FetchedDoesNotHold,
}

/// How far R5 got with the fetch of version N−1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    /// Not tried yet.
    NotYet,
    /// A record that hashes to `prev` passed its checks. `dropped` are the
    /// voters (indices into the answers) that gave no record, or one that does
    /// not hash to `prev`, before it: they are no votes.
    Confirmed { dropped: Vec<usize> },
    /// Every voter was tried and none gave such a record: all dropped.
    NoneConfirmed,
}

/// What R2 or R5 decides from the answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Refuse(Refusal),
    /// R5: fetch version N−1 from these voters, in this order (the closest to
    /// the key first, as the answers are given), then decide again.
    Fetch(Vec<usize>),
    /// Verify the record's signature, then store it.
    Accept,
    /// No answer to the sender: never accept on silence.
    NoAnswer,
}

/// What a fetched version N−1 proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchCheck {
    /// It does not hash to `prev`: that voter is no vote, try the next.
    NotPrev,
    /// It hashes to `prev` and fails its form or does not commit to the key
    /// of the record sent: `Conflict`.
    DoesNotHold,
    /// It holds. For N = 1 it is version 0, whose self-signature must verify
    /// too (`verify_version_zero`), or the outcome is `Conflict`.
    Confirmed { verify_version_zero: bool },
}

/// The nodes that may hold a record among those a replica asked: it is one of
/// the `k` replicas itself (open point 5).
pub fn replicas_asked(k: usize, asked: usize) -> usize {
    asked.min(k.saturating_sub(1))
}

/// Matching answers R5 needs out of `n` (open point 5):
/// `f = max(1, ⌊(n − 1)/3⌋)`, `max(2, min(n, ⌈(n + f + 1)/2⌉))`. With `n < 2`
/// it is more than `n`, so the quorum is never reached.
pub fn store_quorum(n: usize) -> usize {
    let f = (n.saturating_sub(1) / 3).max(1);
    (n + f + 1).div_ceil(2).min(n).max(2)
}

/// Steps 1 to 3 of section 3 for `incoming`, sent under `key` by `request`,
/// at a replica holding `stored`.
pub fn decide_locally(
    request: Request,
    key: &[u8; ID_LEN],
    stored: Option<&[u8]>,
    incoming: &[u8],
) -> Local {
    // Step 1: the form, before anything else.
    let form = match record_form(key, incoming) {
        Ok(form) => form,
        Err(error) => return Local::Invalid(error),
    };
    // Version 0 follows no version: an UPDATE of it has nothing to replace.
    if request == Request::Update && form.seq == 0 {
        return Local::Invalid(FormError::Field("seq"));
    }
    let Some(stored) = stored else {
        return match request {
            Request::Store => Local::AskNetwork(form),
            Request::Update => Local::MissingPrevious(None),
        };
    };
    // R1: the bytes of a record verified when it was stored.
    if stored == incoming {
        return Local::AlreadyStored;
    }
    // Step 3, by what the replica holds. A stored record without the form of
    // a DID record (stored before this rule, or by a test) is kept, and
    // anything else is refused.
    let Ok(held) = record_form(key, stored) else {
        return Local::Conflict(LocalConflict::OtherKey);
    };
    if held.seq.checked_add(1) == Some(form.seq) {
        // R3: the successor of the stored version, decided locally.
        if form.prev != Some(digest_bytes(stored)) {
            return Local::Conflict(LocalConflict::WrongPrev);
        }
        if form.key_hash != held.next_key_hash {
            return Local::Conflict(LocalConflict::UncommittedKey);
        }
        return Local::VerifyAndReplace;
    }
    if held.seq > form.seq {
        return Local::Stale { stored: held.seq };
    }
    if held.seq == form.seq {
        // R4 at the place of the stored version.
        if document_of(stored).ok() == document_of(incoming).ok() {
            return Local::Conflict(LocalConflict::SignedTwice);
        }
        if held.key_hash == form.key_hash {
            return Local::VerifyDuplicity;
        }
        return Local::Conflict(LocalConflict::OtherKey);
    }
    // A version below N−1: the record stays, and nobody is asked.
    Local::MissingPrevious(Some(held.seq))
}

/// R2: a version 0 (`incoming` its `record_hash`) at a replica that holds
/// nothing. `asked` nodes were asked, `answers` are those that hold a record,
/// `everyone_answered` whether every node asked answered.
pub fn decide_version_zero(
    k: usize,
    asked: usize,
    incoming: &[u8; ID_LEN],
    answers: &[Answer],
    everyone_answered: bool,
) -> Verdict {
    if asked == 0 {
        return Verdict::NoAnswer;
    }
    // Refusals first. The DID has moved on only by the quorum's word: a
    // single holder of a later version must not stop the owner's replay.
    let newer: Vec<u64> = answers
        .iter()
        .map(|a| a.seq)
        .filter(|seq| *seq >= 1)
        .collect();
    if newer.len() >= store_quorum(replicas_asked(k, asked)) {
        let seq = newer.iter().copied().max().unwrap_or(1);
        return Verdict::Refuse(Refusal::NewerClaimed { seq });
    }
    if let Some(other) = answers.iter().find(|a| a.seq == 0 && a.hash != *incoming) {
        return Verdict::Refuse(Refusal::OtherVersion {
            seq: 0,
            hash: other.hash,
        });
    }
    if everyone_answered {
        Verdict::Accept
    } else {
        Verdict::NoAnswer
    }
}

/// R5: a version N ≥ 1 (`form` its form, `incoming` its `record_hash`) at a
/// replica that holds nothing. Called first with `Fetch::NotYet`, and again
/// with the outcome of the fetch when it answers `Verdict::Fetch`.
///
/// Every row that trusts the answers is here, so that a later condition on
/// them (answers from disjoint paths) has one place to go (open point 5).
pub fn decide_successor(
    k: usize,
    asked: usize,
    form: &RecordForm,
    incoming: &[u8; ID_LEN],
    answers: &[Answer],
    everyone_answered: bool,
    fetch: &Fetch,
) -> Verdict {
    let seq = form.seq;
    // Refusals first: one is enough, even with a node still silent.
    if let Some(newer) = answers.iter().map(|a| a.seq).filter(|s| *s > seq).max() {
        return Verdict::Refuse(Refusal::NewerClaimed { seq: newer });
    }
    if let Some(other) = answers.iter().find(|a| a.seq == seq && a.hash != *incoming) {
        return Verdict::Refuse(Refusal::OtherVersion {
            seq,
            hash: other.hash,
        });
    }
    if let Some(other) = answers
        .iter()
        .find(|a| a.seq + 1 == seq && Some(a.hash) != form.prev)
    {
        return Verdict::Refuse(Refusal::NotFollowing { hash: other.hash });
    }
    // Open point 26: a holder behind, or a record that skips versions.
    if let Some(behind) = answers.iter().find(|a| a.seq + 1 < seq) {
        return Verdict::Refuse(Refusal::HolderBehind { seq: behind.seq });
    }
    // Without a refusal, a row accepts only once every node asked answered.
    if asked == 0 || !everyone_answered {
        return Verdict::NoAnswer;
    }
    let voters: Vec<usize> = (0..answers.len())
        .filter(|index| answers[*index].seq + 1 == seq)
        .collect();
    let confirmed = match fetch {
        Fetch::NotYet if !voters.is_empty() => return Verdict::Fetch(voters),
        Fetch::NotYet | Fetch::NoneConfirmed => 0,
        Fetch::Confirmed { dropped } => {
            // Version 0 proves its own binding: one fetched version 0 that
            // commits to the record's key is enough (open point 19).
            if seq == 1 {
                return Verdict::Accept;
            }
            voters
                .iter()
                .filter(|index| !dropped.contains(index))
                .count()
        }
    };
    let holders = answers
        .iter()
        .filter(|a| a.seq == seq && a.hash == *incoming)
        .count();
    let votes = holders + if seq >= 2 { confirmed } else { 0 };
    if votes >= store_quorum(replicas_asked(k, asked)) {
        Verdict::Accept
    } else {
        Verdict::NoAnswer
    }
}

/// The version N−1 fetched for a record of form `form` sent under `key`.
pub fn check_fetched(key: &[u8; ID_LEN], form: &RecordForm, fetched: &[u8]) -> FetchCheck {
    if form.prev != Some(digest_bytes(fetched)) {
        return FetchCheck::NotPrev;
    }
    let Ok(previous) = record_form(key, fetched) else {
        return FetchCheck::DoesNotHold;
    };
    if previous.seq + 1 != form.seq || previous.next_key_hash != form.key_hash {
        return FetchCheck::DoesNotHold;
    }
    FetchCheck::Confirmed {
        verify_version_zero: previous.seq == 0,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_chain::{new_key, sha256, sign, Chain};
    use super::*;

    fn hash(record: &[u8]) -> [u8; ID_LEN] {
        sha256(record)
    }

    fn answer(seq: u64, record: &[u8]) -> Answer {
        Answer {
            seq,
            hash: hash(record),
        }
    }

    // ---- store_quorum ------------------------------------------------------

    #[test]
    fn store_quorum_follows_open_point_5() {
        for (n, quorum) in [
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 4),
            (7, 5),
            (9, 6),
            (19, 13),
        ] {
            assert_eq!(store_quorum(n), quorum, "n = {n}");
        }
        // One node can never reach the quorum.
        assert!(store_quorum(1) > 1);
        // k = 3, 5, 10, 20 asking every other replica.
        assert_eq!(store_quorum(replicas_asked(3, 2)), 2);
        assert_eq!(store_quorum(replicas_asked(5, 4)), 3);
        assert_eq!(store_quorum(replicas_asked(10, 9)), 6);
        assert_eq!(store_quorum(replicas_asked(20, 30)), 13);
        assert_eq!(replicas_asked(20, 4), 4);
    }

    // ---- Steps 1 to 3 --------------------------------------------------------

    /// Step 1 comes first: a record that fails it is `InvalidRecord`, whatever
    /// the replica holds, and an UPDATE of a version 0 too, even with the bytes
    /// the replica holds.
    #[test]
    fn a_record_that_fails_the_form_is_invalid_first() {
        let chain = Chain::with_versions(1);
        let other = Chain::new();
        for request in [Request::Store, Request::Update] {
            for stored in [None, Some(chain.version(0)), Some(chain.version(1))] {
                assert!(
                    matches!(
                        decide_locally(request, &chain.key, stored, other.version(0)),
                        Local::Invalid(_)
                    ),
                    "{request:?} of another DID's record, stored {:?}",
                    stored.map(|s| record_form(&chain.key, s).map(|f| f.seq))
                );
            }
        }
        for stored in [None, Some(chain.version(0))] {
            assert!(matches!(
                decide_locally(Request::Update, &chain.key, stored, chain.version(0)),
                Local::Invalid(_)
            ));
        }
    }

    /// R1: the same bytes are `AlreadyStored`, by STORE or UPDATE.
    #[test]
    fn the_same_bytes_are_already_stored() {
        let chain = Chain::with_versions(2);
        for seq in 0..=2 {
            assert_eq!(
                decide_locally(
                    Request::Store,
                    &chain.key,
                    Some(chain.version(seq)),
                    chain.version(seq)
                ),
                Local::AlreadyStored
            );
        }
        assert_eq!(
            decide_locally(
                Request::Update,
                &chain.key,
                Some(chain.version(2)),
                chain.version(2)
            ),
            Local::AlreadyStored
        );
    }

    #[test]
    fn a_store_at_a_replica_that_holds_nothing_asks_the_network() {
        let chain = Chain::with_versions(2);
        for seq in 0..=2 {
            let Local::AskNetwork(form) =
                decide_locally(Request::Store, &chain.key, None, chain.version(seq))
            else {
                panic!("version {seq} should ask the network");
            };
            assert_eq!(form, record_form(&chain.key, chain.version(seq)).unwrap());
        }
    }

    /// The replica holding version N−1 checks version N alone (R3), by STORE
    /// or UPDATE.
    #[test]
    fn a_successor_of_the_stored_version_is_verified_and_replaces_it() {
        let chain = Chain::with_versions(3);
        for request in [Request::Store, Request::Update] {
            for seq in 1..=3 {
                assert_eq!(
                    decide_locally(
                        request,
                        &chain.key,
                        Some(chain.version(seq - 1)),
                        chain.version(seq)
                    ),
                    Local::VerifyAndReplace,
                    "{request:?} of version {seq}"
                );
            }
        }
    }

    /// A version N whose `prev` is not the stored version N−1, or whose key is
    /// not the committed one (an attacker's, or the stored key kept), is a
    /// fork, decided without asking anyone.
    #[test]
    fn a_fork_of_the_stored_version_is_a_conflict() {
        let chain = Chain::with_versions(1);
        let v1 = chain.version(1);
        let attacker = new_key();
        let wrong_prev = sign(
            &chain.doc(
                2,
                Some(b"another record"),
                chain.keys[2].public_key(),
                new_key().public_key(),
            ),
            &chain.keys[2],
        );
        let wrong_key = sign(
            &chain.doc(2, Some(v1), attacker.public_key(), new_key().public_key()),
            &attacker,
        );
        let kept_key = sign(
            &chain.doc(
                2,
                Some(v1),
                chain.keys[1].public_key(),
                new_key().public_key(),
            ),
            &chain.keys[1],
        );
        for request in [Request::Store, Request::Update] {
            assert_eq!(
                decide_locally(request, &chain.key, Some(v1), &wrong_prev),
                Local::Conflict(LocalConflict::WrongPrev)
            );
            for forged in [&wrong_key, &kept_key] {
                assert_eq!(
                    decide_locally(request, &chain.key, Some(v1), forged),
                    Local::Conflict(LocalConflict::UncommittedKey)
                );
            }
        }
    }

    /// The key security case: right after version 0, a version 1 whose `prev`
    /// is the real hash of version 0, signed with a key version 0 does not
    /// commit to, even by the holder of version 0's own key.
    #[test]
    fn a_forged_version_1_after_version_0_is_refused_by_a_holder() {
        let chain = Chain::new();
        for signer in [new_key(), chain.keys[0].clone()] {
            let forged = sign(
                &chain.doc(
                    1,
                    Some(chain.version(0)),
                    signer.public_key(),
                    new_key().public_key(),
                ),
                &signer,
            );
            assert_eq!(
                decide_locally(Request::Store, &chain.key, Some(chain.version(0)), &forged),
                Local::Conflict(LocalConflict::UncommittedKey)
            );
        }
    }

    /// R4: a replica holding a later version answers `Stale` without
    /// verifying anything, a late version 0 included.
    #[test]
    fn an_older_version_is_stale() {
        let chain = Chain::with_versions(3);
        for seq in 0..3 {
            for request in [Request::Store, Request::Update] {
                if request == Request::Update && seq == 0 {
                    continue; // step 1 refuses it first
                }
                assert_eq!(
                    decide_locally(
                        request,
                        &chain.key,
                        Some(chain.version(3)),
                        chain.version(seq)
                    ),
                    Local::Stale { stored: 3 },
                    "{request:?} of version {seq}"
                );
            }
        }
    }

    /// R4 at the same place: signed twice, proven duplicity once its signature
    /// verifies, or a plain conflict with another key.
    #[test]
    fn another_record_at_the_same_place_is_a_conflict_by_kind() {
        let chain = Chain::with_versions(2);
        let doc = chain.doc(
            2,
            Some(chain.version(1)),
            chain.keys[2].public_key(),
            chain.keys[3].public_key(),
        );
        let signed_again = sign(&doc, &chain.keys[2]);
        assert_ne!(
            signed_again,
            chain.version(2),
            "ML-DSA signing is randomized"
        );
        let mut other_doc = doc.clone();
        other_doc["service"][0]["serviceEndpoint"] = json!("http://attacker.example");
        let duplicity = sign(&other_doc, &chain.keys[2]);
        let attacker = new_key();
        let other_key = sign(
            &chain.doc(
                2,
                Some(chain.version(1)),
                attacker.public_key(),
                new_key().public_key(),
            ),
            &attacker,
        );
        for request in [Request::Store, Request::Update] {
            assert_eq!(
                decide_locally(request, &chain.key, Some(chain.version(2)), &signed_again),
                Local::Conflict(LocalConflict::SignedTwice)
            );
            assert_eq!(
                decide_locally(request, &chain.key, Some(chain.version(2)), &duplicity),
                Local::VerifyDuplicity
            );
            assert_eq!(
                decide_locally(request, &chain.key, Some(chain.version(2)), &other_key),
                Local::Conflict(LocalConflict::OtherKey)
            );
        }
        // Version 0 signed again: the same document, so the same DID.
        let chain = Chain::new();
        let again = sign(
            &chain.doc(
                0,
                None,
                chain.keys[0].public_key(),
                chain.keys[1].public_key(),
            ),
            &chain.keys[0],
        );
        assert_eq!(
            decide_locally(Request::Store, &chain.key, Some(chain.version(0)), &again),
            Local::Conflict(LocalConflict::SignedTwice)
        );
    }

    /// A replica two or more versions behind is not touched: it answers
    /// `MissingPrevious` with its `seq`, by STORE or UPDATE; an UPDATE at a
    /// replica that holds nothing answers `MissingPrevious` without one.
    #[test]
    fn a_replica_behind_or_empty_misses_the_previous_version() {
        let chain = Chain::with_versions(5);
        for request in [Request::Store, Request::Update] {
            for stored in 0..4 {
                assert_eq!(
                    decide_locally(
                        request,
                        &chain.key,
                        Some(chain.version(stored)),
                        chain.version(5)
                    ),
                    Local::MissingPrevious(Some(stored as u64)),
                    "{request:?}, stored {stored}"
                );
            }
        }
        assert_eq!(
            decide_locally(Request::Update, &chain.key, None, chain.version(5)),
            Local::MissingPrevious(None)
        );
        // A forged version 7 at a replica holding the genuine version 5.
        let attacker = new_key();
        let forged = sign(
            &chain.doc(
                7,
                Some(b"made up"),
                attacker.public_key(),
                new_key().public_key(),
            ),
            &attacker,
        );
        assert_eq!(
            decide_locally(Request::Store, &chain.key, Some(chain.version(5)), &forged),
            Local::MissingPrevious(Some(5))
        );
    }

    /// The owner keeps the next key as a seed and rebuilds the key pair only
    /// to sign the next version: the rebuilt key is the one version 0 commits
    /// to, and the next version follows it.
    #[test]
    fn the_key_rebuilt_from_the_committed_seed_signs_the_next_version() {
        use super::super::test_chain::{derive, document, key_of, PLACEHOLDER};
        use super::super::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
        use crate::crypto::mldsa::MlDsa65KeyPair;

        let seed = [42u8; MlDsa65KeyPair::SEED_LEN];
        let current = new_key();
        let committed = MlDsa65KeyPair::from_seed(&seed)
            .unwrap()
            .public_key()
            .to_vec();
        let (did, doc) = derive(&document(
            PLACEHOLDER,
            current.public_key(),
            0,
            None,
            &committed,
        ));
        let v0 = sign(&doc, &current);
        let key = key_of(&did);

        // Later, at the rotation: the key pair is rebuilt from the seed.
        let rebuilt = MlDsa65KeyPair::from_seed(&seed).unwrap();
        let mut v1_doc = document(
            &did,
            rebuilt.public_key(),
            1,
            Some(&v0),
            new_key().public_key(),
        );
        v1_doc["id"] = json!(did);
        let v1 = sign(&v1_doc, &rebuilt);
        assert_eq!(
            decide_locally(Request::Update, &key, Some(&v0), &v1),
            Local::VerifyAndReplace
        );
        assert!(DIDSignatureVerifierHandler::new("unused")
            .handle_signature_verification(&v1)
            .unwrap());
    }

    // ---- R2 ------------------------------------------------------------------

    #[test]
    fn r2_refuses_a_version_0_when_the_quorum_claims_a_later_one() {
        let chain = Chain::with_versions(2);
        let v0 = hash(chain.version(0));
        // k = 20: 19 asked, quorum 13.
        let newer: Vec<Answer> = (0..13)
            .map(|i| answer(1 + (i % 2), chain.version(1 + (i as usize % 2))))
            .collect();
        assert_eq!(
            decide_version_zero(20, 19, &v0, &newer, true),
            Verdict::Refuse(Refusal::NewerClaimed { seq: 2 })
        );
        assert_eq!(
            decide_version_zero(20, 19, &v0, &newer[..12], true),
            Verdict::Accept
        );
        // k = 3: the other two replicas.
        let two = [answer(1, chain.version(1)), answer(2, chain.version(2))];
        assert!(matches!(
            decide_version_zero(3, 2, &v0, &two, true),
            Verdict::Refuse(Refusal::NewerClaimed { .. })
        ));
        assert_eq!(
            decide_version_zero(3, 2, &v0, &two[..1], true),
            Verdict::Accept
        );
    }

    #[test]
    fn r2_refuses_a_version_0_when_a_node_holds_another_one() {
        let chain = Chain::new();
        let again = sign(
            &chain.doc(
                0,
                None,
                chain.keys[0].public_key(),
                chain.keys[1].public_key(),
            ),
            &chain.keys[0],
        );
        let mine = hash(&again);
        let answers = [answer(0, chain.version(0))];
        assert_eq!(
            decide_version_zero(20, 5, &mine, &answers, true),
            Verdict::Refuse(Refusal::OtherVersion {
                seq: 0,
                hash: hash(chain.version(0))
            })
        );
        // The same version 0 is no refusal.
        assert_eq!(
            decide_version_zero(20, 5, &hash(chain.version(0)), &answers, true),
            Verdict::Accept
        );
    }

    #[test]
    fn r2_gives_no_answer_on_silence_or_with_nobody_to_ask() {
        let chain = Chain::new();
        let v0 = hash(chain.version(0));
        assert_eq!(
            decide_version_zero(20, 5, &v0, &[], false),
            Verdict::NoAnswer
        );
        assert_eq!(
            decide_version_zero(20, 0, &v0, &[], true),
            Verdict::NoAnswer
        );
        assert_eq!(decide_version_zero(20, 5, &v0, &[], true), Verdict::Accept);
        // A refusal still wins over a silent node.
        let other = [Answer {
            seq: 0,
            hash: [9; ID_LEN],
        }];
        assert!(matches!(
            decide_version_zero(20, 5, &v0, &other, false),
            Verdict::Refuse(_)
        ));
    }

    // ---- R5 ------------------------------------------------------------------

    fn successor(chain: &Chain, seq: usize) -> (RecordForm, [u8; ID_LEN]) {
        (
            record_form(&chain.key, chain.version(seq)).unwrap(),
            hash(chain.version(seq)),
        )
    }

    #[test]
    fn r5_refuses_on_any_refusing_answer_even_with_a_silent_node() {
        let chain = Chain::with_versions(4);
        let (form, mine) = successor(&chain, 3);
        let attacker = new_key();
        let fork = sign(
            &chain.doc(
                3,
                Some(chain.version(2)),
                attacker.public_key(),
                new_key().public_key(),
            ),
            &attacker,
        );
        let other_two = sign(
            &chain.doc(2, Some(b"x"), attacker.public_key(), new_key().public_key()),
            &attacker,
        );
        for (refusing, refusal) in [
            (
                answer(4, chain.version(4)),
                Refusal::NewerClaimed { seq: 4 },
            ),
            (
                answer(3, &fork),
                Refusal::OtherVersion {
                    seq: 3,
                    hash: hash(&fork),
                },
            ),
            (
                answer(2, &other_two),
                Refusal::NotFollowing {
                    hash: hash(&other_two),
                },
            ),
            (
                answer(1, chain.version(1)),
                Refusal::HolderBehind { seq: 1 },
            ),
            (
                answer(0, chain.version(0)),
                Refusal::HolderBehind { seq: 0 },
            ),
        ] {
            // Before and after accepting answers, with or without silence.
            let accepting = [answer(3, chain.version(3)), answer(3, chain.version(3))];
            for answers in [
                vec![refusing, accepting[0], accepting[1]],
                vec![accepting[0], accepting[1], refusing],
            ] {
                for everyone_answered in [true, false] {
                    assert_eq!(
                        decide_successor(
                            3,
                            3,
                            &form,
                            &mine,
                            &answers,
                            everyone_answered,
                            &Fetch::NotYet
                        ),
                        Verdict::Refuse(refusal),
                        "{refusal:?}, everyone answered: {everyone_answered}"
                    );
                }
            }
        }
    }

    /// With N = 1 one answer `(0, prev)` is enough, once version 0 is fetched
    /// and checked; with N ≥ 2 such answers are votes.
    #[test]
    fn r5_fetches_version_n_minus_1_from_its_voters_closest_first() {
        let chain = Chain::with_versions(2);
        let (form, mine) = successor(&chain, 1);
        let answers = [answer(0, chain.version(0))];
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &answers, true, &Fetch::NotYet),
            Verdict::Fetch(vec![0])
        );
        let confirmed = Fetch::Confirmed { dropped: vec![] };
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &answers, true, &confirmed),
            Verdict::Accept
        );
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &answers, true, &Fetch::NoneConfirmed),
            Verdict::NoAnswer
        );

        let (form, mine) = successor(&chain, 2);
        let answers = [
            answer(2, chain.version(2)),
            answer(1, chain.version(1)),
            answer(1, chain.version(1)),
        ];
        assert_eq!(
            decide_successor(3, 2, &form, &mine, &answers[1..], true, &Fetch::NotYet),
            Verdict::Fetch(vec![0, 1])
        );
        assert_eq!(
            decide_successor(20, 3, &form, &mine, &answers, true, &Fetch::NotYet),
            Verdict::Fetch(vec![1, 2])
        );
        // n = 3, quorum 3: one vote (N, h) and two confirmed (N−1, prev).
        assert_eq!(
            decide_successor(
                20,
                3,
                &form,
                &mine,
                &answers,
                true,
                &Fetch::Confirmed { dropped: vec![] }
            ),
            Verdict::Accept
        );
        // A dropped voter is no vote: one short of the quorum.
        assert_eq!(
            decide_successor(
                20,
                3,
                &form,
                &mine,
                &answers,
                true,
                &Fetch::Confirmed { dropped: vec![1] }
            ),
            Verdict::NoAnswer
        );
        assert_eq!(
            decide_successor(20, 3, &form, &mine, &answers, true, &Fetch::NoneConfirmed),
            Verdict::NoAnswer
        );
    }

    #[test]
    fn r5_accepts_on_the_quorum_and_not_one_short() {
        let chain = Chain::with_versions(3);
        let (form, mine) = successor(&chain, 3);
        let votes: Vec<Answer> = (0..13).map(|_| answer(3, chain.version(3))).collect();
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &votes, true, &Fetch::NotYet),
            Verdict::Accept
        );
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &votes[..12], true, &Fetch::NotYet),
            Verdict::NoAnswer
        );
        // Every node asked must have answered.
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &votes, false, &Fetch::NotYet),
            Verdict::NoAnswer
        );
        // Nobody to ask, or one node: the quorum row never accepts.
        assert_eq!(
            decide_successor(20, 0, &form, &mine, &[], true, &Fetch::NotYet),
            Verdict::NoAnswer
        );
        assert_eq!(
            decide_successor(20, 1, &form, &mine, &votes[..1], true, &Fetch::NotYet),
            Verdict::NoAnswer
        );
        // No node holds anything: no votes, no answer (not an accept).
        assert_eq!(
            decide_successor(20, 19, &form, &mine, &[], true, &Fetch::NotYet),
            Verdict::NoAnswer
        );
    }

    /// Open point 26: one honest holder of the current version among 19
    /// stops a forged version with a far `seq` that the other 18 vote for.
    #[test]
    fn r5_one_honest_holder_stops_a_far_forgery() {
        let chain = Chain::with_versions(3);
        let attacker = new_key();
        let forged = sign(
            &chain.doc(
                9,
                Some(b"made up"),
                attacker.public_key(),
                new_key().public_key(),
            ),
            &attacker,
        );
        let form = record_form(&chain.key, &forged).unwrap();
        let mut answers: Vec<Answer> = (0..18).map(|_| answer(9, &forged)).collect();
        answers.push(answer(3, chain.version(3)));
        assert_eq!(
            decide_successor(
                20,
                19,
                &form,
                &hash(&forged),
                &answers,
                true,
                &Fetch::NotYet
            ),
            Verdict::Refuse(Refusal::HolderBehind { seq: 3 })
        );
    }

    // ---- The fetch -------------------------------------------------------------

    #[test]
    fn a_fetched_record_must_hash_to_prev_bind_and_commit() {
        let chain = Chain::with_versions(2);
        let v1 = record_form(&chain.key, chain.version(1)).unwrap();
        assert_eq!(
            check_fetched(&chain.key, &v1, chain.version(0)),
            FetchCheck::Confirmed {
                verify_version_zero: true
            }
        );
        let v2 = record_form(&chain.key, chain.version(2)).unwrap();
        assert_eq!(
            check_fetched(&chain.key, &v2, chain.version(1)),
            FetchCheck::Confirmed {
                verify_version_zero: false
            }
        );
        // A record that is not version N−1: it does not hash to prev.
        assert_eq!(
            check_fetched(&chain.key, &v2, chain.version(0)),
            FetchCheck::NotPrev
        );
        assert_eq!(
            check_fetched(&chain.key, &v2, b"not a record"),
            FetchCheck::NotPrev
        );
    }

    /// One node serves a made-up version 0′ committing to its own key, after
    /// which its version 1′ follows: version 0′ does not bind to the key.
    #[test]
    fn a_made_up_version_0_does_not_hold() {
        let chain = Chain::new();
        let (attacker, next) = (new_key(), new_key());
        let mut doc = chain.doc(0, None, attacker.public_key(), next.public_key());
        doc["service"][0]["serviceEndpoint"] = json!("http://attacker.example");
        let made_up = sign(&doc, &attacker);
        let forged = sign(
            &chain.doc(1, Some(&made_up), next.public_key(), new_key().public_key()),
            &next,
        );
        let form = record_form(&chain.key, &forged).unwrap();
        assert_eq!(
            check_fetched(&chain.key, &form, &made_up),
            FetchCheck::DoesNotHold
        );
    }

    /// With N ≥ 2 a made-up version N−1 that binds by its suffix and commits
    /// to the attacker's key passes the fetch: it is one vote, and the quorum
    /// decides.
    #[test]
    fn a_made_up_version_n_minus_1_is_one_vote() {
        let chain = Chain::with_versions(1);
        let (attacker, next) = (new_key(), new_key());
        let made_up = sign(
            &chain.doc(
                1,
                Some(chain.version(0)),
                attacker.public_key(),
                next.public_key(),
            ),
            &attacker,
        );
        let forged = sign(
            &chain.doc(2, Some(&made_up), next.public_key(), new_key().public_key()),
            &next,
        );
        let form = record_form(&chain.key, &forged).unwrap();
        assert_eq!(
            check_fetched(&chain.key, &form, &made_up),
            FetchCheck::Confirmed {
                verify_version_zero: false
            }
        );
        let answers = [answer(1, &made_up)];
        let confirmed = Fetch::Confirmed { dropped: vec![] };
        assert_eq!(
            decide_successor(20, 4, &form, &hash(&forged), &answers, true, &confirmed),
            Verdict::NoAnswer
        );
        // A version N whose key the fetched version N−1 does not commit to.
        let uncommitted = sign(
            &chain.doc(
                2,
                Some(&made_up),
                new_key().public_key(),
                new_key().public_key(),
            ),
            &next,
        );
        let form = record_form(&chain.key, &uncommitted).unwrap();
        assert_eq!(
            check_fetched(&chain.key, &form, &made_up),
            FetchCheck::DoesNotHold
        );
    }
}
