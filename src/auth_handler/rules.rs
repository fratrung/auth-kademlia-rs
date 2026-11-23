//! Whether a replica takes a DID record, as pure functions.
//!
//! They read the stored record, the incoming one and the answers of other
//! nodes, and decide. They verify no signature and ask nobody: where a
//! decision rests on a signature it says so, and the node verifies it.
//!
//! Every record proves its own key from the DID, so authenticity never rests
//! on what other nodes say. Their answers matter only as evidence that a
//! record has been superseded, and only once the record that proves it is
//! shown and verified.

use std::cmp::Ordering;

use crate::utils::digest_bytes;

use super::did::{document_of, FormError};
use super::tree::{tree_form, Hash, TreeForm};

/// Two valid records of one DID at the same position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    /// The same document signed again: same content, another signature.
    RepeatedSigning,
    /// Different documents signed by the key of that position.
    Duplicity,
}

/// What a replica does with a record, by what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Local {
    /// The record fails its form: `InvalidRecord`.
    Invalid(FormError),
    /// The same bytes as stored.
    AlreadyStored,
    /// Nothing stored: check the network before storing.
    AskNetwork(TreeForm),
    /// A higher position than the stored one: verify the signature, then
    /// replace the stored record.
    VerifyAndReplace,
    /// The replica holds a higher position.
    Stale { stored: u64 },
    /// Another record at the stored position: verify its signature. Valid,
    /// it is a conflict of this kind and the stored record stays; invalid,
    /// the record is `InvalidRecord`.
    VerifyConflict(Conflict),
}

/// A node's answer to `FindHash`: the position and hash of its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub seq: u64,
    pub hash: Hash,
}

/// What a replica's record proves against a record being published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    Nothing,
    /// A higher position: the published record is superseded.
    Superseded,
    /// Another record at the same position.
    Conflict(Conflict),
}

/// What a replica holding `stored` does with `incoming`, sent under `key`.
pub fn decide_locally(key: &Hash, stored: Option<&[u8]>, incoming: &[u8]) -> Local {
    let form = match tree_form(key, incoming) {
        Ok(form) => form,
        Err(error) => return Local::Invalid(error),
    };
    let Some(stored) = stored else {
        return Local::AskNetwork(form);
    };
    if stored == incoming {
        return Local::AlreadyStored;
    }
    // Only verified records are stored, so one without this form predates
    // it: any valid record replaces it.
    let Ok(held) = tree_form(key, stored) else {
        return Local::VerifyAndReplace;
    };
    match form.seq.cmp(&held.seq) {
        Ordering::Greater => Local::VerifyAndReplace,
        Ordering::Less => Local::Stale { stored: held.seq },
        Ordering::Equal if document_of(stored).ok() == document_of(incoming).ok() => {
            Local::VerifyConflict(Conflict::RepeatedSigning)
        }
        Ordering::Equal => Local::VerifyConflict(Conflict::Duplicity),
    }
}

/// The answers an empty replica follows up before storing a record at
/// `seq`: one per distinct claimed record above `seq`, from the closest node
/// that claimed it (answers come closest first), at most `limit`. A claim at
/// or below `seq` cannot supersede the record, so it is not fetched; nor does
/// a claim alone refuse anything.
pub fn claims_to_fetch(seq: u64, answers: &[Answer], limit: usize) -> Vec<usize> {
    let mut picked: Vec<usize> = Vec::new();
    for (index, answer) in answers.iter().enumerate() {
        if picked.len() == limit {
            break;
        }
        let repeated = picked.iter().any(|&seen| answers[seen] == *answer);
        if answer.seq > seq && !repeated {
            picked.push(index);
        }
    }
    picked
}

/// The form of `fetched`, the record a node gave for its claim `claimed`,
/// when it proves that a record at `seq` is superseded: it hashes to the
/// claim, binds to `key` and holds a higher position. The caller then
/// verifies its signature.
pub fn shows_higher(key: &Hash, seq: u64, claimed: &Hash, fetched: &[u8]) -> Option<TreeForm> {
    if digest_bytes(fetched) != *claimed {
        return None;
    }
    tree_form(key, fetched).ok().filter(|form| form.seq > seq)
}

/// What `held`, a replica's record of the DID `key`, proves against
/// `published`: what that replica decides for `published` by what it holds.
/// For `Superseded` and `Conflict` the caller verifies the signature of
/// `held`.
pub fn shown_against(key: &Hash, published: &[u8], held: &[u8]) -> Proof {
    match decide_locally(key, Some(held), published) {
        Local::Stale { .. } => Proof::Superseded,
        Local::VerifyConflict(kind) => Proof::Conflict(kind),
        Local::Invalid(_)
        | Local::AlreadyStored
        | Local::AskNetwork(_)
        | Local::VerifyAndReplace => Proof::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_tree::{body, sha256, sign, TreeOwner, PLACEHOLDER};
    use super::super::tree::PROOF;
    use super::*;

    fn answer(seq: u64, record: &[u8]) -> Answer {
        Answer {
            seq,
            hash: sha256(record),
        }
    }

    #[test]
    fn a_record_that_fails_its_form_is_invalid_before_anything_else() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let mut doc = owner.doc(6, Some(&v5));
        doc[PROOF]["code"] = json!("not a code");
        let bad = sign(&doc, &owner.keys[6]);
        for stored in [None, Some(v5.as_slice())] {
            assert!(matches!(
                decide_locally(&owner.key, stored, &bad),
                Local::Invalid(FormError::Field("code"))
            ));
        }
    }

    #[test]
    fn the_same_bytes_are_already_stored() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        assert_eq!(
            decide_locally(&owner.key, Some(&v5), &v5),
            Local::AlreadyStored
        );
    }

    #[test]
    fn a_replica_that_holds_nothing_asks_the_network() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        assert!(matches!(
            decide_locally(&owner.key, None, &v5),
            Local::AskNetwork(TreeForm { seq: 5, .. })
        ));
    }

    /// Any higher position replaces the stored one, without the positions in
    /// between and whatever record its `prev` names.
    #[test]
    fn a_higher_position_replaces_the_stored_one() {
        let owner = TreeOwner::new(1);
        let v3 = owner.record(3, Some(b"2"));
        for prev in [&v3[..], b"another record"] {
            let v5 = owner.record(5, Some(prev));
            assert_eq!(
                decide_locally(&owner.key, Some(&v3), &v5),
                Local::VerifyAndReplace
            );
        }
    }

    #[test]
    fn a_lower_position_is_stale() {
        let owner = TreeOwner::new(1);
        let v3 = owner.record(3, Some(b"2"));
        let v5 = owner.record(5, Some(&v3));
        assert_eq!(
            decide_locally(&owner.key, Some(&v5), &v3),
            Local::Stale { stored: 5 }
        );
    }

    /// The key of 5 signing at 6 is outside the tree, even at a holder of 5.
    #[test]
    fn another_positions_key_is_invalid_at_a_holder() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let forged = owner.record_from(
            &body(PLACEHOLDER, owner.keys[5].public_key(), 6, Some(&v5)),
            6,
        );
        assert!(matches!(
            decide_locally(&owner.key, Some(&v5), &forged),
            Local::Invalid(FormError::NotInTree)
        ));
    }

    #[test]
    fn another_record_at_the_stored_position_is_a_conflict_by_kind() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let signed_again = owner.record(5, Some(b"4"));
        assert_ne!(signed_again, v5, "ML-DSA signs with fresh randomness");
        assert_eq!(
            decide_locally(&owner.key, Some(&v5), &signed_again),
            Local::VerifyConflict(Conflict::RepeatedSigning)
        );
        let mut other = owner.doc(5, Some(b"4"));
        other["service"][0]["serviceEndpoint"] = json!("http://example.com/other");
        let other = sign(&other, &owner.keys[5]);
        assert_eq!(
            decide_locally(&owner.key, Some(&v5), &other),
            Local::VerifyConflict(Conflict::Duplicity)
        );
    }

    #[test]
    fn only_distinct_higher_claims_are_fetched_closest_first_up_to_the_limit() {
        let owner = TreeOwner::new(1);
        let (v3, v6, v7) = (
            owner.record(3, Some(b"2")),
            owner.record(6, Some(b"5")),
            owner.record(7, Some(b"6")),
        );
        let answers = [
            answer(3, &v3),
            answer(6, &v6),
            answer(5, b"another record at 5"),
            answer(6, &v6),
            answer(7, &v7),
            answer(9, b"a claim nobody can show"),
        ];
        assert_eq!(claims_to_fetch(5, &answers, 19), vec![1, 4, 5]);
        assert_eq!(claims_to_fetch(5, &answers, 2), vec![1, 4]);
        assert_eq!(claims_to_fetch(9, &answers, 19), Vec::<usize>::new());
    }

    /// One node answering under made-up ids costs at most `limit` fetches,
    /// however many distinct records it claims.
    #[test]
    fn made_up_claims_cost_at_most_the_limit() {
        let answers: Vec<Answer> = (0..100u8)
            .map(|i| Answer {
                seq: 62,
                hash: [i; 32],
            })
            .collect();
        assert_eq!(claims_to_fetch(5, &answers, 19).len(), 19);
    }

    #[test]
    fn a_fetched_record_shows_a_higher_position_only_if_it_holds_its_claim() {
        let (owner, other) = (TreeOwner::new(1), TreeOwner::new(2));
        let v6 = owner.record(6, Some(b"5"));
        assert_eq!(
            shows_higher(&owner.key, 5, &sha256(&v6), &v6).map(|form| form.seq),
            Some(6)
        );
        // Another claim, a position not above 5, another DID.
        assert!(shows_higher(&owner.key, 5, &sha256(b"other"), &v6).is_none());
        assert!(shows_higher(&owner.key, 6, &sha256(&v6), &v6).is_none());
        let theirs = other.record(6, Some(b"5"));
        assert!(shows_higher(&owner.key, 5, &sha256(&theirs), &theirs).is_none());
    }

    #[test]
    fn a_replicas_record_proves_what_that_replica_decides() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let v3 = owner.record(3, Some(b"2"));
        assert_eq!(shown_against(&owner.key, &v5, &v6), Proof::Superseded);
        assert_eq!(
            shown_against(&owner.key, &v5, &owner.record(5, Some(b"4"))),
            Proof::Conflict(Conflict::RepeatedSigning)
        );
        for held in [
            &v3[..],
            &v5[..],
            &TreeOwner::new(2).record(6, Some(b"5"))[..],
        ] {
            assert_eq!(shown_against(&owner.key, &v5, held), Proof::Nothing);
        }
    }
}
