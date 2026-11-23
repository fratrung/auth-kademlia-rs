//! The owner's side of a DID's rotation-key tree, held in memory: the key
//! pair and activation code of each position, and the signed record of a
//! position. A device keeps these secrets behind its custody
//! backend; tests, examples and the testbed use this type directly.

use aws_lc_rs::rand;
use serde_json::Value;
use thiserror::Error;

use crate::crypto::mldsa::MlDsa65KeyPair;
use crate::crypto::signature_verifier::VerifierError;

use super::did::{canonical_bytes, FormError};
use super::tree::{
    document_at, draft_body_hash, leaf_hash, tree_form, Genesis, Hash, Tree, CODE_LEN, POSITIONS,
};
use super::RECORD_ALGORITHM;

/// Bytes of an ML-DSA-65 seed.
pub const SEED_LEN: usize = 32;

/// Bytes of the algorithm field that starts every record.
const ALGORITHM_FIELD: usize = 12;

#[derive(Debug, Error)]
pub enum OwnerError {
    #[error("the system random generator failed")]
    Random,
    #[error("a tree needs {POSITIONS} seeds and {POSITIONS} codes")]
    Secrets,
    #[error("no position {0} in the tree")]
    Position(u64),
    #[error(transparent)]
    Key(#[from] VerifierError),
    #[error(transparent)]
    Form(#[from] FormError),
}

/// `| algorithm, null-padded to 12 bytes | signature | document |`
pub fn signed_record(signature: &[u8], document: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(ALGORITHM_FIELD + signature.len() + document.len());
    record.extend_from_slice(RECORD_ALGORITHM.as_bytes());
    record.resize(ALGORITHM_FIELD, 0);
    record.extend_from_slice(signature);
    record.extend_from_slice(document);
    record
}

/// One DID's tree with its secrets.
pub struct OwnerTree {
    keys: Vec<MlDsa65KeyPair>,
    codes: Vec<[u8; CODE_LEN]>,
    tree: Tree,
}

impl OwnerTree {
    /// A tree of fresh seeds and codes from AWS-LC's random generator.
    pub fn generate() -> Result<Self, OwnerError> {
        let mut seeds = vec![[0u8; SEED_LEN]; POSITIONS];
        let mut codes = vec![[0u8; CODE_LEN]; POSITIONS];
        for secret in seeds.iter_mut().chain(codes.iter_mut()) {
            rand::fill(secret).map_err(|_| OwnerError::Random)?;
        }
        Self::from_secrets(&seeds, &codes)
    }

    /// The tree of one seed and one code per position.
    pub fn from_secrets(
        seeds: &[[u8; SEED_LEN]],
        codes: &[[u8; CODE_LEN]],
    ) -> Result<Self, OwnerError> {
        if seeds.len() != POSITIONS || codes.len() != POSITIONS {
            return Err(OwnerError::Secrets);
        }
        let keys = seeds
            .iter()
            .map(|seed| MlDsa65KeyPair::from_seed(seed))
            .collect::<Result<Vec<_>, _>>()?;
        let leaves: Vec<Hash> = (0u32..)
            .zip(keys.iter().zip(codes))
            .map(|(index, (key, code))| leaf_hash(index, key.public_key(), code))
            .collect();
        let tree = Tree::new(&leaves).ok_or(OwnerError::Secrets)?;
        Ok(Self {
            keys,
            codes: codes.to_vec(),
            tree,
        })
    }

    /// The raw public key of `position`.
    pub fn public_key(&self, position: u64) -> Option<&[u8]> {
        let index = usize::try_from(position).ok()?;
        self.keys.get(index).map(MlDsa65KeyPair::public_key)
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    /// The genesis of the DID whose document 0 is built from `initial`: a
    /// draft body with the key of position 0, no `id`, and the placeholder in
    /// place of the DID.
    pub fn genesis(&self, initial: &Value) -> Result<Genesis, OwnerError> {
        Ok(Genesis {
            initial_body_hash: draft_body_hash(initial)?,
            root: self.tree.root(),
        })
    }

    /// The record of `position` from its draft body: completed with the DID
    /// and the proof, signed by the position's key, and checked as a replica
    /// checks it before it leaves.
    pub fn record(
        &self,
        genesis: &Genesis,
        draft: &Value,
        position: u64,
    ) -> Result<Vec<u8>, OwnerError> {
        let index = usize::try_from(position).map_err(|_| OwnerError::Position(position))?;
        let (Some(key), Some(code), Some(path)) = (
            self.keys.get(index),
            self.codes.get(index),
            u32::try_from(index).ok().and_then(|at| self.tree.path(at)),
        ) else {
            return Err(OwnerError::Position(position));
        };
        let document = canonical_bytes(&document_at(draft, genesis, code, &path)?)?;
        let record = signed_record(&key.sign(&document)?, &document);
        tree_form(&genesis.key(), &record)?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::super::test_tree::{body, sha256, TreeOwner, PLACEHOLDER};
    use super::super::tree::{TreeForm, PROOF};
    use super::super::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
    use super::*;

    fn verifies(record: &[u8]) -> bool {
        let handler: Arc<dyn SignatureVerifierHandler> =
            Arc::new(DIDSignatureVerifierHandler::new("unused"));
        handler
            .handle_signature_verification(record)
            .unwrap_or(false)
    }

    fn document(record: &[u8]) -> Value {
        let start = ALGORITHM_FIELD + crate::crypto::mldsa::signature_len();
        serde_json::from_slice(&record[start..]).unwrap()
    }

    #[test]
    fn records_of_a_generated_tree_have_the_form_and_verify() {
        let owner = OwnerTree::generate().unwrap();
        let initial = body(PLACEHOLDER, owner.public_key(0).unwrap(), 0, None);
        let genesis = owner.genesis(&initial).unwrap();
        let v0 = owner.record(&genesis, &initial, 0).unwrap();
        assert!(verifies(&v0));
        let draft = body(PLACEHOLDER, owner.public_key(5).unwrap(), 5, Some(&v0));
        let v5 = owner.record(&genesis, &draft, 5).unwrap();
        assert!(verifies(&v5));
        assert_eq!(
            tree_form(&genesis.key(), &v5),
            Ok(TreeForm {
                seq: 5,
                prev: Some(sha256(&v0)),
                key_hash: sha256(owner.public_key(5).unwrap()),
            })
        );
    }

    /// The same secrets give the tree and documents the tests compute alone.
    #[test]
    fn the_same_secrets_give_the_tests_tree_and_documents() {
        let expected = TreeOwner::new(3);
        let seeds: Vec<[u8; SEED_LEN]> = (0..POSITIONS as u8)
            .map(|i| sha256(&[3, i, 0x5e]))
            .collect();
        let codes: Vec<[u8; CODE_LEN]> = (0..POSITIONS as u8)
            .map(|i| sha256(&[3, i, 0xc0]))
            .collect();
        let owner = OwnerTree::from_secrets(&seeds, &codes).unwrap();
        assert_eq!(owner.root(), expected.root());
        let initial = body(PLACEHOLDER, owner.public_key(0).unwrap(), 0, None);
        let genesis = owner.genesis(&initial).unwrap();
        assert_eq!(genesis.key(), expected.key);
        let draft = body(PLACEHOLDER, owner.public_key(5).unwrap(), 5, Some(b"4"));
        let record = owner.record(&genesis, &draft, 5).unwrap();
        assert_eq!(document(&record), expected.doc(5, Some(b"4")));
    }

    #[test]
    fn a_record_that_a_replica_would_refuse_never_leaves() {
        let owner = OwnerTree::generate().unwrap();
        let initial = body(PLACEHOLDER, owner.public_key(0).unwrap(), 0, None);
        let genesis = owner.genesis(&initial).unwrap();
        // The reserved position, and beyond the tree.
        let draft = body(PLACEHOLDER, owner.public_key(63).unwrap(), 63, Some(b"62"));
        assert!(matches!(
            owner.record(&genesis, &draft, 63),
            Err(OwnerError::Form(FormError::Field("seq")))
        ));
        assert!(matches!(
            owner.record(&genesis, &draft, 64),
            Err(OwnerError::Position(64))
        ));
        // A draft whose seq or key is not the position's.
        let draft = body(PLACEHOLDER, owner.public_key(5).unwrap(), 6, Some(b"5"));
        assert!(owner.record(&genesis, &draft, 5).is_err());
        let draft = body(PLACEHOLDER, owner.public_key(6).unwrap(), 5, Some(b"4"));
        assert!(matches!(
            owner.record(&genesis, &draft, 5),
            Err(OwnerError::Form(FormError::NotInTree))
        ));
        // A document 0 other than the one the genesis commits to.
        let mut other = initial.clone();
        other["service"] = json!([]);
        assert!(matches!(
            owner.record(&genesis, &other, 0),
            Err(OwnerError::Form(FormError::WrongKey))
        ));
        // A draft that already holds a proof.
        let mut proven = initial;
        proven[PROOF] = json!({});
        assert!(owner.record(&genesis, &proven, 0).is_err());
    }

    #[test]
    fn secrets_must_cover_every_position() {
        let seeds = vec![[1u8; SEED_LEN]; POSITIONS - 1];
        let codes = vec![[2u8; CODE_LEN]; POSITIONS];
        assert!(matches!(
            OwnerTree::from_secrets(&seeds, &codes),
            Err(OwnerError::Secrets)
        ));
    }
}
