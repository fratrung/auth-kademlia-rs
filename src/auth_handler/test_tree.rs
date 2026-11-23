//! The 64 positions of one DID's tree, for the tests.
//!
//! The tree, the genesis and the DID are computed here with `sha2` and
//! `serde_json` alone, as the Python application computes them, so that the
//! tests of `tree.rs` do not rest on the code they test.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto::mldsa::MlDsa65KeyPair;
use crate::utils::ID_LEN;

use super::RECORD_ALGORITHM;

/// What a draft holds in place of its own DID before the DID is known.
pub(crate) const PLACEHOLDER: &str = "did:iiot:self";

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; ID_LEN] {
    Sha256::digest(bytes).into()
}

/// `| algorithm | signature of body | body |`
pub(crate) fn record_of(body: &[u8], signer: &MlDsa65KeyPair) -> Vec<u8> {
    let mut record = vec![0u8; 12];
    record[..RECORD_ALGORITHM.len()].copy_from_slice(RECORD_ALGORITHM.as_bytes());
    record.extend_from_slice(&signer.sign(body).expect("ML-DSA-65 signing"));
    record.extend_from_slice(body);
    record
}

/// A record of `doc` as `serde_json` writes it: sorted keys, no whitespace.
pub(crate) fn sign(doc: &Value, signer: &MlDsa65KeyPair) -> Vec<u8> {
    record_of(
        &serde_json::to_vec(doc).expect("a document serializes"),
        signer,
    )
}

/// Write `did` wherever a string value is the placeholder or starts with it
/// followed by `#`, `?` or `/`.
pub(crate) fn put_did(value: &mut Value, did: &str) {
    match value {
        Value::String(text) => {
            if let Some(rest) = text.strip_prefix(PLACEHOLDER) {
                if rest.is_empty() || rest.starts_with(['#', '?', '/']) {
                    *text = format!("{did}{rest}");
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| put_did(item, did)),
        Value::Object(map) => map.values_mut().for_each(|item| put_did(item, did)),
        _ => {}
    }
}

/// Positions of the tree: 64, of height 6.
pub(crate) const POSITIONS: usize = 64;

/// The body of position `seq`: no `id`, no `treeProof`, its own DID written
/// as `did`. `prev` is the record the owner names as its previous
/// publication.
pub(crate) fn body(did: &str, public_key: &[u8], seq: u64, prev: Option<&[u8]>) -> Value {
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#k0"),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65", "pub": b64(public_key) },
        }],
        "authentication": [format!("{did}#k0")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device",
        }],
        "seq": seq,
    });
    if let Some(prev) = prev {
        doc["prev"] = json!(b64(&sha256(prev)));
    }
    doc
}

/// SHA-256(0x00 ‖ index, 4 bytes big-endian ‖ public key ‖ code).
pub(crate) fn leaf(index: u32, public_key: &[u8], code: &[u8]) -> [u8; ID_LEN] {
    sha256(&[&[0u8][..], &index.to_be_bytes(), public_key, code].concat())
}

/// SHA-256(0x01 ‖ left ‖ right).
pub(crate) fn node(left: &[u8; ID_LEN], right: &[u8; ID_LEN]) -> [u8; ID_LEN] {
    sha256(&[&[1u8][..], left, right].concat())
}

/// The levels of the tree of `leaves`, from the leaves up to the root.
fn levels_of(leaves: Vec<[u8; ID_LEN]>) -> Vec<Vec<[u8; ID_LEN]>> {
    let mut levels = vec![leaves];
    while levels.last().map_or(0, Vec::len) > 1 {
        let below = &levels[levels.len() - 1];
        let above = below
            .chunks(2)
            .map(|pair| node(&pair[0], &pair[1]))
            .collect();
        levels.push(above);
    }
    levels
}

/// One DID: the keys and codes of its 64 positions, its tree, its genesis.
pub(crate) struct TreeOwner {
    /// `keys[i]` signs position `i`, from a fixed seed.
    pub(crate) keys: Arc<Vec<MlDsa65KeyPair>>,
    pub(crate) codes: Vec<[u8; 32]>,
    /// `levels[0]` are the leaves, the last level the root.
    pub(crate) levels: Vec<Vec<[u8; ID_LEN]>>,
    pub(crate) genesis: Value,
    pub(crate) did: String,
    /// The DHT key: the SHA-256 of the canonical genesis.
    pub(crate) key: [u8; ID_LEN],
}

impl TreeOwner {
    /// A new DID; `tag` makes its seeds and codes differ from another
    /// owner's.
    pub(crate) fn new(tag: u8) -> Self {
        let keys: Vec<MlDsa65KeyPair> = (0..POSITIONS)
            .map(|i| {
                MlDsa65KeyPair::from_seed(&sha256(&[tag, i as u8, 0x5e]))
                    .expect("ML-DSA-65 key from a seed")
            })
            .collect();
        let codes: Vec<[u8; 32]> = (0..POSITIONS)
            .map(|i| sha256(&[tag, i as u8, 0xc0]))
            .collect();
        let leaves = (0..POSITIONS)
            .map(|i| leaf(i as u32, keys[i].public_key(), &codes[i]))
            .collect();
        let initial = body(PLACEHOLDER, keys[0].public_key(), 0, None);
        Self::from_parts(Arc::new(keys), codes, levels_of(leaves), &initial)
    }

    fn from_parts(
        keys: Arc<Vec<MlDsa65KeyPair>>,
        codes: Vec<[u8; 32]>,
        levels: Vec<Vec<[u8; ID_LEN]>>,
        initial: &Value,
    ) -> Self {
        let root = levels[levels.len() - 1][0];
        let genesis = json!({
            "hashAlg": "SHA-256",
            "height": 6,
            "initialBodyHash": b64(&sha256(&serde_json::to_vec(initial).expect("a body"))),
            "root": b64(&root),
            "sigAlg": "ML-DSA-65",
            "version": 1,
        });
        let key = sha256(&serde_json::to_vec(&genesis).expect("a genesis"));
        Self {
            keys,
            codes,
            levels,
            genesis,
            did: format!("did:iiot:{}", b64(&key)),
            key,
        }
    }

    /// The same keys, codes and tree under another initial body: another
    /// genesis, so another DID.
    pub(crate) fn with_initial_body(&self, initial: &Value) -> Self {
        Self::from_parts(
            Arc::clone(&self.keys),
            self.codes.clone(),
            self.levels.clone(),
            initial,
        )
    }

    pub(crate) fn root(&self) -> [u8; ID_LEN] {
        self.levels[self.levels.len() - 1][0]
    }

    /// The membership path of `index`: the siblings from the leaf's up.
    pub(crate) fn path(&self, index: usize) -> Vec<u8> {
        let mut path = Vec::with_capacity(6 * ID_LEN);
        let mut at = index;
        for level in &self.levels[..self.levels.len() - 1] {
            path.extend_from_slice(&level[at ^ 1]);
            at /= 2;
        }
        path
    }

    /// The signed document of position `seq` from `body`, which holds the
    /// placeholder in place of the DID: as the custody backend completes it.
    pub(crate) fn complete(&self, body: &Value, seq: usize) -> Value {
        let mut doc = body.clone();
        put_did(&mut doc, &self.did);
        doc["id"] = json!(self.did);
        doc["treeProof"] = json!({
            "code": b64(&self.codes[seq]),
            "genesis": self.genesis,
            "path": b64(&self.path(seq)),
        });
        doc
    }

    /// The document of position `seq`, with this position's key.
    pub(crate) fn doc(&self, seq: usize, prev: Option<&[u8]>) -> Value {
        self.complete(
            &body(PLACEHOLDER, self.keys[seq].public_key(), seq as u64, prev),
            seq,
        )
    }

    /// The record of position `seq`, signed by its key.
    pub(crate) fn record(&self, seq: usize, prev: Option<&[u8]>) -> Vec<u8> {
        sign(&self.doc(seq, prev), &self.keys[seq])
    }

    /// The record of position `seq` from `body`, signed by its key.
    pub(crate) fn record_from(&self, body: &Value, seq: usize) -> Vec<u8> {
        sign(&self.complete(body, seq), &self.keys[seq])
    }
}
