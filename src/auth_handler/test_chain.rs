//! Chains of versions of one DID, for the tests (ADR 0005, sections 1 and 2).
//!
//! The DID of version 0 is computed here as the Python application computes
//! it (serialize the draft, SHA-256, base64url), without `did.rs`, so that the
//! tests of the binding do not rest on the code they test.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto::mldsa::MlDsa65KeyPair;
use crate::utils::ID_LEN;

use super::RECORD_ALGORITHM;

/// What a document holds in place of its own DID before the DID is known.
pub(crate) const PLACEHOLDER: &str = "did:iiot:self";

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; ID_LEN] {
    Sha256::digest(bytes).into()
}

pub(crate) fn new_key() -> MlDsa65KeyPair {
    MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation")
}

/// `| algorithm | signature of body | body |`
pub(crate) fn record_of(body: &[u8], signer: &MlDsa65KeyPair) -> Vec<u8> {
    let mut record = vec![0u8; 12];
    record[..RECORD_ALGORITHM.len()].copy_from_slice(RECORD_ALGORITHM.as_bytes());
    record.extend_from_slice(&signer.sign(body).expect("ML-DSA-65 signing"));
    record.extend_from_slice(body);
    record
}

/// A record of `doc`, serialized as `serde_json` writes it: sorted keys, no
/// whitespace.
pub(crate) fn sign(doc: &Value, signer: &MlDsa65KeyPair) -> Vec<u8> {
    record_of(
        &serde_json::to_vec(doc).expect("a document serializes"),
        signer,
    )
}

/// The document of a version, without `id`, its own DID written as `did`.
/// `prev` is the record of the version before, `next_key` the raw public key
/// that will sign the version after.
pub(crate) fn document(
    did: &str,
    public_key: &[u8],
    seq: u64,
    prev: Option<&[u8]>,
    next_key: &[u8],
) -> Value {
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
        "nextKeyHash": b64(&sha256(next_key)),
    });
    if let Some(prev) = prev {
        doc["prev"] = json!(b64(&sha256(prev)));
    }
    doc
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

/// The DID of a draft of version 0 (no `id`, the placeholder in place of the
/// DID), and the document with the DID in place and `id` added.
pub(crate) fn derive(draft: &Value) -> (String, Value) {
    let hash = sha256(&serde_json::to_vec(draft).expect("a draft serializes"));
    let did = format!("did:iiot:{}", b64(&hash));
    let mut doc = draft.clone();
    put_did(&mut doc, &did);
    doc["id"] = json!(did);
    (did, doc)
}

/// The DHT key of a DID: its suffix, decoded.
pub(crate) fn key_of(did: &str) -> [u8; ID_LEN] {
    let suffix = did.strip_prefix("did:iiot:").expect("a did:iiot DID");
    URL_SAFE_NO_PAD
        .decode(suffix)
        .expect("base64url")
        .try_into()
        .expect("32 bytes")
}

/// The versions of one DID, each signed by the key the one before committed
/// to. `keys[n]` signs version `n`; the last key is the committed next one.
pub(crate) struct Chain {
    pub(crate) did: String,
    pub(crate) key: [u8; ID_LEN],
    pub(crate) records: Vec<Vec<u8>>,
    pub(crate) keys: Vec<MlDsa65KeyPair>,
}

impl Chain {
    /// Version 0 of a new DID.
    pub(crate) fn new() -> Self {
        let keys = vec![new_key(), new_key()];
        let draft = document(
            PLACEHOLDER,
            keys[0].public_key(),
            0,
            None,
            keys[1].public_key(),
        );
        let (did, doc) = derive(&draft);
        let record = sign(&doc, &keys[0]);
        Self {
            key: key_of(&did),
            did,
            records: vec![record],
            keys,
        }
    }

    /// Versions 0 to `last`.
    pub(crate) fn with_versions(last: usize) -> Self {
        let mut chain = Self::new();
        for _ in 0..last {
            chain.grow();
        }
        chain
    }

    /// Add the next version, signed by the committed key and committing to a
    /// new one.
    pub(crate) fn grow(&mut self) -> Vec<u8> {
        let seq = self.records.len();
        self.keys.push(new_key());
        let doc = self.doc(
            seq as u64,
            Some(&self.records[seq - 1]),
            self.keys[seq].public_key(),
            self.keys[seq + 1].public_key(),
        );
        let record = sign(&doc, &self.keys[seq]);
        self.records.push(record.clone());
        record
    }

    /// A document of this DID with these fields, `id` included.
    pub(crate) fn doc(
        &self,
        seq: u64,
        prev: Option<&[u8]>,
        public_key: &[u8],
        next_key: &[u8],
    ) -> Value {
        let mut doc = document(&self.did, public_key, seq, prev, next_key);
        doc["id"] = json!(self.did);
        doc
    }

    pub(crate) fn version(&self, seq: usize) -> &[u8] {
        &self.records[seq]
    }
}
