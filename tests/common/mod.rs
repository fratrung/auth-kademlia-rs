//! Shared helpers for integration tests.
//!
//! Provides DID document construction, signed-record assembly, and server
//! factory functions reused across test files.  Not a test binary itself
//! (lives in a subdirectory).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::{ForgetfulStorage, DEFAULT_MAX_STORAGE_BYTES, DEFAULT_TTL};

// ─────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// Recursively sort all object keys so JSON serialisation is deterministic.
pub fn sort_json_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

/// Serialise a DID Document to canonical (sorted-key, compact) JSON bytes.
pub fn encode_did_document(doc: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_json_keys(doc)).expect("DID Document serialisation failed")
}

// ─────────────────────────────────────────────────────────────────────────────
// DID record helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build the AuthKademlia signed record:
///
/// ```text
/// | algorithm (12 bytes, null-padded) | ML-DSA-65 signature | DID Document JSON |
/// ```
pub fn build_signed_record(doc: &Value, secret_key: &MlDsa65KeyPair, algorithm: &str) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    let mut alg_field = [0u8; 12];
    let copy_len = algorithm.len().min(12);
    alg_field[..copy_len].copy_from_slice(&algorithm.as_bytes()[..copy_len]);

    let detached_sig = secret_key.sign(&doc_bytes).unwrap();
    let signature = detached_sig.as_slice();

    let mut record = Vec::with_capacity(12 + signature.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(signature);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Build a minimal `did:iiot` DID Document with its ML-DSA-65 key (RFC 9964)
/// and no key agreement key (ADR 0003).
pub fn build_did_document(did: &str, signing_pk: &[u8]) -> Value {
    let signing_x = base64url_encode(signing_pk);
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65", "pub": signing_x }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "service": [{
            "id": format!("{}#device", did),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Server factory
// ─────────────────────────────────────────────────────────────────────────────

/// Create and start a DHT node on the given port.
///
/// Uses `issuer_pub_key.bin` as the issuer key path (only needed for
/// status-list key — not for regular DID record operations).
pub async fn start_node(port: u16) -> Server {
    start_node_with_max_storage_bytes(port, DEFAULT_MAX_STORAGE_BYTES).await
}

pub async fn start_node_with_max_storage_bytes(port: u16, max_storage_bytes: usize) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
        DEFAULT_TTL,
        max_storage_bytes,
    ));
    let mut server = Server::new(handler, 20, 3, None, Some(storage), true);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    server
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-certifying DIDs and chains of versions (ADR 0005)
// ─────────────────────────────────────────────────────────────────────────────

/// What a draft of version 0 holds in place of its own DID.
pub const PLACEHOLDER: &str = "did:iiot:self";

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// The document of one version, without `id`, its own DID written as `did`:
/// `prev` is the record of the version before, `next_key` the raw public key
/// that signs the version after.
pub fn version_document(
    did: &str,
    public_key: &[u8],
    seq: u64,
    prev: Option<&[u8]>,
    next_key: &[u8],
) -> Value {
    let mut doc = build_did_document(did, public_key);
    let object = doc.as_object_mut().expect("a document is an object");
    object.remove("id");
    object.insert("seq".into(), json!(seq));
    object.insert(
        "nextKeyHash".into(),
        json!(base64url_encode(&sha256(next_key))),
    );
    if let Some(prev) = prev {
        object.insert("prev".into(), json!(base64url_encode(&sha256(prev))));
    }
    doc
}

/// Put `did` wherever a string value is the placeholder, or starts with it
/// followed by `#`, `?` or `/`.
fn put_did(value: &mut Value, did: &str) {
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

/// The DID of a draft of version 0, computed as the Python application does
/// (canonical JSON, SHA-256, base64url), and the document with the DID in place.
pub fn derive(draft: &Value) -> (String, Value) {
    let hash = sha256(&encode_did_document(draft));
    let did = format!("did:iiot:{}", base64url_encode(&hash));
    let mut doc = draft.clone();
    put_did(&mut doc, &did);
    doc["id"] = json!(did);
    (did, doc)
}

/// The versions of one DID, each signed by the key the one before committed
/// to. `keys[n]` signs version `n`; the last key is the committed next one.
pub struct Chain {
    pub did: String,
    pub key: [u8; 32],
    pub records: Vec<Vec<u8>>,
    pub keys: Vec<MlDsa65KeyPair>,
}

impl Chain {
    pub fn new() -> Self {
        let keys = vec![
            MlDsa65KeyPair::generate().unwrap(),
            MlDsa65KeyPair::generate().unwrap(),
        ];
        let draft = version_document(
            PLACEHOLDER,
            keys[0].public_key(),
            0,
            None,
            keys[1].public_key(),
        );
        let (did, doc) = derive(&draft);
        let record = build_signed_record(&doc, &keys[0], "ML-DSA-65");
        let suffix = did.strip_prefix("did:iiot:").unwrap();
        let key = URL_SAFE_NO_PAD.decode(suffix).unwrap().try_into().unwrap();
        Self {
            did,
            key,
            records: vec![record],
            keys,
        }
    }

    /// Versions 0 to `last`.
    pub fn with_versions(last: usize) -> Self {
        let mut chain = Self::new();
        for _ in 0..last {
            chain.grow();
        }
        chain
    }

    /// Add the next version, signed by the committed key.
    pub fn grow(&mut self) -> Vec<u8> {
        let seq = self.records.len();
        self.keys.push(MlDsa65KeyPair::generate().unwrap());
        let doc = self.doc(
            seq as u64,
            Some(&self.records[seq - 1]),
            self.keys[seq].public_key(),
            self.keys[seq + 1].public_key(),
        );
        let record = build_signed_record(&doc, &self.keys[seq], "ML-DSA-65");
        self.records.push(record.clone());
        record
    }

    /// A document of this DID with these fields, `id` included.
    pub fn doc(&self, seq: u64, prev: Option<&[u8]>, public_key: &[u8], next_key: &[u8]) -> Value {
        let mut doc = version_document(&self.did, public_key, seq, prev, next_key);
        doc["id"] = json!(self.did);
        doc
    }

    /// Another version `seq` at the same place, after `prev`, signed by
    /// `signer` and committing to a new key.
    pub fn forge(&self, seq: u64, prev: &[u8], signer: &MlDsa65KeyPair) -> Vec<u8> {
        let next = MlDsa65KeyPair::generate().unwrap();
        let doc = self.doc(seq, Some(prev), signer.public_key(), next.public_key());
        build_signed_record(&doc, signer, "ML-DSA-65")
    }

    pub fn version(&self, seq: usize) -> Vec<u8> {
        self.records[seq].clone()
    }

    /// Versions 0 to `seq − 1`: what the owner passes to `update` with
    /// version `seq`.
    pub fn earlier(&self, seq: usize) -> Vec<Vec<u8>> {
        self.records[..seq].to_vec()
    }
}

impl Chain {
    /// Version `seq` signed again: the same document, other bytes (ML-DSA
    /// signing is randomized), so another record at the same place.
    pub fn signed_again(&self, seq: usize) -> Vec<u8> {
        let doc = self.doc(
            seq as u64,
            (seq > 0).then(|| self.records[seq - 1].as_slice()),
            self.keys[seq].public_key(),
            self.keys[seq + 1].public_key(),
        );
        build_signed_record(&doc, &self.keys[seq], "ML-DSA-65")
    }
}

/// Version 0 of a new DID whose document holds `public_key`, signed by
/// `signer` (which may not match it): `(DID, record)`.
pub fn version0(public_key: &[u8], signer: &MlDsa65KeyPair) -> (String, Vec<u8>) {
    let next = MlDsa65KeyPair::generate().unwrap();
    let draft = version_document(PLACEHOLDER, public_key, 0, None, next.public_key());
    let (did, doc) = derive(&draft);
    (did, build_signed_record(&doc, signer, "ML-DSA-65"))
}

/// Version 0 of a new DID: `(DID, record)`.
pub fn new_did_record() -> (String, Vec<u8>) {
    let key = MlDsa65KeyPair::generate().unwrap();
    version0(key.public_key(), &key)
}

/// The DHT key of a DID: its suffix, decoded.
pub fn key_of(did: &str) -> [u8; 32] {
    auth_kademlia_rs::network::dht_key(did).expect("a did:iiot DID")
}
