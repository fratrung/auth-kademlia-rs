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

use auth_kademlia_rs::auth_handler::owner::OwnerTree;
use auth_kademlia_rs::auth_handler::tree::Genesis;
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
/// and no key agreement key.
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
// DIDs whose rotation keys are committed in a tree
// ─────────────────────────────────────────────────────────────────────────────

/// What a draft holds in place of its own DID.
pub const PLACEHOLDER: &str = "did:iiot:self";

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// The draft body of position `seq`, its own DID written as `did`: `prev`
/// is the record the owner names as its previous publication.
pub fn version_document(did: &str, public_key: &[u8], seq: u64, prev: Option<&[u8]>) -> Value {
    let mut doc = build_did_document(did, public_key);
    let object = doc.as_object_mut().expect("a document is an object");
    object.remove("id");
    object.insert("seq".into(), json!(seq));
    if let Some(prev) = prev {
        object.insert("prev".into(), json!(base64url_encode(&sha256(prev))));
    }
    doc
}

/// The algorithm field and the signature, before the document.
fn header_len() -> usize {
    12 + auth_kademlia_rs::crypto::mldsa::signature_len()
}

/// `record` with its document signed again by `signer`.
pub fn resign(record: &[u8], signer: &MlDsa65KeyPair) -> Vec<u8> {
    let document = &record[header_len()..];
    let mut out = record[..12].to_vec();
    out.extend_from_slice(&signer.sign(document).unwrap());
    out.extend_from_slice(document);
    out
}

/// The document of `record`.
pub fn document(record: &[u8]) -> Value {
    serde_json::from_slice(&record[header_len()..]).unwrap()
}

/// The positions of one DID published so far: `records[i]` is position `i`.
pub struct Chain {
    pub did: String,
    pub key: [u8; 32],
    pub records: Vec<Vec<u8>>,
    pub owner: OwnerTree,
    pub genesis: Genesis,
    seeds: Vec<[u8; 32]>,
}

impl Chain {
    /// Position 0 of a new DID.
    pub fn new() -> Self {
        let seeds: Vec<[u8; 32]> = (0..64).map(|_| rand::random()).collect();
        let codes: Vec<[u8; 32]> = (0..64).map(|_| rand::random()).collect();
        let owner = OwnerTree::from_secrets(&seeds, &codes).unwrap();
        let initial = version_document(PLACEHOLDER, owner.public_key(0).unwrap(), 0, None);
        let genesis = owner.genesis(&initial).unwrap();
        let record = owner.record(&genesis, &initial, 0).unwrap();
        Self {
            did: genesis.did(),
            key: genesis.key(),
            records: vec![record],
            owner,
            genesis,
            seeds,
        }
    }

    /// The key pair of position `seq`.
    pub fn key_pair(&self, seq: usize) -> MlDsa65KeyPair {
        MlDsa65KeyPair::from_seed(&self.seeds[seq]).unwrap()
    }

    /// Positions 0 to `last`.
    pub fn with_versions(last: usize) -> Self {
        let mut chain = Self::new();
        for _ in 0..last {
            chain.grow();
        }
        chain
    }

    /// Publish the next position, after the last one.
    pub fn grow(&mut self) -> Vec<u8> {
        let seq = self.records.len();
        let record = self.at(seq, Some(&self.records[seq - 1]));
        self.records.push(record.clone());
        record
    }

    /// A record at position `seq` naming `prev`, whatever was published.
    pub fn at(&self, seq: usize, prev: Option<&[u8]>) -> Vec<u8> {
        let draft = version_document(
            PLACEHOLDER,
            self.owner.public_key(seq as u64).unwrap(),
            seq as u64,
            prev,
        );
        self.owner
            .record(&self.genesis, &draft, seq as u64)
            .unwrap()
    }

    pub fn version(&self, seq: usize) -> Vec<u8> {
        self.records[seq].clone()
    }

    /// Position `seq` signed again: the same document, other bytes (ML-DSA
    /// signing is randomized), so another record at the same position.
    pub fn signed_again(&self, seq: usize) -> Vec<u8> {
        let draft = version_document(
            PLACEHOLDER,
            self.owner.public_key(seq as u64).unwrap(),
            seq as u64,
            (seq > 0).then(|| self.records[seq - 1].as_slice()),
        );
        self.owner
            .record(&self.genesis, &draft, seq as u64)
            .unwrap()
    }

    /// Another document at position `seq`, with another service endpoint.
    pub fn other_document(&self, seq: usize, prev: Option<&[u8]>) -> Vec<u8> {
        let mut draft = version_document(
            PLACEHOLDER,
            self.owner.public_key(seq as u64).unwrap(),
            seq as u64,
            prev,
        );
        draft["service"][0]["serviceEndpoint"] = json!("http://example.com/other");
        self.owner
            .record(&self.genesis, &draft, seq as u64)
            .unwrap()
    }

    /// A forgery at position `seq`: the public proof of that position, with
    /// `signer`'s key in the document, signed by `signer`. Its leaf is not
    /// in the tree.
    pub fn forge(&self, seq: usize, prev: &[u8], signer: &MlDsa65KeyPair) -> Vec<u8> {
        let mut doc = document(&self.at(seq, Some(prev)));
        doc["verificationMethod"][0]["publicKeyJwk"]["pub"] =
            json!(base64url_encode(signer.public_key()));
        build_signed_record(&doc, signer, "ML-DSA-65")
    }
}

/// Position 0 of a new DID in the right form, signed by `signer` instead of
/// its own key: `(DID, record)`.
pub fn badly_signed_record(signer: &MlDsa65KeyPair) -> (String, Vec<u8>) {
    let chain = Chain::new();
    (chain.did.clone(), resign(&chain.version(0), signer))
}

/// Position 0 of a new DID: `(DID, record)`.
pub fn new_did_record() -> (String, Vec<u8>) {
    let chain = Chain::new();
    (chain.did.clone(), chain.version(0))
}

/// The DHT key of a DID: its suffix, decoded.
pub fn key_of(did: &str) -> [u8; 32] {
    auth_kademlia_rs::network::dht_key(did).expect("a did:iiot DID")
}
