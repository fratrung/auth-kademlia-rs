//! Shared helpers for integration tests.
//!
//! Provides DID document construction, signed-record assembly, and server
//! factory functions reused across test files.  Not a test binary itself
//! (lives in a subdirectory).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use uuid::Uuid;

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
/// | algorithm (12 bytes, null-padded) | Dilithium-2 signature | DID Document JSON |
/// ```
pub fn build_signed_record(
    doc: &Value,
    secret_key: &dilithium2::SecretKey,
    algorithm: &str,
) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    let mut alg_field = [0u8; 12];
    let copy_len = algorithm.len().min(12);
    alg_field[..copy_len].copy_from_slice(&algorithm.as_bytes()[..copy_len]);

    let detached_sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let signature = detached_sig.as_bytes();

    let mut record = Vec::with_capacity(12 + signature.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(signature);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Generate a random `did:iiot` URI.
pub fn generate_did_iiot() -> String {
    format!("did:iiot:{}", Uuid::new_v4())
}

/// Build a minimal `did:iiot` DID Document with one Dilithium-2 and one Kyber-512 key.
pub fn build_did_document(
    did: &str,
    dilithium_pk: &dilithium2::PublicKey,
    kyber_pk: &kyber512::PublicKey,
) -> Value {
    let dx = base64url_encode(dilithium_pk.as_bytes());
    let kx = base64url_encode(kyber_pk.as_bytes());
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2", "x": dx }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512", "x": kx }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "keyAgreement":   [ format!("{}#k1", did) ],
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
