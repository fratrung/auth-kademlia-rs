#![allow(dead_code)]

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::utils::ID_LEN;

pub fn rt() -> tokio::runtime::Runtime {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("failed to build runtime")
}

/// Start a node with signature cache disabled.
pub async fn start_node(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, None, None, false);
    srv.listen(port, "127.0.0.1").await.expect("listen failed");
    srv
}

/// Start a node with signature cache disabled and a deterministic node ID.
pub async fn start_node_with_id(port: u16, node_id: [u8; ID_LEN]) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, Some(node_id), None, false);
    srv.listen(port, "127.0.0.1").await.expect("listen failed");
    srv
}

/// Start a node with signature cache enabled.
pub async fn start_node_cached(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, None, None, true);
    srv.listen(port, "127.0.0.1").await.expect("listen failed");
    srv
}

/// Poll `check` every `interval` until it returns `Some(T)` or `timeout` elapses.
pub async fn poll_until<F, Fut, T>(timeout: Duration, interval: Duration, mut check: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = check().await {
            return Some(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(interval).await;
    }
}

fn sort_json_keys(v: &Value) -> Value {
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

pub fn generate_did_iiot() -> String {
    format!("did:iiot:{}", Uuid::new_v4())
}

pub fn build_did_document(did: &str, signing_pk: &[u8]) -> Value {
    let signing_x = URL_SAFE_NO_PAD.encode(signing_pk);
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did), "type": "JsonWebKey2020", "controller": did,
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

pub fn build_signed_record(doc: &Value, secret_key: &MlDsa65KeyPair, algorithm: &str) -> Vec<u8> {
    let doc_bytes =
        serde_json::to_vec(&sort_json_keys(doc)).expect("DID Document serialisation failed");
    let mut alg_field = [0u8; 12];
    let copy_len = algorithm.len().min(12);
    alg_field[..copy_len].copy_from_slice(&algorithm.as_bytes()[..copy_len]);
    let sig = secret_key.sign(&doc_bytes).unwrap();
    let sig_bytes = sig.as_slice();
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Generate a random valid DID record. Returns `(dht_key, signed_record_bytes)`.
pub fn make_record() -> (String, Vec<u8>) {
    let dsk = MlDsa65KeyPair::generate().unwrap();
    let dpk = dsk.public_key().to_vec();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &dpk);
    let record = build_signed_record(&doc, &dsk, "ML-DSA-65");
    (key, record)
}
