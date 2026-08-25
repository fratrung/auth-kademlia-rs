#![allow(dead_code)]

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPublicKey};
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

pub fn build_did_document(
    did: &str,
    dilithium_pk: &dilithium2::PublicKey,
    kyber_pk: &kyber512::PublicKey,
) -> Value {
    let dx = URL_SAFE_NO_PAD.encode(dilithium_pk.as_bytes());
    let kx = URL_SAFE_NO_PAD.encode(kyber_pk.as_bytes());
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did), "type": "JsonWebKey2020", "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2", "x": dx }
            },
            {
                "id": format!("{}#k1", did), "type": "JsonWebKey2020", "controller": did,
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

pub fn build_signed_record(
    doc: &Value,
    secret_key: &dilithium2::SecretKey,
    algorithm: &str,
) -> Vec<u8> {
    let doc_bytes =
        serde_json::to_vec(&sort_json_keys(doc)).expect("DID Document serialisation failed");
    let mut alg_field = [0u8; 12];
    let copy_len = algorithm.len().min(12);
    alg_field[..copy_len].copy_from_slice(&algorithm.as_bytes()[..copy_len]);
    let sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let sig_bytes = sig.as_bytes();
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Generate a random valid DID record. Returns `(dht_key, signed_record_bytes)`.
pub fn make_record() -> (String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &dpk, &kpk);
    let record = build_signed_record(&doc, &dsk, "Dilithium-2");
    (key, record)
}
