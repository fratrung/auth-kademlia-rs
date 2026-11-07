//! DID records shared by the testbed binaries: the same document layout as the
//! other entry points, with canonical (sorted) keys. Each binary uses part of it.
#![allow(dead_code)]

use auth_kademlia_rs::crypto::mldsa::{self as mldsa, MlDsa65KeyPair};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const ALGORITHM: &str = "ML-DSA-65";

pub fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| (key.clone(), sorted(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// A DID Document with its ML-DSA-65 key (RFC 9964) and no key agreement
/// key: ML-KEM keys are ephemeral, outside the DHT (ADR 0003).
pub fn did_document(did: &str, signing: &[u8]) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#k0"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "AKP", "alg": ALGORITHM,
                                  "pub": URL_SAFE_NO_PAD.encode(signing) }
            }
        ],
        "authentication": [format!("{did}#k0")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    })
}

/// `[algorithm: 12 B][ML-DSA-65 signature][DID Document JSON]`
pub fn signed_record(document: &Value, secret_key: &MlDsa65KeyPair) -> Vec<u8> {
    let body = serde_json::to_vec(&sorted(document)).expect("a DID Document serializes");
    let mut record = vec![0u8; 12];
    record[..ALGORITHM.len()].copy_from_slice(ALGORITHM.as_bytes());
    record.extend_from_slice(&secret_key.sign(&body).expect("ML-DSA-65 signing"));
    record.extend_from_slice(&body);
    record
}

pub fn short_hash(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes)[..6])
}

/// The DID of a record and a short hash of its signing key, so versions can
/// be told apart in the output.
pub fn describe(record: &[u8]) -> Value {
    let document: Option<Value> = record
        .get(12 + mldsa::signature_len()..)
        .and_then(|body| serde_json::from_slice(body).ok());
    let Some(document) = document else {
        return json!({ "bytes": record.len(), "error": "not a DID record" });
    };
    let signing_key = document["verificationMethod"][0]["publicKeyJwk"]["pub"]
        .as_str()
        .and_then(|key| URL_SAFE_NO_PAD.decode(key).ok())
        .map(|bytes| short_hash(&bytes));
    json!({
        "did": document["id"],
        "signing_key": signing_key,
        "bytes": record.len(),
    })
}

pub fn signing_key_of(record: &[u8]) -> String {
    describe(record)["signing_key"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

/// One version of this node's DID Document.
pub struct Version {
    pub secret_key: MlDsa65KeyPair,
    pub record: Vec<u8>,
}

impl Version {
    pub fn generate(did: &str) -> Self {
        let secret_key = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
        let signing = secret_key.public_key().to_vec();
        let record = signed_record(&did_document(did, &signing), &secret_key);
        Self { secret_key, record }
    }
}

/// The DID a record claims, read from its document.
pub fn did_of(record: &[u8]) -> Option<String> {
    let document: Value =
        serde_json::from_slice(record.get(12 + mldsa::signature_len()..)?).ok()?;
    document["id"].as_str().map(str::to_string)
}
