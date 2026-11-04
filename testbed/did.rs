//! DID records shared by the testbed binaries: the same document layout as the
//! other entry points, with canonical (sorted) keys. Each binary uses part of it.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const ALGORITHM: &str = "Dilithium-2";
pub const SIGNATURE_LEN: usize = 2420;

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

pub fn did_document(
    did: &str,
    signing: &dilithium2::PublicKey,
    agreement: &kyber512::PublicKey,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#k0"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2",
                                  "x": URL_SAFE_NO_PAD.encode(signing.as_bytes()) }
            },
            {
                "id": format!("{did}#k1"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512",
                                  "x": URL_SAFE_NO_PAD.encode(agreement.as_bytes()) }
            }
        ],
        "authentication": [format!("{did}#k0")],
        "keyAgreement": [format!("{did}#k1")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    })
}

/// `[algorithm: 12 B][Dilithium-2 signature][DID Document JSON]`
pub fn signed_record(document: &Value, secret_key: &dilithium2::SecretKey) -> Vec<u8> {
    let body = serde_json::to_vec(&sorted(document)).expect("a DID Document serializes");
    let mut record = vec![0u8; 12];
    record[..ALGORITHM.len()].copy_from_slice(ALGORITHM.as_bytes());
    record.extend_from_slice(dilithium2::detached_sign(&body, secret_key).as_bytes());
    record.extend_from_slice(&body);
    record
}

pub fn short_hash(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes)[..6])
}

/// The DID of a record and short hashes of its two public keys, so versions
/// can be told apart in the output.
pub fn describe(record: &[u8]) -> Value {
    let document: Option<Value> = record
        .get(12 + SIGNATURE_LEN..)
        .and_then(|body| serde_json::from_slice(body).ok());
    let Some(document) = document else {
        return json!({ "bytes": record.len(), "error": "not a DID record" });
    };
    let key = |index: usize| {
        document["verificationMethod"][index]["publicKeyJwk"]["x"]
            .as_str()
            .and_then(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .map(|bytes| short_hash(&bytes))
    };
    json!({
        "did": document["id"],
        "signing_key": key(0),
        "agreement_key": key(1),
        "bytes": record.len(),
    })
}

pub fn signing_key_of(record: &[u8]) -> String {
    describe(record)["signing_key"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

/// One version of this node's DID Document. The Kyber secret key is not
/// kept: the testbed does not run key agreement.
pub struct Version {
    pub secret_key: dilithium2::SecretKey,
    pub record: Vec<u8>,
}

impl Version {
    pub fn generate(did: &str) -> Self {
        let (signing, secret_key) = dilithium2::keypair();
        let (agreement, _) = kyber512::keypair();
        let record = signed_record(&did_document(did, &signing, &agreement), &secret_key);
        Self { secret_key, record }
    }
}

/// The DID a record claims, read from its document.
pub fn did_of(record: &[u8]) -> Option<String> {
    let document: Value = serde_json::from_slice(record.get(12 + SIGNATURE_LEN..)?).ok()?;
    document["id"].as_str().map(str::to_string)
}
