//! DID records shared by the testbed binaries (ADR 0005): version 0 of a new
//! DID, the versions after it, and forged versions. Each binary uses part of
//! it.
#![allow(dead_code)]

use auth_kademlia_rs::auth_handler::did::{canonical_bytes, derive_did, PLACEHOLDER};
use auth_kademlia_rs::crypto::mldsa::{self as mldsa, MlDsa65KeyPair};
use auth_kademlia_rs::utils::digest_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const ALGORITHM: &str = "ML-DSA-65";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn new_key() -> MlDsa65KeyPair {
    MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation")
}

/// A DID Document with its ML-DSA-65 key (RFC 9964) and no key agreement
/// key: ML-KEM keys are ephemeral, outside the DHT (ADR 0003). It holds
/// `seq`, `prev` (the base64url SHA-256 of the record before, from version 1)
/// and `nextKeyHash`, the hash of the key that alone may sign the next
/// version. It has no `id`: version 0 gets it from `derive_did`.
fn document(did: &str, signing: &[u8], seq: u64, prev: Option<&str>, next: &[u8]) -> Value {
    let mut document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": format!("{did}#k0"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "AKP", "alg": ALGORITHM, "pub": b64(signing) }
            }
        ],
        "authentication": [format!("{did}#k0")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }],
        "seq": seq,
        "nextKeyHash": b64(&digest_bytes(next)),
    });
    if let Some(prev) = prev {
        document["prev"] = json!(prev);
    }
    document
}

/// `[algorithm: 12 B][ML-DSA-65 signature][DID Document JSON]`, the document
/// in canonical form.
pub fn signed_record(document: &Value, secret_key: &MlDsa65KeyPair) -> Vec<u8> {
    let body = canonical_bytes(document).expect("a DID Document in canonical form");
    let mut record = vec![0u8; 12];
    record[..ALGORITHM.len()].copy_from_slice(ALGORITHM.as_bytes());
    record.extend_from_slice(&secret_key.sign(&body).expect("ML-DSA-65 signing"));
    record.extend_from_slice(&body);
    record
}

/// Version 0 of a new DID, signed by `signing` and committing to `next`: the
/// DID and the record.
pub fn version_zero(signing: &MlDsa65KeyPair, next: &MlDsa65KeyPair) -> (String, Vec<u8>) {
    let draft = document(
        PLACEHOLDER,
        signing.public_key(),
        0,
        None,
        next.public_key(),
    );
    let (did, document) = derive_did(&draft).expect("version 0 gives its DID");
    (did, signed_record(&document, signing))
}

/// Version `seq` of `did`, after the record `prev`: signed by `signing`, the
/// key the version before committed to, and committing to `next`.
pub fn version_after(
    did: &str,
    seq: u64,
    prev: &[u8],
    signing: &MlDsa65KeyPair,
    next: &MlDsa65KeyPair,
) -> Vec<u8> {
    let prev = b64(&digest_bytes(prev));
    signed_version(did, seq, &prev, signing, next)
}

fn signed_version(
    did: &str,
    seq: u64,
    prev: &str,
    signing: &MlDsa65KeyPair,
    next: &MlDsa65KeyPair,
) -> Vec<u8> {
    let mut document = document(
        did,
        signing.public_key(),
        seq,
        Some(prev),
        next.public_key(),
    );
    document["id"] = json!(did);
    signed_record(&document, signing)
}

/// A forged version for the DID of `observed`: the version a replica may take
/// next, self-signed by a key of the attacker's own, which no version
/// committed to. For an observed version N ≥ 1 it is another version N with
/// the same `prev`; for a version 0, a version 1 after it. Only a replica
/// that cannot check the key against the version before could take it.
pub fn forge(observed: &[u8]) -> Option<Vec<u8>> {
    let document = document_of(observed)?;
    let did = document["id"].as_str()?;
    let seq = document["seq"].as_u64()?;
    let (attacker, next) = (new_key(), new_key());
    if seq == 0 {
        return Some(version_after(did, 1, observed, &attacker, &next));
    }
    let prev = document["prev"].as_str()?;
    Some(signed_version(did, seq, prev, &attacker, &next))
}

fn document_of(record: &[u8]) -> Option<Value> {
    serde_json::from_slice(record.get(12 + mldsa::signature_len()..)?).ok()
}

pub fn short_hash(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes)[..6])
}

/// The DID and version of a record and a short hash of its signing key, so
/// versions can be told apart in the output.
pub fn describe(record: &[u8]) -> Value {
    let Some(document) = document_of(record) else {
        return json!({ "bytes": record.len(), "error": "not a DID record" });
    };
    let signing_key = document["verificationMethod"][0]["publicKeyJwk"]["pub"]
        .as_str()
        .and_then(|key| URL_SAFE_NO_PAD.decode(key).ok())
        .map(|bytes| short_hash(&bytes));
    json!({
        "did": document["id"],
        "seq": document["seq"],
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

/// The `seq` of a record, read from its document.
pub fn seq_of(record: &[u8]) -> Option<u64> {
    document_of(record)?["seq"].as_u64()
}

/// The DID a record claims, read from its document.
pub fn did_of(record: &[u8]) -> Option<String> {
    document_of(record)?["id"].as_str().map(str::to_string)
}
