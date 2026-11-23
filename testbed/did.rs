//! DID records shared by the testbed binaries: position 0 of a new DID, the
//! positions after it, and forged records. Each binary uses part of it.
#![allow(dead_code)]

use auth_kademlia_rs::auth_handler::did::{canonical_bytes, PLACEHOLDER};
use auth_kademlia_rs::auth_handler::owner::{signed_record, OwnerTree};
use auth_kademlia_rs::auth_handler::tree::Genesis;
use auth_kademlia_rs::crypto::mldsa::{self as mldsa, MlDsa65KeyPair};
use auth_kademlia_rs::utils::digest_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

pub const ALGORITHM: &str = "ML-DSA-65";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn new_key() -> MlDsa65KeyPair {
    MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation")
}

/// The draft of position `seq`: its ML-DSA-65 key (RFC 9964), no key
/// agreement key, its own DID written as the placeholder, no `id`, and after
/// position 0 the hash of the record it follows.
fn draft(signing: &[u8], seq: u64, prev: Option<&[u8]>) -> Value {
    let did = PLACEHOLDER;
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
    });
    if let Some(prev) = prev {
        document["prev"] = json!(b64(&digest_bytes(prev)));
    }
    document
}

/// The tree of a new DID, its genesis, the DID and position 0.
pub fn new_did() -> (OwnerTree, Genesis, String, Vec<u8>) {
    let owner = OwnerTree::generate().expect("a rotation-key tree");
    let initial = draft(owner.public_key(0).expect("position 0"), 0, None);
    let genesis = owner.genesis(&initial).expect("a draft body");
    let record = owner.record(&genesis, &initial, 0).expect("position 0");
    let did = genesis.did();
    (owner, genesis, did, record)
}

/// Position `seq` of the DID, naming `prev` as the record it follows.
pub fn position(owner: &OwnerTree, genesis: &Genesis, seq: u64, prev: &[u8]) -> Vec<u8> {
    let public_key = owner.public_key(seq).expect("a position of the tree");
    owner
        .record(genesis, &draft(public_key, seq, Some(prev)), seq)
        .expect("a record of the tree")
}

/// A forged record for the DID of `observed`: the next position, with its
/// public proof copied, the attacker's own key in the document and its
/// signature. The key is not the tree's at that position, so no replica
/// takes it, whatever the network says.
pub fn forge(observed: &[u8]) -> Option<Vec<u8>> {
    let mut document = document_of(observed)?;
    let seq = document["seq"].as_u64()?;
    let attacker = new_key();
    document["seq"] = json!(seq + 1);
    document["prev"] = json!(b64(&digest_bytes(observed)));
    document["verificationMethod"][0]["publicKeyJwk"]["pub"] = json!(b64(attacker.public_key()));
    let body = canonical_bytes(&document).ok()?;
    Some(signed_record(&attacker.sign(&body).ok()?, &body))
}

fn document_of(record: &[u8]) -> Option<Value> {
    serde_json::from_slice(record.get(12 + mldsa::signature_len()..)?).ok()
}

pub fn short_hash(bytes: &[u8]) -> String {
    hex::encode(&digest_bytes(bytes)[..6])
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
