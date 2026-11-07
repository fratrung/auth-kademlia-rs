//! Integration tests for the cryptographic layer.
//!
//! Context: every record stored in the DHT carries an algorithm tag, a raw
//! signature, and a DID Document. A node accepts only ML-DSA-65 records (ADR
//! 0003); the Ed25519 and RSA implementations stay in `crypto/`, reachable
//! through `SignatureVerifierFactory` / `SignerFactory` but by no record.
//!
//! These tests cover:
//!   1. Sign-then-verify round-trips for ML-DSA-65 and Ed25519.
//!   2. Rejection of tampered messages and wrong keys.
//!   3. Factory dispatch correctness and unknown-algorithm errors.
//!   4. Algorithm-string to signature-length resolution.
//!   5. End-to-end DID record creation and verification via
//!      `DIDSignatureVerifierHandler` (the handler used by the server).

use std::path::PathBuf;

use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use uuid::Uuid;

use auth_kademlia_rs::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use auth_kademlia_rs::crypto::factory::{SignatureVerifierFactory, SignerFactory};
use auth_kademlia_rs::crypto::signature_verifier::resolve_alg_and_length;
use auth_kademlia_rs::utils::digest;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
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

fn canonical_json(v: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_json_keys(v)).unwrap()
}

/// A DID Document whose only key is ML-DSA-65, in the form of RFC 9964.
fn build_did_doc_mldsa65(did: &str, jwk: Value) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#k0", did),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk
        }],
        "authentication": [ format!("{}#k0", did) ],
        "service": [{"id": format!("{}#d", did), "type": "DeviceAgent",
                     "serviceEndpoint": "http://example.com"}]
    })
}

fn mldsa65_jwk(pk: &[u8]) -> Value {
    json!({ "kty": "AKP", "alg": "ML-DSA-65", "pub": base64url(pk) })
}

/// `algorithm (12 B) | signature | document`, the algorithm field null-padded.
fn build_record(algorithm: &str, signature: &[u8], doc: &Value) -> Vec<u8> {
    let mut alg = [0u8; 12];
    alg[..algorithm.len()].copy_from_slice(algorithm.as_bytes());
    let mut record = alg.to_vec();
    record.extend_from_slice(signature);
    record.extend_from_slice(&canonical_json(doc));
    record
}

fn build_record_mldsa65(doc: &Value, sk: &MlDsa65KeyPair) -> Vec<u8> {
    let sig = sk.sign(&canonical_json(doc)).unwrap();
    build_record("ML-DSA-65", sig.as_slice(), doc)
}

/// A DID Document whose only key is the ML-DSA-65 key `pk`.
fn build_did_doc(did: &str, pk: &[u8]) -> Value {
    build_did_doc_mldsa65(did, mldsa65_jwk(pk))
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON canonicalisation
// ─────────────────────────────────────────────────────────────────────────────

/// `sort_json_keys` must produce byte-identical output on repeated calls with
/// equal input — including nested objects and arrays.
#[test]
fn test_sort_json_keys_is_deterministic_and_canonical() {
    let doc = json!({
        "z_key": "last",
        "a_key": "first",
        "nested": {
            "z_nested": 99,
            "a_nested": [3, 1, 2],
            "m_nested": { "b": false, "a": true }
        },
        "array": [
            { "z": 1, "a": 0 },
            { "y": 2, "b": 1 }
        ]
    });

    // Repeated calls must produce identical bytes.
    let bytes_1 = canonical_json(&doc);
    let bytes_2 = canonical_json(&doc);
    assert_eq!(bytes_1, bytes_2, "canonical_json must be deterministic");

    let text = String::from_utf8(bytes_1).unwrap();

    // Top-level keys must be in alphabetical order: a_key < array < nested < z_key.
    let pos_a_key = text.find("\"a_key\"").expect("a_key not found");
    let pos_array = text.find("\"array\"").expect("array not found");
    let pos_nested = text.find("\"nested\"").expect("nested not found");
    let pos_z_key = text.find("\"z_key\"").expect("z_key not found");
    assert!(pos_a_key < pos_array, "a_key must precede array");
    assert!(pos_array < pos_nested, "array must precede nested");
    assert!(pos_nested < pos_z_key, "nested must precede z_key");

    // Nested keys in m_nested must also be sorted: a < b.
    let pos_a_nested = text.find("\"a\":true").expect("\"a\":true not found");
    let pos_b_nested = text.find("\"b\":false").expect("\"b\":false not found");
    assert!(pos_a_nested < pos_b_nested, "a must precede b in m_nested");

    // Array element order must be preserved (not sorted): first element has "z",
    // second has "y".
    let pos_z_elem = text.find("\"z\":1").expect("\"z\":1 not found");
    let pos_y_elem = text.find("\"y\":2").expect("\"y\":2 not found");
    assert!(
        pos_z_elem < pos_y_elem,
        "array element order must be preserved"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm resolution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_resolve_rsa_length() {
    let (alg, len) = resolve_alg_and_length("RSA").unwrap();
    assert_eq!(alg, "RSA");
    assert_eq!(len, 256);
}

#[test]
fn test_resolve_ed25519_length() {
    let (alg, len) = resolve_alg_and_length("Ed25519").unwrap();
    assert_eq!(alg, "Ed25519");
    assert_eq!(len, 64);
}

#[test]
fn test_resolve_unknown_algorithm_fails() {
    for alg in ["ECDSA", "ML-DSA", "Dilithium", "Dilithium-2", "ML-DSA-44"] {
        assert!(resolve_alg_and_length(alg).is_err(), "{alg}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory dispatch
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_factory_unknown_algorithm_returns_error() {
    assert!(SignatureVerifierFactory::get_verifier("ECDSA").is_err());
    assert!(SignerFactory::get_signer("ECDSA").is_err());
    assert!(SignatureVerifierFactory::get_verifier("").is_err());
}

#[test]
fn test_factory_known_algorithms_return_ok() {
    for alg in &["ML-DSA-65", "Ed25519", "RSA"] {
        assert!(
            SignatureVerifierFactory::get_verifier(alg).is_ok(),
            "get_verifier({}) should succeed",
            alg
        );
        assert!(
            SignerFactory::get_signer(alg).is_ok(),
            "get_signer({}) should succeed",
            alg
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA-65 sign / verify
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ml_dsa_65_sign_and_verify() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let msg = b"ml-dsa-65 test message";

    let signer = SignerFactory::get_signer("ML-DSA-65").unwrap();
    let sig = signer.sign(&sk.private_key().unwrap(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("ML-DSA-65").unwrap();
    assert!(
        verifier.verify(&pk, &sig, msg).unwrap(),
        "valid ML-DSA-65 signature must verify"
    );
}

#[test]
fn test_ml_dsa_65_tampered_message_rejected() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let msg = b"original message";

    let signer = SignerFactory::get_signer("ML-DSA-65").unwrap();
    let sig = signer.sign(&sk.private_key().unwrap(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("ML-DSA-65").unwrap();
    let tampered = b"tampered message!";
    assert!(
        !verifier.verify(&pk, &sig, tampered).unwrap(),
        "signature over different message must not verify"
    );
}

#[test]
fn test_ml_dsa_65_wrong_key_rejected() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let wrong_pk = MlDsa65KeyPair::generate().unwrap().public_key().to_vec(); // different keypair
    let msg = b"message signed with sk";

    let signer = SignerFactory::get_signer("ML-DSA-65").unwrap();
    let sig = signer.sign(&sk.private_key().unwrap(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("ML-DSA-65").unwrap();
    assert!(
        !verifier.verify(&wrong_pk, &sig, msg).unwrap(),
        "signature must not verify under a different public key"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 sign / verify
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ed25519_sign_and_verify() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let private_bytes = signing_key.to_bytes(); // 32-byte seed
    let public_bytes = verifying_key.to_bytes(); // 32 bytes
    let msg = b"ed25519 test message";

    let signer = SignerFactory::get_signer("Ed25519").unwrap();
    let sig = signer.sign(&private_bytes, msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Ed25519").unwrap();
    assert!(
        verifier.verify(&public_bytes, &sig, msg).unwrap(),
        "valid Ed25519 signature must verify"
    );
}

#[test]
fn test_ed25519_tampered_message_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let private_bytes = signing_key.to_bytes();
    let public_bytes = signing_key.verifying_key().to_bytes();

    let signer = SignerFactory::get_signer("Ed25519").unwrap();
    let sig = signer.sign(&private_bytes, b"original").unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Ed25519").unwrap();
    assert!(!verifier.verify(&public_bytes, &sig, b"tampered").unwrap());
}

#[test]
fn test_ed25519_wrong_key_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let private_bytes = signing_key.to_bytes();
    let wrong_pub = wrong_key.verifying_key().to_bytes();
    let msg = b"signed with key A";

    let signer = SignerFactory::get_signer("Ed25519").unwrap();
    let sig = signer.sign(&private_bytes, msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Ed25519").unwrap();
    assert!(!verifier.verify(&wrong_pub, &sig, msg).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end: DIDSignatureVerifierHandler self-signed record
// ─────────────────────────────────────────────────────────────────────────────

/// A well-formed signed DID record passes `handle_signature_verification`.
/// This exercises the full chain: alg extraction → sig-length resolution →
/// public-key extraction from the DID Document → verification.
#[test]
fn test_did_handler_accepts_valid_self_signed_record() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let doc = build_did_doc(&did, &pk);
    let record = build_record_mldsa65(&doc, &sk);

    // issuer_pub_key.bin path is irrelevant for self-signed verification.
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    assert!(
        handler.handle_signature_verification(&record).unwrap(),
        "valid self-signed record must pass verification"
    );
}

#[test]
fn test_did_handler_accepts_record_bound_to_requested_key() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let uuid = Uuid::new_v4().to_string();
    let doc = build_did_doc(&format!("did:iiot:{uuid}"), &pk);
    let record = build_record_mldsa65(&doc, &sk);
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));

    assert!(
        handler
            .handle_key_binding_verification(&digest(&uuid), &record)
            .unwrap(),
        "the DID UUID digest must match the requested DHT key"
    );
}

#[test]
fn test_did_handler_rejects_record_bound_to_another_key() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let record_uuid = Uuid::new_v4().to_string();
    let requested_uuid = Uuid::new_v4().to_string();
    let doc = build_did_doc(&format!("did:iiot:{record_uuid}"), &pk);
    let record = build_record_mldsa65(&doc, &sk);
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));

    assert!(
        !handler
            .handle_key_binding_verification(&digest(&requested_uuid), &record)
            .unwrap(),
        "a valid record must not be publishable under another DID UUID"
    );
}

#[test]
fn test_did_handler_rejects_non_uuid_did_identifier() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let doc = build_did_doc("did:iiot:not-a-uuid", &pk);
    let record = build_record_mldsa65(&doc, &sk);
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));

    assert!(
        handler
            .handle_key_binding_verification(&digest("not-a-uuid"), &record)
            .is_err(),
        "did:iiot identifiers must contain a UUID"
    );
}

/// A record whose signature was produced with a DIFFERENT key than the one
/// embedded in the DID Document must be rejected.
#[test]
fn test_did_handler_rejects_mismatched_key_in_record() {
    let pk = MlDsa65KeyPair::generate().unwrap().public_key().to_vec();
    let wrong_sk = MlDsa65KeyPair::generate().unwrap(); // key mismatch
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let doc = build_did_doc(&did, &pk); // public key from keypair A
    let record = build_record_mldsa65(&doc, &wrong_sk); // signed with keypair B's secret key

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    let result = handler.handle_signature_verification(&record).unwrap();
    assert!(!result, "mismatched key should cause verification failure");
}

/// A record whose DID Document JSON has been tampered with after signing
/// must be rejected.
#[test]
fn test_did_handler_rejects_tampered_did_document() {
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let doc = build_did_doc(&did, &pk);
    let mut record = build_record_mldsa65(&doc, &sk);

    // Flip the last byte of the DID Document section.
    if let Some(last) = record.last_mut() {
        *last ^= 0xFF;
    }

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    // Either returns Err (parse error due to corrupted JSON) or Ok(false).
    let ok = handler
        .handle_signature_verification(&record)
        .unwrap_or(false);
    assert!(!ok, "tampered DID Document must fail verification");
}

/// `handle_signature_verification` on a too-short record returns an error.
#[test]
fn test_did_handler_rejects_malformed_record() {
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    let short_record = vec![0u8; 5]; // shorter than the 12-byte algorithm field
    assert!(
        handler
            .handle_signature_verification(&short_record)
            .is_err(),
        "a record shorter than 12 bytes must return an error"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Key-rotation verification (update flow)
// ─────────────────────────────────────────────────────────────────────────────

/// The update verification flow:
/// - old record is signed with old keypair (self-signed)
/// - new record is signed with new keypair (self-signed)
/// - auth_signature = Sign(new_record, old_secret_key) proves the rotation
#[test]
fn test_did_handler_accepts_valid_key_rotation() {
    let old_sk = MlDsa65KeyPair::generate().unwrap();
    let old_pk = old_sk.public_key().to_vec();
    let new_sk = MlDsa65KeyPair::generate().unwrap();
    let new_pk = new_sk.public_key().to_vec();
    let did = format!("did:iiot:{}", Uuid::new_v4());

    let old_doc = build_did_doc(&did, &old_pk);
    let old_record = build_record_mldsa65(&old_doc, &old_sk);

    let new_doc = build_did_doc(&did, &new_pk);
    let new_record = build_record_mldsa65(&new_doc, &new_sk);

    // auth_signature = Sign(new_record_bytes, old_secret_key)
    let auth_sig_detached = old_sk.sign(&new_record).unwrap();
    let auth_sig = auth_sig_detached.clone();

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    assert!(
        handler
            .handle_update_verification(&new_record, &old_record, &auth_sig)
            .unwrap(),
        "valid key-rotation update must be accepted"
    );
}

/// Update where new_record has a valid auth_sig but an invalid self-signature
/// (the DID Document embeds key A's public key but was signed with key B) is
/// rejected at step 3 of verify_key_rotation.
#[test]
fn test_did_handler_rejects_update_with_invalid_new_record_self_sig() {
    let old_sk = MlDsa65KeyPair::generate().unwrap();
    let old_pk = old_sk.public_key().to_vec();
    let new_pk = MlDsa65KeyPair::generate().unwrap().public_key().to_vec();
    let wrong_new_sk = MlDsa65KeyPair::generate().unwrap(); // key mismatch for self-sig
    let did = format!("did:iiot:{}", Uuid::new_v4());

    let old_doc = build_did_doc(&did, &old_pk);
    let old_record = build_record_mldsa65(&old_doc, &old_sk);

    // new_record: doc embeds new_pk but is signed with wrong_new_sk → invalid self-sig
    let new_doc = build_did_doc(&did, &new_pk);
    let new_record = build_record_mldsa65(&new_doc, &wrong_new_sk);

    // auth_sig is produced correctly with old_sk
    let auth_sig = old_sk.sign(&new_record).unwrap();

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    assert!(
        !handler
            .handle_update_verification(&new_record, &old_record, &auth_sig)
            .unwrap(),
        "update must be rejected when the new record's self-signature is invalid"
    );
}

/// Key rotation with a wrong auth signature (not produced with the old key) fails.
#[test]
fn test_did_handler_rejects_invalid_auth_signature_on_update() {
    let old_sk = MlDsa65KeyPair::generate().unwrap();
    let old_pk = old_sk.public_key().to_vec();
    let new_sk = MlDsa65KeyPair::generate().unwrap();
    let new_pk = new_sk.public_key().to_vec();
    let unrelated_sk = MlDsa65KeyPair::generate().unwrap(); // wrong key for auth_sig
    let did = format!("did:iiot:{}", Uuid::new_v4());

    let old_doc = build_did_doc(&did, &old_pk);
    let old_record = build_record_mldsa65(&old_doc, &old_sk);

    let new_doc = build_did_doc(&did, &new_pk);
    let new_record = build_record_mldsa65(&new_doc, &new_sk);

    // Sign with WRONG key — should fail step 2 of key-rotation verification.
    let bad_sig = unrelated_sk.sign(&new_record).unwrap();
    let bad_sig_bytes = bad_sig.clone();

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    assert!(
        !handler
            .handle_update_verification(&new_record, &old_record, &bad_sig_bytes)
            .unwrap(),
        "update with wrong auth signature must be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA-65 records (ADR 0003)
// ─────────────────────────────────────────────────────────────────────────────

/// The signature length of a record comes from the crate, not from a literal,
/// and a signature has that length.
#[test]
fn ml_dsa_65_signature_length_is_the_crates() {
    let crate_len = aws_lc_rs::signature::ML_DSA_65_SIGNING.signature_len();
    assert_eq!(resolve_alg_and_length("ML-DSA-65").unwrap().1, crate_len);
    let key = MlDsa65KeyPair::generate().unwrap();
    assert_eq!(key.sign(b"message").unwrap().len(), crate_len);
}

/// A complete ML-DSA-65 record verifies and is bound to the key of its DID.
#[test]
fn an_ml_dsa_65_record_verifies_and_binds_to_its_key() {
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("unused"));
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let uuid = Uuid::new_v4().to_string();
    let did = format!("did:iiot:{uuid}");
    let record = build_record_mldsa65(&build_did_doc_mldsa65(&did, mldsa65_jwk(&pk)), &sk);

    assert!(handler.handle_signature_verification(&record).unwrap());
    assert!(handler
        .handle_key_binding_verification(&digest(&uuid), &record)
        .unwrap());
}

/// The record's header and its key must name the same algorithm, in the key
/// type of RFC 9964.
#[test]
fn an_ml_dsa_65_record_whose_key_says_otherwise_is_refused() {
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("unused"));
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let pub_b64 = base64url(&pk);
    for jwk in [
        json!({ "kty": "AKP", "alg": "ML-DSA-44", "pub": pub_b64 }),
        json!({ "kty": "OKP", "alg": "ML-DSA-65", "pub": pub_b64 }),
        json!({ "kty": "AKP", "pub": pub_b64 }),
        json!({ "kty": "OKP", "crv": "Dilithium2", "x": pub_b64 }),
    ] {
        let record = build_record_mldsa65(&build_did_doc_mldsa65(&did, jwk.clone()), &sk);
        assert!(
            !matches!(handler.handle_signature_verification(&record), Ok(true)),
            "accepted a record whose key is {jwk}"
        );
    }
}

/// A node accepts only ML-DSA-65 records: an Ed25519 record that is correctly
/// self-signed is refused, and so are the other algorithm fields.
#[test]
fn records_with_another_algorithm_are_refused() {
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("unused"));
    let signing_key = SigningKey::generate(&mut OsRng);
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let jwk = json!({ "kty": "OKP", "crv": "Ed25519",
                      "x": base64url(signing_key.verifying_key().as_bytes()) });
    let doc = build_did_doc_mldsa65(&did, jwk);
    let ed25519_sig = SignerFactory::get_signer("Ed25519")
        .unwrap()
        .sign(&signing_key.to_bytes(), &canonical_json(&doc))
        .unwrap();
    let ed25519_record = build_record("Ed25519", &ed25519_sig, &doc);
    assert!(!matches!(
        handler.handle_signature_verification(&ed25519_record),
        Ok(true)
    ));

    for algorithm in ["Dilithium-2", "Dilithium-3", "Dilithium-5", "RSA"] {
        let record = build_record(algorithm, &[0u8; 4627], &doc);
        assert!(
            !matches!(handler.handle_signature_verification(&record), Ok(true)),
            "accepted a record with algorithm {algorithm}"
        );
    }
}
