//! Integration tests for the cryptographic layer.
//!
//! Context: AuthKademlia supports three signature families — Dilithium (all
//! three security levels), Ed25519, and RSA.  Each record stored in the DHT
//! carries an algorithm tag, a raw signature, and a DID Document.  The
//! `SignatureVerifierFactory` / `SignerFactory` dispatch to the correct
//! implementation at runtime.
//!
//! These tests cover:
//!   1. Sign-then-verify round-trips for Dilithium-2/3/5 and Ed25519.
//!   2. Rejection of tampered messages and wrong keys.
//!   3. Factory dispatch correctness and unknown-algorithm errors.
//!   4. Algorithm-string to signature-length resolution.
//!   5. End-to-end DID record creation and verification via
//!      `DIDSignatureVerifierHandler` (the handler used by the server).

use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use uuid::Uuid;

use auth_kademlia_rs::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use auth_kademlia_rs::crypto::factory::{SignatureVerifierFactory, SignerFactory};
use auth_kademlia_rs::crypto::signature_verifier::{
    dilithium_level_from_pubkey_len, resolve_alg_and_length,
};
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

/// Build a minimal DID Document with a Dilithium-2 verification key.
fn build_did_doc_d2(did: &str, pk: &dilithium2::PublicKey) -> Value {
    let (kyber_pk, _) = kyber512::keypair();
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#k0", did),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2", "x": base64url(pk.as_bytes()) }
        },{
            "id": format!("{}#k1", did),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512", "x": base64url(kyber_pk.as_bytes()) }
        }],
        "authentication": [ format!("{}#k0", did) ],
        "keyAgreement":   [ format!("{}#k1", did) ],
        "service": [{"id": format!("{}#d", did), "type": "DeviceAgent",
                     "serviceEndpoint": "http://example.com"}]
    })
}

/// Build a signed DHT record: `alg_field(12) | signature | DID Doc JSON`.
fn build_record_d2(doc: &Value, sk: &dilithium2::SecretKey) -> Vec<u8> {
    let doc_bytes = canonical_json(doc);
    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");
    let sig = dilithium2::detached_sign(&doc_bytes, sk);
    let mut rec = Vec::with_capacity(12 + sig.as_bytes().len() + doc_bytes.len());
    rec.extend_from_slice(&alg);
    rec.extend_from_slice(sig.as_bytes());
    rec.extend_from_slice(&doc_bytes);
    rec
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
fn test_resolve_dilithium_levels() {
    assert_eq!(
        resolve_alg_and_length("Dilithium-2").unwrap(),
        ("Dilithium".into(), 2420)
    );
    assert_eq!(
        resolve_alg_and_length("Dilithium-3").unwrap(),
        ("Dilithium".into(), 3293)
    );
    assert_eq!(
        resolve_alg_and_length("Dilithium-5").unwrap(),
        ("Dilithium".into(), 4595)
    );
}

#[test]
fn test_resolve_unknown_algorithm_fails() {
    assert!(resolve_alg_and_length("ECDSA").is_err());
    assert!(resolve_alg_and_length("Dilithium").is_err()); // missing level
}

#[test]
fn test_dilithium_level_from_pubkey_length() {
    assert_eq!(dilithium_level_from_pubkey_len(1312), Some(2));
    assert_eq!(dilithium_level_from_pubkey_len(1952), Some(3));
    assert_eq!(dilithium_level_from_pubkey_len(2592), Some(5));
    assert_eq!(dilithium_level_from_pubkey_len(1234), None);
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
    for alg in &[
        "Dilithium-2",
        "Dilithium-3",
        "Dilithium-5",
        "Ed25519",
        "RSA",
    ] {
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
// Dilithium-2 sign / verify
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dilithium2_sign_and_verify() {
    let (pk, sk) = dilithium2::keypair();
    let msg = b"dilithium-2 test message";

    let signer = SignerFactory::get_signer("Dilithium-2").unwrap();
    let sig = signer.sign(sk.as_bytes(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-2").unwrap();
    assert!(
        verifier.verify(pk.as_bytes(), &sig, msg).unwrap(),
        "valid Dilithium-2 signature must verify"
    );
}

#[test]
fn test_dilithium2_tampered_message_rejected() {
    let (pk, sk) = dilithium2::keypair();
    let msg = b"original message";

    let signer = SignerFactory::get_signer("Dilithium-2").unwrap();
    let sig = signer.sign(sk.as_bytes(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-2").unwrap();
    let tampered = b"tampered message!";
    assert!(
        !verifier.verify(pk.as_bytes(), &sig, tampered).unwrap(),
        "signature over different message must not verify"
    );
}

#[test]
fn test_dilithium2_wrong_key_rejected() {
    let (_, sk) = dilithium2::keypair();
    let (wrong_pk, _) = dilithium2::keypair(); // different keypair
    let msg = b"message signed with sk";

    let signer = SignerFactory::get_signer("Dilithium-2").unwrap();
    let sig = signer.sign(sk.as_bytes(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-2").unwrap();
    assert!(
        !verifier.verify(wrong_pk.as_bytes(), &sig, msg).unwrap(),
        "signature must not verify under a different public key"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dilithium-3 sign / verify
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dilithium3_sign_and_verify() {
    let (pk, sk) = dilithium3::keypair();
    let msg = b"dilithium-3 test";

    let signer = SignerFactory::get_signer("Dilithium-3").unwrap();
    let sig = signer.sign(sk.as_bytes(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-3").unwrap();
    assert!(verifier.verify(pk.as_bytes(), &sig, msg).unwrap());
}

#[test]
fn test_dilithium3_tampered_message_rejected() {
    let (pk, sk) = dilithium3::keypair();
    let signer = SignerFactory::get_signer("Dilithium-3").unwrap();
    let sig = signer.sign(sk.as_bytes(), b"original").unwrap();
    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-3").unwrap();
    assert!(!verifier.verify(pk.as_bytes(), &sig, b"tampered").unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// Dilithium-5 sign / verify
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dilithium5_sign_and_verify() {
    let (pk, sk) = dilithium5::keypair();
    let msg = b"dilithium-5 highest security level";

    let signer = SignerFactory::get_signer("Dilithium-5").unwrap();
    let sig = signer.sign(sk.as_bytes(), msg).unwrap();

    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-5").unwrap();
    assert!(verifier.verify(pk.as_bytes(), &sig, msg).unwrap());
}

#[test]
fn test_dilithium5_tampered_message_rejected() {
    let (pk, sk) = dilithium5::keypair();
    let signer = SignerFactory::get_signer("Dilithium-5").unwrap();
    let sig = signer.sign(sk.as_bytes(), b"original").unwrap();
    let verifier = SignatureVerifierFactory::get_verifier("Dilithium-5").unwrap();
    assert!(!verifier.verify(pk.as_bytes(), &sig, b"tampered").unwrap());
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
    let (pk, sk) = dilithium2::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let doc = build_did_doc_d2(&did, &pk);
    let record = build_record_d2(&doc, &sk);

    // issuer_pub_key.bin path is irrelevant for self-signed verification.
    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    assert!(
        handler.handle_signature_verification(&record).unwrap(),
        "valid self-signed record must pass verification"
    );
}

#[test]
fn test_did_handler_accepts_record_bound_to_requested_key() {
    let (pk, sk) = dilithium2::keypair();
    let uuid = Uuid::new_v4().to_string();
    let doc = build_did_doc_d2(&format!("did:iiot:{uuid}"), &pk);
    let record = build_record_d2(&doc, &sk);
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
    let (pk, sk) = dilithium2::keypair();
    let record_uuid = Uuid::new_v4().to_string();
    let requested_uuid = Uuid::new_v4().to_string();
    let doc = build_did_doc_d2(&format!("did:iiot:{record_uuid}"), &pk);
    let record = build_record_d2(&doc, &sk);
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
    let (pk, sk) = dilithium2::keypair();
    let doc = build_did_doc_d2("did:iiot:not-a-uuid", &pk);
    let record = build_record_d2(&doc, &sk);
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
    let (pk, _) = dilithium2::keypair();
    let (_, wrong_sk) = dilithium2::keypair(); // key mismatch
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let doc = build_did_doc_d2(&did, &pk); // public key from keypair A
    let record = build_record_d2(&doc, &wrong_sk); // signed with keypair B's secret key

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    let result = handler.handle_signature_verification(&record).unwrap();
    assert!(!result, "mismatched key should cause verification failure");
}

/// A record whose DID Document JSON has been tampered with after signing
/// must be rejected.
#[test]
fn test_did_handler_rejects_tampered_did_document() {
    let (pk, sk) = dilithium2::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let doc = build_did_doc_d2(&did, &pk);
    let mut record = build_record_d2(&doc, &sk);

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
    let (old_pk, old_sk) = dilithium2::keypair();
    let (new_pk, new_sk) = dilithium2::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());

    let old_doc = build_did_doc_d2(&did, &old_pk);
    let old_record = build_record_d2(&old_doc, &old_sk);

    let new_doc = build_did_doc_d2(&did, &new_pk);
    let new_record = build_record_d2(&new_doc, &new_sk);

    // auth_signature = Sign(new_record_bytes, old_secret_key)
    let auth_sig_detached = dilithium2::detached_sign(&new_record, &old_sk);
    let auth_sig = auth_sig_detached.as_bytes().to_vec();

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
    let (old_pk, old_sk) = dilithium2::keypair();
    let (new_pk, _) = dilithium2::keypair();
    let (_, wrong_new_sk) = dilithium2::keypair(); // key mismatch for self-sig
    let did = format!("did:iiot:{}", Uuid::new_v4());

    let old_doc = build_did_doc_d2(&did, &old_pk);
    let old_record = build_record_d2(&old_doc, &old_sk);

    // new_record: doc embeds new_pk but is signed with wrong_new_sk → invalid self-sig
    let new_doc = build_did_doc_d2(&did, &new_pk);
    let new_record = build_record_d2(&new_doc, &wrong_new_sk);

    // auth_sig is produced correctly with old_sk
    let auth_sig = dilithium2::detached_sign(&new_record, &old_sk)
        .as_bytes()
        .to_vec();

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
    let (old_pk, old_sk) = dilithium2::keypair();
    let (new_pk, new_sk) = dilithium2::keypair();
    let (_, unrelated_sk) = dilithium2::keypair(); // wrong key for auth_sig
    let did = format!("did:iiot:{}", Uuid::new_v4());

    let old_doc = build_did_doc_d2(&did, &old_pk);
    let old_record = build_record_d2(&old_doc, &old_sk);

    let new_doc = build_did_doc_d2(&did, &new_pk);
    let new_record = build_record_d2(&new_doc, &new_sk);

    // Sign with WRONG key — should fail step 2 of key-rotation verification.
    let bad_sig = dilithium2::detached_sign(&new_record, &unrelated_sk);
    let bad_sig_bytes = bad_sig.as_bytes().to_vec();

    let handler = DIDSignatureVerifierHandler::new(PathBuf::from("irrelevant.bin"));
    assert!(
        !handler
            .handle_update_verification(&new_record, &old_record, &bad_sig_bytes)
            .unwrap(),
        "update with wrong auth signature must be rejected"
    );
}
