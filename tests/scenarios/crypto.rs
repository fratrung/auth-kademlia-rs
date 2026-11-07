//! Scenario: cryptographic security invariants end-to-end.
//!
//! These tests exercise the full DHT path (set/update) to verify that the
//! security properties documented in AGENTS.md hold at the protocol level,
//! not just at the handler unit-test level.
//!
//! Covered invariants:
//!   1. Tampered payload → rejected at set() (wrong sig over modified bytes)
//!   2. Algorithm field injection → rejected (Ed25519 field, ML-DSA-65 sig)
//!   3. Key rotation downgrade attack → rejected after v1→v2 rotation,
//!      an attacker who holds sk1 cannot submit v1 as "new record" to
//!      replace v2 (they would need sk2, which they do not possess)
//!   4. Key rotation chain: only the current key owner can authorise the next
//!      rotation — old keys are revoked after each rotation.
//!
//! Ports: 15860–15865, 15886–15887.

#[path = "common.rs"]
mod common;

use auth_kademlia_rs::crypto::mldsa::{self as mldsa, MlDsa65KeyPair};
use common::{
    build_did_document, build_signed_record, generate_did_iiot, make_record, rt, start_node,
};

/// A record whose payload bytes have been tampered with must be rejected.
/// The signature was produced over the original bytes — any modification
/// invalidates the signature under the embedded public key.
///
/// Port: 15860.
#[test]
fn tampered_payload_rejected() {
    rt().block_on(async {
        let node = start_node(15860).await;
        let (key, mut record) = make_record();

        // Flip one byte in the DID Document section (after alg[12] + signature).
        let tamper_pos = 12 + mldsa::signature_len() + 10;
        record[tamper_pos] ^= 0xFF;

        let result = node.set(&key, record).await;
        assert!(
            result.is_none(),
            "set with tampered payload must return None"
        );

        // Original key must remain unoccupied — nothing was stored.
        let stored = node.get(&key).await;
        assert!(stored.is_none(), "tampered record must not be stored");
    });
}

/// A record whose algorithm field has been replaced with a different algorithm
/// string must be rejected. A node accepts only ML-DSA-65 records (ADR 0003),
/// so the record is refused before any verifier is chosen; were Ed25519
/// accepted, its 64-byte signature length would still cut the record in the
/// wrong place.
///
/// Port: 15861.
#[test]
fn algorithm_field_injection_rejected() {
    rt().block_on(async {
        let node = start_node(15861).await;
        let (key, mut record) = make_record(); // genuine ML-DSA-65 record

        // Replace the 12-byte algorithm field with "Ed25519", an algorithm no
        // record may use.
        let mut alg = [0u8; 12];
        alg[..7].copy_from_slice(b"Ed25519");
        record[..12].copy_from_slice(&alg);

        let result = node.set(&key, record).await;
        assert!(
            result.is_none(),
            "algorithm field injection must be rejected"
        );
    });
}

/// After a v1→v2 key rotation, an attacker who still holds sk1 cannot
/// substitute v1 back as the "new record". Producing a valid auth_signature
/// over v1 requires signing with sk2 — which the attacker does not have.
///
/// AGENTS.md invariant: "downgrade attacks are impossible: to submit record_v1
/// as 'new' when record_v2 is stored, an attacker would need to sign with sk_v2."
///
/// Ports: 15862–15863, 15886.
#[test]
fn downgrade_attack_after_rotation_rejected() {
    rt().block_on(async {
        let node_a = start_node(15862).await;
        let node_b = start_node(15863).await;
        let node_c = start_node(15886).await;
        node_b
            .bootstrap(vec![("127.0.0.1".to_string(), 15862)])
            .await;
        node_c
            .bootstrap(vec![("127.0.0.1".to_string(), 15862)])
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // v1: owner publishes with keypair_1.
        let sk1 = MlDsa65KeyPair::generate().unwrap();
        let pk1 = sk1.public_key().to_vec();
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap().to_string();
        let doc_v1 = build_did_document(&did, &pk1);
        let record_v1 = build_signed_record(&doc_v1, &sk1, "ML-DSA-65");

        assert_eq!(
            node_a.set(&key, record_v1.clone()).await,
            Some(true),
            "v1 store must succeed"
        );

        // Legitimate v1→v2 rotation: auth_sig = sign(record_v2, sk1).
        let sk2 = MlDsa65KeyPair::generate().unwrap();
        let pk2 = sk2.public_key().to_vec();
        let doc_v2 = build_did_document(&did, &pk2);
        let record_v2 = build_signed_record(&doc_v2, &sk2, "ML-DSA-65");
        let auth_v1_to_v2 = sk1.sign(&record_v2).unwrap();

        assert_eq!(
            node_a
                .update(&key, record_v2.clone(), Some(auth_v1_to_v2))
                .await,
            Some(true),
            "legitimate rotation v1→v2 must succeed"
        );

        // Downgrade attempt: attacker tries to submit v1 as "update" to v2.
        // They produce auth_sig = sign(record_v1, sk1) — using the key they still hold.
        // Protocol checks: verify(pk2, auth_sig, record_v1) → fails (sk1 ≠ sk2).
        let fake_auth = sk1.sign(&record_v1).unwrap();

        let downgrade = node_b
            .update(&key, record_v1.clone(), Some(fake_auth))
            .await;
        assert!(
            downgrade.is_none(),
            "downgrade attack must be rejected — attacker cannot produce auth_sig with sk2"
        );

        // v2 must still be the current record — the downgrade had no effect.
        let current = node_a.get(&key).await;
        assert_eq!(
            current,
            Some(record_v2),
            "v2 must remain after failed downgrade attempt"
        );
    });
}

/// After v1→v2 rotation, the old key (sk1) cannot authorise a third rotation.
/// Only sk2 (the current owner) can produce a valid auth_signature for v3.
///
/// Also verifies the positive case: sk2 does authorise v2→v3.
///
/// Ports: 15864–15865, 15887.
#[test]
fn revoked_key_cannot_authorise_further_rotation() {
    rt().block_on(async {
        let mut node_a = start_node(15864).await;
        let node_b = start_node(15865).await;
        let node_c = start_node(15887).await;
        node_b
            .bootstrap(vec![("127.0.0.1".to_string(), 15864)])
            .await;
        node_c
            .bootstrap(vec![("127.0.0.1".to_string(), 15864)])
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // v1 → v2 rotation (legitimate).
        let sk1 = MlDsa65KeyPair::generate().unwrap();
        let pk1 = sk1.public_key().to_vec();
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap().to_string();
        let doc_v1 = build_did_document(&did, &pk1);
        let record_v1 = build_signed_record(&doc_v1, &sk1, "ML-DSA-65");

        assert_eq!(
            node_a.set(&key, record_v1.clone()).await,
            Some(true),
            "v1 store must succeed"
        );

        let sk2 = MlDsa65KeyPair::generate().unwrap();
        let pk2 = sk2.public_key().to_vec();
        let doc_v2 = build_did_document(&did, &pk2);
        let record_v2 = build_signed_record(&doc_v2, &sk2, "ML-DSA-65");
        let auth_v1_v2 = sk1.sign(&record_v2).unwrap();
        assert_eq!(
            node_a
                .update(&key, record_v2.clone(), Some(auth_v1_v2))
                .await,
            Some(true),
            "v1→v2 rotation must succeed"
        );

        // Wait for the v1→v2 UPDATE RPC to propagate to both replicas.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Build v3; try to authorise with the revoked sk1.
        // node_a is used as the caller: its update_digest sends UPDATE RPCs to
        // the replicas, which hold v2 and can verify the rotation correctly.
        let sk3 = MlDsa65KeyPair::generate().unwrap();
        let pk3 = sk3.public_key().to_vec();
        let doc_v3 = build_did_document(&did, &pk3);
        let record_v3 = build_signed_record(&doc_v3, &sk3, "ML-DSA-65");
        let bad_auth = sk1.sign(&record_v3).unwrap();

        let rejected = node_a.update(&key, record_v3.clone(), Some(bad_auth)).await;
        assert!(
            rejected.is_none(),
            "revoked key sk1 must not authorise v2→v3 rotation"
        );

        // Positive case: sk2 (current owner) DOES authorise v2→v3.
        let good_auth = sk2.sign(&record_v3).unwrap();
        let accepted = node_a
            .update(&key, record_v3.clone(), Some(good_auth))
            .await;
        assert_eq!(
            accepted,
            Some(true),
            "current key sk2 must authorise v2→v3 rotation"
        );

        let current = node_b.get(&key).await;
        assert_eq!(current, Some(record_v3), "v3 must be the current record");

        node_a.stop().await;
    });
}
