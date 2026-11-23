//! Scenario: cryptographic security invariants end-to-end.
//!
//! These tests exercise the full DHT path (set) to verify that the
//! security properties documented in AGENTS.md hold at the protocol level,
//! not just at the handler unit-test level.
//!
//! Covered invariants:
//!   1. Tampered payload → rejected at set() (wrong sig over modified bytes)
//!   2. Algorithm field injection → rejected (Ed25519 field, ML-DSA-65 sig)
//!   3. Downgrade after rotations → rejected: a replica holding position 2
//!      refuses position 1, sent again by anyone, as stale
//!   4. Only the key the tree commits to at a position signs it; a key
//!      revealed at an earlier position cannot.
//!
//! Ports: 15860–15865, 15886–15887.

#[path = "common.rs"]
mod common;

use auth_kademlia_rs::crypto::mldsa;
use common::{make_record, rt, start_node, Chain};

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
/// string must be rejected. A node accepts only ML-DSA-65 records, so the
/// record is refused before any verifier is chosen.
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

/// After two rotations, position 1 sent again is refused as stale by every
/// replica holding position 2: a lower position never replaces a higher one,
/// whoever holds the keys it was signed with.
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

        let chain = Chain::with_versions(2);
        let key = chain.did.clone();
        assert_eq!(
            node_a.set(&key, chain.version(0)).await,
            Some(true),
            "position 0 must be stored"
        );
        for seq in 1..=2 {
            assert_eq!(
                node_a.set(&key, chain.version(seq)).await,
                Some(true),
                "legitimate rotation to position {seq} must succeed"
            );
        }

        let downgrade = node_b.set(&key, chain.version(1)).await;
        assert_ne!(downgrade, Some(true), "a downgrade must not be confirmed");
        assert_eq!(
            node_a.get(&key).await,
            Some(chain.version(2)),
            "position 2 must remain after the downgrade attempt"
        );
    });
}

/// A key revealed at an earlier position cannot sign a later one: only the
/// key the tree commits to at that position can. The owner's node refuses
/// the forged record before sending it; the genuine one is accepted.
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

        let chain = Chain::with_versions(3);
        let key = chain.did.clone();
        assert_eq!(
            node_a.set(&key, chain.version(0)).await,
            Some(true),
            "position 0 must be stored"
        );
        for seq in 1..=2 {
            assert_eq!(
                node_a.set(&key, chain.version(seq)).await,
                Some(true),
                "rotation to position {seq} must succeed"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Position 3 signed with the key position 1 revealed.
        let forged = chain.forge(3, &chain.version(2), &chain.key_pair(1));
        assert!(
            node_a.set(&key, forged).await.is_none(),
            "the key of position 1 must not sign position 3"
        );

        assert_eq!(
            node_a.set(&key, chain.version(3)).await,
            Some(true),
            "the key of position 3 must sign position 3"
        );
        assert_eq!(
            node_b.get(&key).await,
            Some(chain.version(3)),
            "position 3 must be the current record"
        );

        node_a.stop().await;
    });
}
