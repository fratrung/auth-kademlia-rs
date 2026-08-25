//! Full DHT integration tests — multi-node flows.
//!
//! Context: these tests exercise the complete application stack: UDP sockets,
//! the Kademlia protocol layer, routing-table updates, and cryptographic record
//! verification.  Each test spins up real DHT nodes on loopback and validates
//! the end-to-end behaviour described in the README.
//!
//! Covered flows:
//!   1. Two-node bootstrap — nodes discover each other.
//!   2. Cross-node publish & retrieve — Node A stores, Node B retrieves.
//!   3. Idempotent retry and conflicting-value rejection.
//!   4. Key-rotation update — a DID owner rotates their key (update flow).
//!   5. Authenticated delete — a DID owner deletes their record.
//!   6. Invalid-signature rejection — malformed records are refused on `set`.
//!   7. Bootstrap with no reachable peers — returns empty list gracefully.
//!
//! Port allocation (each test uses a dedicated range to allow parallel execution):
//!   - test 1: 15700–15701
//!   - test 2: 15710–15711
//!   - test 3: 15720–15721
//!   - test 4: 15730–15732
//!   - test 5: 15740–15741
//!   - test 6: 15750
//!   - test 7: 15760
//!   - storage-capacity report: 15895-15896

mod common;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::DetachedSignature;
use tokio::time::{sleep, Duration};

use auth_kademlia_rs::network::SetOutcome;

use common::{
    build_did_document, build_signed_record, generate_did_iiot, start_node,
    start_node_with_max_storage_bytes,
};

/// Two nodes bootstrap from each other and end up in each other's routing table.
#[tokio::test]
async fn test_two_node_bootstrap_discover_each_other() {
    let _node1 = start_node(15700).await;
    let node2 = start_node(15701).await;

    let discovered = node2
        .bootstrap(vec![("127.0.0.1".to_string(), 15700)])
        .await;

    // After bootstrap, node2 should have discovered node1 (and possibly itself).
    assert!(
        !discovered.is_empty(),
        "bootstrap should discover at least the seed node"
    );

    // node2 should now have node1 as a bootstrappable neighbour.
    let neighbours = node2.bootstrappable_neighbors().await;
    assert!(
        !neighbours.is_empty(),
        "after bootstrap, routing table should contain at least one neighbour"
    );
}

/// Node A stores a signed DID record; Node B retrieves it.
/// This is the primary use case described in the README.
#[tokio::test]
async fn test_set_on_node_a_and_get_from_node_b() {
    let mut node_a = start_node(15710).await;
    let node_b = start_node(15711).await;

    // Bootstrap so both nodes are aware of each other.
    node_b
        .bootstrap(vec![("127.0.0.1".to_string(), 15710)])
        .await;
    sleep(Duration::from_millis(200)).await;

    // Build a valid signed DID record.
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let doc = build_did_document(&did, &dpk, &kpk);
    let key = did.split(':').next_back().unwrap().to_string();
    let record = build_signed_record(&doc, &dsk, "Dilithium-2");

    // Node A publishes the record.
    let store_result = node_a.set(&key, record.clone()).await;
    assert!(
        store_result.unwrap_or(false),
        "set should succeed on the first call"
    );

    // Node B retrieves it — may come from node_a via the network.
    let retrieved = node_b.get(&key).await;
    assert!(
        retrieved.is_some(),
        "Node B should be able to retrieve the record stored by Node A"
    );

    // Verify the retrieved bytes match what was stored.
    assert_eq!(retrieved.unwrap(), record);

    node_a.stop().await;
}

/// Re-publishing identical bytes is idempotent; different bytes still conflict.
#[tokio::test]
async fn test_set_is_idempotent_but_rejects_conflicting_value() {
    let mut node = start_node(15720).await;
    let node_b = start_node(15721).await;
    node_b
        .bootstrap(vec![("127.0.0.1".to_string(), 15720)])
        .await;
    sleep(Duration::from_millis(200)).await;

    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let doc = build_did_document(&did, &dpk, &kpk);
    let key = did.split(':').next_back().unwrap().to_string();
    let record = build_signed_record(&doc, &dsk, "Dilithium-2");

    // First set must succeed.
    let first = node.set(&key, record.clone()).await;
    assert!(first.unwrap_or(false), "first set must succeed");

    // An identical retry acknowledges already-present replicas.
    let second = node.set(&key, record.clone()).await;
    assert_eq!(second, Some(true), "an identical retry must be idempotent");

    // A different valid record for the same DHT key remains a conflict.
    let (other_dpk, other_dsk) = dilithium2::keypair();
    let (other_kpk, _) = kyber512::keypair();
    let other_doc = build_did_document(&did, &other_dpk, &other_kpk);
    let conflicting_record = build_signed_record(&other_doc, &other_dsk, "Dilithium-2");
    assert!(
        node.set(&key, conflicting_record).await.is_none(),
        "immutable records must reject different bytes for an occupied key"
    );

    node.stop().await;
}

/// A DID owner rotates their key using the `update` operation:
///   1. Store old record (signed with old keypair).
///   2. Build new record (signed with new keypair).
///   3. auth_sig = Sign(new_record_bytes, old_secret_key) — proves ownership.
///   4. `update` succeeds; subsequent `get` returns the new record.
#[tokio::test]
async fn test_update_did_record_key_rotation() {
    let mut node1 = start_node(15730).await;
    let mut node2 = start_node(15731).await;
    let mut node3 = start_node(15732).await;

    node2
        .bootstrap(vec![("127.0.0.1".to_string(), 15730)])
        .await;
    node3
        .bootstrap(vec![("127.0.0.1".to_string(), 15730)])
        .await;
    sleep(Duration::from_millis(300)).await;

    // ── Step 1: generate old keypair and publish original record ──────────────
    let (old_pk, old_sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk, &kpk);
    let old_record = build_signed_record(&old_doc, &old_sk, "Dilithium-2");

    let stored = node2.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // ── Step 2: generate new keypair and build new record ─────────────────────
    let (new_pk, new_sk) = dilithium2::keypair();
    let (new_kpk, _) = kyber512::keypair();
    let new_doc = build_did_document(&did, &new_pk, &new_kpk);
    let new_record = build_signed_record(&new_doc, &new_sk, "Dilithium-2");

    // ── Step 3: auth_sig proves old owner authorises this rotation ────────────
    // The protocol verifies: old_pub_key.verify(new_record, auth_sig)
    let auth_sig_ds = dilithium2::detached_sign(&new_record, &old_sk);
    let auth_sig = auth_sig_ds.as_bytes().to_vec();

    // ── Step 4: update via node3 ──────────────────────────────────────────────
    let updated = node3.update(&key, new_record.clone(), Some(auth_sig)).await;
    assert!(updated.unwrap_or(false), "key-rotation update must succeed");

    // ── Step 5: all nodes must return the NEW record ─────────────────────────
    // Give the network a moment to propagate the update.
    sleep(Duration::from_millis(500)).await;

    // node1 — neutral observer, verifies network-wide propagation.
    let from_node1 = node1.get(&key).await;
    assert!(
        from_node1.is_some(),
        "node1 must return the new record after update"
    );
    assert_eq!(
        from_node1.unwrap(),
        new_record,
        "node1: retrieved record must match the new record"
    );

    // node2 — original storing node; must no longer serve the old record.
    let from_node2 = node2.get(&key).await;
    assert!(
        from_node2.is_some(),
        "node2 must return the new record after update"
    );
    assert_eq!(
        from_node2.unwrap(),
        new_record,
        "node2: old record must be replaced by the new one"
    );

    node1.stop().await;
    node2.stop().await;
    node3.stop().await;
}

/// A DID owner deletes their record by signing a delete message with their key.
/// After deletion, `get` returns None.
#[tokio::test]
async fn test_delete_did_record() {
    let mut node1 = start_node(15740).await;
    let node2 = start_node(15741).await;

    node2
        .bootstrap(vec![("127.0.0.1".to_string(), 15740)])
        .await;
    sleep(Duration::from_millis(500)).await;

    // Store a record.
    let (pk, sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &pk, &kpk);
    let record = build_signed_record(&doc, &sk, "Dilithium-2");

    let stored = node1.set(&key, record.clone()).await;
    assert!(
        stored.unwrap_or(false),
        "store must succeed before delete test"
    );
    sleep(Duration::from_millis(500)).await;

    // Build and sign the delete message.
    let delete_msg = b"DELETE THIS DID RECORD";
    let del_sig_ds = dilithium2::detached_sign(delete_msg, &sk);
    let del_sig = del_sig_ds.as_bytes().to_vec();

    // Node2 requests the delete.
    let deleted = node2.delete(&key, del_sig, delete_msg.to_vec()).await;
    assert!(
        deleted.unwrap_or(false),
        "authenticated delete must succeed"
    );

    // After deletion, get should return None.
    sleep(Duration::from_millis(500)).await;
    let after = node1.get(&key).await;
    assert!(
        after.is_none(),
        "get after authenticated delete must return None"
    );

    node1.stop().await;
}

/// A record whose embedded signature does not match the public key in the
/// DID Document must be rejected by `set` (returns None).
#[tokio::test]
async fn test_invalid_signature_record_rejected_on_set() {
    let mut node = start_node(15750).await;

    let (pk, _correct_sk) = dilithium2::keypair();
    let (_, wrong_sk) = dilithium2::keypair(); // different secret key — mismatch!
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();

    // Build a record: DID Doc embeds `pk` (key A's public key) but the
    // signature is produced with `wrong_sk` (key B's secret key).
    let doc = build_did_document(&did, &pk, &kpk);
    let invalid_record = build_signed_record(&doc, &wrong_sk, "Dilithium-2");

    let result = node.set(&key, invalid_record).await;
    assert!(
        result.is_none(),
        "set with mismatched signature must return None"
    );

    node.stop().await;
}

/// Bootstrapping against an address where no node is listening returns an
/// empty discovered list gracefully (no panic, no hang).
#[tokio::test]
async fn test_bootstrap_unreachable_peer_returns_empty() {
    let node = start_node(15760).await;

    // Port 15799 has no listener.
    let discovered = node.bootstrap(vec![("127.0.0.1".to_string(), 15799)]).await;

    assert!(
        discovered.is_empty(),
        "bootstrap against an unreachable peer must return an empty list"
    );
}

/// `update` must return None when the submitted new record has a valid
/// auth_signature (proving ownership of the old key) but an invalid
/// self-signature (the embedded public key does not match the signing key).
///
/// This exercises the rpc_update path on a live three-replica setup.
#[tokio::test]
async fn test_update_rejected_when_new_record_self_sig_invalid() {
    let mut node1 = start_node(15780).await;
    let node2 = start_node(15781).await;
    let node3 = start_node(15885).await;

    node2
        .bootstrap(vec![("127.0.0.1".to_string(), 15780)])
        .await;
    node3
        .bootstrap(vec![("127.0.0.1".to_string(), 15780)])
        .await;
    sleep(Duration::from_millis(200)).await;

    // Store a valid original record on node1.
    let (old_pk, old_sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk, &kpk);
    let old_record = build_signed_record(&old_doc, &old_sk, "Dilithium-2");

    let stored = node1.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // Build a new record where the DID Document embeds new_pk but the
    // record is signed with wrong_new_sk — self-signature is invalid.
    let (new_pk, _) = dilithium2::keypair();
    let (_, wrong_new_sk) = dilithium2::keypair();
    let (new_kpk, _) = kyber512::keypair();
    let new_doc = build_did_document(&did, &new_pk, &new_kpk);
    let invalid_new_record = build_signed_record(&new_doc, &wrong_new_sk, "Dilithium-2");

    // auth_sig is correctly signed with the old key — ownership proof is valid,
    // but the new record's self-signature is invalid.
    let auth_sig = dilithium2::detached_sign(&invalid_new_record, &old_sk)
        .as_bytes()
        .to_vec();

    let result = node2.update(&key, invalid_new_record, Some(auth_sig)).await;
    assert!(
        result.is_none(),
        "update must be rejected when the new record's self-signature is invalid"
    );

    // Original record must still be retrievable.
    let still_there = node1.get(&key).await;
    assert!(
        still_there.is_some(),
        "original record must remain after rejected update"
    );
    assert_eq!(still_there.unwrap(), old_record);

    node1.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Update rejected when auth_sig uses a wrong key (port 15782–15784)
// ─────────────────────────────────────────────────────────────────────────────

/// `update` must return None when the auth_signature is produced by a third
/// party (not the old key owner), even if the new record carries a valid
/// self-signature.  The original record must survive the failed attempt.
///
/// This exercises step 2 of `verify_key_rotation`: the auth_sig is checked
/// against the OLD public key embedded in the stored record.
#[tokio::test]
async fn test_update_rejected_when_auth_signature_uses_wrong_key() {
    let mut node1 = start_node(15782).await;
    let node2 = start_node(15783).await;
    let mut node3 = start_node(15784).await;

    node2
        .bootstrap(vec![("127.0.0.1".to_string(), 15782)])
        .await;
    node3
        .bootstrap(vec![("127.0.0.1".to_string(), 15782)])
        .await;
    sleep(Duration::from_millis(300)).await;

    // Store valid original record.
    let (old_pk, old_sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk, &kpk);
    let old_record = build_signed_record(&old_doc, &old_sk, "Dilithium-2");

    let stored = node2.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // Build a new record with a valid self-signature.
    let (new_pk, new_sk) = dilithium2::keypair();
    let (new_kpk, _) = kyber512::keypair();
    let new_doc = build_did_document(&did, &new_pk, &new_kpk);
    let new_record = build_signed_record(&new_doc, &new_sk, "Dilithium-2");

    // auth_sig produced with an UNRELATED key — attacker does not own the old key.
    let (_, unrelated_sk) = dilithium2::keypair();
    let bad_auth_sig = dilithium2::detached_sign(&new_record, &unrelated_sk)
        .as_bytes()
        .to_vec();

    // Update via node3 must be rejected.
    let result = node3.update(&key, new_record, Some(bad_auth_sig)).await;
    assert!(
        result.is_none(),
        "update with wrong auth_sig must return None"
    );

    // Original record must still be retrievable from a neutral node.
    sleep(Duration::from_millis(200)).await;
    let still_there = node1.get(&key).await;
    assert!(
        still_there.is_some(),
        "original record must survive a rejected update"
    );
    assert_eq!(
        still_there.unwrap(),
        old_record,
        "record content must be unchanged"
    );

    node1.stop().await;
    node3.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Delete rejected when signature uses a wrong key (ports 15785–15786, 15884)
// ─────────────────────────────────────────────────────────────────────────────

/// `delete` must return None when the auth_signature is not produced by the
/// record owner.  The record must remain in the DHT after the failed attempt.
#[tokio::test]
async fn test_delete_rejected_when_signature_uses_wrong_key() {
    let mut node1 = start_node(15785).await;
    let node2 = start_node(15786).await;
    let node3 = start_node(15884).await;

    node2
        .bootstrap(vec![("127.0.0.1".to_string(), 15785)])
        .await;
    node3
        .bootstrap(vec![("127.0.0.1".to_string(), 15785)])
        .await;
    sleep(Duration::from_millis(200)).await;

    // Store a valid record on node1.
    let (pk, sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &pk, &kpk);
    let record = build_signed_record(&doc, &sk, "Dilithium-2");

    let stored = node1.set(&key, record.clone()).await;
    assert!(stored.unwrap_or(false), "store must succeed");
    sleep(Duration::from_millis(200)).await;

    // Attempt delete with an UNRELATED key — not the record owner.
    let (_, unrelated_sk) = dilithium2::keypair();
    let delete_msg = b"DELETE THIS DID RECORD";
    let bad_sig = dilithium2::detached_sign(delete_msg, &unrelated_sk)
        .as_bytes()
        .to_vec();

    let result = node2.delete(&key, bad_sig, delete_msg.to_vec()).await;
    assert!(result.is_none(), "delete with wrong key must return None");

    // Record must still be retrievable after the rejected delete.
    sleep(Duration::from_millis(200)).await;
    let still_there = node1.get(&key).await;
    assert!(
        still_there.is_some(),
        "record must survive a rejected delete"
    );
    assert_eq!(
        still_there.unwrap(),
        record,
        "record content must be unchanged"
    );

    node1.stop().await;
}

#[tokio::test]
async fn test_set_detailed_reports_capacity_degraded_replication() {
    let mut limited = start_node_with_max_storage_bytes(15895, 0).await;
    let mut replica = start_node(15896).await;
    replica
        .bootstrap(vec![("127.0.0.1".to_string(), 15895)])
        .await;
    sleep(Duration::from_millis(200)).await;

    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let record = build_signed_record(&build_did_document(&did, &dpk, &kpk), &dsk, "Dilithium-2");

    let outcome = limited.set_detailed(&key, record.clone()).await;
    let report = match outcome {
        SetOutcome::Degraded(report) => report,
        other => panic!("expected degraded publication, got {other:?}"),
    };
    assert_eq!(report.expected_replicas, 2);
    assert_eq!(report.capacity_rejections, 1);
    assert_eq!(report.acknowledged_replicas(), 1);
    assert_eq!(replica.get(&key).await, Some(record));

    limited.stop().await;
    replica.stop().await;
}
