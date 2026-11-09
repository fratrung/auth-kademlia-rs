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
//!   5. Invalid-signature rejection — malformed records are refused on `set`.
//!   6. Bootstrap with no reachable peers — returns empty list gracefully.
//!   7. DID identifier binding — a record cannot occupy another DID's key.
//!   8. Shutdown — `stop` and `drop` terminate the node and release its port.
//!   9. Recovery — contacts survive an outage and nodes rejoin on their own.
//!
//! Port allocation (each test uses a dedicated range to allow parallel execution):
//!   - test 1: 15700–15701
//!   - test 2: 15710–15711
//!   - test 3: 15720–15721
//!   - test 4: 15730–15732
//!   - test 5: 15750
//!   - test 6: 15760
//!   - test 7: 15897
//!   - storage-capacity report: 15895-15896
//!   - shutdown: 15898-15899, 15901-15903
//!   - recovery: 15906-15912
//!   - dead peer during publication: 15924-15927

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};

use auth_kademlia_rs::network::{SetOutcome, SetRejection};
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::{digest, ID_LEN};

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
    let dsk = MlDsa65KeyPair::generate().unwrap();
    let dpk = dsk.public_key().to_vec();
    let did = generate_did_iiot();
    let doc = build_did_document(&did, &dpk);
    let key = did.split(':').next_back().unwrap().to_string();
    let record = build_signed_record(&doc, &dsk, "ML-DSA-65");

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

    let dsk = MlDsa65KeyPair::generate().unwrap();
    let dpk = dsk.public_key().to_vec();
    let did = generate_did_iiot();
    let doc = build_did_document(&did, &dpk);
    let key = did.split(':').next_back().unwrap().to_string();
    let record = build_signed_record(&doc, &dsk, "ML-DSA-65");

    // First set must succeed.
    let first = node.set(&key, record.clone()).await;
    assert!(first.unwrap_or(false), "first set must succeed");

    // An identical retry acknowledges already-present replicas.
    let second = node.set(&key, record.clone()).await;
    assert_eq!(second, Some(true), "an identical retry must be idempotent");

    // A different valid record for the same DHT key remains a conflict.
    let other_dsk = MlDsa65KeyPair::generate().unwrap();
    let other_dpk = other_dsk.public_key().to_vec();
    let other_doc = build_did_document(&did, &other_dpk);
    let conflicting_record = build_signed_record(&other_doc, &other_dsk, "ML-DSA-65");
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
    let old_sk = MlDsa65KeyPair::generate().unwrap();
    let old_pk = old_sk.public_key().to_vec();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk);
    let old_record = build_signed_record(&old_doc, &old_sk, "ML-DSA-65");

    let stored = node2.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // ── Step 2: generate new keypair and build new record ─────────────────────
    let new_sk = MlDsa65KeyPair::generate().unwrap();
    let new_pk = new_sk.public_key().to_vec();
    let new_doc = build_did_document(&did, &new_pk);
    let new_record = build_signed_record(&new_doc, &new_sk, "ML-DSA-65");

    // ── Step 3: auth_sig proves old owner authorises this rotation ────────────
    // The protocol verifies: old_pub_key.verify(new_record, auth_sig)
    let auth_sig_ds = old_sk.sign(&new_record).unwrap();
    let auth_sig = auth_sig_ds.as_slice().to_vec();

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

/// A record whose embedded signature does not match the public key in the
/// DID Document must be rejected by `set` (returns None).
#[tokio::test]
async fn test_invalid_signature_record_rejected_on_set() {
    let mut node = start_node(15750).await;

    let _correct_sk = MlDsa65KeyPair::generate().unwrap();
    let pk = _correct_sk.public_key().to_vec();
    let wrong_sk = MlDsa65KeyPair::generate().unwrap(); // different secret key — mismatch!
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();

    // Build a record: DID Doc embeds `pk` (key A's public key) but the
    // signature is produced with `wrong_sk` (key B's secret key).
    let doc = build_did_document(&did, &pk);
    let invalid_record = build_signed_record(&doc, &wrong_sk, "ML-DSA-65");

    let result = node.set(&key, invalid_record).await;
    assert!(
        result.is_none(),
        "set with mismatched signature must return None"
    );

    node.stop().await;
}

/// A valid self-signed record cannot be stored under a key derived from a
/// different DID UUID.
#[tokio::test]
async fn test_valid_record_rejected_under_another_did_key() {
    let mut node = start_node(15897).await;
    let sk = MlDsa65KeyPair::generate().unwrap();
    let pk = sk.public_key().to_vec();
    let record_did = generate_did_iiot();
    let requested_did = generate_did_iiot();
    let requested_key = requested_did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&record_did, &pk);
    let record = build_signed_record(&doc, &sk, "ML-DSA-65");

    assert!(
        node.set(&requested_key, record.clone()).await.is_none(),
        "set must reject a valid DID Document submitted under another UUID"
    );

    node.storage.set(digest(&requested_key).to_vec(), record);
    assert!(node.get(&requested_key).await.is_none());

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
    let old_sk = MlDsa65KeyPair::generate().unwrap();
    let old_pk = old_sk.public_key().to_vec();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk);
    let old_record = build_signed_record(&old_doc, &old_sk, "ML-DSA-65");

    let stored = node1.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // Build a new record where the DID Document embeds new_pk but the
    // record is signed with wrong_new_sk — self-signature is invalid.
    let new_pk = MlDsa65KeyPair::generate().unwrap().public_key().to_vec();
    let wrong_new_sk = MlDsa65KeyPair::generate().unwrap();
    let new_doc = build_did_document(&did, &new_pk);
    let invalid_new_record = build_signed_record(&new_doc, &wrong_new_sk, "ML-DSA-65");

    // auth_sig is correctly signed with the old key — ownership proof is valid,
    // but the new record's self-signature is invalid.
    let auth_sig = old_sk.sign(&invalid_new_record).unwrap();

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
    let old_sk = MlDsa65KeyPair::generate().unwrap();
    let old_pk = old_sk.public_key().to_vec();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk);
    let old_record = build_signed_record(&old_doc, &old_sk, "ML-DSA-65");

    let stored = node2.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // Build a new record with a valid self-signature.
    let new_sk = MlDsa65KeyPair::generate().unwrap();
    let new_pk = new_sk.public_key().to_vec();
    let new_doc = build_did_document(&did, &new_pk);
    let new_record = build_signed_record(&new_doc, &new_sk, "ML-DSA-65");

    // auth_sig produced with an UNRELATED key — attacker does not own the old key.
    let unrelated_sk = MlDsa65KeyPair::generate().unwrap();
    let bad_auth_sig = unrelated_sk.sign(&new_record).unwrap();

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

#[tokio::test]
async fn test_set_detailed_reports_capacity_degraded_replication() {
    let mut limited = start_node_with_max_storage_bytes(15895, 0).await;
    let mut replica = start_node(15896).await;
    replica
        .bootstrap(vec![("127.0.0.1".to_string(), 15895)])
        .await;
    sleep(Duration::from_millis(200)).await;

    let dsk = MlDsa65KeyPair::generate().unwrap();
    let dpk = dsk.public_key().to_vec();
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let record = build_signed_record(&build_did_document(&did, &dpk), &dsk, "ML-DSA-65");

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

/// Well below the 2.5 s RPC timeout: `stop` must not wait on any peer.
const STOP_BUDGET: Duration = Duration::from_secs(1);

/// A stopped node must notify its peer without waiting for a reply, release
/// its port, and be able to rejoin the network on that same port.
#[tokio::test]
async fn test_stop_is_prompt_releases_port_and_allows_rejoin() {
    let mut node = start_node(15898).await;
    let peer = start_node(15899).await;
    peer.bootstrap(vec![("127.0.0.1".to_string(), 15898)]).await;
    sleep(Duration::from_millis(200)).await;
    assert_eq!(peer.stats().await.routing_nodes, 1);

    timeout(STOP_BUDGET, node.stop())
        .await
        .expect("stop must not wait for a Leave response");
    assert!(!node.stats().await.listening);

    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        peer.stats().await.routing_nodes,
        0,
        "the peer must process Leave and remove the stopped node"
    );

    std::net::UdpSocket::bind(("127.0.0.1", 15898)).expect("stop must release the port");
    node.stop().await; // A second stop is a no-op.

    node.listen(15898, "127.0.0.1")
        .await
        .expect("a stopped server must be able to listen again");
    let rejoined = node.bootstrap(vec![("127.0.0.1".to_string(), 15899)]).await;
    assert!(!rejoined.is_empty(), "the restarted node must rejoin");
    sleep(Duration::from_millis(200)).await;
    assert_eq!(peer.stats().await.routing_nodes, 1);
}

/// Dropping a server without calling `stop` must not leak a running node.
#[tokio::test]
async fn test_dropping_server_releases_port() {
    let node = start_node(15901).await;
    drop(node);

    timeout(Duration::from_secs(1), async {
        while std::net::UdpSocket::bind(("127.0.0.1", 15901)).is_err() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dropping the server must release the port");
}

/// `stop` must also cancel background work already waiting on a dead peer:
/// here, replication to a new contact that never answers.
#[tokio::test]
async fn test_stop_cancels_in_flight_replication() {
    let mut node = start_node(15902).await;
    let _silent_peer = std::net::UdpSocket::bind(("127.0.0.1", 15903)).expect("bind");
    node.storage.set(vec![7; ID_LEN], b"record".to_vec());
    node.protocol
        .as_ref()
        .expect("node is listening")
        .rpc_ping([9; ID_LEN], ("127.0.0.1".to_string(), 15903))
        .await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        node.stats().await.routing_nodes,
        1,
        "the replication task must have started"
    );

    timeout(STOP_BUDGET, node.stop())
        .await
        .expect("stop must not wait for in-flight replication");
    std::net::UdpSocket::bind(("127.0.0.1", 15902)).expect("stop must release the port");
}

/// Long enough for a probe that started just before the network came back to
/// time out, for its backoff to elapse, and for the next probe to succeed.
const RECOVERY_BUDGET: Duration = Duration::from_secs(30);

/// Build a valid record for a new DID, returning `(did, dht_key, record)`.
fn new_record() -> (String, String, Vec<u8>) {
    let did = generate_did_iiot();
    let key = did.split(':').next_back().unwrap().to_string();
    let record = record_for_did(&did);
    (did, key, record)
}

fn record_for_did(did: &str) -> Vec<u8> {
    let dsk = MlDsa65KeyPair::generate().unwrap();
    let dpk = dsk.public_key().to_vec();
    build_signed_record(&build_did_document(did, &dpk), &dsk, "ML-DSA-65")
}

/// Forward datagrams between two nodes until the returned flag is raised, which
/// drops everything. The first node reaches the second at `port_towards_b`, and
/// the second sees the first at `port_towards_a`.
async fn start_interruptible_link(
    port_a: u16,
    port_b: u16,
    port_towards_b: u16,
    port_towards_a: u16,
) -> Arc<AtomicBool> {
    let towards_b = Arc::new(
        UdpSocket::bind(("127.0.0.1", port_towards_b))
            .await
            .unwrap(),
    );
    let towards_a = Arc::new(
        UdpSocket::bind(("127.0.0.1", port_towards_a))
            .await
            .unwrap(),
    );
    let down = Arc::new(AtomicBool::new(false));
    let addr = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));

    for (rx, tx, destination) in [
        (towards_b.clone(), towards_a.clone(), addr(port_b)),
        (towards_a, towards_b, addr(port_a)),
    ] {
        let down = Arc::clone(&down);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((len, _)) = rx.recv_from(&mut buf).await {
                if !down.load(Ordering::Relaxed) {
                    let _ = tx.send_to(&buf[..len], destination).await;
                }
            }
        });
    }
    down
}

/// Kademlia §4.1: a node that loses its connection must not void its table. After
/// the outage both nodes reconnect with no outside help, the record published in
/// the meantime reaches the other replica, and first-writer-wins applies again.
#[tokio::test]
async fn test_outage_keeps_contacts_and_nodes_recover_on_their_own() {
    let (port_a, port_b, port_towards_b, port_towards_a) = (15906, 15907, 15908, 15909);
    let a = start_node(port_a).await;
    let b = start_node(port_b).await;
    let down = start_interruptible_link(port_a, port_b, port_towards_b, port_towards_a).await;
    a.bootstrap(vec![("127.0.0.1".to_string(), port_towards_b)])
        .await;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(a.stats().await.live_routing_nodes, 1);
    assert_eq!(b.stats().await.live_routing_nodes, 1);

    down.store(true, Ordering::Relaxed);
    let (_, absent_a, _) = new_record();
    let (_, absent_b, _) = new_record();
    let (found_a, found_b) = tokio::join!(a.get(&absent_a), b.get(&absent_b));
    assert!(found_a.is_none() && found_b.is_none());
    for node in [&a, &b] {
        let stats = node.stats().await;
        assert_eq!(
            stats.routing_nodes, 1,
            "a timeout must not remove the contact"
        );
        assert_eq!(stats.live_routing_nodes, 0);
    }

    let (_, during_outage, record) = new_record();
    let outcome = a.set_detailed(&during_outage, record).await;
    assert!(
        matches!(outcome, SetOutcome::Degraded(_)),
        "a node that is cut off must not report a complete publication: {outcome:?}"
    );

    down.store(false, Ordering::Relaxed);
    timeout(RECOVERY_BUDGET, async {
        while b.storage.get(&digest(&during_outage)).is_none() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the record published during the outage must reach the other replica");

    let (did, key, record) = new_record();
    let outcome = a.set_detailed(&key, record.clone()).await;
    assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
    assert_eq!(b.get(&key).await, Some(record));

    let outcome = b.set_detailed(&key, record_for_did(&did)).await;
    assert!(
        matches!(
            outcome,
            SetOutcome::Rejected {
                reason: SetRejection::ExistingRecord,
                ..
            }
        ),
        "{outcome:?}"
    );
}

/// A node that starts before its seed keeps trying, and hands over what it
/// published while cut off.
#[tokio::test]
async fn test_node_joins_when_its_seed_starts_late() {
    let (port, seed_port) = (15910, 15911);
    let node = start_node(port).await;
    assert!(node
        .bootstrap(vec![("127.0.0.1".to_string(), seed_port)])
        .await
        .is_empty());

    let (_, key, record) = new_record();
    let outcome = node.set_detailed(&key, record).await;
    assert!(
        matches!(outcome, SetOutcome::Degraded(_)),
        "a node with an unreachable seed is cut off, not alone: {outcome:?}"
    );

    let seed = start_node(seed_port).await;
    timeout(RECOVERY_BUDGET, async {
        while seed.storage.get(&digest(&key)).is_none() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the node must join and hand over its record");
    assert_eq!(node.stats().await.live_routing_nodes, 1);
}

/// Kademlia §2.3 and §4.1: a dead peer is neither a replica nor worth another
/// timeout, even though the other nodes have not tried it and keep reporting it.
/// The empty replicas ask the network before storing, and their first lookup
/// waits for the dead peer too: they refuse rather than guess, so the first
/// publication is degraded until a retry, and the second is not.
#[tokio::test]
async fn test_set_ignores_a_dead_peer_that_others_keep_reporting() {
    let writer = start_node(15924).await;
    let peer_a = start_node(15925).await;
    let peer_b = start_node(15926).await;
    let _silent = std::net::UdpSocket::bind(("127.0.0.1", 15927)).expect("bind");
    writer
        .bootstrap(vec![
            ("127.0.0.1".to_string(), 15925),
            ("127.0.0.1".to_string(), 15926),
        ])
        .await;
    sleep(Duration::from_millis(300)).await;
    let dead = Node::new(
        digest("dead-peer"),
        Some("127.0.0.1".to_string()),
        Some(15927),
    );
    for node in [&writer, &peer_a, &peer_b] {
        let protocol = node.protocol.as_ref().expect("node is listening");
        protocol.router.write().await.add_contact(dead.clone());
    }

    let (_, key, record) = new_record();
    let first = writer.set_detailed(&key, record.clone()).await;
    assert!(matches!(first, SetOutcome::Degraded(_)), "{first:?}");
    assert_eq!(first.report().expected_replicas, 3);
    assert_eq!(
        first.report().stored_replicas,
        1,
        "only the writer's own copy"
    );
    assert_eq!(
        first.report().unavailable_nodes,
        3,
        "the dead peer, and the two replicas that could not hear from it"
    );
    let retry = writer.set_detailed(&key, record).await;
    assert!(matches!(retry, SetOutcome::Complete(_)), "{retry:?}");
    assert_eq!(retry.report().unavailable_nodes, 1);

    let (_, key, record) = new_record();
    let started = std::time::Instant::now();
    let second = writer.set_detailed(&key, record).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the second publication took {:?}",
        started.elapsed()
    );
    assert!(matches!(second, SetOutcome::Complete(_)), "{second:?}");
    assert_eq!(second.report().unavailable_nodes, 1);
}

/// The first node of a network has nobody to reach, so one copy is complete.
#[tokio::test]
async fn test_node_that_never_had_contacts_publishes_completely() {
    let node = start_node(15912).await;
    let (_, key, record) = new_record();
    let outcome = node.set_detailed(&key, record).await;
    assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
}
