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
    build_signed_record, key_of, new_did_record, start_node, start_node_with_max_storage_bytes,
    version0, Chain,
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

    // Version 0 of a new DID.
    let (key, record) = new_did_record();

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

    let chain = Chain::new();
    let key = chain.did.clone();
    let record = chain.version(0);

    // First set must succeed.
    let first = node.set(&key, record.clone()).await;
    assert!(first.unwrap_or(false), "first set must succeed");

    // An identical retry acknowledges already-present replicas.
    let second = node.set(&key, record.clone()).await;
    assert_eq!(second, Some(true), "an identical retry must be idempotent");

    // Another valid record at the same place, the same version 0 signed
    // again, remains a conflict.
    let conflicting_record = chain.signed_again(0);
    assert!(
        node.set(&key, conflicting_record).await.is_none(),
        "immutable records must reject different bytes for an occupied key"
    );

    node.stop().await;
}

/// A DID owner rotates its key with `update`: version 1 is signed by the key
/// version 0 committed to, and carries no other authorization. Every node then
/// returns version 1.
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

    let chain = Chain::with_versions(1);
    let key = chain.did.clone();
    let stored = node2.set(&key, chain.version(0)).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    let updated = node3.update(&key, chain.version(1), chain.earlier(1)).await;
    assert!(updated.unwrap_or(false), "key-rotation update must succeed");

    // Give the network a moment to propagate the update.
    sleep(Duration::from_millis(500)).await;
    for (name, node) in [("node1", &node1), ("node2", &node2)] {
        assert_eq!(
            node.get(&key).await,
            Some(chain.version(1)),
            "{name} must return version 1 after the update"
        );
    }

    node1.stop().await;
    node2.stop().await;
    node3.stop().await;
}

/// A record whose embedded signature does not match the public key in the
/// DID Document must be rejected by `set` (returns None).
#[tokio::test]
async fn test_invalid_signature_record_rejected_on_set() {
    let mut node = start_node(15750).await;

    let correct = MlDsa65KeyPair::generate().unwrap();
    let wrong = MlDsa65KeyPair::generate().unwrap(); // different secret key — mismatch!
    let (key, invalid_record) = version0(correct.public_key(), &wrong);

    let result = node.set(&key, invalid_record).await;
    assert!(
        result.is_none(),
        "set with mismatched signature must return None"
    );

    node.stop().await;
}

/// A valid self-signed record cannot be stored, or read, under another DID.
#[tokio::test]
async fn test_valid_record_rejected_under_another_did_key() {
    let mut node = start_node(15897).await;
    let (_, record) = new_did_record();
    let (requested_did, _) = new_did_record();

    assert!(
        node.set(&requested_did, record.clone()).await.is_none(),
        "set must reject a valid DID Document submitted under another DID"
    );

    node.storage.set(key_of(&requested_did).to_vec(), record);
    assert!(node.get(&requested_did).await.is_none());

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

/// `update` must return None when the new version names the committed key but
/// is not signed by it: its self-signature is invalid.
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

    let chain = Chain::with_versions(1);
    let key = chain.did.clone();
    let stored = node1.set(&key, chain.version(0)).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    let doc = chain.doc(
        1,
        Some(&chain.version(0)),
        chain.keys[1].public_key(),
        chain.keys[2].public_key(),
    );
    let wrong = MlDsa65KeyPair::generate().unwrap();
    let invalid_new_record = build_signed_record(&doc, &wrong, "ML-DSA-65");

    let result = node2
        .update(&key, invalid_new_record, chain.earlier(1))
        .await;
    assert!(
        result.is_none(),
        "update must be rejected when the new record's self-signature is invalid"
    );
    assert_eq!(
        node1.get(&key).await,
        Some(chain.version(0)),
        "the original record must remain after a rejected update"
    );

    node1.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Update rejected when signed by a key that was not committed (15782–15784)
// ─────────────────────────────────────────────────────────────────────────────

/// `update` must return None when the new version is self-signed by a key
/// the version before did not commit to: the owner's node sees it against
/// the earlier versions it is given, and sends nothing. The original record
/// survives.
#[tokio::test]
async fn test_update_rejected_when_signed_by_an_uncommitted_key() {
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

    let chain = Chain::with_versions(1);
    let key = chain.did.clone();
    let stored = node2.set(&key, chain.version(0)).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    let unrelated = MlDsa65KeyPair::generate().unwrap();
    let new_record = chain.forge(1, &chain.version(0), &unrelated);
    let result = node3.update(&key, new_record, chain.earlier(1)).await;
    assert!(
        result.is_none(),
        "an update signed by a key that was not committed must return None"
    );

    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        node1.get(&key).await,
        Some(chain.version(0)),
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

    let (key, record) = new_did_record();

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

/// Version 0 of a new DID, returning `(did, record)`.
fn new_record() -> (String, Vec<u8>) {
    new_did_record()
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
    let (absent_a, _) = new_record();
    let (absent_b, _) = new_record();
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

    let (during_outage, record) = new_record();
    let outcome = a.set_detailed(&during_outage, record).await;
    assert!(
        matches!(outcome, SetOutcome::Degraded(_)),
        "a node that is cut off must not report a complete publication: {outcome:?}"
    );

    down.store(false, Ordering::Relaxed);
    timeout(RECOVERY_BUDGET, async {
        while b.storage.get(&key_of(&during_outage)).is_none() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the record published during the outage must reach the other replica");

    let chain = Chain::new();
    let key = chain.did.clone();
    let record = chain.version(0);
    let outcome = a.set_detailed(&key, record.clone()).await;
    assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
    assert_eq!(b.get(&key).await, Some(record));

    let outcome = b.set_detailed(&key, chain.signed_again(0)).await;
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

    let (key, record) = new_record();
    let outcome = node.set_detailed(&key, record).await;
    assert!(
        matches!(outcome, SetOutcome::Degraded(_)),
        "a node with an unreachable seed is cut off, not alone: {outcome:?}"
    );

    let seed = start_node(seed_port).await;
    timeout(RECOVERY_BUDGET, async {
        while seed.storage.get(&key_of(&key)).is_none() {
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

    let (key, record) = new_record();
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

    let (key, record) = new_record();
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
    let (key, record) = new_record();
    let outcome = node.set_detailed(&key, record).await;
    assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
}
