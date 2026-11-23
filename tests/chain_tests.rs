//! DIDs whose rotation keys are committed in a tree, over real UDP: a
//! rotation that replicas take directly at any position, empty replicas
//! filled by the owner, refusals that count only once shown, and what an old
//! genuine record sent by anyone can still do.
//!
//! Each node's id is placed at a chosen distance from the DID's key, so the
//! replicas are known, and each replica's state is written into its storage
//! before the operation. Ports: 15954-15985.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use auth_kademlia_rs::network::{Server, SetOutcome, SetRejection, SetReport};
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::protocol::StoreStatus;
use auth_kademlia_rs::storage::IStorage;

use common::Chain;

fn runtime() -> tokio::runtime::Runtime {
    let parallelism = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("failed to build test runtime")
}

/// An id at XOR distance `distance` from `key`, in its first byte: larger
/// distances are farther.
fn id_at(key: [u8; 32], distance: u8) -> [u8; 32] {
    let mut id = key;
    id[0] ^= distance;
    id
}

async fn node(port: u16, id: [u8; 32], k: usize) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut server = Server::new(handler, k, 3, Some(id), None, false);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    server
}

/// Nodes at the given distances from `key`, on consecutive ports from
/// `first_port`, each knowing all the others.
async fn network(key: [u8; 32], first_port: u16, distances: &[u8], k: usize) -> Vec<Server> {
    let mut nodes = vec![];
    for (index, distance) in distances.iter().enumerate() {
        nodes.push(node(first_port + index as u16, id_at(key, *distance), k).await);
    }
    for (i, server) in nodes.iter().enumerate() {
        let protocol = server.protocol.as_ref().expect("listening");
        let mut router = protocol.router.write().await;
        for (j, other) in nodes.iter().enumerate() {
            if i != j {
                router.add_contact(Node::new(
                    other.node.id,
                    Some("127.0.0.1".to_string()),
                    Some(first_port + j as u16),
                ));
            }
        }
    }
    nodes
}

fn hold(server: &Server, chain: &Chain, record: &[u8]) {
    server.storage.set(chain.key.to_vec(), record.to_vec());
}

/// Which position of `chain` `server` holds: `"v<n>"`, `"other"` for a
/// record that is no published position of the chain, or `None`.
fn held(server: &Server, chain: &Chain) -> Option<String> {
    let record = server.storage.get(&chain.key)?;
    Some(
        match chain.records.iter().position(|version| *version == record) {
            Some(seq) => format!("v{seq}"),
            None => "other".to_string(),
        },
    )
}

fn v(seq: usize) -> Option<String> {
    Some(format!("v{seq}"))
}

/// What `from` gets when it sends `record` to `to` by STORE.
async fn store_from(
    from: &Server,
    to: &Server,
    chain: &Chain,
    record: &[u8],
) -> Option<StoreStatus> {
    let protocol = from.protocol.as_ref().expect("listening");
    let port = to
        .protocol
        .as_ref()
        .expect("listening")
        .socket
        .local_addr()
        .expect("bound")
        .port();
    let target = Node::new(to.node.id, Some("127.0.0.1".to_string()), Some(port));
    protocol
        .call_store_rpc(&target, chain.key, record.to_vec())
        .await
}

// ---- Rotation -----------------------------------------------------------------------------

/// Replicas at positions 1 and 2 and an empty one all take position 5
/// directly: none needs the positions in between.
#[test]
fn a_rotation_takes_every_replica_to_the_current_position() {
    runtime().block_on(async {
        let chain = Chain::with_versions(5);
        let nodes = network(chain.key, 15954, &[200, 1, 2, 3], 20).await;
        hold(&nodes[1], &chain, &chain.version(1));
        hold(&nodes[2], &chain, &chain.version(2));
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(5)).await;
        assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
        for node in &nodes[1..] {
            assert_eq!(held(node, &chain), v(5));
        }
    });
}

/// Every replica lost its copy while the owner was away: the owner's next
/// publication fills them all, with no quorum to reach.
#[test]
fn the_owner_restores_every_empty_replica() {
    runtime().block_on(async {
        let chain = Chain::with_versions(3);
        let nodes = network(chain.key, 15958, &[200, 1, 2, 3], 20).await;
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(3)).await;
        assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
        for node in &nodes[1..] {
            assert_eq!(held(node, &chain), v(3));
        }
    });
}

/// The owner, a replica itself, writes its record locally without checking
/// the network: it sends no `FindHash` (counted with the `counters`
/// feature).
#[test]
fn the_owner_stores_its_record_without_asking() {
    runtime().block_on(async {
        let chain = Chain::new();
        let nodes = network(chain.key, 15962, &[1, 2], 20).await;
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(0)).await;
        assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
        assert_eq!(held(&nodes[0], &chain), v(0));
        assert_eq!(held(&nodes[1], &chain), v(0));
        #[cfg(feature = "counters")]
        {
            let sent = nodes[0].counters().expect("listening").sent;
            assert_eq!(sent.get("FindHash").map_or(0, |s| s.datagrams), 0);
        }
    });
}

// ---- Refusals that count only once shown ----------------------------------------------

/// A replica holding the same document signed again shows it: the
/// publication is rejected as an existing record, and the replica keeps its
/// copy. At position 0 this is a DID created twice by its owner.
#[test]
fn another_record_at_the_published_position_is_shown_and_rejects() {
    runtime().block_on(async {
        for (seq, first_port) in [(0usize, 15964u16), (2, 15967)] {
            let chain = Chain::with_versions(2);
            let nodes = network(chain.key, first_port, &[200, 1, 2], 20).await;
            let again = chain.signed_again(seq);
            hold(&nodes[1], &chain, &again);
            let outcome = nodes[0].set_detailed(&chain.did, chain.version(seq)).await;
            assert!(
                matches!(
                    outcome,
                    SetOutcome::Rejected {
                        reason: SetRejection::ExistingRecord,
                        ..
                    }
                ),
                "position {seq}: {outcome:?}"
            );
            assert_eq!(nodes[1].storage.get(&chain.key), Some(again));
        }
    });
}

/// A replica holding a valid higher position shows it: the publication is
/// superseded. The empty replica fetches that position during its check,
/// refuses too, and keeps it.
#[test]
fn a_higher_position_on_a_replica_supersedes_the_publication() {
    runtime().block_on(async {
        let chain = Chain::with_versions(3);
        let nodes = network(chain.key, 15970, &[200, 1, 2], 20).await;
        hold(&nodes[1], &chain, &chain.version(3));
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(2)).await;
        assert!(
            matches!(
                outcome,
                SetOutcome::Rejected {
                    reason: SetRejection::NewerVersion,
                    report: SetReport {
                        stale_rejections: 2,
                        unproven_refusals: 0,
                        ..
                    },
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(held(&nodes[1], &chain), v(3));
        assert_eq!(held(&nodes[2], &chain), v(3));
    });
}

/// A replica that holds a forged record, written past every check, takes the
/// genuine one: a stored record that does not bind proves nothing.
#[test]
fn a_forged_record_on_a_replica_does_not_stop_the_publication() {
    runtime().block_on(async {
        let chain = Chain::with_versions(1);
        let nodes = network(chain.key, 15973, &[200, 1, 2], 20).await;
        let attacker = MlDsa65KeyPair::generate().unwrap();
        hold(
            &nodes[1],
            &chain,
            &chain.forge(1, &chain.version(0), &attacker),
        );
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(0)).await;
        assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
        assert_eq!(held(&nodes[1], &chain), v(0));
        assert_eq!(held(&nodes[2], &chain), v(0));
    });
}

// ---- An old genuine record, sent by anyone ---------------------------------------------

/// Every published record is public. Sent to an empty replica that can see a
/// holder of position 3, position 1 is refused as stale and the replica keeps
/// 3. Sent to an empty replica that sees no higher position, it is stored:
/// the record is authentic, only superseded, and the reader's credential
/// check is what refuses its key.
#[test]
fn an_old_genuine_record_is_stored_only_where_nothing_higher_is_shown() {
    runtime().block_on(async {
        let chain = Chain::with_versions(3);
        let nodes = network(chain.key, 15976, &[200, 1, 2], 20).await;
        let (sender, empty) = (&nodes[0], &nodes[2]);
        hold(&nodes[1], &chain, &chain.version(3));
        assert_eq!(
            store_from(sender, empty, &chain, &chain.version(1)).await,
            Some(StoreStatus::Stale)
        );
        assert_eq!(held(empty, &chain), v(3));

        let nodes = network(chain.key, 15979, &[200, 1, 2], 20).await;
        let (sender, empty) = (&nodes[0], &nodes[2]);
        assert_eq!(
            store_from(sender, empty, &chain, &chain.version(1)).await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(held(empty, &chain), v(1));
        // The owner's next publication takes it to the current position.
        assert_eq!(
            store_from(sender, empty, &chain, &chain.version(3)).await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(held(empty, &chain), v(3));
    });
}

/// Publishing at a position the replicas do not take is fast to tell: a
/// higher position shown by a replica answers before the check's deadline.
#[test]
fn a_superseded_publication_is_decided_before_the_deadline() {
    runtime().block_on(async {
        let chain = Chain::with_versions(4);
        let nodes = network(chain.key, 15982, &[200, 1, 2, 3], 20).await;
        hold(&nodes[1], &chain, &chain.version(4));
        let started = Instant::now();
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(2)).await;
        assert!(
            matches!(
                outcome,
                SetOutcome::Rejected {
                    reason: SetRejection::NewerVersion,
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_millis(2500));
    });
}
