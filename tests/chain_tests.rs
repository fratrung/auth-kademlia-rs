//! Self-certifying DIDs and pre-rotated chains of versions over real UDP
//! (ADR 0005): publication of version 0, `update` with the owner's earlier
//! versions, the replay of the chain to replicas that miss versions, and the
//! gap an old version used to leave open.
//!
//! Each node's id is placed at a chosen distance from the DID's key, so the
//! replicas are known, and each replica's state is written into its storage
//! before the operation. Ports: 15954-16017.

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

/// Which version of `chain` `server` holds: `"v<n>"`, `"other"` for a record
/// that is no version of the chain, or `None`.
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

fn other() -> Option<String> {
    Some("other".to_string())
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

// ---- Create and update ----------------------------------------------------------------

/// `set` creates a DID: a version N ≥ 1 is refused before anything is sent.
#[test]
fn set_refuses_a_later_version_without_sending_anything() {
    runtime().block_on(async {
        let chain = Chain::with_versions(1);
        let nodes = network(chain.key, 15954, &[200, 1], 20).await;
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(0)).await;
        assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");

        let other = Chain::with_versions(1);
        let outcome = nodes[0].set_detailed(&other.did, other.version(1)).await;
        assert!(
            matches!(
                outcome,
                SetOutcome::Rejected {
                    reason: SetRejection::UseUpdate,
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(outcome.report(), &SetReport::default());
        assert!(nodes.iter().all(|n| n.storage.get(&other.key).is_none()));
    });
}

/// `update` publishes a version N ≥ 1, and refuses a version 0. It reads no
/// copy first: no value lookup, no network check of its own record.
#[test]
fn update_refuses_version_0_and_reads_no_copy() {
    runtime().block_on(async {
        let chain = Chain::with_versions(1);
        let nodes = network(chain.key, 15956, &[200, 1], 20).await;
        hold(&nodes[1], &chain, &chain.version(0));

        assert_eq!(
            nodes[0].update(&chain.did, chain.version(0), vec![]).await,
            None
        );
        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(1), chain.earlier(1))
                .await,
            Some(true)
        );
        assert_eq!(held(&nodes[1], &chain), v(1));
        assert_eq!(held(&nodes[0], &chain), v(1));
        #[cfg(feature = "counters")]
        {
            let sent = nodes[0].counters().expect("listening").sent;
            for kind in ["FindValue", "FindHash"] {
                assert_eq!(sent.get(kind).map_or(0, |s| s.datagrams), 0, "{kind}");
            }
        }
    });
}

/// The closest replica serves a forged version N−1: `update` reads no copy,
/// so it does not stop there; that replica refuses the fork, the others
/// take the update.
#[test]
fn update_completes_when_a_replica_serves_a_forged_previous_version() {
    runtime().block_on(async {
        let chain = Chain::with_versions(2);
        let nodes = network(chain.key, 15958, &[200, 1, 2, 3], 20).await;
        let attacker = MlDsa65KeyPair::generate().unwrap();
        let forged = chain.forge(1, &chain.version(0), &attacker);
        hold(&nodes[0], &chain, &chain.version(1));
        hold(&nodes[1], &chain, &forged);
        hold(&nodes[2], &chain, &chain.version(1));
        hold(&nodes[3], &chain, &chain.version(1));

        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(2), chain.earlier(2))
                .await,
            Some(true)
        );
        assert_eq!(held(&nodes[1], &chain), other());
        for server in [&nodes[0], &nodes[2], &nodes[3]] {
            assert_eq!(held(server, &chain), v(2));
        }
    });
}

// ---- The replay -----------------------------------------------------------------------------

/// Copies below the quorum: with `k` = 3, one holder of the current version
/// and two empty replicas. Their network check cannot accept the current
/// version, so the owner replays its chain from version 0, and one call
/// restores every replica.
#[test]
fn the_owner_restores_every_replica_below_the_quorum() {
    runtime().block_on(async {
        let chain = Chain::with_versions(2);
        let nodes = network(chain.key, 15962, &[200, 1, 2, 3], 3).await;
        hold(&nodes[1], &chain, &chain.version(2));

        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(2), chain.earlier(2))
                .await,
            Some(true)
        );
        for server in &nodes[1..] {
            assert_eq!(held(server, &chain), v(2));
        }
        assert_eq!(
            held(&nodes[0], &chain),
            None,
            "the owner is not a replica here"
        );
    });
}

/// A replica two versions behind gets the versions it misses, one at a time,
/// and then a forged version two ahead of it leaves it untouched.
#[test]
fn a_replica_behind_gets_the_versions_it_misses() {
    runtime().block_on(async {
        let chain = Chain::with_versions(3);
        let nodes = network(chain.key, 15966, &[200, 1, 2], 20).await;
        hold(&nodes[1], &chain, &chain.version(1));
        hold(&nodes[2], &chain, &chain.version(2));

        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(3), chain.earlier(3))
                .await,
            Some(true)
        );
        for server in &nodes {
            assert_eq!(held(server, &chain), v(3));
        }

        let attacker = MlDsa65KeyPair::generate().unwrap();
        let forged = chain.forge(5, b"made up", &attacker);
        assert_eq!(
            store_from(&nodes[0], &nodes[1], &chain, &forged).await,
            Some(StoreStatus::MissingPrevious { seq: 3 })
        );
        assert_eq!(held(&nodes[1], &chain), v(3));
    });
}

/// `k` = 20: 7 replicas at version N, 6 two versions behind, 7 empty. The
/// owner repairs the replicas behind first, so the empty ones count 13
/// holders of version N, the quorum, and one call fills them all.
#[test]
fn the_replicas_behind_are_repaired_before_the_empty_ones() {
    runtime().block_on(async {
        let chain = Chain::with_versions(4);
        let mut distances = vec![200];
        distances.extend(1..=20);
        let nodes = network(chain.key, 15969, &distances, 20).await;
        for server in &nodes[1..=7] {
            hold(server, &chain, &chain.version(4));
        }
        for server in &nodes[8..=13] {
            hold(server, &chain, &chain.version(2));
        }

        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(4), chain.earlier(4))
                .await,
            Some(true)
        );
        let at_current = nodes[1..]
            .iter()
            .filter(|s| held(s, &chain) == v(4))
            .count();
        assert_eq!(at_current, 20);
    });
}

/// One node holding another version 0 (signed again with the first key)
/// stops the owner's replay at its first step: the call ends, without
/// looping, and the empty replica stays empty.
#[test]
fn another_version_0_stops_the_replay_and_the_call_ends() {
    runtime().block_on(async {
        let chain = Chain::with_versions(2);
        let nodes = network(chain.key, 15990, &[200, 1, 2, 3], 3).await;
        let again = common::build_signed_record(
            &chain.doc(
                0,
                None,
                chain.keys[0].public_key(),
                chain.keys[1].public_key(),
            ),
            &chain.keys[0],
            "ML-DSA-65",
        );
        hold(&nodes[1], &chain, &chain.version(2));
        hold(&nodes[2], &chain, &again);

        let started = Instant::now();
        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(2), chain.earlier(2))
                .await,
            Some(false)
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(held(&nodes[1], &chain), v(2));
        assert_eq!(held(&nodes[2], &chain), other());
        assert_eq!(held(&nodes[3], &chain), None);
    });
}

/// The owner's own node, a replica that lacks version N−1, writes its chain
/// locally without asking the network, and the new version only once the
/// quorum is met.
#[test]
fn the_owner_writes_its_chain_locally_and_the_new_version_after_the_quorum() {
    runtime().block_on(async {
        let chain = Chain::with_versions(2);
        let nodes = network(chain.key, 15994, &[1, 2, 3], 20).await;
        hold(&nodes[1], &chain, &chain.version(1));
        hold(&nodes[2], &chain, &chain.version(1));
        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(2), chain.earlier(2))
                .await,
            Some(true)
        );
        for server in &nodes {
            assert_eq!(held(server, &chain), v(2));
        }
        #[cfg(feature = "counters")]
        assert_eq!(
            nodes[0]
                .counters()
                .expect("listening")
                .sent
                .get("FindHash")
                .map_or(0, |s| s.datagrams),
            0
        );

        // The other replicas hold a fork of version 1: no quorum, and the
        // owner keeps its chain up to version 1.
        let chain = Chain::with_versions(2);
        let nodes = network(chain.key, 15997, &[1, 2, 3], 20).await;
        let attacker = MlDsa65KeyPair::generate().unwrap();
        let forged = chain.forge(1, &chain.version(0), &attacker);
        hold(&nodes[1], &chain, &forged);
        hold(&nodes[2], &chain, &forged);
        assert_eq!(
            nodes[0]
                .update(&chain.did, chain.version(2), chain.earlier(2))
                .await,
            Some(false)
        );
        assert_eq!(held(&nodes[0], &chain), v(1));
    });
}

/// The gap of the old UPDATE, closed: after a rotation a restarted replica
/// refuses a forged version by STORE and takes the genuine one through
/// replication, and the next rotation succeeds while a replica still holds
/// the version before it.
#[test]
fn an_update_succeeds_while_an_old_version_is_still_on_a_replica() {
    runtime().block_on(async {
        let chain = Chain::with_versions(2);
        let nodes = network(chain.key, 16000, &[200, 1, 2, 3, 4], 20).await;
        let (owner, a, b, c, restarted) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3], &nodes[4]);
        hold(a, &chain, &chain.version(1));
        hold(b, &chain, &chain.version(1));
        hold(c, &chain, &chain.version(0));

        let attacker = MlDsa65KeyPair::generate().unwrap();
        let forged = chain.forge(1, &chain.version(0), &attacker);
        assert_eq!(
            store_from(owner, restarted, &chain, &forged).await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(held(restarted, &chain), None);
        assert_eq!(
            store_from(a, restarted, &chain, &chain.version(1)).await,
            Some(StoreStatus::Stored)
        );

        assert_eq!(
            owner
                .update(&chain.did, chain.version(2), chain.earlier(2))
                .await,
            Some(true)
        );
        for server in [a, b, c, restarted] {
            assert_eq!(held(server, &chain), v(2));
        }
    });
}

// ---- Publication -----------------------------------------------------------------------

/// The lookup of `set` only reads. Here it finds another record at the same
/// place (version 0 signed again), so `set` refuses before sending anything,
/// and the nearest node that lacked the record gets no copy of what the
/// lookup found.
#[test]
fn the_lookup_of_set_leaves_no_copy_behind() {
    runtime().block_on(async {
        let chain = Chain::new();
        let nodes = network(chain.key, 16005, &[1, 2, 3, 200], 3).await;
        hold(&nodes[0], &chain, &chain.version(0));
        hold(&nodes[1], &chain, &chain.version(0));
        let outcome = nodes[3]
            .set_detailed(&chain.did, chain.signed_again(0))
            .await;
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
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(held(&nodes[2], &chain), None);
    });
}

/// The owner's own node stores its version 0 without asking the network.
#[cfg(feature = "counters")]
#[test]
fn the_owner_stores_its_version_0_without_asking() {
    runtime().block_on(async {
        let chain = Chain::new();
        let nodes = network(chain.key, 16009, &[1, 2], 20).await;
        let outcome = nodes[0].set_detailed(&chain.did, chain.version(0)).await;
        assert!(matches!(outcome, SetOutcome::Complete(_)), "{outcome:?}");
        assert_eq!(held(&nodes[1], &chain), v(0));
        let sent = nodes[0].counters().expect("listening").sent;
        assert_eq!(sent.get("FindHash").map_or(0, |s| s.datagrams), 0);
    });
}

// ---- The genuine chain sent by anyone ------------------------------------------------------

/// Anyone holds every published version. At or above the quorum an empty
/// replica refuses to start again from version 0, so the genuine chain sent
/// by anyone stops there; and one holder of version 0 refuses another
/// version 0 of a DID that never rotated, signed again with its key. Below
/// the quorum the chain starts: the owner's replay relies on it
/// (`the_owner_restores_every_replica_below_the_quorum`).
#[test]
fn the_genuine_chain_sent_by_anyone_starts_only_below_the_quorum() {
    runtime().block_on(async {
        let chain = Chain::with_versions(3);
        // k = 3: two holders of version 3 are the quorum of the empty replica.
        let nodes = network(chain.key, 16011, &[200, 1, 2, 3], 3).await;
        let (sender, empty) = (&nodes[0], &nodes[3]);
        hold(&nodes[1], &chain, &chain.version(3));
        hold(&nodes[2], &chain, &chain.version(3));
        assert_eq!(
            store_from(sender, empty, &chain, &chain.version(0)).await,
            Some(StoreStatus::NewerClaimed)
        );
        assert_eq!(held(empty, &chain), None);

        // A DID that never rotated: version 0 signed again with its key.
        let fresh = Chain::new();
        let nodes = network(fresh.key, 16015, &[200, 1, 2], 3).await;
        hold(&nodes[1], &fresh, &fresh.version(0));
        let again = common::build_signed_record(
            &fresh.doc(
                0,
                None,
                fresh.keys[0].public_key(),
                fresh.keys[1].public_key(),
            ),
            &fresh.keys[0],
            "ML-DSA-65",
        );
        assert_eq!(
            store_from(&nodes[0], &nodes[2], &fresh, &again).await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(held(&nodes[2], &fresh), None);
    });
}
