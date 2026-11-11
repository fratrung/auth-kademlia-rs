//! End-to-end consistency tests for DID Documents and the issuer Status List.
//!
//! Every test uses real UDP nodes and valid ML-DSA-65 records. Records are
//! injected only after bootstrap so the tests control the exact replica state.
//! Ports: 15866-15894, 15904-15905, 15913-15923, 15928-15953.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::crypto::mldsa::MlDsa65KeyPair;
use auth_kademlia_rs::fragmentation::MAX_REASSEMBLY_ENTRIES_PER_PEER;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::protocol::{StoreStatus, UpdateStatus};
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use common::{build_signed_record, Chain};

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

fn node_id(marker: u8) -> [u8; ID_LEN] {
    [marker; ID_LEN]
}

async fn start_node(port: u16, issuer_key: &Path, id: [u8; ID_LEN]) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(issuer_key));
    let mut server = Server::new(handler, 20, 3, Some(id), None, false);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    server
}

async fn bootstrap_to(requester: &Server, ports: &[u16]) {
    let peers = ports
        .iter()
        .map(|port| ("127.0.0.1".to_string(), *port))
        .collect();
    let discovered = requester.bootstrap(peers).await;
    assert!(
        discovered.len() >= ports.len(),
        "requester did not discover the complete test group"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
}

async fn add_known_peer(server: &Server, id: [u8; ID_LEN], port: u16) {
    let protocol = server.protocol.as_ref().expect("node must be listening");
    protocol.router.write().await.add_contact(Node::new(
        id,
        Some("127.0.0.1".to_string()),
        Some(port),
    ));
}

fn id_at_distance(key: [u8; ID_LEN], distance: u8) -> [u8; ID_LEN] {
    let mut id = key;
    id[0] ^= distance;
    id
}

/// Version 0 of `chain` signed again: the same document, other bytes (ML-DSA
/// signing is randomized), so another record at the same place.
fn signed_again(chain: &Chain) -> Vec<u8> {
    let doc = chain.doc(
        0,
        None,
        chain.keys[0].public_key(),
        chain.keys[1].public_key(),
    );
    build_signed_record(&doc, &chain.keys[0], "ML-DSA-65")
}

fn issuer_record(payload: &[u8], secret_key: &MlDsa65KeyPair) -> Vec<u8> {
    let mut algorithm = [0_u8; 12];
    algorithm[..9].copy_from_slice(b"ML-DSA-65");
    let signature = secret_key.sign(payload).unwrap();

    let mut record = Vec::with_capacity(12 + signature.as_slice().len() + payload.len());
    record.extend_from_slice(&algorithm);
    record.extend_from_slice(signature.as_slice());
    record.extend_from_slice(payload);
    record
}

struct TemporaryIssuerKey(PathBuf);

impl TemporaryIssuerKey {
    fn create(port: u16, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "auth-kademlia-quorum-issuer-{}-{}.bin",
            std::process::id(),
            port
        ));
        std::fs::write(&path, bytes).expect("failed to write temporary issuer key");
        Self(path)
    }
}

impl Drop for TemporaryIssuerKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Replicas at different versions of the same DID: the read returns one of
/// them, the first that binds and verifies.
#[test]
fn remote_did_get_returns_a_record_when_replicas_disagree() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let requester = start_node(15866, issuer, node_id(1)).await;
        let peer_a = start_node(15867, issuer, node_id(2)).await;
        let peer_b = start_node(15868, issuer, node_id(3)).await;
        let peer_c = start_node(15869, issuer, node_id(4)).await;
        bootstrap_to(&requester, &[15867, 15868, 15869]).await;

        let chain = Chain::with_versions(2);
        peer_a.storage.set(chain.key.to_vec(), chain.version(0));
        peer_b.storage.set(chain.key.to_vec(), chain.version(1));
        peer_c.storage.set(chain.key.to_vec(), chain.version(2));

        let found = requester
            .get(&chain.did)
            .await
            .expect("a valid record exists");
        assert!(
            chain.records.contains(&found),
            "the read must return one of the valid records"
        );
    });
}

#[test]
fn remote_did_get_returns_a_single_valid_copy() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let requester = start_node(15913, issuer, node_id(40)).await;
        let holder = start_node(15914, issuer, node_id(41)).await;
        let _without_copy = start_node(15915, issuer, node_id(42)).await;
        bootstrap_to(&requester, &[15914, 15915]).await;

        let chain = Chain::new();
        holder.storage.set(chain.key.to_vec(), chain.version(0));

        assert_eq!(requester.get(&chain.did).await, Some(chain.version(0)));
    });
}

#[test]
fn remote_did_get_skips_an_invalid_record() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::new();
        let dkey = chain.key;

        let requester = start_node(15916, issuer, node_id(50)).await;
        let bad_a = start_node(15917, issuer, id_at_distance(dkey, 0x01)).await;
        let bad_b = start_node(15918, issuer, id_at_distance(dkey, 0x02)).await;
        let bad_c = start_node(15919, issuer, id_at_distance(dkey, 0x03)).await;
        let good = start_node(15920, issuer, id_at_distance(dkey, 0x04)).await;
        bootstrap_to(&requester, &[15917, 15918, 15919, 15920]).await;

        let record = chain.version(0);
        let mut tampered = record.clone();
        tampered[12] ^= 0xFF;
        for peer in [&bad_a, &bad_b, &bad_c] {
            peer.storage.set(dkey.to_vec(), tampered.clone());
        }
        good.storage.set(dkey.to_vec(), record.clone());

        assert_eq!(
            requester.get(&chain.did).await,
            Some(record),
            "records that fail verification must not end the read"
        );
    });
}

#[test]
fn remote_did_get_does_not_wait_for_a_dead_peer() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::new();
        let dkey = chain.key;

        let requester = start_node(15921, issuer, node_id(60)).await;
        let holder = start_node(15922, issuer, id_at_distance(dkey, 0x02)).await;
        bootstrap_to(&requester, &[15922]).await;
        let _silent = std::net::UdpSocket::bind(("127.0.0.1", 15923)).expect("bind");
        add_known_peer(&requester, id_at_distance(dkey, 0x01), 15923).await;

        let record = chain.version(0);
        holder.storage.set(dkey.to_vec(), record.clone());

        let started = std::time::Instant::now();
        assert_eq!(requester.get(&chain.did).await, Some(record));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the read took {:?}",
            started.elapsed()
        );
    });
}

#[test]
fn remote_did_get_follows_kademlia_multihop_discovery() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::new();
        let dkey = chain.key;
        let record = chain.version(0);

        let requester = start_node(15888, issuer, id_at_distance(dkey, 0xF0)).await;
        let relay_a = start_node(15889, issuer, id_at_distance(dkey, 0x70)).await;
        let relay_b = start_node(15890, issuer, id_at_distance(dkey, 0x80)).await;
        let relay_c = start_node(15891, issuer, id_at_distance(dkey, 0x90)).await;
        let replica_a = start_node(15892, issuer, id_at_distance(dkey, 0x01)).await;
        let replica_b = start_node(15893, issuer, id_at_distance(dkey, 0x02)).await;
        let replica_c = start_node(15894, issuer, id_at_distance(dkey, 0x03)).await;

        // The requester knows only relays. Relays know only the closer replicas.
        for (_relay, id, port) in [
            (&relay_a, relay_a.node.id, 15889),
            (&relay_b, relay_b.node.id, 15890),
            (&relay_c, relay_c.node.id, 15891),
        ] {
            add_known_peer(&requester, id, port).await;
        }
        for relay in [&relay_a, &relay_b, &relay_c] {
            for (id, port) in [
                (replica_a.node.id, 15892),
                (replica_b.node.id, 15893),
                (replica_c.node.id, 15894),
            ] {
                add_known_peer(relay, id, port).await;
            }
        }
        replica_a.storage.set(dkey.to_vec(), record.clone());
        replica_b.storage.set(dkey.to_vec(), record.clone());
        replica_c.storage.set(dkey.to_vec(), record.clone());

        assert_eq!(
            requester.get(&chain.did).await,
            Some(record),
            "lookup must follow closer nodes returned by relays"
        );
    });
}

#[test]
fn local_did_get_keeps_the_fast_path() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let requester = start_node(15874, issuer, node_id(20)).await;
        let chain = Chain::new();
        requester.storage.set(chain.key.to_vec(), chain.version(0));

        assert_eq!(
            requester.get(&chain.did).await,
            Some(chain.version(0)),
            "a valid local DID Document must not require the network"
        );
    });
}

#[test]
fn status_list_uses_local_copy_as_one_vote() {
    runtime().block_on(async {
        let issuer_secret_key = MlDsa65KeyPair::generate().unwrap();
        let issuer_public_key = issuer_secret_key.public_key().to_vec();
        let issuer_file = TemporaryIssuerKey::create(15875, &issuer_public_key);
        let requester = start_node(15875, &issuer_file.0, node_id(30)).await;
        let peer_a = start_node(15876, &issuer_file.0, node_id(31)).await;
        let peer_b = start_node(15877, &issuer_file.0, node_id(32)).await;
        bootstrap_to(&requester, &[15876, 15877]).await;

        let dkey = digest(STATUS_LIST_KEY);
        let old_record = issuer_record(b"status-list-v1", &issuer_secret_key);
        let new_record = issuer_record(b"status-list-v2", &issuer_secret_key);
        requester.storage.set(dkey.to_vec(), old_record);
        peer_a.storage.set(dkey.to_vec(), new_record.clone());
        peer_b.storage.set(dkey.to_vec(), new_record.clone());

        assert_eq!(
            requester.get(STATUS_LIST_KEY).await,
            Some(new_record),
            "two remote status-list replicas must override one stale local copy"
        );
    });
}

/// Pins the exact key and document used by the Python issuer: a mismatch here
/// makes every Status List publication fail while the issuer ignores the result.
#[test]
fn issuer_publishes_and_updates_the_status_list_under_its_python_key() {
    runtime().block_on(async {
        const ISSUER_KEY: &str = "status-list";
        let issuer_secret_key = MlDsa65KeyPair::generate().unwrap();
        let issuer_public_key = issuer_secret_key.public_key().to_vec();
        let issuer_file = TemporaryIssuerKey::create(15904, &issuer_public_key);
        let issuer = start_node(15904, &issuer_file.0, node_id(60)).await;
        let proxy = start_node(15905, &issuer_file.0, node_id(61)).await;
        bootstrap_to(&issuer, &[15905]).await;

        assert_eq!(STATUS_LIST_KEY, ISSUER_KEY);
        let document = |version: u8| format!(r#"{{"id":"status-list","status_list":[{version}]}}"#);
        let first = issuer_record(document(1).as_bytes(), &issuer_secret_key);
        let second = issuer_record(document(2).as_bytes(), &issuer_secret_key);

        assert_eq!(issuer.set(ISSUER_KEY, first.clone()).await, Some(true));
        assert_eq!(proxy.get(ISSUER_KEY).await, Some(first));
        assert_eq!(
            issuer.update(ISSUER_KEY, second.clone(), vec![]).await,
            Some(true)
        );
        assert_eq!(proxy.get(ISSUER_KEY).await, Some(second));
    });
}

/// The other replicas hold version 0 signed again, so version 1 does not
/// follow theirs and they refuse it: no quorum, and the owner does not commit
/// version 1 locally.
#[test]
fn update_without_quorum_preserves_the_local_record() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(1);
        let dkey = chain.key;
        let requester = start_node(15878, issuer, dkey).await;
        let peer_a = start_node(15879, issuer, node_id(41)).await;
        let peer_b = start_node(15880, issuer, node_id(42)).await;
        bootstrap_to(&requester, &[15879, 15880]).await;

        let other_record = signed_again(&chain);
        requester.storage.set(dkey.to_vec(), chain.version(0));
        peer_a.storage.set(dkey.to_vec(), other_record.clone());
        peer_b.storage.set(dkey.to_vec(), other_record.clone());

        assert_eq!(
            requester
                .update(&chain.did, chain.version(1), chain.earlier(1))
                .await,
            Some(false),
            "a prospective local vote alone must not satisfy a 2-of-3 update"
        );
        assert_eq!(
            requester.storage.get(&dkey),
            Some(chain.version(0)),
            "failed quorum must not commit the new local value"
        );
        for peer in [&peer_a, &peer_b] {
            assert_eq!(
                peer.storage.get(&dkey).as_ref(),
                Some(&other_record),
                "a replica holding another record must not be changed"
            );
        }
    });
}

#[test]
fn update_commits_locally_after_quorum() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(1);
        let dkey = chain.key;
        let requester = start_node(15881, issuer, dkey).await;
        let peer_a = start_node(15882, issuer, node_id(51)).await;
        let peer_b = start_node(15883, issuer, node_id(52)).await;
        bootstrap_to(&requester, &[15882, 15883]).await;

        for server in [&requester, &peer_a, &peer_b] {
            server.storage.set(dkey.to_vec(), chain.version(0));
        }

        assert_eq!(
            requester
                .update(&chain.did, chain.version(1), chain.earlier(1))
                .await,
            Some(true),
            "the local replica and acknowledged remote replicas must reach quorum"
        );
        assert_eq!(
            requester.storage.get(&dkey),
            Some(chain.version(1)),
            "the local value must be committed after quorum"
        );
    });
}

/// A reply lost after the update was applied: the owner repeats the same
/// update. It must succeed and complete the replicas that missed it, whichever
/// copies already moved to the new version.
#[test]
fn retrying_an_applied_update_succeeds_and_completes_the_replicas() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(1);
        let dkey = chain.key;
        let requester = start_node(15928, issuer, dkey).await;
        let peer_a = start_node(15929, issuer, node_id(61)).await;
        let peer_b = start_node(15930, issuer, node_id(62)).await;
        bootstrap_to(&requester, &[15929, 15930]).await;

        // (requester, peer_a, peer_b) before the retry; true = version 1.
        for state in [(true, true, false), (false, true, true), (true, true, true)] {
            let pick = |is_new: bool| chain.version(usize::from(is_new));
            requester.storage.set(dkey.to_vec(), pick(state.0));
            peer_a.storage.set(dkey.to_vec(), pick(state.1));
            peer_b.storage.set(dkey.to_vec(), pick(state.2));

            assert_eq!(
                requester
                    .update(&chain.did, chain.version(1), chain.earlier(1))
                    .await,
                Some(true),
                "retrying an applied update must succeed, state {state:?}"
            );
            for (name, server) in [
                ("requester", &requester),
                ("peer_a", &peer_a),
                ("peer_b", &peer_b),
            ] {
                assert_eq!(
                    server.storage.get(&dkey),
                    Some(chain.version(1)),
                    "{name} must hold the new version after the retry, state {state:?}"
                );
            }
        }
    });
}

/// A replica that already holds the version acknowledges the update without
/// verifying or writing: the answer means "I hold this record". An older
/// version sent to a replica holding a newer one is refused as stale.
#[test]
fn replica_acknowledges_an_update_it_already_holds() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(3);
        let dkey = chain.key;
        let replica_id = node_id(63);
        let replica = start_node(15931, issuer, replica_id).await;
        let sender = start_node(15932, issuer, node_id(64)).await;
        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15931));

        replica.storage.set(dkey.to_vec(), chain.version(2));
        assert_eq!(
            protocol
                .call_update_rpc_answer(&target, dkey, chain.version(2))
                .await,
            Some(UpdateStatus::AlreadyStored),
            "a repeated update must be acknowledged"
        );
        assert_eq!(replica.storage.get(&dkey), Some(chain.version(2)));

        replica.storage.set(dkey.to_vec(), chain.version(3));
        assert_eq!(
            protocol
                .call_update_rpc_answer(&target, dkey, chain.version(2))
                .await,
            Some(UpdateStatus::Stale),
            "an older version must be refused"
        );
        assert_eq!(
            replica.storage.get(&dkey),
            Some(chain.version(3)),
            "a refused update must not change the replica"
        );
    });
}

/// The gap of the authorization that travelled only with the UPDATE, closed
/// by the chain: the empty replicas refuse the UPDATE for lack of version 0,
/// take version 1 by STORE once their network check finds the owner's
/// version 0 that commits to its key, and the update succeeds while the old
/// version is in the network.
#[test]
fn update_fills_empty_replicas_while_the_old_version_is_in_the_network() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(1);
        let dkey = chain.key;
        // Not the key itself: lookups leave out a node whose id is the key,
        // and the empty replicas must find the owner's copy.
        let requester = start_node(15933, issuer, id_at_distance(dkey, 0x01)).await;
        let peer_a = start_node(15934, issuer, node_id(65)).await;
        let peer_b = start_node(15935, issuer, node_id(66)).await;
        bootstrap_to(&requester, &[15934, 15935]).await;
        requester.storage.set(dkey.to_vec(), chain.version(0));

        assert_eq!(
            requester
                .update(&chain.did, chain.version(1), chain.earlier(1))
                .await,
            Some(true),
            "empty replicas must take the version that follows the one in the network"
        );
        for (name, server) in [
            ("requester", &requester),
            ("peer_a", &peer_a),
            ("peer_b", &peer_b),
        ] {
            assert_eq!(server.storage.get(&dkey), Some(chain.version(1)), "{name}");
        }
    });
}

/// An UPDATE needs the version before it: a replica without the record
/// answers that it misses it and stays empty. The same version sent as STORE
/// is stored, once the replica's network check finds version 0 at the
/// sender.
#[test]
fn replica_without_the_record_refuses_an_update_but_takes_a_store() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(1);
        let dkey = chain.key;
        let replica_id = node_id(67);
        let replica = start_node(15936, issuer, replica_id).await;
        let sender = start_node(15937, issuer, node_id(68)).await;
        // The replica must know someone to ask about the record.
        add_known_peer(&replica, node_id(68), 15937).await;
        sender.storage.set(dkey.to_vec(), chain.version(0));
        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15936));

        assert_eq!(
            protocol
                .call_update_rpc_answer(&target, dkey, chain.version(1))
                .await,
            Some(UpdateStatus::MissingPrevious { seq: None }),
            "a replica without the version before must refuse the update"
        );
        assert_eq!(
            replica.storage.get(&dkey),
            None,
            "a refused update must store nothing"
        );
        assert_eq!(
            protocol
                .call_store_rpc(&target, dkey, chain.version(1))
                .await,
            Some(StoreStatus::Stored),
            "the same version sent as STORE must be stored"
        );
        assert_eq!(replica.storage.get(&dkey), Some(chain.version(1)));
    });
}

/// An empty replica asks the nodes closest to the key before storing. Another
/// version 1 than the one they hold is refused and not stored, as a forged
/// version would be; the version they hold is stored.
#[test]
fn empty_replica_refuses_a_record_other_than_the_one_in_the_network() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::with_versions(1);
        let dkey = chain.key;
        let replica_id = node_id(69);
        let replica = start_node(15938, issuer, replica_id).await;
        let holder_a = start_node(15939, issuer, node_id(70)).await;
        let holder_b = start_node(15940, issuer, node_id(71)).await;
        let sender = start_node(15941, issuer, node_id(72)).await;
        bootstrap_to(&replica, &[15939, 15940]).await;

        let attacker = MlDsa65KeyPair::generate().unwrap();
        let forged = chain.forge(1, &chain.version(0), &attacker);
        holder_a.storage.set(dkey.to_vec(), chain.version(1));
        holder_b.storage.set(dkey.to_vec(), chain.version(1));

        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15938));
        assert_eq!(
            protocol.call_store_rpc(&target, dkey, forged).await,
            Some(StoreStatus::Conflict),
            "a record other than the one in the network must be refused"
        );
        assert_eq!(
            replica.storage.get(&dkey),
            None,
            "a refused record must not be stored"
        );
        assert_eq!(
            protocol
                .call_store_rpc(&target, dkey, chain.version(1))
                .await,
            Some(StoreStatus::Stored),
            "the record the network holds must be stored"
        );
        assert_eq!(replica.storage.get(&dkey), Some(chain.version(1)));
    });
}

/// A first publication: no node holds the DID, so the empty replica stores
/// its version 0.
#[test]
fn empty_replica_takes_a_record_no_node_holds() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::new();
        let dkey = chain.key;
        let replica_id = node_id(73);
        let replica = start_node(15942, issuer, replica_id).await;
        let sender = start_node(15943, issuer, node_id(74)).await;
        let _other = start_node(15944, issuer, node_id(75)).await;
        bootstrap_to(&replica, &[15943, 15944]).await;

        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15942));
        assert_eq!(
            protocol
                .call_store_rpc(&target, dkey, chain.version(0))
                .await,
            Some(StoreStatus::Stored),
            "a record no node holds must be stored"
        );
        assert_eq!(replica.storage.get(&dkey), Some(chain.version(0)));
    });
}

/// The nodes answer the check with the version and SHA-256 of the record they
/// hold, and a hash cannot be verified: a node holding another version 0
/// blocks the STORE even when that record is invalid. Honest nodes store only
/// verified records, so only a dishonest node holds an invalid one, and it
/// could block the STORE anyway by not answering.
#[test]
fn a_node_holding_an_invalid_copy_blocks_the_store() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::new();
        let dkey = chain.key;
        let replica_id = node_id(76);
        let replica = start_node(15945, issuer, replica_id).await;
        let liar = start_node(15946, issuer, node_id(77)).await;
        let sender = start_node(15947, issuer, node_id(78)).await;
        bootstrap_to(&replica, &[15946]).await;

        let mut tampered = signed_again(&chain);
        tampered[12] ^= 0xFF;
        liar.storage.set(dkey.to_vec(), tampered);

        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15945));
        assert_eq!(
            protocol
                .call_store_rpc(&target, dkey, chain.version(0))
                .await,
            Some(StoreStatus::Conflict),
            "a different hash in the network must block the STORE"
        );
        assert_eq!(replica.storage.get(&dkey), None);
    });
}

/// A STORE to an empty replica waits for a lookup, whose answers reach the
/// replica through the same workers that read its requests. Several such
/// STOREs at once must not hold those workers: every lookup must still
/// receive its answer and find the record in the network. Answers are spread
/// over the workers in turn, so a single held worker is enough to delay some.
/// One sender and one holder: each can have at most
/// `MAX_REASSEMBLY_ENTRIES_PER_PEER` fragmented messages in flight to the
/// replica, and the rest would be dropped.
#[test]
fn many_stores_to_an_empty_replica_all_get_their_lookup_answers() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let replica_id = node_id(79);
        let replica = start_node(15948, issuer, replica_id).await;
        let holder = start_node(15949, issuer, node_id(80)).await;
        let sender = start_node(15950, issuer, node_id(81)).await;
        bootstrap_to(&replica, &[15949]).await;

        let count = MAX_REASSEMBLY_ENTRIES_PER_PEER;
        let mut forged_records = Vec::with_capacity(count);
        for _ in 0..count {
            let chain = Chain::new();
            holder.storage.set(chain.key.to_vec(), chain.version(0));
            forged_records.push((chain.key, signed_again(&chain)));
        }

        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15948));
        let answers = futures::future::join_all(
            forged_records
                .iter()
                .map(|(dkey, forged)| protocol.call_store_rpc(&target, *dkey, forged.clone())),
        )
        .await;

        for (index, answer) in answers.into_iter().enumerate() {
            assert_eq!(
                answer,
                Some(StoreStatus::Conflict),
                "STORE {index} of {count} must find the record in the network"
            );
        }
        for (dkey, _) in &forged_records {
            assert_eq!(replica.storage.get(dkey), None);
        }
    });
}

/// When a node the replica asks does not answer, the replica cannot tell
/// whether it holds another record, so it refuses the STORE (fail-safe
/// default). It does not answer, and the sender counts it as unavailable.
/// The silent node is then marked as not responding and left out, so the
/// next STORE is checked with the sender alone.
#[test]
fn empty_replica_refuses_a_store_when_a_node_does_not_answer() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let chain = Chain::new();
        let dkey = chain.key;
        let replica_id = node_id(82);
        let replica = start_node(15951, issuer, replica_id).await;
        let sender = start_node(15952, issuer, node_id(83)).await;
        let _silent = std::net::UdpSocket::bind(("127.0.0.1", 15953)).expect("bind");
        add_known_peer(&replica, node_id(84), 15953).await;
        add_known_peer(&replica, node_id(83), 15952).await;

        let record = chain.version(0);
        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15951));
        assert_eq!(
            protocol.call_store_rpc(&target, dkey, record.clone()).await,
            None,
            "a replica that did not hear from every node must not answer"
        );
        assert_eq!(
            replica.storage.get(&dkey),
            None,
            "a refused record must not be stored"
        );
        assert_eq!(
            protocol.call_store_rpc(&target, dkey, record.clone()).await,
            Some(StoreStatus::Stored),
            "the silent node must be left out of the next check"
        );
        assert_eq!(replica.storage.get(&dkey), Some(record));
    });
}
