//! End-to-end consistency tests for DID Documents and the issuer Status List.
//!
//! Every test uses real UDP nodes and valid Dilithium records. Records are
//! injected only after bootstrap so the tests control the exact replica state.
//! Ports: 15866-15894, 15904-15905, 15913-15923, 15928-15953.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::fragmentation::MAX_REASSEMBLY_ENTRIES_PER_PEER;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::protocol::StoreStatus;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::{digest, ID_LEN, STATUS_LIST_KEY};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

use common::{build_did_document, build_signed_record, generate_did_iiot};

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

fn did_record(did: &str) -> (Vec<u8>, dilithium2::SecretKey) {
    let (signing_key, secret_key) = dilithium2::keypair();
    let (agreement_key, _) = kyber512::keypair();
    let document = build_did_document(did, &signing_key, &agreement_key);
    let record = build_signed_record(&document, &secret_key, "Dilithium-2");
    (record, secret_key)
}

fn issuer_record(payload: &[u8], secret_key: &dilithium2::SecretKey) -> Vec<u8> {
    let mut algorithm = [0_u8; 12];
    algorithm[..11].copy_from_slice(b"Dilithium-2");
    let signature = dilithium2::detached_sign(payload, secret_key);

    let mut record = Vec::with_capacity(12 + signature.as_bytes().len() + payload.len());
    record.extend_from_slice(&algorithm);
    record.extend_from_slice(signature.as_bytes());
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

#[test]
fn remote_did_get_returns_a_record_when_replicas_disagree() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let requester = start_node(15866, issuer, node_id(1)).await;
        let peer_a = start_node(15867, issuer, node_id(2)).await;
        let peer_b = start_node(15868, issuer, node_id(3)).await;
        let peer_c = start_node(15869, issuer, node_id(4)).await;
        bootstrap_to(&requester, &[15867, 15868, 15869]).await;

        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let (record_a, _) = did_record(&did);
        let (record_b, _) = did_record(&did);
        let (record_c, _) = did_record(&did);

        peer_a.storage.set(dkey.to_vec(), record_a.clone());
        peer_b.storage.set(dkey.to_vec(), record_b.clone());
        peer_c.storage.set(dkey.to_vec(), record_c.clone());

        let found = requester.get(key).await.expect("a valid record exists");
        assert!(
            [record_a, record_b, record_c].contains(&found),
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

        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let (record, _) = did_record(&did);
        holder.storage.set(digest(key).to_vec(), record.clone());

        assert_eq!(requester.get(key).await, Some(record));
    });
}

#[test]
fn remote_did_get_skips_an_invalid_record() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);

        let requester = start_node(15916, issuer, node_id(50)).await;
        let bad_a = start_node(15917, issuer, id_at_distance(dkey, 0x01)).await;
        let bad_b = start_node(15918, issuer, id_at_distance(dkey, 0x02)).await;
        let bad_c = start_node(15919, issuer, id_at_distance(dkey, 0x03)).await;
        let good = start_node(15920, issuer, id_at_distance(dkey, 0x04)).await;
        bootstrap_to(&requester, &[15917, 15918, 15919, 15920]).await;

        let (record, _) = did_record(&did);
        let mut tampered = record.clone();
        tampered[12] ^= 0xFF;
        for peer in [&bad_a, &bad_b, &bad_c] {
            peer.storage.set(dkey.to_vec(), tampered.clone());
        }
        good.storage.set(dkey.to_vec(), record.clone());

        assert_eq!(
            requester.get(key).await,
            Some(record),
            "records that fail verification must not end the read"
        );
    });
}

#[test]
fn remote_did_get_does_not_wait_for_a_dead_peer() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);

        let requester = start_node(15921, issuer, node_id(60)).await;
        let holder = start_node(15922, issuer, id_at_distance(dkey, 0x02)).await;
        bootstrap_to(&requester, &[15922]).await;
        let _silent = std::net::UdpSocket::bind(("127.0.0.1", 15923)).expect("bind");
        add_known_peer(&requester, id_at_distance(dkey, 0x01), 15923).await;

        let (record, _) = did_record(&did);
        holder.storage.set(dkey.to_vec(), record.clone());

        let started = std::time::Instant::now();
        assert_eq!(requester.get(key).await, Some(record));
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
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let (record, _) = did_record(&did);

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
            requester.get(key).await,
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
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let record = did_record(&did).0;

        requester.storage.set(digest(key).to_vec(), record.clone());

        assert_eq!(
            requester.get(key).await,
            Some(record),
            "a valid local DID Document must not require the network"
        );
    });
}

#[test]
fn status_list_uses_local_copy_as_one_vote() {
    runtime().block_on(async {
        let (issuer_public_key, issuer_secret_key) = dilithium2::keypair();
        let issuer_file = TemporaryIssuerKey::create(15875, issuer_public_key.as_bytes());
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
        let (issuer_public_key, issuer_secret_key) = dilithium2::keypair();
        let issuer_file = TemporaryIssuerKey::create(15904, issuer_public_key.as_bytes());
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
            issuer.update(ISSUER_KEY, second.clone(), None).await,
            Some(true)
        );
        assert_eq!(proxy.get(ISSUER_KEY).await, Some(second));
    });
}

#[test]
fn update_without_quorum_preserves_the_local_record() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let requester = start_node(15878, issuer, dkey).await;
        let peer_a = start_node(15879, issuer, node_id(41)).await;
        let peer_b = start_node(15880, issuer, node_id(42)).await;
        bootstrap_to(&requester, &[15879, 15880]).await;

        let (old_record, old_secret_key) = did_record(&did);
        let (new_record, _) = did_record(&did);
        let (other_record, _) = did_record(&did);
        let authorization = dilithium2::detached_sign(&new_record, &old_secret_key)
            .as_bytes()
            .to_vec();
        requester.storage.set(dkey.to_vec(), old_record.clone());
        // The replicas hold another record for this DID: they refuse the
        // update, and the STORE that follows it gets a conflict.
        peer_a.storage.set(dkey.to_vec(), other_record.clone());
        peer_b.storage.set(dkey.to_vec(), other_record.clone());

        assert_eq!(
            requester.update(key, new_record, Some(authorization)).await,
            Some(false),
            "a prospective local vote alone must not satisfy a 2-of-3 update"
        );
        assert_eq!(
            requester.storage.get(&dkey),
            Some(old_record),
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
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let requester = start_node(15881, issuer, dkey).await;
        let peer_a = start_node(15882, issuer, node_id(51)).await;
        let peer_b = start_node(15883, issuer, node_id(52)).await;
        bootstrap_to(&requester, &[15882, 15883]).await;

        let (old_record, old_secret_key) = did_record(&did);
        let (new_record, _) = did_record(&did);
        let authorization = dilithium2::detached_sign(&new_record, &old_secret_key)
            .as_bytes()
            .to_vec();
        requester.storage.set(dkey.to_vec(), old_record.clone());
        peer_a.storage.set(dkey.to_vec(), old_record.clone());
        peer_b.storage.set(dkey.to_vec(), old_record);

        assert_eq!(
            requester
                .update(key, new_record.clone(), Some(authorization))
                .await,
            Some(true),
            "the local replica and acknowledged remote replicas must reach quorum"
        );
        assert_eq!(
            requester.storage.get(&dkey),
            Some(new_record),
            "the local value must be committed after quorum"
        );
    });
}

/// A reply lost after the update was applied: the owner repeats the same
/// update. It must succeed and complete the replicas that missed it, whichever
/// copies already moved to the new record.
#[test]
fn retrying_an_applied_update_succeeds_and_completes_the_replicas() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let requester = start_node(15928, issuer, dkey).await;
        let peer_a = start_node(15929, issuer, node_id(61)).await;
        let peer_b = start_node(15930, issuer, node_id(62)).await;
        bootstrap_to(&requester, &[15929, 15930]).await;

        let (old_record, old_secret_key) = did_record(&did);
        let (new_record, _) = did_record(&did);
        let authorization = dilithium2::detached_sign(&new_record, &old_secret_key)
            .as_bytes()
            .to_vec();

        // (requester, peer_a, peer_b) before the retry; true = new record.
        for state in [(true, true, false), (false, true, true), (true, true, true)] {
            let pick = |is_new: bool| {
                if is_new {
                    new_record.clone()
                } else {
                    old_record.clone()
                }
            };
            requester.storage.set(dkey.to_vec(), pick(state.0));
            peer_a.storage.set(dkey.to_vec(), pick(state.1));
            peer_b.storage.set(dkey.to_vec(), pick(state.2));

            assert_eq!(
                requester
                    .update(key, new_record.clone(), Some(authorization.clone()))
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
                    server.storage.get(&dkey).as_ref(),
                    Some(&new_record),
                    "{name} must hold the new record after the retry, state {state:?}"
                );
            }
        }
    });
}

/// A replica that already holds the record acknowledges the update without
/// verifying or writing: the answer means "I hold this record". An old update
/// still goes through full verification and is refused.
#[test]
fn replica_acknowledges_an_update_it_already_holds() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let dkey = digest(did.split(':').next_back().unwrap());
        let replica_id = node_id(63);
        let replica = start_node(15931, issuer, replica_id).await;
        let sender = start_node(15932, issuer, node_id(64)).await;
        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15931));

        let (_v1, sk1) = did_record(&did);
        let (v2, _) = did_record(&did);
        let (v3, _) = did_record(&did);
        let auth_v2 = dilithium2::detached_sign(&v2, &sk1).as_bytes().to_vec();

        replica.storage.set(dkey.to_vec(), v2.clone());
        assert!(
            protocol
                .call_update_rpc(&target, dkey, v2.clone(), auth_v2.clone())
                .await,
            "a repeated update must be acknowledged"
        );
        assert!(
            protocol
                .call_update_rpc(&target, dkey, v2.clone(), vec![0u8; auth_v2.len()])
                .await,
            "the acknowledgement says the replica holds the record, not that the signature is valid"
        );
        assert_eq!(replica.storage.get(&dkey), Some(v2.clone()));

        replica.storage.set(dkey.to_vec(), v3.clone());
        assert!(
            !protocol.call_update_rpc(&target, dkey, v2, auth_v2).await,
            "an old update must still be verified against the newer record and refused"
        );
        assert_eq!(
            replica.storage.get(&dkey),
            Some(v3),
            "a refused update must not change the replica"
        );
    });
}

/// Responsible replicas that do not hold the record cannot verify the
/// rotation, so they refuse the update, and the owner sends them the new
/// record as STORE. An empty replica asks the network first: while the owner
/// still holds the old record, the new one differs from the copy it finds, so
/// it refuses the STORE too. The update fails and changes nothing. This is a
/// known gap: the empty replica has no authorization to check the new record
/// against the old one.
#[test]
fn update_cannot_fill_empty_replicas_while_the_old_record_is_in_the_network() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        // Not the key itself: lookups leave out a node whose id is the key,
        // and the empty replicas must find the owner's copy.
        let requester = start_node(15933, issuer, id_at_distance(dkey, 0x01)).await;
        let peer_a = start_node(15934, issuer, node_id(65)).await;
        let peer_b = start_node(15935, issuer, node_id(66)).await;
        bootstrap_to(&requester, &[15934, 15935]).await;

        let (old_record, old_secret_key) = did_record(&did);
        let (new_record, _) = did_record(&did);
        let authorization = dilithium2::detached_sign(&new_record, &old_secret_key)
            .as_bytes()
            .to_vec();
        requester.storage.set(dkey.to_vec(), old_record.clone());

        assert_eq!(
            requester.update(key, new_record, Some(authorization)).await,
            Some(false),
            "empty replicas must refuse a record other than the one in the network"
        );
        assert_eq!(
            requester.storage.get(&dkey),
            Some(old_record),
            "the owner must keep the old record"
        );
        for (name, server) in [("peer_a", &peer_a), ("peer_b", &peer_b)] {
            assert_eq!(server.storage.get(&dkey), None, "{name} must stay empty");
        }
    });
}

/// An update is accepted only as a verified rotation, so a replica without
/// the record refuses it and stays empty. The same record sent as STORE is
/// stored, because no node holds another one.
#[test]
fn replica_without_the_record_refuses_an_update_but_takes_a_store() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let dkey = digest(did.split(':').next_back().unwrap());
        let replica_id = node_id(67);
        let replica = start_node(15936, issuer, replica_id).await;
        let sender = start_node(15937, issuer, node_id(68)).await;
        // The replica must know someone to ask about the record.
        add_known_peer(&replica, node_id(68), 15937).await;
        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15936));

        let (_old_record, old_secret_key) = did_record(&did);
        let (new_record, _) = did_record(&did);
        let authorization = dilithium2::detached_sign(&new_record, &old_secret_key)
            .as_bytes()
            .to_vec();

        assert!(
            !protocol
                .call_update_rpc(&target, dkey, new_record.clone(), authorization)
                .await,
            "a replica without the record cannot verify the rotation and must refuse it"
        );
        assert_eq!(
            replica.storage.get(&dkey),
            None,
            "a refused update must store nothing"
        );
        assert_eq!(
            protocol
                .call_store_rpc(&target, dkey, new_record.clone())
                .await,
            Some(StoreStatus::Stored),
            "the same record sent as STORE must be stored"
        );
        assert_eq!(replica.storage.get(&dkey), Some(new_record));
    });
}

/// An empty replica asks the nodes closest to the key before storing. A
/// record other than the one they hold is refused and not stored, as a forged
/// document for an existing DID would be; the record they hold is stored.
#[test]
fn empty_replica_refuses_a_record_other_than_the_one_in_the_network() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let dkey = digest(did.split(':').next_back().unwrap());
        let replica_id = node_id(69);
        let replica = start_node(15938, issuer, replica_id).await;
        let holder_a = start_node(15939, issuer, node_id(70)).await;
        let holder_b = start_node(15940, issuer, node_id(71)).await;
        let sender = start_node(15941, issuer, node_id(72)).await;
        bootstrap_to(&replica, &[15939, 15940]).await;

        let (record, _) = did_record(&did);
        let (forged, _) = did_record(&did);
        holder_a.storage.set(dkey.to_vec(), record.clone());
        holder_b.storage.set(dkey.to_vec(), record.clone());

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
            protocol.call_store_rpc(&target, dkey, record.clone()).await,
            Some(StoreStatus::Stored),
            "the record the network holds must be stored"
        );
        assert_eq!(replica.storage.get(&dkey), Some(record));
    });
}

/// A first publication: no node holds the DID, so the empty replica stores
/// the record.
#[test]
fn empty_replica_takes_a_record_no_node_holds() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let dkey = digest(did.split(':').next_back().unwrap());
        let replica_id = node_id(73);
        let replica = start_node(15942, issuer, replica_id).await;
        let sender = start_node(15943, issuer, node_id(74)).await;
        let _other = start_node(15944, issuer, node_id(75)).await;
        bootstrap_to(&replica, &[15943, 15944]).await;

        let (record, _) = did_record(&did);
        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15942));
        assert_eq!(
            protocol.call_store_rpc(&target, dkey, record.clone()).await,
            Some(StoreStatus::Stored),
            "a record no node holds must be stored"
        );
        assert_eq!(replica.storage.get(&dkey), Some(record));
    });
}

/// The nodes answer the check with the SHA-256 of the record they hold, and
/// a hash cannot be verified: a node holding a different record blocks the
/// STORE even when that record is invalid. Honest nodes store only verified
/// records, so only a dishonest node holds an invalid one, and it could block
/// the STORE anyway by not answering.
#[test]
fn a_node_holding_an_invalid_copy_blocks_the_store() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let dkey = digest(did.split(':').next_back().unwrap());
        let replica_id = node_id(76);
        let replica = start_node(15945, issuer, replica_id).await;
        let liar = start_node(15946, issuer, node_id(77)).await;
        let sender = start_node(15947, issuer, node_id(78)).await;
        bootstrap_to(&replica, &[15946]).await;

        let (record, _) = did_record(&did);
        let (other, _) = did_record(&did);
        let mut tampered = other;
        tampered[12] ^= 0xFF;
        liar.storage.set(dkey.to_vec(), tampered);

        let protocol = sender.protocol.as_ref().expect("sender must be listening");
        let target = Node::new(replica_id, Some("127.0.0.1".to_string()), Some(15945));
        assert_eq!(
            protocol.call_store_rpc(&target, dkey, record).await,
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
            let did = generate_did_iiot();
            let dkey = digest(did.split(':').next_back().unwrap());
            let (record, _) = did_record(&did);
            let (forged, _) = did_record(&did);
            holder.storage.set(dkey.to_vec(), record);
            forged_records.push((dkey, forged));
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
        let did = generate_did_iiot();
        let dkey = digest(did.split(':').next_back().unwrap());
        let replica_id = node_id(82);
        let replica = start_node(15951, issuer, replica_id).await;
        let sender = start_node(15952, issuer, node_id(83)).await;
        let _silent = std::net::UdpSocket::bind(("127.0.0.1", 15953)).expect("bind");
        add_known_peer(&replica, node_id(84), 15953).await;
        add_known_peer(&replica, node_id(83), 15952).await;

        let (record, _) = did_record(&did);
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
