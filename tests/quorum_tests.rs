//! End-to-end consistency tests for DID Documents and the issuer Status List.
//!
//! Every test uses real UDP nodes and valid Dilithium records. Records are
//! injected only after bootstrap so the tests control the exact replica state.
//! Ports: 15866-15894.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
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
    protocol
        .router
        .write()
        .await
        .add_contact(Node::new(id, Some("127.0.0.1".to_string()), Some(port)));
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
fn remote_did_get_returns_two_of_three_majority() {
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
        let (old_record, _) = did_record(&did);
        let (new_record, _) = did_record(&did);

        peer_a.storage.set(dkey.to_vec(), old_record);
        peer_b.storage.set(dkey.to_vec(), new_record.clone());
        peer_c.storage.set(dkey.to_vec(), new_record.clone());

        assert_eq!(
            requester.get(key).await,
            Some(new_record),
            "two byte-identical, valid replicas must win a 2-of-3 read"
        );
    });
}

#[test]
fn remote_did_get_rejects_three_way_split() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let requester = start_node(15870, issuer, node_id(10)).await;
        let peer_a = start_node(15871, issuer, node_id(11)).await;
        let peer_b = start_node(15872, issuer, node_id(12)).await;
        let peer_c = start_node(15873, issuer, node_id(13)).await;
        bootstrap_to(&requester, &[15871, 15872, 15873]).await;

        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let (record_a, _) = did_record(&did);
        let (record_b, _) = did_record(&did);
        let (record_c, _) = did_record(&did);

        peer_a.storage.set(dkey.to_vec(), record_a);
        peer_b.storage.set(dkey.to_vec(), record_b);
        peer_c.storage.set(dkey.to_vec(), record_c);

        assert_eq!(
            requester.get(key).await,
            None,
            "three divergent valid replicas must not select an arbitrary value"
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
            "lookup must follow closer nodes returned by relays before collecting its three votes"
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
            "a valid local DID Document must not require network quorum"
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

#[test]
fn update_without_quorum_preserves_the_local_record() {
    runtime().block_on(async {
        let issuer = Path::new("issuer_pub_key.bin");
        let did = generate_did_iiot();
        let key = did.split(':').next_back().unwrap();
        let dkey = digest(key);
        let requester = start_node(15878, issuer, dkey).await;
        let _peer_a = start_node(15879, issuer, node_id(41)).await;
        let _peer_b = start_node(15880, issuer, node_id(42)).await;
        bootstrap_to(&requester, &[15879, 15880]).await;

        let (old_record, old_secret_key) = did_record(&did);
        let (new_record, _) = did_record(&did);
        let authorization = dilithium2::detached_sign(&new_record, &old_secret_key)
            .as_bytes()
            .to_vec();
        requester.storage.set(dkey.to_vec(), old_record.clone());

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
