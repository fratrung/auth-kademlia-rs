//! Repair over real UDP: a reader whose served record failed its check looks
//! for the record its credential names and stores it. Records are injected
//! after bootstrap, so the tests control what each node holds.
//! Ports: 16031-16039.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::ID_LEN;

use common::{sha256, Chain};

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

async fn start_node(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(Path::new("unused")));
    let id = [(port % 251) as u8; ID_LEN];
    let mut server = Server::new(handler, 20, 3, Some(id), None, false);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    server
}

/// A reader at `reader` that knows the nodes at `others`.
async fn network(reader: u16, others: &[u16]) -> (Server, Vec<Server>) {
    let mut nodes = vec![];
    for port in others {
        nodes.push(start_node(*port).await);
    }
    let reader = start_node(reader).await;
    let peers = others
        .iter()
        .map(|port| ("127.0.0.1".to_string(), *port))
        .collect();
    assert!(reader.bootstrap(peers).await.len() >= others.len());
    tokio::time::sleep(Duration::from_millis(100)).await;
    (reader, nodes)
}

fn key_hash(chain: &Chain, seq: u64) -> [u8; 32] {
    sha256(chain.owner.public_key(seq).expect("a position of the tree"))
}

/// The reader serves 5 from its storage, without the network, though a node
/// holds 6; repaired for 6, it serves 6, also once the others are gone.
#[test]
fn a_reader_repairs_its_record_and_then_serves_the_new_one_locally() {
    runtime().block_on(async {
        let (reader, mut others) = network(16031, &[16032, 16033]).await;
        let chain = Chain::with_versions(6);
        let (v5, v6) = (chain.version(5), chain.version(6));
        reader.storage.set(chain.key.to_vec(), v5.clone());
        others[0].storage.set(chain.key.to_vec(), v5.clone());
        others[1].storage.set(chain.key.to_vec(), v6.clone());

        assert_eq!(reader.get(&chain.did).await, Some(v5.clone()));
        assert_eq!(
            reader
                .repair(&chain.did, &v5, 6, &key_hash(&chain, 6))
                .await,
            Some(v6.clone())
        );
        assert_eq!(reader.storage.get(&chain.key), Some(v6.clone()));

        for node in &mut others {
            node.stop().await;
        }
        assert_eq!(reader.get(&chain.did).await, Some(v6));
    });
}

/// Another key at 6, a position nobody holds, or a record whose key is not
/// the tree's: no match, and the reader keeps 5.
#[test]
fn a_repair_without_the_expected_record_keeps_the_served_one() {
    runtime().block_on(async {
        let (reader, others) = network(16034, &[16035, 16036, 16037]).await;
        let chain = Chain::with_versions(7);
        let v5 = chain.version(5);
        let forged = chain.forge(6, &v5, &chain.key_pair(5));
        reader.storage.set(chain.key.to_vec(), v5.clone());
        others[0].storage.set(chain.key.to_vec(), v5.clone());
        others[1].storage.set(chain.key.to_vec(), chain.version(6));
        others[2].storage.set(chain.key.to_vec(), forged);

        let forged_key = sha256(chain.key_pair(5).public_key());
        for (seq, expected_key) in [
            (6, key_hash(&chain, 7)),
            (7, key_hash(&chain, 7)),
            (6, forged_key),
        ] {
            assert_eq!(
                reader.repair(&chain.did, &v5, seq, &expected_key).await,
                None,
                "position {seq}"
            );
            assert_eq!(reader.storage.get(&chain.key), Some(v5.clone()));
        }
    });
}

/// The only node the reader knows does not answer: no match within the
/// deadline, and the reader keeps 5.
#[test]
fn a_repair_gives_up_when_nobody_answers() {
    runtime().block_on(async {
        let reader = start_node(16038).await;
        let protocol = reader.protocol.as_ref().expect("listening");
        protocol.router.write().await.add_contact(Node::new(
            [7; ID_LEN],
            Some("127.0.0.1".to_string()),
            Some(16039),
        ));
        let chain = Chain::with_versions(6);
        let v5 = chain.version(5);
        reader.storage.set(chain.key.to_vec(), v5.clone());

        let started = Instant::now();
        assert_eq!(
            reader
                .repair(&chain.did, &v5, 6, &key_hash(&chain, 6))
                .await,
            None
        );
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(reader.storage.get(&chain.key), Some(v5));
    });
}
