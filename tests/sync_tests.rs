//! A node that starts asks its neighbours for the records it should hold,
//! over real UDP: after a restart with nothing on disk, after a restart from
//! its data directory that missed a rotation, and as a seed that never
//! bootstraps. The neighbours never noticed it was gone, so none of them
//! sends it its records on its own. Each node of a test has its own loopback
//! address (Linux routes all of 127.0.0.0/8 to loopback), so that the node
//! that starts asks more than one of them. Ports: 16049-16057.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::{ForgetfulStorage, IStorage, DEFAULT_TTL};
use auth_kademlia_rs::utils::ID_LEN;
use tokio::time::sleep;

use common::Chain;

/// How long a node that starts may take to hold its records again: a
/// synchronization takes milliseconds on loopback, and a node with no seeds
/// starts it at the next maintenance tick, once a second.
const REFILLED_WITHIN: Duration = Duration::from_secs(5);

async fn start(ip: &str, port: u16, tag: u8, storage: ForgetfulStorage) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(Path::new("unused")));
    let mut server = Server::new(
        handler,
        20,
        3,
        Some([tag; ID_LEN]),
        Some(Arc::new(storage)),
        false,
    );
    // The port of a node just dropped is released once its tasks end.
    for _ in 0..100 {
        if server.listen(port, ip).await.is_ok() {
            return server;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("cannot listen on {ip}:{port}");
}

fn in_memory() -> ForgetfulStorage {
    ForgetfulStorage::new(DEFAULT_TTL)
}

/// A fresh directory, removed when dropped.
struct DataDir(PathBuf);

impl DataDir {
    fn new(port: u16) -> Self {
        let name = format!(
            "akrs-sync-{}-{port}-{}",
            std::process::id(),
            rand::random::<u32>()
        );
        Self(std::env::temp_dir().join(name))
    }

    fn storage(&self) -> ForgetfulStorage {
        ForgetfulStorage::persistent(&self.0, DEFAULT_TTL, 1 << 20).expect("data dir")
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hold(server: &Server, records: &[([u8; ID_LEN], Vec<u8>)]) {
    for (key, record) in records {
        server.storage.set(key.to_vec(), record.clone());
    }
}

/// Whether `server` holds exactly `records` before `wait` is over.
async fn holds_within(
    server: &Server,
    records: &[([u8; ID_LEN], Vec<u8>)],
    wait: Duration,
) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if records
            .iter()
            .all(|(key, record)| server.storage.get(key).as_ref() == Some(record))
        {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn first_positions(count: usize) -> Vec<([u8; ID_LEN], Vec<u8>)> {
    (0..count)
        .map(|_| {
            let chain = Chain::new();
            (chain.key, chain.version(0))
        })
        .collect()
}

fn seed(port: u16) -> Vec<(String, u16)> {
    vec![("127.0.0.1".to_string(), port)]
}

/// C crashes, without telling anyone, and starts again at once with nothing:
/// it holds the records of A and B again without a republication.
#[tokio::test]
async fn a_node_that_restarts_empty_at_once_holds_its_records_again() {
    let a = start("127.0.0.1", 16049, 1, in_memory()).await;
    let b = start("127.0.0.2", 16050, 2, in_memory()).await;
    let c = start("127.0.0.3", 16051, 3, in_memory()).await;
    b.bootstrap(seed(16049)).await;
    c.bootstrap(seed(16049)).await;
    let records = first_positions(3);
    hold(&a, &records);
    hold(&b, &records);

    drop(c);
    let c = start("127.0.0.3", 16051, 3, in_memory()).await;
    c.bootstrap(seed(16049)).await;

    assert!(holds_within(&c, &records, REFILLED_WITHIN).await);
}

/// C holds position 0 on disk and crashes; position 1 reaches A and B
/// meanwhile. Started again from its directory, C holds position 1 without
/// a republication.
#[tokio::test]
async fn a_node_restarted_from_its_data_directory_takes_the_rotation_it_missed() {
    let dir = DataDir::new(16054);
    let mut chain = Chain::new();
    let a = start("127.0.0.1", 16052, 4, in_memory()).await;
    let b = start("127.0.0.2", 16053, 5, in_memory()).await;
    let c = start("127.0.0.3", 16054, 6, dir.storage()).await;
    b.bootstrap(seed(16052)).await;
    c.bootstrap(seed(16052)).await;
    let first = [(chain.key, chain.version(0))];
    hold(&a, &first);
    hold(&b, &first);
    hold(&c, &first);

    drop(c);
    let rotated = [(chain.key, chain.grow())];
    hold(&a, &rotated);
    hold(&b, &rotated);
    let c = start("127.0.0.3", 16054, 6, dir.storage()).await;
    assert!(holds_within(&c, &first, Duration::ZERO).await);
    c.bootstrap(seed(16052)).await;

    assert!(holds_within(&c, &rotated, REFILLED_WITHIN).await);
}

/// The seed A restarts empty and never bootstraps: once a node reaches it,
/// it looks itself up and holds the records of B and C again.
#[tokio::test]
async fn a_seed_that_restarts_empty_holds_its_records_once_a_node_reaches_it() {
    let a = start("127.0.0.1", 16055, 7, in_memory()).await;
    let b = start("127.0.0.2", 16056, 8, in_memory()).await;
    let c = start("127.0.0.3", 16057, 9, in_memory()).await;
    b.bootstrap(seed(16055)).await;
    c.bootstrap(seed(16055)).await;
    let records = first_positions(3);
    hold(&b, &records);
    hold(&c, &records);

    drop(a);
    let a = start("127.0.0.1", 16055, 7, in_memory()).await;
    b.bootstrap(seed(16055)).await;

    assert!(holds_within(&a, &records, REFILLED_WITHIN).await);
}
