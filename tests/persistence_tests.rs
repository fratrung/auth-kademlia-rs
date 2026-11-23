//! A replica that keeps its records on disk, over real UDP: what it serves
//! after a power cut, and what it answers when the disk refuses a write.
//! Ports: 16042-16045.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::{Server, SetOutcome};
use auth_kademlia_rs::storage::{ForgetfulStorage, IStorage, DEFAULT_TTL};
use auth_kademlia_rs::utils::ID_LEN;

use common::Chain;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build test runtime")
}

/// A fresh directory, removed when dropped.
struct DataDir(PathBuf);

impl DataDir {
    fn new(port: u16) -> Self {
        let name = format!(
            "akrs-it-{}-{port}-{}",
            std::process::id(),
            rand::random::<u32>()
        );
        Self(std::env::temp_dir().join(name))
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        set_read_only(&self.0, false);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `false` when the process writes to the directory anyway, as root does.
fn set_read_only(dir: &Path, read_only: bool) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mode = if read_only { 0o555 } else { 0o755 };
    if std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).is_err() {
        return false;
    }
    let probe = dir.join("probe");
    let writable = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    read_only != writable
}

async fn start(port: u16, storage: ForgetfulStorage) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(Path::new("unused")));
    let id = [(port % 251) as u8; ID_LEN];
    let mut server = Server::new(handler, 20, 3, Some(id), Some(Arc::new(storage)), false);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    server
}

fn persistent(dir: &DataDir) -> ForgetfulStorage {
    ForgetfulStorage::persistent(&dir.0, DEFAULT_TTL, 1 << 20).expect("data dir")
}

/// A node stores 6 over 5 and loses power: no shutdown, no flush. Restarted
/// from its directory with no peer to ask, it serves the exact bytes of 6.
#[test]
fn a_restarted_replica_serves_its_record_with_no_peer() {
    runtime().block_on(async {
        let dir = DataDir::new(16042);
        let chain = Chain::with_versions(6);
        let node = start(16042, persistent(&dir)).await;
        assert!(matches!(
            node.set_detailed(&chain.did, chain.version(5)).await,
            SetOutcome::Complete(_)
        ));
        assert!(matches!(
            node.set_detailed(&chain.did, chain.version(6)).await,
            SetOutcome::Complete(_)
        ));
        drop(node);

        let restarted = start(16043, persistent(&dir)).await;
        assert_eq!(restarted.get(&chain.did).await, Some(chain.version(6)));
    });
}

/// The replica's disk refuses the write of 6 while it holds 5: it does not
/// confirm 6, the owner counts it as unavailable, and it keeps 5, also after
/// a restart.
#[test]
fn a_replica_that_cannot_write_does_not_confirm_the_record() {
    runtime().block_on(async {
        let dir = DataDir::new(16044);
        let chain = Chain::with_versions(6);
        let replica = start(16044, persistent(&dir)).await;
        let owner = start(16045, ForgetfulStorage::new(DEFAULT_TTL)).await;
        assert!(!owner
            .bootstrap(vec![("127.0.0.1".to_string(), 16044)])
            .await
            .is_empty());
        tokio::time::sleep(Duration::from_millis(100)).await;
        replica.storage.set(chain.key.to_vec(), chain.version(5));
        if !set_read_only(&dir.0, true) {
            eprintln!("skipped: this process writes to a read-only directory");
            return;
        }

        let outcome = owner.set_detailed(&chain.did, chain.version(6)).await;
        assert!(outcome.report().unavailable_nodes >= 1, "{outcome:?}");
        assert_eq!(replica.storage.get(&chain.key), Some(chain.version(5)));

        set_read_only(&dir.0, false);
        drop(replica);
        assert_eq!(persistent(&dir).get(&chain.key), Some(chain.version(5)));
    });
}
