#![allow(dead_code)]

/// The record builders of the integration tests, shared with the scenarios.
#[path = "../common/mod.rs"]
mod shared;

#[allow(unused_imports)]
pub use shared::{key_of, new_did_record, version0, Chain};

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::utils::ID_LEN;

pub fn rt() -> tokio::runtime::Runtime {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("failed to build runtime")
}

/// Start a node with signature cache disabled.
pub async fn start_node(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, None, None, false);
    srv.listen(port, "127.0.0.1").await.expect("listen failed");
    srv
}

/// Start a node with signature cache disabled and a deterministic node ID.
pub async fn start_node_with_id(port: u16, node_id: [u8; ID_LEN]) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, Some(node_id), None, false);
    srv.listen(port, "127.0.0.1").await.expect("listen failed");
    srv
}

/// Start a node with signature cache enabled.
pub async fn start_node_cached(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer_pub_key.bin",
    )));
    let mut srv = Server::new(handler, 20, 3, None, None, true);
    srv.listen(port, "127.0.0.1").await.expect("listen failed");
    srv
}

/// Poll `check` every `interval` until it returns `Some(T)` or `timeout` elapses.
pub async fn poll_until<F, Fut, T>(timeout: Duration, interval: Duration, mut check: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = check().await {
            return Some(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(interval).await;
    }
}

/// Version 0 of a new DID. Returns `(did, signed_record_bytes)`.
pub fn make_record() -> (String, Vec<u8>) {
    new_did_record()
}
