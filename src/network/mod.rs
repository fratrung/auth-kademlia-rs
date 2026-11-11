//! The public API of a node: `Server`.
//!
//! This file holds the struct, its constructor, `listen`, `stop` and
//! `bootstrap`; its other methods are split by operation:
//! - `publish.rs`: SET, and the report of a publication;
//! - `read.rs`: GET;
//! - `update.rs`: UPDATE, a key rotation;
//! - `maintenance.rs`: refresh, republication, recovery, stats and saved state.

mod maintenance;
mod publish;
mod read;
mod update;

pub use maintenance::ServerStats;
pub use publish::{SetOutcome, SetRejection, SetReport};
use std::sync::Arc;

use read::read_quorum;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;

use crate::auth_handler::did::key_of_did;
use crate::auth_handler::{verify_record, SignatureVerifierHandler};
use crate::crawling::NodeSpiderCrawl;
use crate::node::Node;
use crate::protocol::KademliaProtocol;
use crate::signature_cache::SignatureCache;
use crate::storage::{ForgetfulStorage, DEFAULT_TTL};
use crate::utils::{digest, digest_bytes, ID_LEN, STATUS_LIST_KEY};

pub struct Server {
    pub ksize: usize,
    pub alpha: usize,
    pub storage: Arc<ForgetfulStorage>,
    pub node: Node,
    pub protocol: Option<Arc<KademliaProtocol>>,
    signature_handler: Arc<dyn SignatureVerifierHandler>,
    /// Shared with `KademliaProtocol` so a cache hit at the network layer
    /// (rpc_store) is visible at the API layer (get/set) and vice versa.
    /// `None` when the cache is disabled.
    sig_cache: Option<Arc<SignatureCache>>,
}

/// The DHT key of `name`: the decoded suffix of a DID (ADR 0005), or the
/// fixed key of the Status List. `None` for any other text.
pub fn dht_key(name: &str) -> Option<[u8; ID_LEN]> {
    if name == STATUS_LIST_KEY {
        Some(digest(STATUS_LIST_KEY))
    } else {
        key_of_did(name)
    }
}

impl Server {
    /// Create a new server instance.
    ///
    /// - `signature_handler` — pluggable signature verification strategy.
    /// - `ksize`             — Kademlia k parameter (bucket size).
    /// - `alpha`             — lookup concurrency factor.
    /// - `node_id`           — fixed node ID; `None` picks one at random.
    /// - `storage`           — custom storage; `None` uses the default TTL store.
    /// - `use_cache`         — enable the ML-DSA verification cache
    pub fn new(
        signature_handler: Arc<dyn SignatureVerifierHandler>,
        ksize: usize,
        alpha: usize,
        node_id: Option<[u8; ID_LEN]>,
        storage: Option<Arc<ForgetfulStorage>>,
        use_cache: bool,
    ) -> Self {
        let storage = storage.unwrap_or_else(|| Arc::new(ForgetfulStorage::new(DEFAULT_TTL)));

        let node = match node_id {
            Some(id) => Node::from_id(id),
            None => {
                use rand::RngCore;
                let mut b = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut b);
                Node::from_id(digest_bytes(&b))
            }
        };

        let sig_cache = use_cache.then(|| Arc::new(SignatureCache::new(4096)));

        Self {
            ksize,
            alpha,
            storage,
            node,
            protocol: None,
            signature_handler,
            sig_cache,
        }
    }

    /// Bind to `interface:port` and start the receive loop.
    ///
    /// Datagrams are round-robin dispatched to `available_parallelism()` workers,
    /// each backed by a dedicated `mpsc::channel(256)`. When all channels are
    /// full the receive loop blocks on the base worker rather than dropping.
    pub async fn listen(&mut self, port: u16, interface: &str) -> tokio::io::Result<()> {
        let addr = format!("{}:{}", interface, port);
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        log::info!("Node {} listening on {}", self.node.long_id, addr);

        let protocol = Arc::new(KademliaProtocol::new(
            self.node.clone(),
            Arc::clone(&socket),
            Arc::clone(&self.storage),
            self.ksize,
            self.alpha,
            Arc::clone(&self.signature_handler),
            self.sig_cache.clone(),
        ));
        protocol
            .router
            .write()
            .await
            .set_min_lookup_contacts(read_quorum(self.alpha));
        self.protocol = Some(Arc::clone(&protocol));

        const WORKER_QUEUE_DEPTH: usize = 256;
        let num_workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);

        let mut senders = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(WORKER_QUEUE_DEPTH);
            senders.push(tx);
            let proto = Arc::clone(&protocol);
            protocol.spawn_task(async move {
                while let Some((data, peer)) = rx.recv().await {
                    proto.handle_datagram(data, peer).await;
                }
            });
        }

        protocol.spawn_task(async move {
            let mut buf = vec![0u8; 65_536];
            let mut idx = 0usize;
            'receive: loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let mut job = (buf[..len].to_vec(), peer);
                        let base = idx;
                        for i in 0..num_workers {
                            let w = (base + i) % num_workers;
                            match senders[w].try_send(job) {
                                Ok(()) => {
                                    idx = (w + 1) % num_workers;
                                    continue 'receive;
                                }
                                Err(TrySendError::Full(returned))
                                | Err(TrySendError::Closed(returned)) => {
                                    job = returned;
                                }
                            }
                        }
                        let w = base % num_workers;
                        let _ = senders[w].send(job).await;
                        idx = (w + 1) % num_workers;
                    }
                    Err(e) => log::error!("UDP recv error: {}", e),
                }
            }
        });

        self.schedule_refresh();
        self.schedule_maintenance();
        self.schedule_stats_log();
        Ok(())
    }

    /// Notify neighbours of departure, cancel all background tasks, and release
    /// the socket. Stored records are kept, and `listen` may be called again.
    /// The socket stays bound if the caller still holds a clone of `protocol`.
    pub async fn stop(&mut self) {
        let Some(proto) = self.protocol.take() else {
            return;
        };
        let neighbors = proto.router.read().await.find_neighbors(&self.node, None);
        log::info!("Notifying {} neighbours of departure", neighbors.len());
        futures::future::join_all(
            neighbors
                .iter()
                .map(|neighbor| proto.call_leave_rpc(neighbor)),
        )
        .await;
        proto.shutdown_tasks().await;
    }

    /// Ping each address in `addrs`, then run a `NodeSpiderCrawl` to populate
    /// the routing table. Returns the k-closest nodes discovered.
    pub async fn bootstrap(&self, addrs: Vec<(String, u16)>) -> Vec<Node> {
        log::debug!("Bootstrapping with {} initial contacts", addrs.len());
        if let Some(proto) = &self.protocol {
            proto.remember_seeds(&addrs);
        }
        let mut futs = vec![];
        for addr in addrs {
            futs.push(self.bootstrap_node(addr));
        }
        let nodes: Vec<Node> = futures::future::join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect();

        match &self.protocol {
            Some(proto) => {
                NodeSpiderCrawl::new(
                    Arc::clone(proto),
                    self.node.clone(),
                    nodes,
                    self.ksize,
                    self.alpha,
                )
                .find()
                .await
            }
            None => vec![],
        }
    }

    async fn bootstrap_node(&self, addr: (String, u16)) -> Option<Node> {
        let proto = self.protocol.as_ref()?;
        let (ok, id_bytes) = proto.call_ping_addr(&addr).await;
        if !ok || id_bytes.len() != ID_LEN {
            return None;
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_bytes);
        Some(Node::new(id, Some(addr.0), Some(addr.1)))
    }

    /// Verify `value` for `key` (`auth_handler::verify_record`).
    async fn verify_value(&self, key: &str, value: &[u8]) -> bool {
        let Some(dkey) = dht_key(key) else {
            return false;
        };
        verify_record(
            &self.signature_handler,
            self.sig_cache.as_deref(),
            &dkey,
            value,
        )
        .await
    }

    /// Return the addresses of known neighbours suitable for bootstrapping.
    pub async fn bootstrappable_neighbors(&self) -> Vec<(String, u16)> {
        match &self.protocol {
            Some(proto) => proto
                .router
                .read()
                .await
                .find_neighbors(&self.node, None)
                .into_iter()
                .filter_map(|n| n.address())
                .collect(),
            None => vec![],
        }
    }
}

impl Drop for Server {
    /// Background tasks own the protocol and its socket, so they must not
    /// outlive the server. Unlike `stop`, this sends no `Leave` and does not
    /// wait, so the socket closes shortly after the tasks are cancelled.
    fn drop(&mut self) {
        if let Some(proto) = &self.protocol {
            proto.abort_tasks();
        }
    }
}
