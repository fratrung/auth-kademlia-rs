//! Kademlia protocol over UDP.
//!
//! `KademliaProtocol` owns a node's socket, routing table and storage. This
//! file holds the struct, its constructor and its tasks; its methods are split
//! by what they do:
//! - `messages.rs`: the messages and their wire format;
//! - `transport.rs`: sending, resends, receiving and reassembly;
//! - `handlers.rs`: the answer to each request except STORE;
//! - `store_check.rs`: STORE and the network check of an empty replica;
//! - `client.rs`: the requests this node sends;
//! - `contacts.rs`: failing and returning contacts, refresh ids;
//! - `welcome.rs`: nodes met through a message, and their records.

mod client;
mod contacts;
mod handlers;
mod messages;
mod store_check;
#[cfg(test)]
mod test_support;
mod transport;
mod welcome;

pub use handlers::FindValueResult;
pub use messages::{record_hash, RpcMessage, StoreStatus, WireNode, RECORD_HASH_LEN};
use transport::{PendingMap, RequestKey};
use welcome::WELCOME_CONCURRENCY;

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicUsize};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Instant;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::task::JoinSet;

use crate::auth_handler::SignatureVerifierHandler;
use crate::counters::Counters;
use crate::fragmentation::ReassemblyMap;
use crate::node::Node;
use crate::retransmit::RoundTrips;
use crate::routing::RoutingTable;
use crate::signature_cache::SignatureCache;
use crate::storage::ForgetfulStorage;
use crate::utils::ID_LEN;

pub struct KademliaProtocol {
    pub router: Arc<RwLock<RoutingTable>>,
    pub storage: Arc<ForgetfulStorage>,
    pub source_node: Node,
    pub socket: Arc<UdpSocket>,
    pub signature_handler: Arc<dyn SignatureVerifierHandler>,
    /// Lookup parameters, for the lookups this node makes on its own.
    ksize: usize,
    alpha: usize,
    /// STOREs waiting for a lookup (`MAX_STORE_LOOKUPS`).
    store_lookups: Arc<AtomicUsize>,
    /// Shared with `Server` so a verification result cached in one layer is
    /// immediately reused by the other. `None` when the cache is disabled.
    sig_cache: Option<Arc<SignatureCache>>,
    /// Nodes waiting for, or receiving, the records they should hold.
    welcome_in_flight: DashMap<[u8; ID_LEN], ()>,
    /// Bounds whole-storage scans caused by newly discovered peers.
    welcome_permits: Arc<Semaphore>,
    /// Oldest contacts of full buckets being pinged (Kademlia §2.2).
    oldest_pings_in_flight: DashMap<[u8; ID_LEN], ()>,
    pending: PendingMap,
    /// Round trips to the peers this node asks, to know when a request or
    /// its answer was lost.
    round_trips: RoundTrips,
    /// Requests carrying a record being handled (`InProgress`).
    requests_in_progress: Arc<DashMap<RequestKey, ()>>,
    /// What this node sent (feature `counters`; empty without it).
    counters: Counters,
    /// Start from a random value, not 0, so that after `stop` and `listen`
    /// an answer or a fragment meant for the old protocol does not match a
    /// request or a message of the new one.
    next_msg_id: AtomicU32,
    next_frag_id: AtomicU32,
    reassembly: ReassemblyMap,
    last_reassembly_gc: Mutex<Instant>,
    /// Every task that keeps this protocol and its socket alive. `None` once
    /// the node has stopped, so no task can start during or after shutdown.
    tasks: StdMutex<Option<JoinSet<()>>>,
    /// Bootstrap addresses, kept so that an isolated node can rejoin.
    seeds: StdMutex<Vec<(String, u16)>>,
}

impl KademliaProtocol {
    pub fn new(
        source_node: Node,
        socket: Arc<UdpSocket>,
        storage: Arc<ForgetfulStorage>,
        ksize: usize,
        alpha: usize,
        signature_handler: Arc<dyn SignatureVerifierHandler>,
        sig_cache: Option<Arc<SignatureCache>>,
    ) -> Self {
        let router = RoutingTable::new(source_node.clone(), ksize);
        Self {
            router: Arc::new(RwLock::new(router)),
            storage,
            source_node,
            socket,
            signature_handler,
            ksize,
            alpha,
            store_lookups: Arc::new(AtomicUsize::new(0)),
            sig_cache,
            welcome_in_flight: DashMap::new(),
            welcome_permits: Arc::new(Semaphore::new(WELCOME_CONCURRENCY)),
            oldest_pings_in_flight: DashMap::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            round_trips: RoundTrips::default(),
            requests_in_progress: Arc::new(DashMap::new()),
            counters: Counters::default(),
            next_msg_id: AtomicU32::new(rand::random()),
            next_frag_id: AtomicU32::new(rand::random()),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
            last_reassembly_gc: Mutex::new(Instant::now()),
            tasks: StdMutex::new(Some(JoinSet::new())),
            seeds: StdMutex::new(Vec::new()),
        }
    }

    /// Run `task` until it finishes or the node stops. Finished tasks are
    /// reaped here so the set stays bounded by the tasks actually running.
    pub(crate) fn spawn_task<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tasks) = tasks.as_mut() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(task);
        }
    }

    pub(crate) fn remember_seeds(&self, addrs: &[(String, u16)]) {
        let mut seeds = self.seeds.lock().unwrap_or_else(PoisonError::into_inner);
        for addr in addrs {
            if !seeds.contains(addr) {
                seeds.push(addr.clone());
            }
        }
    }

    pub(crate) fn seeds(&self) -> Vec<(String, u16)> {
        self.seeds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn take_tasks(&self) -> Option<JoinSet<()>> {
        self.tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Cancel every task and wait until each one has released the protocol.
    pub(crate) async fn shutdown_tasks(&self) {
        if let Some(mut tasks) = self.take_tasks() {
            tasks.shutdown().await;
        }
    }

    /// Cancel every task without waiting. Dropping a `JoinSet` aborts its tasks.
    pub(crate) fn abort_tasks(&self) {
        drop(self.take_tasks());
    }

    /// What this node has sent since it started (feature `counters`).
    #[cfg(feature = "counters")]
    pub fn counters(&self) -> crate::counters::CounterSnapshot {
        self.counters.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use super::test_support::{test_protocol, TestHandler};

    /// A node that listens again does not start from the same message and
    /// fragment ids, so an answer or a fragment sent to it before it stopped
    /// does not match a request or a message of the new one.
    #[tokio::test]
    async fn a_new_protocol_does_not_start_from_the_same_ids() {
        let handler = Arc::new(TestHandler::new(true, true));
        let first = test_protocol(handler.clone(), false).await;
        let second = test_protocol(handler, false).await;
        assert_ne!(
            first.next_msg_id.load(Ordering::Relaxed),
            second.next_msg_id.load(Ordering::Relaxed)
        );
        assert_ne!(
            first.next_frag_id.load(Ordering::Relaxed),
            second.next_frag_id.load(Ordering::Relaxed)
        );
    }
}
