/// Kademlia protocol layer with a real UDP transport.
///
/// `KademliaProtocol` owns the UDP socket, serialises/deserialises messages
/// with `bincode`, dispatches incoming RPCs to the appropriate handler, and
/// exposes `call_*` methods for sending outbound RPCs to remote peers.
///
/// Message framing: every datagram is a `bincode`-encoded `(u32 msg_id, RpcEnvelope)`.
/// Responses are correlated by `msg_id` via a `PendingMap`.
///
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use log;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Notify, RwLock, Semaphore};
use tokio::task::JoinSet;

use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{FindPayload, RawResponse, SpiderProtocol, ValueSearch, ValueSpiderCrawl};
use crate::fragmentation::{
    encode_fragments, parse_fragment, ReassemblyEntry, ReassemblyMap, FRAG_CHUNK_SIZE,
    MAX_MESSAGE_SIZE, MAX_REASSEMBLY_ENTRIES, MAX_REASSEMBLY_ENTRIES_PER_PEER,
    REASSEMBLY_GC_INTERVAL, REASSEMBLY_TTL,
};
use crate::node::Node;
use crate::retransmit::{RoundTrips, MAX_RESENDS};
use crate::routing::RoutingTable;
use crate::signature_cache::{SignatureCache, VerificationDomain};
use crate::storage::{ForgetfulStorage, IStorage, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

/// Timeout for a single RPC call. A lookup pays it once for a contact that does
/// not respond: after that the contact is marked as failing and skipped.
const RPC_TIMEOUT: Duration = Duration::from_millis(2500);
/// A contact silent for this long may have missed records when it comes back.
const RETURNED_AFTER: Duration = RPC_TIMEOUT;
/// How long an empty replica asks the network about a record it was sent,
/// below `RPC_TIMEOUT` so that its answer reaches the sender in time.
const STORE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2000);
/// STOREs waiting for that lookup at once. Beyond this a STORE is dropped
/// without an answer, as an overloaded node drops datagrams.
const MAX_STORE_LOOKUPS: usize = 256;

/// Explicit result of a STORE request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum StoreStatus {
    Stored,
    AlreadyStored,
    Conflict,
    CapacityExceeded,
    InvalidRecord,
}

impl From<StorageWriteStatus> for StoreStatus {
    fn from(status: StorageWriteStatus) -> Self {
        match status {
            StorageWriteStatus::Stored => Self::Stored,
            StorageWriteStatus::AlreadyStored => Self::AlreadyStored,
            StorageWriteStatus::Conflict => Self::Conflict,
            StorageWriteStatus::CapacityExceeded => Self::CapacityExceeded,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcMessage {
    Ping {
        sender_id: [u8; ID_LEN],
    },
    Pong {
        sender_id: [u8; ID_LEN],
    },
    Store {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
    },
    StoreResult {
        status: StoreStatus,
    },
    Update {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    },
    UpdateResult {
        ok: bool,
    },
    UpdateStatusList {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
    },
    UpdateStatusListResult {
        ok: bool,
    },
    FindNode {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindNodeResult {
        nodes: Vec<WireNode>,
    },
    FindValue {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindValueNodes {
        nodes: Vec<WireNode>,
    },
    FindValueHit {
        value: Vec<u8>,
    },
    Leave {
        sender_id: [u8; ID_LEN],
    },
    /// Whether the node holds a record for `key`, asked by an empty replica
    /// before a STORE. A node that holds one answers with its SHA-256
    /// (`FindHashHit`), one that does not with closer nodes (`FindValueNodes`).
    /// The answer fits in one datagram, unlike a whole record.
    FindHash {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindHashHit {
        hash: [u8; RECORD_HASH_LEN],
    },
    /// Sent at once for a request that carries a record (`Store`, `Update`,
    /// `UpdateStatusList`), whose answer may take a while: the request
    /// arrived and is being handled, so the sender does not send it again yet.
    /// Sent again for each copy that arrives meanwhile.
    Received,
}

/// Length of `record_hash`.
pub const RECORD_HASH_LEN: usize = 32;

/// SHA-256 of a whole record, as a node answers `FindHash`.
pub fn record_hash(record: &[u8]) -> [u8; RECORD_HASH_LEN] {
    Sha256::digest(record).into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireNode {
    pub id: [u8; ID_LEN],
    pub ip: Option<String>,
    pub port: Option<u16>,
}

impl From<&Node> for WireNode {
    fn from(n: &Node) -> Self {
        Self {
            id: n.id,
            ip: n.ip.clone(),
            port: n.port,
        }
    }
}

impl From<WireNode> for Node {
    fn from(w: WireNode) -> Self {
        Node::new(w.id, w.ip, w.port)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Frame {
    msg_id: u32,
    is_request: bool,
    message: RpcMessage,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ExpectedResponse {
    Pong,
    StoreResult,
    UpdateResult,
    UpdateStatusListResult,
    FindNodeResult,
    FindValueResult,
    FindHashResult,
    NoResponse,
}

impl ExpectedResponse {
    fn for_request(message: &RpcMessage) -> Self {
        match message {
            RpcMessage::Ping { .. } => Self::Pong,
            RpcMessage::Store { .. } => Self::StoreResult,
            RpcMessage::Update { .. } => Self::UpdateResult,
            RpcMessage::UpdateStatusList { .. } => Self::UpdateStatusListResult,
            RpcMessage::FindNode { .. } => Self::FindNodeResult,
            RpcMessage::FindValue { .. } => Self::FindValueResult,
            RpcMessage::FindHash { .. } => Self::FindHashResult,
            RpcMessage::Leave { .. } => Self::NoResponse,
            _ => Self::NoResponse,
        }
    }

    fn accepts(self, message: &RpcMessage) -> bool {
        match self {
            Self::Pong => matches!(message, RpcMessage::Pong { .. }),
            Self::StoreResult => matches!(message, RpcMessage::StoreResult { .. }),
            Self::UpdateResult => matches!(message, RpcMessage::UpdateResult { .. }),
            Self::UpdateStatusListResult => {
                matches!(message, RpcMessage::UpdateStatusListResult { .. })
            }
            Self::FindNodeResult => matches!(message, RpcMessage::FindNodeResult { .. }),
            Self::FindValueResult => matches!(
                message,
                RpcMessage::FindValueHit { .. } | RpcMessage::FindValueNodes { .. }
            ),
            Self::FindHashResult => matches!(
                message,
                RpcMessage::FindHashHit { .. } | RpcMessage::FindValueNodes { .. }
            ),
            Self::NoResponse => false,
        }
    }

    /// Whether the request gets a receipt before its answer.
    fn after_receipt(self) -> bool {
        matches!(
            self,
            Self::StoreResult | Self::UpdateResult | Self::UpdateStatusListResult
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pong => "Pong",
            Self::StoreResult => "StoreResult",
            Self::UpdateResult => "UpdateResult",
            Self::UpdateStatusListResult => "UpdateStatusListResult",
            Self::FindNodeResult => "FindNodeResult",
            Self::FindValueResult => "FindValueHit|FindValueNodes",
            Self::FindHashResult => "FindHashHit|FindValueNodes",
            Self::NoResponse => "no response",
        }
    }
}

fn rpc_message_name(message: &RpcMessage) -> &'static str {
    match message {
        RpcMessage::Ping { .. } => "Ping",
        RpcMessage::Pong { .. } => "Pong",
        RpcMessage::Store { .. } => "Store",
        RpcMessage::StoreResult { .. } => "StoreResult",
        RpcMessage::Update { .. } => "Update",
        RpcMessage::UpdateResult { .. } => "UpdateResult",
        RpcMessage::UpdateStatusList { .. } => "UpdateStatusList",
        RpcMessage::UpdateStatusListResult { .. } => "UpdateStatusListResult",
        RpcMessage::FindNode { .. } => "FindNode",
        RpcMessage::FindNodeResult { .. } => "FindNodeResult",
        RpcMessage::FindValue { .. } => "FindValue",
        RpcMessage::FindValueHit { .. } => "FindValueHit",
        RpcMessage::FindValueNodes { .. } => "FindValueNodes",
        RpcMessage::Leave { .. } => "Leave",
        RpcMessage::FindHash { .. } => "FindHash",
        RpcMessage::FindHashHit { .. } => "FindHashHit",
        RpcMessage::Received => "Received",
    }
}

/// A request waiting for its answer.
struct PendingCall {
    peer: SocketAddr,
    expected: ExpectedResponse,
    reply: oneshot::Sender<RpcMessage>,
    /// Signalled for each receipt (`Received`) the peer sends.
    received: Arc<Notify>,
}

type PendingMap = Arc<Mutex<HashMap<u32, PendingCall>>>;

/// The record a request carries, if any. Its answer comes only after the
/// record is handled, so the request gets a receipt first (`Received`).
fn carried_record(message: &RpcMessage) -> Option<&[u8]> {
    match message {
        RpcMessage::Store { value, .. }
        | RpcMessage::Update { value, .. }
        | RpcMessage::UpdateStatusList { value, .. } => Some(value),
        _ => None,
    }
}

/// A request that carries a record, being handled: its sender's address and
/// the SHA-256 of the whole request. A copy of it, sent again because the
/// receipt or the answer was late, is identical, so it is recognised and not
/// handled twice. Another request under the same msg_id is not a copy.
type RequestKey = (SocketAddr, [u8; RECORD_HASH_LEN]);

/// Marks a request as being handled until dropped.
struct InProgress {
    requests: Arc<DashMap<RequestKey, ()>>,
    key: RequestKey,
}

impl InProgress {
    /// `None` if the request is already being handled: this is a copy.
    fn start(requests: &Arc<DashMap<RequestKey, ()>>, key: RequestKey) -> Option<Self> {
        if requests.insert(key, ()).is_some() {
            return None;
        }
        Some(Self {
            requests: Arc::clone(requests),
            key,
        })
    }
}

impl Drop for InProgress {
    fn drop(&mut self) {
        self.requests.remove(&self.key);
    }
}

/// Removes a pending RPC when `call` ends, including when its caller cancels it
/// by dropping the future, so a request to a dead peer cannot leak its entry.
struct PendingGuard {
    pending: PendingMap,
    msg_id: u32,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.try_lock() {
            pending.remove(&self.msg_id);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let pending = Arc::clone(&self.pending);
            let msg_id = self.msg_id;
            runtime.spawn(async move {
                pending.lock().await.remove(&msg_id);
            });
        }
    }
}

/// Replications to new nodes that run at once. Each one scans the whole
/// storage.
const WELCOME_CONCURRENCY: usize = 1;
/// Nodes waiting for, or receiving, the records they should hold. A node met
/// beyond this still enters the routing table, and gets its records from the
/// hourly republication.
const MAX_WELCOME_QUEUE: usize = 256;
/// Records whose neighbours are computed under one read lock of the routing
/// table, while scanning the storage for a new node.
const WELCOME_SCAN_CHUNK: usize = 256;
const REPLICATION_CONCURRENCY: usize = 4;

/// What an empty replica learns from the network about a record it was sent.
enum NetworkCopy {
    /// Every node asked answered: none holds the record, or they hold the
    /// same one.
    NoneOrSame,
    /// A node holds another record: it answered with another hash.
    Other,
    /// Some node did not answer, or there was nobody to ask.
    Unknown,
}

/// One of the `MAX_STORE_LOOKUPS` places for a STORE waiting for a lookup,
/// given back when dropped, also if the task never runs.
struct StoreLookupSlot(Arc<AtomicUsize>);

impl StoreLookupSlot {
    fn take(count: &Arc<AtomicUsize>) -> Option<Self> {
        if count.fetch_add(1, Ordering::AcqRel) >= MAX_STORE_LOOKUPS {
            count.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self(Arc::clone(count)))
    }
}

impl Drop for StoreLookupSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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
            next_msg_id: AtomicU32::new(0),
            next_frag_id: AtomicU32::new(0),
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

    async fn note_failure(&self, peer: &Node) {
        self.router.write().await.record_failure(peer);
    }

    /// Returns how long the contact had been failing, if it was. The read lock
    /// keeps the common case, a healthy contact, off the write lock.
    ///
    /// Only the registered endpoint can vouch for a failing contact, so a forged
    /// message cannot redirect it. A stale contact also accepts a new endpoint,
    /// otherwise a peer that changed address could never be reached again.
    async fn note_alive(&self, node: &Node) -> Option<Duration> {
        {
            let router = self.router.read().await;
            if !router.has_failures(&node.id) {
                return None;
            }
            let from_registered_endpoint = router
                .get_contact(&node.id)
                .is_some_and(|contact| contact.same_home_as(node));
            if !from_registered_endpoint && !router.is_stale(&node.id) {
                return None;
            }
        }
        self.router.write().await.record_success(&node.id)
    }

    /// Ping up to `limit` failing contacts whose backoff has elapsed. Probing
    /// here keeps the cost of a dead contact out of user lookups.
    pub(crate) async fn probe_failing_contacts(self: &Arc<Self>, limit: usize) {
        let due = self.router.read().await.contacts_due_for_probe(limit);
        futures::future::join_all(due.iter().map(|node| self.call_ping_node(node))).await;
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

    fn next_id(&self) -> u32 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_frag_id_val(&self) -> u32 {
        self.next_frag_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Drop reassembly buffers older than `REASSEMBLY_TTL` at a bounded cadence.
    /// This keeps the O(n) sweep off the per-fragment hot path.
    async fn gc_reassembly(&self) {
        let now = Instant::now();
        {
            let mut last_gc = self.last_reassembly_gc.lock().await;
            if now.duration_since(*last_gc) < REASSEMBLY_GC_INTERVAL {
                return;
            }
            *last_gc = now;
        }

        let mut map = self.reassembly.lock().await;
        map.retain(|_, entry| now.duration_since(entry.created_at) < REASSEMBLY_TTL);
    }

    /// A node made contact: add it to the routing table at once (Kademlia
    /// §2.2), and queue the records it should hold (§2.5). Only the records
    /// are bounded, because finding them scans the whole storage: one scan
    /// runs at a time and at most `MAX_WELCOME_QUEUE` nodes wait for it.
    async fn schedule_welcome_if_new(self: &Arc<Self>, node: Node) {
        let returned = self
            .note_alive(&node)
            .await
            .is_some_and(|silent_for| silent_for >= RETURNED_AFTER);
        if !returned && !self.router.read().await.is_new_node(&node) {
            return;
        }
        self.add_contact(node.clone()).await;

        if self.welcome_in_flight.contains_key(&node.id) {
            return;
        }
        if self.welcome_in_flight.len() >= MAX_WELCOME_QUEUE {
            log::debug!(
                "Replication queue full: {} gets its records from the next republication",
                node
            );
            return;
        }
        if self.welcome_in_flight.insert(node.id, ()).is_some() {
            return;
        }
        let p = Arc::clone(self);
        self.spawn_task(async move {
            if let Ok(_permit) = Arc::clone(&p.welcome_permits).acquire_owned().await {
                p.replicate_to(&node).await;
            }
            p.welcome_in_flight.remove(&node.id);
        });
    }

    /// Add `node` to the routing table. A full bucket that cannot split gives
    /// its oldest contact, which is pinged to learn whether it is still there
    /// (§2.2): at most one ping per contact at a time, however many new nodes
    /// fall into that bucket.
    async fn add_contact(self: &Arc<Self>, node: Node) {
        let oldest = self.router.write().await.add_contact(node);
        let Some(oldest) = oldest else {
            return;
        };
        if self.oldest_pings_in_flight.insert(oldest.id, ()).is_some() {
            return;
        }
        let p = Arc::clone(self);
        self.spawn_task(async move {
            p.call_ping_node(&oldest).await;
            p.oldest_pings_in_flight.remove(&oldest.id);
        });
    }

    /// Serialize and fragment a frame for `addr`. `None` if it cannot be sent.
    fn encode_frame(&self, addr: SocketAddr, frame: &Frame) -> Option<Vec<Vec<u8>>> {
        let bytes = match bincode::serialize(frame) {
            Ok(b) => b,
            Err(e) => {
                log::error!("Serialization error: {}", e);
                return None;
            }
        };

        if bytes.len() > MAX_MESSAGE_SIZE {
            log::error!(
                "Refusing to send {} byte message (limit {})",
                bytes.len(),
                MAX_MESSAGE_SIZE
            );
            return None;
        }

        let frag_id = self.next_frag_id_val();
        let datagrams = encode_fragments(frag_id, &bytes);

        if datagrams.len() > 1 {
            log::debug!(
                "Sending {} byte frame to {} as {} fragments (frag_id={})",
                bytes.len(),
                addr,
                datagrams.len(),
                frag_id
            );
        }
        Some(datagrams)
    }

    /// Send the datagrams of one frame. Returns false if any fails to be
    /// transmitted.
    async fn send_datagrams(&self, addr: SocketAddr, datagrams: &[Vec<u8>]) -> bool {
        for dg in datagrams {
            if let Err(e) = self.socket.send_to(dg, addr).await {
                log::warn!("UDP send to {} failed: {}", addr, e);
                return false;
            }
        }
        true
    }

    /// Serialize, fragment, and send a frame to `addr`. Returns false if any
    /// fragment fails to be transmitted.
    async fn send_frame(&self, addr: SocketAddr, frame: &Frame) -> bool {
        match self.encode_frame(addr, frame) {
            Some(datagrams) => self.send_datagrams(addr, &datagrams).await,
            None => false,
        }
    }

    /// Send an RPC request to `addr` and wait for the matching response, for
    /// at most `RPC_TIMEOUT`.
    ///
    /// Over UDP the request or its answer can be lost. With no sign of the
    /// peer after a few of its round trips (`RoundTrips::resend_after`), the
    /// same datagrams are sent again, up to `MAX_RESENDS` times, waiting
    /// twice as long each time. Copies keep the fragment id, so a copy also
    /// completes a message that lost a fragment. A receipt (`Received`) means
    /// the request arrived and is being handled: the next copy waits longer,
    /// and only asks again for an answer that may have been lost.
    async fn call(&self, addr: SocketAddr, message: RpcMessage) -> Option<RpcMessage> {
        let msg_id = self.next_id();
        let frame = Frame {
            msg_id,
            is_request: true,
            message,
        };
        // The answer to a request carrying a record comes after the record is
        // handled, so it does not measure the round trip; its receipt does.
        let answer_measures = carried_record(&frame.message).is_none();
        let datagrams = self.encode_frame(addr, &frame)?;

        let (reply, mut answer) = oneshot::channel();
        let received = Arc::new(Notify::new());
        self.pending.lock().await.insert(
            msg_id,
            PendingCall {
                peer: addr,
                expected: ExpectedResponse::for_request(&frame.message),
                reply,
                received: Arc::clone(&received),
            },
        );
        let _guard = PendingGuard {
            pending: Arc::clone(&self.pending),
            msg_id,
        };

        let first_sent = tokio::time::Instant::now();
        let deadline = first_sent + RPC_TIMEOUT;
        if !self.send_datagrams(addr, &datagrams).await {
            return None;
        }
        let mut wait = self.round_trips.resend_after(addr);
        let mut next_send = first_sent + wait;
        let mut resends = 0;
        let mut receipts = 0;
        loop {
            tokio::select! {
                result = &mut answer => {
                    let Ok(response) = result else {
                        log::debug!("Response channel closed for msg_id={}", msg_id);
                        return None;
                    };
                    // Karn's algorithm: after a copy, the answer may be to either.
                    if answer_measures && resends == 0 {
                        self.round_trips.record(addr, first_sent.elapsed());
                    }
                    return Some(response);
                }
                _ = received.notified() => {
                    receipts += 1;
                    wait = if receipts == 1 {
                        if resends == 0 {
                            self.round_trips.record(addr, first_sent.elapsed());
                        }
                        self.round_trips.resend_after(addr) * 2
                    } else {
                        wait * 2
                    };
                    next_send = tokio::time::Instant::now() + wait;
                }
                _ = tokio::time::sleep_until(next_send.min(deadline)) => {
                    if tokio::time::Instant::now() >= deadline {
                        log::debug!("RPC timeout for msg_id={}", msg_id);
                        return None;
                    }
                    if resends == MAX_RESENDS {
                        next_send = deadline;
                        continue;
                    }
                    resends += 1;
                    log::debug!(
                        "No answer from {} for msg_id={} after {:?}, sending it again ({}/{})",
                        addr,
                        msg_id,
                        wait,
                        resends,
                        MAX_RESENDS
                    );
                    if !self.send_datagrams(addr, &datagrams).await {
                        return None;
                    }
                    wait *= 2;
                    next_send = tokio::time::Instant::now() + wait;
                }
            }
        }
    }

    /// Parse and dispatch an incoming UDP datagram.
    /// Datagrams are reassembled from fragments before being deserialized.
    /// Responses are routed to waiting `call()` callers via the pending map.
    /// Requests are handled inline and a response is sent back.
    pub async fn handle_datagram(self: &Arc<Self>, data: Vec<u8>, peer: SocketAddr) {
        let (header, chunk) = match parse_fragment(&data) {
            Some(parts) => parts,
            None => {
                log::warn!(
                    "Discarded datagram from {} without valid fragment header",
                    peer
                );
                return;
            }
        };

        let payload: Vec<u8> = if header.total == 1 {
            chunk.to_vec()
        } else {
            // Bound memory usage upfront: refuse fragments that would push the
            // logical message over the size limit.
            let projected = (header.total as usize).saturating_mul(FRAG_CHUNK_SIZE);
            if projected > MAX_MESSAGE_SIZE {
                log::warn!(
                    "Discarded oversized fragmented message from {} ({} fragments)",
                    peer,
                    header.total
                );
                return;
            }

            self.gc_reassembly().await;

            let key = (peer, header.frag_id);
            let mut map = self.reassembly.lock().await;
            if !map.contains_key(&key) {
                if map.len() >= MAX_REASSEMBLY_ENTRIES {
                    log::warn!("Discarded fragment from {}: reassembly map is full", peer);
                    return;
                }
                let peer_entries = map
                    .keys()
                    .filter(|(entry_peer, _)| *entry_peer == peer)
                    .count();
                if peer_entries >= MAX_REASSEMBLY_ENTRIES_PER_PEER {
                    log::warn!(
                        "Discarded fragment from {}: per-peer reassembly limit reached",
                        peer
                    );
                    return;
                }
                map.insert(key, ReassemblyEntry::new(header.total));
            }

            let expected_total = match map.get(&key) {
                Some(entry) => entry.total,
                None => {
                    log::warn!(
                        "Discarded fragment from {}: reassembly entry disappeared",
                        peer
                    );
                    return;
                }
            };
            if expected_total != header.total {
                map.remove(&key);
                log::warn!(
                    "Inconsistent total for frag_id={} from {} (got {}, expected {})",
                    header.frag_id,
                    peer,
                    header.total,
                    expected_total
                );
                return;
            }

            let complete = match map.get_mut(&key) {
                Some(entry) => entry.insert(header.index, chunk.to_vec()),
                None => {
                    log::warn!(
                        "Discarded fragment from {}: reassembly entry disappeared",
                        peer
                    );
                    return;
                }
            };
            if !complete {
                return;
            }

            let entry = match map.remove(&key) {
                Some(entry) => entry,
                None => {
                    log::warn!(
                        "Discarded complete message from {}: reassembly entry disappeared",
                        peer
                    );
                    return;
                }
            };
            drop(map);
            match entry.assemble() {
                Some(p) => p,
                None => {
                    log::warn!(
                        "Assembly failed for frag_id={} from {}",
                        header.frag_id,
                        peer
                    );
                    return;
                }
            }
        };

        let frame: Frame = match bincode::deserialize(&payload) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Failed to deserialize: {}", e);
                return;
            }
        };

        if !frame.is_request {
            let message = frame.message;
            if let RpcMessage::Received = message {
                let pending = self.pending.lock().await;
                match pending.get(&frame.msg_id) {
                    Some(call) if call.peer == peer && call.expected.after_receipt() => {
                        call.received.notify_one();
                    }
                    _ => log::debug!(
                        "Discarded receipt for msg_id={} from {}",
                        frame.msg_id,
                        peer
                    ),
                }
                return;
            }
            let tx = {
                let mut pending = self.pending.lock().await;
                match pending
                    .get(&frame.msg_id)
                    .map(|call| (call.peer, call.expected))
                {
                    Some((expected_peer, expected_response))
                        if expected_peer == peer && expected_response.accepts(&message) =>
                    {
                        pending.remove(&frame.msg_id).map(|call| call.reply)
                    }
                    Some((expected_peer, expected_response)) if expected_peer == peer => {
                        log::warn!(
                            "Discarded {} response for msg_id={} from {} (expected {})",
                            rpc_message_name(&message),
                            frame.msg_id,
                            peer,
                            expected_response.name()
                        );
                        None
                    }
                    Some((expected_peer, _)) => {
                        log::warn!(
                            "Discarded response for msg_id={} from {} (expected {})",
                            frame.msg_id,
                            peer,
                            expected_peer
                        );
                        None
                    }
                    None => None,
                }
            };
            if let Some(tx) = tx {
                if let RpcMessage::Pong { sender_id } = &message {
                    let source =
                        Node::new(*sender_id, Some(peer.ip().to_string()), Some(peer.port()));
                    self.schedule_welcome_if_new(source).await;
                }
                let _ = tx.send(message);
            }
            return;
        }

        if carried_record(&frame.message).is_none() {
            let response = self.dispatch_request(frame.message, peer).await;
            self.answer(peer, frame.msg_id, response).await;
            return;
        }

        // A request carrying a record is answered only once the record is
        // handled. A copy of one still being handled, sent again because the
        // receipt was lost or late, gets the receipt again and nothing else.
        let Some(in_progress) =
            InProgress::start(&self.requests_in_progress, (peer, record_hash(&payload)))
        else {
            self.answer(peer, frame.msg_id, Some(RpcMessage::Received))
                .await;
            return;
        };

        // A STORE to an empty replica waits for a lookup, whose answers reach
        // this node through these same workers: handled here, it could leave
        // every worker waiting for answers queued behind it. It runs apart,
        // and its answer leaves when the lookup is over.
        let slot = match &frame.message {
            RpcMessage::Store { key, .. } if self.store_needs_lookup(key) => {
                let Some(slot) = StoreLookupSlot::take(&self.store_lookups) else {
                    log::warn!(
                        "Dropped STORE from {}: {} STOREs already waiting for a lookup",
                        peer,
                        MAX_STORE_LOOKUPS
                    );
                    return;
                };
                Some(slot)
            }
            _ => None,
        };

        // The receipt tells the sender the request arrived, so it does not
        // send it again while it waits for the answer.
        self.answer(peer, frame.msg_id, Some(RpcMessage::Received))
            .await;
        if let Some(slot) = slot {
            let protocol = Arc::clone(self);
            self.spawn_task(async move {
                let _slot = slot;
                let _in_progress = in_progress;
                let response = protocol.dispatch_request(frame.message, peer).await;
                protocol.answer(peer, frame.msg_id, response).await;
            });
            return;
        }

        let response = self.dispatch_request(frame.message, peer).await;
        self.answer(peer, frame.msg_id, response).await;
        drop(in_progress);
    }

    async fn answer(&self, peer: SocketAddr, msg_id: u32, response: Option<RpcMessage>) {
        if let Some(message) = response {
            let frame = Frame {
                msg_id,
                is_request: false,
                message,
            };
            self.send_frame(peer, &frame).await;
        }
    }

    async fn dispatch_request(
        self: &Arc<Self>,
        msg: RpcMessage,
        peer: SocketAddr,
    ) -> Option<RpcMessage> {
        let sender_addr = (peer.ip().to_string(), peer.port());
        match msg {
            RpcMessage::Ping { sender_id } => {
                let resp_id = self.rpc_ping(sender_id, sender_addr).await;
                Some(RpcMessage::Pong { sender_id: resp_id })
            }
            RpcMessage::Store {
                sender_id,
                key,
                value,
            } => self
                .rpc_store(sender_id, sender_addr, key, value)
                .await
                .map(|status| RpcMessage::StoreResult { status }),
            RpcMessage::Update {
                sender_id,
                key,
                value,
                auth_signature,
            } => {
                let ok = self
                    .rpc_update(sender_id, sender_addr, key, value, auth_signature)
                    .await;
                Some(RpcMessage::UpdateResult { ok })
            }
            RpcMessage::UpdateStatusList {
                sender_id,
                key,
                value,
            } => {
                let ok = self
                    .rpc_update_status_list(sender_id, sender_addr, key, value)
                    .await;
                Some(RpcMessage::UpdateStatusListResult { ok })
            }
            RpcMessage::FindNode { sender_id, key } => {
                let nodes = self.rpc_find_node(sender_id, sender_addr, key).await;
                Some(RpcMessage::FindNodeResult {
                    nodes: nodes.iter().map(WireNode::from).collect(),
                })
            }
            RpcMessage::FindValue { sender_id, key } => {
                let result = self.rpc_find_value(sender_id, sender_addr, key).await;
                Some(match result {
                    FindValueResult::Value(v) => RpcMessage::FindValueHit { value: v },
                    FindValueResult::Nodes(ns) => RpcMessage::FindValueNodes {
                        nodes: ns.iter().map(WireNode::from).collect(),
                    },
                })
            }
            RpcMessage::FindHash { sender_id, key } => {
                let result = self.rpc_find_value(sender_id, sender_addr, key).await;
                Some(match result {
                    FindValueResult::Value(v) => RpcMessage::FindHashHit {
                        hash: record_hash(&v),
                    },
                    FindValueResult::Nodes(ns) => RpcMessage::FindValueNodes {
                        nodes: ns.iter().map(WireNode::from).collect(),
                    },
                })
            }
            RpcMessage::Leave { sender_id } => {
                self.rpc_leave(sender_id, sender_addr).await;
                None
            }
            _ => {
                log::warn!("Received unexpected message type");
                None
            }
        }
    }

    pub async fn rpc_ping(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
    ) -> [u8; ID_LEN] {
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        self.source_node.id
    }

    /// Store an authenticated record if this node holds none for `key`.
    /// `None` means no answer: an empty replica had nobody to ask about the
    /// record or did not hear from every node it asked, so the sender counts
    /// it as unavailable.
    pub async fn rpc_store(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Option<StoreStatus> {
        // An empty replica cannot tell a forged record from the owner's: both
        // are self-signed for the same DID. It asks the network first, and
        // refuses a record other than the one already there without verifying
        // its signature: a new version must arrive as an UPDATE. When some node
        // does not answer, or it knows nobody to ask, it refuses too (fail-safe
        // default): accepting would let an attacker win by making answers fail
        // to arrive, as with soft-fail certificate revocation checks.
        if self.store_needs_lookup(&key) {
            // The binding costs a JSON parse, the lookup a message to every
            // node close to the key: a record that does not belong to `key`
            // never starts one.
            if !self.key_binding_is_valid(&key, &value) {
                log::warn!(
                    "rpc_store: record from {} is not bound to {}",
                    sender_addr.0,
                    hex::encode(key)
                );
                return Some(StoreStatus::InvalidRecord);
            }
            match self.network_copy(key, &value).await {
                NetworkCopy::NoneOrSame => {}
                NetworkCopy::Other => {
                    log::warn!(
                        "rpc_store: the network holds another record for {} (from {})",
                        hex::encode(key),
                        sender_addr.0
                    );
                    return Some(StoreStatus::Conflict);
                }
                NetworkCopy::Unknown => {
                    log::warn!(
                        "rpc_store: not every node answered about {}, record from {} refused",
                        hex::encode(key),
                        sender_addr.0
                    );
                    return None;
                }
            }
        }
        if !self.verify_for_key(&key, &value).await {
            log::warn!(
                "rpc_store: invalid record for {} from {}",
                hex::encode(key),
                sender_addr.0
            );
            return Some(StoreStatus::InvalidRecord);
        }

        let status = StoreStatus::from(self.storage.insert_if_absent(key.to_vec(), value));
        match status {
            StoreStatus::Stored | StoreStatus::AlreadyStored => {
                let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
                self.schedule_welcome_if_new(source).await;
            }
            StoreStatus::Conflict => {
                log::warn!(
                    "rpc_store: conflicting record already exists for {}",
                    hex::encode(key)
                );
            }
            StoreStatus::CapacityExceeded => {
                log::warn!(
                    "rpc_store: storage capacity exceeded for {}",
                    hex::encode(key)
                );
            }
            StoreStatus::InvalidRecord => unreachable!("storage does not verify records"),
        }
        Some(status)
    }

    /// A STORE for a DID this node does not hold. A node holding a record
    /// compares it with the one it is sent; the Status List has rules of its own.
    fn store_needs_lookup(&self, key: &[u8; ID_LEN]) -> bool {
        *key != digest(STATUS_LIST_KEY) && self.storage.get(key).is_none()
    }

    /// What the nodes closest to `key` hold, compared with `value`. The
    /// lookup asks them for the SHA-256 of their record (`FindHash`) rather
    /// than the record, asks all of them rather than stopping at the first
    /// that answers with the hash of `value`, ends at the first other hash,
    /// gives up after `STORE_LOOKUP_TIMEOUT`, and leaves no copy on any node.
    /// A hash cannot be verified, so a node answering with another one blocks
    /// the STORE; it could block it anyway by not answering.
    async fn network_copy(self: &Arc<Self>, key: [u8; ID_LEN], value: &[u8]) -> NetworkCopy {
        let target = Node::from_id(key);
        // Contacts known not to respond are left out, even as a last resort:
        // the answer to the sender cannot wait for them.
        let (nearest, among_closest): (Vec<Node>, bool) = {
            let router = self.router.read().await;
            let neighbors = router.find_neighbors(&target, None);
            // By its own table, this node is among the k closest to the key
            // when it knows fewer than k nodes closer to it.
            let own_distance = self.source_node.distance_to(&target);
            let closer = neighbors
                .iter()
                .filter(|node| node.distance_to(&target) < own_distance)
                .count();
            let nearest = neighbors
                .into_iter()
                .filter(|node| !router.has_failures(&node.id))
                .collect();
            (nearest, closer < self.ksize)
        };
        // Nobody to ask, as for a node that has just restarted: it cannot know
        // what the network holds, which is not the same as knowing it is empty.
        if nearest.is_empty() {
            return NetworkCopy::Unknown;
        }
        let deadline = tokio::time::Instant::now() + STORE_LOOKUP_TIMEOUT;
        let own = record_hash(value);
        let find_hash = |protocol: Arc<Self>, peer, target| protocol.call_find_hash(peer, target);
        let mut crawl =
            ValueSpiderCrawl::new(Arc::clone(self), target, nearest, self.ksize, self.alpha);
        // A replica has to hear all of them anyway, so it asks them at once:
        // one round instead of several, and a node it knows cannot be pushed
        // out of the lookup by an earlier answer before it is asked. A node far
        // from the key keeps asking `alpha` at a time: the nodes it knows are
        // replaced at each hop, and asking all of them would ask k per hop.
        if among_closest {
            crawl = crawl.asking_everyone();
        }
        let search = crawl
            .search(Some(deadline), find_hash, |found| async move {
                (found.as_slice() != own.as_slice()).then_some(found)
            })
            .await;
        match search {
            ValueSearch::Found(_) => NetworkCopy::Other,
            ValueSearch::NotFound => NetworkCopy::NoneOrSame,
            ValueSearch::Incomplete => NetworkCopy::Unknown,
        }
    }

    pub async fn rpc_update(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> bool {
        if key == digest(STATUS_LIST_KEY) {
            log::warn!("rpc_update: status-list key requires UpdateStatusList");
            return false;
        }
        let old_value = match self.storage.get(&key) {
            Some(v) => v,
            None => {
                log::error!("rpc_update: record {} not found", hex::encode(key));
                return false;
            }
        };
        // A retry of an update this replica already applied: there is nothing
        // to verify or write. The answer means "I hold this record", not that
        // the signature is valid, so the sender is not added to the routing table.
        if old_value == value {
            return true;
        }
        let handler = Arc::clone(&self.signature_handler);
        let v = value.clone();
        let expected_key = key;
        let ok = tokio::task::spawn_blocking(move || {
            handler
                .handle_key_binding_verification(&expected_key, &old_value)
                .unwrap_or(false)
                && handler
                    .handle_key_binding_verification(&expected_key, &v)
                    .unwrap_or(false)
                && handler
                    .handle_update_verification(&v, &old_value, &auth_signature)
                    .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if !ok {
            log::error!(
                "rpc_update: invalid or unauthorized update for {}",
                hex::encode(key)
            );
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        if self.storage.set(key.to_vec(), value) == StorageWriteStatus::CapacityExceeded {
            log::warn!(
                "rpc_update: storage capacity exceeded for {}",
                hex::encode(key)
            );
            return false;
        }
        true
    }

    pub async fn rpc_update_status_list(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        if key != digest(STATUS_LIST_KEY) {
            log::warn!(
                "rpc_update_status_list: rejected non-status key {}",
                hex::encode(key)
            );
            return false;
        }
        if self.storage.get(&key).is_none() {
            log::error!(
                "rpc_update_status_list: record {} not found",
                hex::encode(key)
            );
            return false;
        }
        let handler = Arc::clone(&self.signature_handler);
        let v = value.clone();
        let ok = tokio::task::spawn_blocking(move || {
            handler
                .handle_issuer_node_signature_verification(&v)
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if !ok {
            log::error!("rpc_update_status_list: unauthenticated update");
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        if self.storage.set(key.to_vec(), value) == StorageWriteStatus::CapacityExceeded {
            log::warn!(
                "rpc_update_status_list: storage capacity exceeded for {}",
                hex::encode(key)
            );
            return false;
        }
        true
    }

    pub async fn rpc_find_node(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> Vec<Node> {
        let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
        self.schedule_welcome_if_new(source.clone()).await;
        let target = Node::from_id(key);
        self.router
            .read()
            .await
            .find_neighbors_to_advertise(&target, Some(&source))
    }

    pub async fn rpc_find_value(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> FindValueResult {
        let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
        self.schedule_welcome_if_new(source.clone()).await;
        if let Some(value) = self.storage.get(&key) {
            if self.key_binding_is_valid(&key, &value) {
                return FindValueResult::Value(value);
            }

            log::warn!(
                "rpc_find_value: refusing invalid stored record for {}",
                hex::encode(key)
            );
        }

        let target = Node::from_id(key);
        let neighbors = self
            .router
            .read()
            .await
            .find_neighbors_to_advertise(&target, Some(&source));
        FindValueResult::Nodes(neighbors)
    }

    pub async fn rpc_leave(&self, sender_id: [u8; ID_LEN], sender_addr: (String, u16)) {
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        let registered = self.router.read().await.get_contact(&sender_id);
        match registered {
            Some(contact) if contact.same_home_as(&source) => {
                log::info!("Node {} is leaving the network", hex::encode(sender_id));
                self.router.write().await.remove_contact(&contact);
            }
            Some(contact) => log::warn!(
                "Ignored Leave for {} from unregistered endpoint {}; registered endpoint is {}",
                hex::encode(sender_id),
                source,
                contact
            ),
            None => log::debug!("Ignored Leave for unknown node {}", hex::encode(sender_id)),
        }
    }

    pub async fn call_ping_addr(&self, addr: &(String, u16)) -> (bool, Vec<u8>) {
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return (false, vec![]),
        };
        let resp = self
            .call(
                sock_addr,
                RpcMessage::Ping {
                    sender_id: self.source_node.id,
                },
            )
            .await;
        match resp {
            Some(RpcMessage::Pong { sender_id }) => (true, sender_id.to_vec()),
            _ => (false, vec![]),
        }
    }

    pub async fn call_store_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Option<StoreStatus> {
        let addr = peer.address()?;
        let sock_addr: SocketAddr = format!("{}:{}", addr.0, addr.1).parse().ok()?;
        match self
            .call(
                sock_addr,
                RpcMessage::Store {
                    sender_id: self.source_node.id,
                    key,
                    value,
                },
            )
            .await
        {
            Some(RpcMessage::StoreResult { status }) => {
                self.note_alive(peer).await;
                Some(status)
            }
            _ => {
                log::warn!("no response from {}", peer);
                self.note_failure(peer).await;
                None
            }
        }
    }

    pub async fn call_update_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> bool {
        self.call_update_rpc_answer(peer, key, value, auth_signature)
            .await
            .unwrap_or(false)
    }

    /// Like `call_update_rpc`, but tells a refusal (`Some(false)`) from no
    /// answer (`None`).
    pub async fn call_update_rpc_answer(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> Option<bool> {
        let addr = peer.address()?;
        let sock_addr: SocketAddr = format!("{}:{}", addr.0, addr.1).parse().ok()?;
        match self
            .call(
                sock_addr,
                RpcMessage::Update {
                    sender_id: self.source_node.id,
                    key,
                    value,
                    auth_signature,
                },
            )
            .await
        {
            Some(RpcMessage::UpdateResult { ok }) => {
                self.note_alive(peer).await;
                Some(ok)
            }
            _ => {
                log::warn!("no response from {}", peer);
                self.note_failure(peer).await;
                None
            }
        }
    }

    pub async fn call_status_list_update_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        let addr = match peer.address() {
            Some(a) => a,
            None => return false,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match self
            .call(
                sock_addr,
                RpcMessage::UpdateStatusList {
                    sender_id: self.source_node.id,
                    key,
                    value,
                },
            )
            .await
        {
            Some(RpcMessage::UpdateStatusListResult { ok }) => {
                self.note_alive(peer).await;
                ok
            }
            _ => {
                log::warn!("no response from {}", peer);
                self.note_failure(peer).await;
                false
            }
        }
    }

    /// Notify `peer` of this node's departure. `Leave` has no response, so
    /// delivery is best-effort and there is nothing to wait for.
    pub async fn call_leave_rpc(&self, peer: &Node) {
        let addr = match peer.address() {
            Some(a) => a,
            None => return,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let frame = Frame {
            msg_id: self.next_id(),
            is_request: true,
            message: RpcMessage::Leave {
                sender_id: self.source_node.id,
            },
        };
        self.send_frame(sock_addr, &frame).await;
    }

    /// Verify `value` for `key`, using the signature cache to skip redundant
    /// PQ crypto on repeated calls with the same record bytes.
    async fn verify_for_key(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
        let is_status = *key == digest(STATUS_LIST_KEY);
        if !self.key_binding_is_valid(key, value) {
            return false;
        }
        let domain = if is_status {
            VerificationDomain::IssuerSigned
        } else {
            VerificationDomain::SelfSigned
        };
        let cache_key = self
            .sig_cache
            .as_ref()
            .map(|_| SignatureCache::compute_key(domain, value));
        if let (Some(cache), Some(ck)) = (&self.sig_cache, &cache_key) {
            if let Some(cached) = cache.get_by_key(ck) {
                return cached;
            }
        }
        let handler = Arc::clone(&self.signature_handler);
        let v = value.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            if is_status {
                handler
                    .handle_issuer_node_signature_verification(&v)
                    .unwrap_or(false)
            } else {
                handler.handle_signature_verification(&v).unwrap_or(false)
            }
        })
        .await
        .unwrap_or(false);
        if let (Some(cache), Some(ck)) = (&self.sig_cache, cache_key) {
            cache.insert_by_key(ck, result);
        }
        result
    }

    fn key_binding_is_valid(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
        *key == digest(STATUS_LIST_KEY)
            || self
                .signature_handler
                .handle_key_binding_verification(key, value)
                .unwrap_or(false)
    }

    /// Add `node` to the routing table and replicate keys that belong to it
    /// (Kademlia §2.5).
    pub async fn welcome_if_new(self: &Arc<Self>, node: Node) {
        if !self.router.read().await.is_new_node(&node) {
            return;
        }
        self.add_contact(node.clone()).await;
        self.replicate_to(&node).await;
    }

    /// Send a node that just joined or just came back the records it should
    /// hold. Replication fires only when `new_node_close` AND `this_closest`
    /// are both true; `node` is left out of the neighbours it is compared
    /// with.
    async fn replicate_to(self: &Arc<Self>, node: &Node) {
        log::info!("Discovered or returning node: {}", node);

        let self_node = self.source_node.clone();
        let mut keys_to_replicate: Vec<([u8; ID_LEN], Vec<u8>)> = Vec::new();
        let mut entries = self.storage.iter_all().into_iter().peekable();
        while entries.peek().is_some() {
            // One read lock per chunk, so that a node making contact meanwhile
            // does not wait for the whole scan to enter the routing table.
            let router = self.router.read().await;
            for (key_vec, value) in entries.by_ref().take(WELCOME_SCAN_CHUNK) {
                if key_vec.len() != ID_LEN {
                    continue;
                }
                let mut key = [0u8; ID_LEN];
                key.copy_from_slice(&key_vec);
                let key_node = Node::from_id(key);

                let neighbors = router.find_neighbors(&key_node, Some(node));

                let new_node_close = match neighbors.last() {
                    Some(last) => node.distance_to(&key_node) < last.distance_to(&key_node),
                    None => true,
                };
                let this_closest = match neighbors.first() {
                    Some(first) => self_node.distance_to(&key_node) < first.distance_to(&key_node),
                    None => true,
                };

                if new_node_close && this_closest {
                    keys_to_replicate.push((key, value));
                }
            }
        }

        stream::iter(keys_to_replicate)
            .for_each_concurrent(REPLICATION_CONCURRENCY, |(key, value)| {
                let p = Arc::clone(self);
                let n = node.clone();
                async move {
                    let _ = p.call_store_rpc(&n, key, value).await;
                }
            })
            .await;
    }

    /// Ping `node` to check liveness (§4.2 LRU eviction).
    ///
    /// A failure is counted, and the node is replaced once stale if a replacement
    /// is available (`record_failure`). On success the Pong response triggers
    /// `welcome_if_new` in `handle_datagram`, refreshing the routing table.
    pub async fn call_ping_node(self: &Arc<Self>, node: &Node) {
        let addr = match node.address() {
            Some(a) => a,
            None => return,
        };
        let (ok, _) = self.call_ping_addr(&addr).await;
        if !ok {
            log::warn!("ping: no response from {}", node);
            self.note_failure(node).await;
        }
        // On success: Pong received in handle_datagram already calls welcome_if_new.
    }

    /// Return a random ID for each lonely bucket, constrained to that bucket's
    /// keyspace range (§2.3). Matches Python: `random.randint(*bucket.range).to_bytes(20, 'big')`.
    pub async fn get_refresh_ids(&self) -> Vec<[u8; ID_LEN]> {
        use rand::RngCore;
        self.router
            .read()
            .await
            .lonely_buckets()
            .iter()
            .map(|b| {
                let lo = *b.range.start();
                let hi = *b.range.end();
                // Uniform id in [lo, hi] over the full 160-bit space.
                let span = hi - lo + primitive_types::U256::one();
                let mut rand_bytes = [0u8; ID_LEN];
                rand::thread_rng().fill_bytes(&mut rand_bytes);
                let r = primitive_types::U256::from_big_endian(&rand_bytes); // in [0, 2^160)
                let val = lo + (r % span);
                // `val <= hi < 2^160`, so the top 12 bytes are zero.
                let mut buf = [0u8; 32];
                val.to_big_endian(&mut buf);
                let mut id = [0u8; ID_LEN];
                id.copy_from_slice(&buf[12..32]);
                id
            })
            .collect()
    }
}

pub enum FindValueResult {
    Nodes(Vec<Node>),
    Value(Vec<u8>),
}

impl KademliaProtocol {
    /// Ask `peer` whether it holds a record for `target`, receiving its
    /// SHA-256 (`FindHash`) instead of the record. A hit is returned as
    /// `FindPayload::Value` holding the hash.
    pub(crate) async fn call_find_hash(self: Arc<Self>, peer: Node, target: Node) -> RawResponse {
        let request = RpcMessage::FindHash {
            sender_id: self.source_node.id,
            key: target.id,
        };
        self.call_find(peer, request).await
    }

    /// Send a `FindValue` or `FindHash` request and translate the answer.
    async fn call_find(self: Arc<Self>, peer: Node, request: RpcMessage) -> RawResponse {
        let addr = match peer.address() {
            Some(a) => a,
            None => return RawResponse(false, FindPayload::Empty),
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return RawResponse(false, FindPayload::Empty),
        };
        match self.call(sock_addr, request).await {
            Some(RpcMessage::FindValueHit { value }) => {
                self.schedule_welcome_if_new(peer).await;
                RawResponse(true, FindPayload::Value(value))
            }
            Some(RpcMessage::FindHashHit { hash }) => {
                self.schedule_welcome_if_new(peer).await;
                RawResponse(true, FindPayload::Value(hash.to_vec()))
            }
            Some(RpcMessage::FindValueNodes { nodes }) => {
                self.schedule_welcome_if_new(peer).await;
                let tuples = nodes
                    .into_iter()
                    .map(|w| (w.id.to_vec(), w.ip, w.port))
                    .collect();
                RawResponse(true, FindPayload::Nodes(tuples))
            }
            _ => {
                log::warn!("no response from {}", peer);
                self.note_failure(&peer).await;
                RawResponse(false, FindPayload::Empty)
            }
        }
    }
}

#[async_trait]
impl SpiderProtocol for KademliaProtocol {
    async fn call_find_node(self: Arc<Self>, peer: Node, target: Node) -> RawResponse {
        let addr = match peer.address() {
            Some(a) => a,
            None => return RawResponse(false, FindPayload::Empty),
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return RawResponse(false, FindPayload::Empty),
        };
        match self
            .call(
                sock_addr,
                RpcMessage::FindNode {
                    sender_id: self.source_node.id,
                    key: target.id,
                },
            )
            .await
        {
            Some(RpcMessage::FindNodeResult { nodes }) => {
                self.schedule_welcome_if_new(peer).await;
                let tuples = nodes
                    .into_iter()
                    .map(|w| (w.id.to_vec(), w.ip, w.port))
                    .collect();
                RawResponse(true, FindPayload::Nodes(tuples))
            }
            _ => {
                log::warn!("no response from {}", peer);
                self.note_failure(&peer).await;
                RawResponse(false, FindPayload::Empty)
            }
        }
    }

    async fn call_find_value(self: Arc<Self>, peer: Node, target: Node) -> RawResponse {
        let request = RpcMessage::FindValue {
            sender_id: self.source_node.id,
            key: target.id,
        };
        self.call_find(peer, request).await
    }

    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
        matches!(
            self.call_store_rpc(peer, key, value).await,
            Some(StoreStatus::Stored | StoreStatus::AlreadyStored)
        )
    }

    async fn failing_among(&self, nodes: &[Node]) -> HashSet<[u8; ID_LEN]> {
        let router = self.router.read().await;
        nodes
            .iter()
            .filter(|node| router.has_failures(&node.id))
            .map(|node| node.id)
            .collect()
    }

    async fn note_no_answer(&self, nodes: &[Node]) {
        for node in nodes {
            self.note_failure(node).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::timeout;

    use crate::auth_handler::AuthHandlerError;
    use crate::signature_cache::VerificationDomain;

    struct TestHandler {
        key_binding_result: bool,
        self_signed_result: bool,
        issuer_signed_result: bool,
        key_binding_calls: AtomicUsize,
        self_signed_calls: AtomicUsize,
        issuer_signed_calls: AtomicUsize,
    }

    impl TestHandler {
        fn new(self_signed_result: bool, issuer_signed_result: bool) -> Self {
            Self {
                key_binding_result: true,
                self_signed_result,
                issuer_signed_result,
                key_binding_calls: AtomicUsize::new(0),
                self_signed_calls: AtomicUsize::new(0),
                issuer_signed_calls: AtomicUsize::new(0),
            }
        }

        fn with_key_binding_result(mut self, result: bool) -> Self {
            self.key_binding_result = result;
            self
        }
    }

    impl SignatureVerifierHandler for TestHandler {
        fn handle_key_binding_verification(
            &self,
            _key: &[u8; ID_LEN],
            _value: &[u8],
        ) -> Result<bool, AuthHandlerError> {
            self.key_binding_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.key_binding_result)
        }

        fn handle_signature_verification(&self, _value: &[u8]) -> Result<bool, AuthHandlerError> {
            self.self_signed_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.self_signed_result)
        }

        fn handle_update_verification(
            &self,
            _value: &[u8],
            _old_value: &[u8],
            _auth_signature: &[u8],
        ) -> Result<bool, AuthHandlerError> {
            Ok(true)
        }

        fn handle_issuer_node_signature_verification(
            &self,
            _value: &[u8],
        ) -> Result<bool, AuthHandlerError> {
            self.issuer_signed_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.issuer_signed_result)
        }
    }

    async fn test_protocol(
        handler: Arc<dyn SignatureVerifierHandler>,
        use_cache: bool,
    ) -> Arc<KademliaProtocol> {
        test_protocol_with_storage(handler, use_cache, Arc::new(ForgetfulStorage::new(-1))).await
    }

    async fn test_protocol_with_storage(
        handler: Arc<dyn SignatureVerifierHandler>,
        use_cache: bool,
        storage: Arc<ForgetfulStorage>,
    ) -> Arc<KademliaProtocol> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        Arc::new(KademliaProtocol::new(
            Node::from_id([1; ID_LEN]),
            socket,
            storage,
            20,
            3,
            handler,
            use_cache.then(|| Arc::new(SignatureCache::new(32))),
        ))
    }

    /// Read datagrams and handle them, as a listening node does.
    fn serve(protocol: &Arc<KademliaProtocol>) {
        let protocol = Arc::clone(protocol);
        tokio::spawn(async move {
            let socket = Arc::clone(&protocol.socket);
            let mut buffer = vec![0u8; 65_536];
            while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
                protocol.handle_datagram(buffer[..len].to_vec(), from).await;
            }
        });
    }

    /// A node that holds nothing and answers lookups, known to `protocol`, so
    /// that a STORE to `protocol` can ask the network.
    async fn give_answering_contact(protocol: &Arc<KademliaProtocol>, id: [u8; ID_LEN]) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let peer = Arc::new(KademliaProtocol::new(
            contact_at(id, port),
            socket,
            Arc::new(ForgetfulStorage::new(-1)),
            20,
            3,
            Arc::new(TestHandler::new(true, true)),
            None,
        ));
        serve(&peer);
        serve(protocol);
        protocol
            .router
            .write()
            .await
            .add_contact(contact_at(id, port));
    }

    impl PendingCall {
        fn new(
            peer: SocketAddr,
            expected: ExpectedResponse,
            reply: oneshot::Sender<RpcMessage>,
        ) -> Self {
            Self {
                peer,
                expected,
                reply,
                received: Arc::new(Notify::new()),
            }
        }
    }

    fn contact_at(id: [u8; ID_LEN], port: u16) -> Node {
        Node::new(id, Some("127.0.0.1".to_string()), Some(port))
    }

    /// A socket standing in for a peer, and the contact that reaches it.
    async fn raw_peer(id: [u8; ID_LEN]) -> (UdpSocket, Node) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        (socket, contact_at(id, port))
    }

    /// Next frame that reaches `socket` within `wait`, which must fit in one
    /// datagram.
    async fn try_read_frame(socket: &UdpSocket, wait: Duration) -> Option<(Frame, SocketAddr)> {
        let mut buffer = vec![0u8; 65_536];
        let (len, from) = timeout(wait, socket.recv_from(&mut buffer))
            .await
            .ok()?
            .unwrap();
        let (header, chunk) = parse_fragment(&buffer[..len]).unwrap();
        assert_eq!(header.total, 1, "a test frame must fit in one datagram");
        Some((bincode::deserialize(chunk).unwrap(), from))
    }

    /// Next frame that reaches `socket`. A test waiting for a frame that never
    /// comes fails instead of hanging.
    async fn read_frame(socket: &UdpSocket) -> (Frame, SocketAddr) {
        try_read_frame(socket, RPC_TIMEOUT + Duration::from_millis(500))
            .await
            .expect("no frame arrived")
    }

    /// Next frame of `kind` (`true` for a request) that reaches `socket`,
    /// skipping the others.
    async fn read_frame_of_kind(socket: &UdpSocket, request: bool) -> (Frame, SocketAddr) {
        loop {
            let (frame, from) = read_frame(socket).await;
            if frame.is_request == request {
                return (frame, from);
            }
        }
    }

    async fn send_raw(
        socket: &UdpSocket,
        to: SocketAddr,
        msg_id: u32,
        is_request: bool,
        message: RpcMessage,
    ) {
        let frame = Frame {
            msg_id,
            is_request,
            message,
        };
        for datagram in encode_fragments(msg_id, &bincode::serialize(&frame).unwrap()) {
            socket.send_to(&datagram, to).await.unwrap();
        }
    }

    /// The first copy of a STORE is lost: the sender sends the same request
    /// again, and does not wait for the RPC timeout.
    #[tokio::test]
    async fn a_store_whose_first_copy_is_lost_is_sent_again() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let (peer, contact) = raw_peer([9; ID_LEN]).await;
        let started = Instant::now();
        let sender = Arc::clone(&protocol);
        let call = tokio::spawn(async move {
            sender
                .call_store_rpc(&contact, [7; ID_LEN], b"one".to_vec())
                .await
        });

        let (first, _) = read_frame(&peer).await;
        let (second, from) = read_frame(&peer).await;
        assert_eq!(second.msg_id, first.msg_id);
        assert!(matches!(second.message, RpcMessage::Store { .. }));
        send_raw(
            &peer,
            from,
            second.msg_id,
            false,
            RpcMessage::StoreResult {
                status: StoreStatus::Stored,
            },
        )
        .await;

        assert_eq!(call.await.unwrap(), Some(StoreStatus::Stored));
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    /// Once a peer has answered, a lost request is sent again after a few of
    /// its round trips, not after the wait for a peer never measured.
    #[tokio::test]
    async fn a_measured_peer_is_asked_again_after_a_few_round_trips() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let (peer, contact) = raw_peer([9; ID_LEN]).await;
        let address = contact.address().unwrap();
        let pong = RpcMessage::Pong {
            sender_id: [9; ID_LEN],
        };

        let sender = Arc::clone(&protocol);
        let target = address.clone();
        let first_call = tokio::spawn(async move { sender.call_ping_addr(&target).await });
        let (ping, from) = read_frame(&peer).await;
        send_raw(&peer, from, ping.msg_id, false, pong.clone()).await;
        assert!(first_call.await.unwrap().0);

        let started = Instant::now();
        let sender = Arc::clone(&protocol);
        let second_call = tokio::spawn(async move { sender.call_ping_addr(&address).await });
        let (lost, _) = read_frame_of_kind(&peer, true).await;
        let (again, from) = read_frame_of_kind(&peer, true).await;
        assert_eq!(again.msg_id, lost.msg_id);
        send_raw(&peer, from, again.msg_id, false, pong).await;
        assert!(second_call.await.unwrap().0);
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "{:?}",
            started.elapsed()
        );
    }

    /// A peer that never answers gets the request once and then
    /// `MAX_RESENDS` more times, and the call still ends at `RPC_TIMEOUT`.
    #[tokio::test]
    async fn a_silent_peer_gets_the_request_at_most_three_times() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let (peer, contact) = raw_peer([9; ID_LEN]).await;
        let address = contact.address().unwrap();
        let started = Instant::now();
        let sender = Arc::clone(&protocol);
        let call = tokio::spawn(async move { sender.call_ping_addr(&address).await });

        let mut copies = 0;
        let end = started + RPC_TIMEOUT + Duration::from_millis(300);
        while try_read_frame(&peer, end.saturating_duration_since(Instant::now()))
            .await
            .is_some()
        {
            copies += 1;
        }
        assert!(!call.await.unwrap().0);
        assert_eq!(copies, 1 + crate::retransmit::MAX_RESENDS);
        assert!(started.elapsed() >= RPC_TIMEOUT);
    }

    /// A receipt is not the answer. If the answer is lost after the receipt,
    /// the sender asks again and takes the answer to the copy.
    #[tokio::test]
    async fn a_lost_answer_after_a_receipt_is_asked_again() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let (peer, contact) = raw_peer([9; ID_LEN]).await;
        let started = Instant::now();
        let sender = Arc::clone(&protocol);
        let call = tokio::spawn(async move {
            sender
                .call_store_rpc(&contact, [7; ID_LEN], b"one".to_vec())
                .await
        });

        let (store, from) = read_frame(&peer).await;
        send_raw(&peer, from, store.msg_id, false, RpcMessage::Received).await;
        // The answer to the first copy is lost; the copy finds the record stored.
        let (again, from) = read_frame(&peer).await;
        assert_eq!(again.msg_id, store.msg_id);
        send_raw(
            &peer,
            from,
            again.msg_id,
            false,
            RpcMessage::StoreResult {
                status: StoreStatus::AlreadyStored,
            },
        )
        .await;

        assert_eq!(call.await.unwrap(), Some(StoreStatus::AlreadyStored));
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    /// A STORE that waits for the network check is acknowledged at once. A
    /// copy that arrives during the check gets the receipt again and does not
    /// start a second check; another request under the same msg_id does.
    #[tokio::test]
    async fn a_store_is_acknowledged_at_once_and_its_copy_is_not_checked_twice() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        // The node's only contact never answers, so the check lasts until
        // its deadline.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        protocol
            .router
            .write()
            .await
            .add_contact(contact_at([5; ID_LEN], silent.local_addr().unwrap().port()));
        let (client, _) = raw_peer([9; ID_LEN]).await;
        let node = protocol.socket.local_addr().unwrap();
        let store = |value: &[u8]| RpcMessage::Store {
            sender_id: [9; ID_LEN],
            key: [7; ID_LEN],
            value: value.to_vec(),
        };

        send_raw(&client, node, 5, true, store(b"one")).await;
        let (receipt, _) = timeout(
            Duration::from_millis(200),
            read_frame_of_kind(&client, false),
        )
        .await
        .expect("a receipt before the check ends");
        assert_eq!(receipt.msg_id, 5);
        assert!(matches!(receipt.message, RpcMessage::Received));
        assert_eq!(protocol.store_lookups.load(Ordering::Acquire), 1);

        send_raw(&client, node, 5, true, store(b"one")).await;
        let (receipt, _) = timeout(
            Duration::from_millis(200),
            read_frame_of_kind(&client, false),
        )
        .await
        .expect("a receipt for the copy");
        assert!(matches!(receipt.message, RpcMessage::Received));
        assert_eq!(protocol.store_lookups.load(Ordering::Acquire), 1);

        send_raw(&client, node, 5, true, store(b"two")).await;
        timeout(
            Duration::from_millis(200),
            read_frame_of_kind(&client, false),
        )
        .await
        .expect("a receipt for the other request");
        assert_eq!(protocol.store_lookups.load(Ordering::Acquire), 2);
    }

    /// The network check of a STORE survives a lost question: the node asked
    /// gets it again, and the STORE is decided well before the check's
    /// deadline.
    #[tokio::test]
    async fn the_store_check_survives_a_lost_question() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let (peer, contact) = raw_peer([5; ID_LEN]).await;
        protocol.router.write().await.add_contact(contact);
        let started = Instant::now();
        let replica = Arc::clone(&protocol);
        let store = tokio::spawn(async move {
            replica
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9015),
                    [7; ID_LEN],
                    b"one".to_vec(),
                )
                .await
        });

        let (lost, _) = read_frame_of_kind(&peer, true).await;
        assert!(matches!(lost.message, RpcMessage::FindHash { .. }));
        let (again, from) = read_frame_of_kind(&peer, true).await;
        assert_eq!(again.msg_id, lost.msg_id);
        send_raw(
            &peer,
            from,
            again.msg_id,
            false,
            RpcMessage::FindValueNodes { nodes: vec![] },
        )
        .await;

        assert_eq!(store.await.unwrap(), Some(StoreStatus::Stored));
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn cancelled_call_leaves_no_pending_entry() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let call = protocol.call(
            silent.local_addr().unwrap(),
            RpcMessage::Ping {
                sender_id: [1; ID_LEN],
            },
        );
        assert!(timeout(Duration::from_millis(50), call).await.is_err());
        assert!(protocol.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn forged_endpoint_cannot_clear_a_failing_contact() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let registered = contact_at([9; ID_LEN], 7000);
        {
            let mut router = protocol.router.write().await;
            router.add_contact(registered.clone());
            router.record_failure(&registered);
        }

        let forged = contact_at([9; ID_LEN], 7001);
        assert!(protocol.note_alive(&forged).await.is_none());
        assert!(protocol.router.read().await.has_failures(&registered.id));

        assert!(protocol.note_alive(&registered).await.is_some());
        assert!(!protocol.router.read().await.has_failures(&registered.id));
    }

    #[tokio::test]
    async fn stale_contact_accepts_a_new_endpoint() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let registered = contact_at([9; ID_LEN], 7000);
        {
            let mut router = protocol.router.write().await;
            router.add_contact(registered.clone());
            let mut now = Instant::now();
            for _ in 0..crate::routing::STALE_AFTER_FAILURES {
                router.record_failure_at(&registered, now);
                now += Duration::from_secs(10_000);
            }
            assert!(router.is_stale(&registered.id));
        }

        let moved = contact_at([9; ID_LEN], 7001);
        assert!(protocol.note_alive(&moved).await.is_some());
        assert!(!protocol.router.read().await.has_failures(&registered.id));
    }

    #[tokio::test]
    async fn update_status_list_cannot_overwrite_a_did_record() {
        let handler = Arc::new(TestHandler::new(true, true));
        let protocol = test_protocol(handler, false).await;
        let did_key = [7; ID_LEN];
        let old_record = b"legitimate did record".to_vec();
        let issuer_record = b"issuer-signed status list".to_vec();
        protocol.storage.set(did_key.to_vec(), old_record.clone());

        assert!(
            !protocol
                .rpc_update_status_list(
                    [2; ID_LEN],
                    ("127.0.0.1".into(), 9000),
                    did_key,
                    issuer_record.clone(),
                )
                .await
        );
        assert_eq!(protocol.storage.get(&did_key), Some(old_record));

        let status_key = digest(STATUS_LIST_KEY);
        protocol
            .storage
            .set(status_key.to_vec(), b"old status list".to_vec());
        assert!(
            protocol
                .rpc_update_status_list(
                    [3; ID_LEN],
                    ("127.0.0.1".into(), 9001),
                    status_key,
                    issuer_record.clone(),
                )
                .await
        );
        assert_eq!(protocol.storage.get(&status_key), Some(issuer_record));

        assert!(
            !protocol
                .rpc_update(
                    [4; ID_LEN],
                    ("127.0.0.1".into(), 9002),
                    status_key,
                    b"wrong update path".to_vec(),
                    vec![],
                )
                .await
        );
    }

    #[tokio::test]
    async fn rpc_store_reports_idempotence_conflict_capacity_and_invalid_records() {
        let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(-1, ID_LEN + 3));
        let protocol =
            test_protocol_with_storage(Arc::new(TestHandler::new(true, true)), false, storage)
                .await;
        give_answering_contact(&protocol, [5; ID_LEN]).await;
        let sender = [2; ID_LEN];
        let address = ("127.0.0.1".to_string(), 9010);
        let key = [7; ID_LEN];

        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), key, b"one".to_vec())
                .await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), key, b"one".to_vec())
                .await,
            Some(StoreStatus::AlreadyStored)
        );
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), key, b"two".to_vec())
                .await,
            Some(StoreStatus::Conflict)
        );
        // The first STORE added the sender as a contact. The key below is new,
        // so the node would ask that contact, which does not exist here.
        let contact = Node::new(sender, Some(address.0.clone()), Some(address.1));
        protocol.router.write().await.remove_contact(&contact);
        assert_eq!(
            protocol
                .rpc_store(sender, address, [8; ID_LEN], b"new".to_vec())
                .await,
            Some(StoreStatus::CapacityExceeded)
        );

        let invalid_protocol = test_protocol(Arc::new(TestHandler::new(false, false)), false).await;
        give_answering_contact(&invalid_protocol, [6; ID_LEN]).await;
        assert_eq!(
            invalid_protocol
                .rpc_store(
                    [3; ID_LEN],
                    ("127.0.0.1".to_string(), 9011),
                    [9; ID_LEN],
                    b"bad".to_vec(),
                )
                .await,
            Some(StoreStatus::InvalidRecord)
        );
    }

    /// The network check of a STORE asks for the record's SHA-256, not for
    /// the record: the answer fits in one datagram, so it is never fragmented.
    /// A node without the record answers with closer nodes, as for FIND_VALUE.
    #[tokio::test]
    async fn find_hash_answers_with_the_record_hash_in_one_datagram() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let key = [7; ID_LEN];
        let record = vec![0xAB; 6000];
        protocol.storage.set(key.to_vec(), record.clone());
        let peer: SocketAddr = "127.0.0.1:9014".parse().unwrap();

        let answer = protocol
            .dispatch_request(
                RpcMessage::FindHash {
                    sender_id: [2; ID_LEN],
                    key,
                },
                peer,
            )
            .await;
        let Some(RpcMessage::FindHashHit { hash }) = answer else {
            panic!("expected the record's hash, got {answer:?}");
        };
        assert_eq!(hash, record_hash(&record));
        let frame = Frame {
            msg_id: 1,
            is_request: false,
            message: RpcMessage::FindHashHit { hash },
        };
        assert!(bincode::serialize(&frame).unwrap().len() <= FRAG_CHUNK_SIZE);

        let answer = protocol
            .dispatch_request(
                RpcMessage::FindHash {
                    sender_id: [2; ID_LEN],
                    key: [8; ID_LEN],
                },
                peer,
            )
            .await;
        assert!(
            matches!(answer, Some(RpcMessage::FindValueNodes { .. })),
            "{answer:?}"
        );
    }

    /// A node that knows nobody, as one that has just restarted, cannot ask
    /// the network about a record it does not hold: it refuses the STORE and
    /// does not answer.
    #[tokio::test]
    async fn store_to_a_node_that_knows_nobody_gets_no_answer() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9012),
                    [7; ID_LEN],
                    b"one".to_vec()
                )
                .await,
            None
        );
        assert_eq!(protocol.storage.get(&[7; ID_LEN]), None);
    }

    /// An empty replica refuses a record that does not belong to the key before
    /// asking the network: the binding costs a JSON parse, the lookup a message
    /// to every node close to the key. The signature is not checked either.
    #[tokio::test]
    async fn a_record_bound_to_another_key_is_refused_before_the_network_check() {
        let handler = Arc::new(TestHandler::new(true, true).with_key_binding_result(false));
        let protocol = test_protocol(handler.clone(), false).await;
        let (peer, contact) = raw_peer([5; ID_LEN]).await;
        protocol.router.write().await.add_contact(contact);
        let started = Instant::now();

        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9016),
                    [7; ID_LEN],
                    b"bound to another key".to_vec(),
                )
                .await,
            Some(StoreStatus::InvalidRecord)
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        assert!(
            try_read_frame(&peer, Duration::from_millis(200))
                .await
                .is_none(),
            "the replica asked the network about a record bound to another key"
        );
        assert_eq!(handler.self_signed_calls.load(Ordering::Relaxed), 0);
        assert_eq!(protocol.storage.get(&[7; ID_LEN]), None);
    }

    /// Answer every request that reaches `socket` with `answer`, until no
    /// request comes for a while.
    fn answer_every_request(socket: UdpSocket, answer: RpcMessage) {
        tokio::spawn(async move {
            while let Some((frame, from)) = try_read_frame(&socket, Duration::from_secs(5)).await {
                if frame.is_request {
                    send_raw(&socket, from, frame.msg_id, false, answer.clone()).await;
                }
            }
        });
    }

    /// A replica among the nodes closest to the key, by its own table, must
    /// hear all of them anyway: it asks them all at once rather than α at a
    /// time. None of them answers, so the STORE is still refused.
    #[tokio::test]
    async fn an_empty_replica_asks_every_known_neighbour_at_once() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let key = [7; ID_LEN];
        let mut peers = vec![];
        for id in [6u8, 5, 4, 3, 0] {
            let (peer, contact) = raw_peer([id; ID_LEN]).await;
            protocol.router.write().await.add_contact(contact);
            peers.push((id, peer));
        }
        let started = tokio::time::Instant::now();
        let replica = Arc::clone(&protocol);
        let store = tokio::spawn(async move {
            replica
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9017),
                    key,
                    b"one".to_vec(),
                )
                .await
        });

        let asked_by = started + Duration::from_millis(300);
        let mut not_asked = vec![];
        for (id, peer) in &peers {
            let wait = asked_by.saturating_duration_since(tokio::time::Instant::now());
            match try_read_frame(peer, wait).await {
                Some((frame, _)) => assert!(
                    matches!(frame.message, RpcMessage::FindHash { key: asked, .. } if asked == key),
                    "{:?}",
                    frame.message
                ),
                None => not_asked.push(*id),
            }
        }
        assert!(
            not_asked.is_empty(),
            "neighbours not asked within 300 ms: {not_asked:?}"
        );
        assert_eq!(store.await.unwrap(), None);
        assert_eq!(protocol.storage.get(&key), None);
    }

    /// A node that knows k nodes closer to the key than itself is not among the
    /// replicas by its own table: it keeps asking `alpha` at a time, since the
    /// nodes it knows would be replaced at the next hop.
    #[tokio::test]
    async fn a_node_far_from_the_key_asks_alpha_neighbours_at_a_time() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let protocol = Arc::new(KademliaProtocol::new(
            Node::from_id([1; ID_LEN]),
            socket,
            Arc::new(ForgetfulStorage::new(-1)),
            5,
            3,
            Arc::new(TestHandler::new(true, true)),
            None,
        ));
        serve(&protocol);
        let key = [7; ID_LEN];
        // Five nodes, all closer to the key than this node, from the closest.
        let mut peers = vec![];
        for first in [6u8, 5, 4, 3, 2] {
            let mut id = [0; ID_LEN];
            id[0] = first;
            let (peer, contact) = raw_peer(id).await;
            protocol.router.write().await.add_contact(contact);
            peers.push((first, peer));
        }
        let started = tokio::time::Instant::now();
        let replica = Arc::clone(&protocol);
        let store = tokio::spawn(async move {
            replica
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9019),
                    key,
                    b"one".to_vec(),
                )
                .await
        });

        let asked_by = started + Duration::from_millis(300);
        let mut asked = vec![];
        for (first, peer) in &peers {
            let wait = asked_by.saturating_duration_since(tokio::time::Instant::now());
            if try_read_frame(peer, wait).await.is_some() {
                asked.push(*first);
            }
        }
        assert_eq!(asked, vec![6, 5, 4]);
        assert_eq!(store.await.unwrap(), None);
        assert_eq!(protocol.storage.get(&key), None);
    }

    /// A neighbour answers the STORE check with made-up nodes closer to the key,
    /// all at its own address, that hold nothing. They must not push out of the
    /// check a node the replica already knows, which holds another record.
    #[tokio::test]
    async fn a_neighbour_cannot_push_a_known_holder_out_of_the_store_check() {
        let handler = Arc::new(TestHandler::new(true, true));
        let protocol = test_protocol(handler.clone(), false).await;
        serve(&protocol);
        let key = [7; ID_LEN];

        // From the closest to the key: an empty node, the liar, another empty
        // node, the holder, a third empty node.
        let (liar, liar_contact) = raw_peer([5; ID_LEN]).await;
        let (holder, holder_contact) = raw_peer([3; ID_LEN]).await;
        let mut contacts = vec![liar_contact.clone(), holder_contact];
        for id in [6u8, 4, 0] {
            let (empty, contact) = raw_peer([id; ID_LEN]).await;
            answer_every_request(empty, RpcMessage::FindValueNodes { nodes: vec![] });
            contacts.push(contact);
        }
        for contact in contacts {
            protocol.router.write().await.add_contact(contact);
        }

        let made_up: Vec<WireNode> = (1..=20u8)
            .map(|n| {
                let mut id = key;
                id[ID_LEN - 1] ^= n;
                WireNode::from(&Node::new(id, liar_contact.ip.clone(), liar_contact.port))
            })
            .collect();
        answer_every_request(liar, RpcMessage::FindValueNodes { nodes: made_up });
        answer_every_request(
            holder,
            RpcMessage::FindHashHit {
                hash: record_hash(b"the owner's record"),
            },
        );

        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9018),
                    key,
                    b"a forged record".to_vec(),
                )
                .await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(handler.self_signed_calls.load(Ordering::Relaxed), 0);
        assert_eq!(protocol.storage.get(&key), None);
    }

    #[tokio::test]
    async fn invalid_store_does_not_remove_spoofed_sender_from_routing_table() {
        let protocol = test_protocol(Arc::new(TestHandler::new(false, false)), false).await;
        let sender_id = [14; ID_LEN];
        let registered = Node::new(sender_id, Some("127.0.0.1".into()), Some(9013));
        protocol
            .router
            .write()
            .await
            .add_contact(registered.clone());
        // The node holds a record for the key, so each STORE is verified
        // without asking the network, whose contact here never answers.
        protocol
            .storage
            .set([15; ID_LEN].to_vec(), b"stored".to_vec());

        for _ in 0..3 {
            assert_eq!(
                protocol
                    .rpc_store(
                        sender_id,
                        ("127.0.0.1".into(), 9999),
                        [15; ID_LEN],
                        b"invalid".to_vec(),
                    )
                    .await,
                Some(StoreStatus::InvalidRecord)
            );
        }

        assert_eq!(
            protocol.router.read().await.get_contact(&sender_id),
            Some(registered),
            "unauthenticated sender IDs must not mutate routing state"
        );
    }

    #[tokio::test]
    async fn rpc_update_preserves_old_value_when_capacity_is_exceeded() {
        let key = [10; ID_LEN];
        let old_value = b"old".to_vec();
        let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
            -1,
            ID_LEN + old_value.len(),
        ));
        assert_eq!(
            storage.set(key.to_vec(), old_value.clone()),
            StorageWriteStatus::Stored
        );
        let protocol =
            test_protocol_with_storage(Arc::new(TestHandler::new(true, true)), false, storage)
                .await;

        assert!(
            !protocol
                .rpc_update(
                    [4; ID_LEN],
                    ("127.0.0.1".to_string(), 9012),
                    key,
                    b"larger".to_vec(),
                    vec![],
                )
                .await
        );
        assert_eq!(protocol.storage.get(&key), Some(old_value));
    }

    #[tokio::test]
    async fn rpc_update_rejects_a_record_bound_to_a_different_key() {
        let key = [16; ID_LEN];
        let old_value = b"old".to_vec();
        let storage = Arc::new(ForgetfulStorage::new(-1));
        storage.set(key.to_vec(), old_value.clone());
        let handler = Arc::new(TestHandler::new(true, true).with_key_binding_result(false));
        let protocol = test_protocol_with_storage(handler, false, storage).await;

        assert!(
            !protocol
                .rpc_update(
                    [17; ID_LEN],
                    ("127.0.0.1".into(), 9014),
                    key,
                    b"valid but mismatched".to_vec(),
                    vec![],
                )
                .await
        );
        assert_eq!(protocol.storage.get(&key), Some(old_value));
    }

    #[tokio::test]
    async fn signature_cache_keeps_issuer_and_self_signed_domains_separate() {
        let handler = Arc::new(TestHandler::new(true, false));
        let protocol = test_protocol(handler.clone(), true).await;
        let value = b"same bytes under different trust roots";
        let ordinary_key = [8; ID_LEN];
        let status_key = digest(STATUS_LIST_KEY);

        assert!(protocol.verify_for_key(&ordinary_key, value).await);
        assert!(
            !protocol.verify_for_key(&status_key, value).await,
            "a self-signed cache entry must not authorize issuer verification"
        );
        assert_eq!(handler.self_signed_calls.load(Ordering::Relaxed), 1);
        assert_eq!(handler.issuer_signed_calls.load(Ordering::Relaxed), 1);

        let self_key = SignatureCache::compute_key(VerificationDomain::SelfSigned, value);
        let issuer_key = SignatureCache::compute_key(VerificationDomain::IssuerSigned, value);
        assert_ne!(self_key, issuer_key);
    }

    #[tokio::test]
    async fn invalid_verifications_are_cached() {
        let handler = Arc::new(TestHandler::new(false, false));
        let protocol = test_protocol(handler.clone(), true).await;
        let key = [13; ID_LEN];
        let value = b"repeatable invalid record";

        assert!(!protocol.verify_for_key(&key, value).await);
        assert!(!protocol.verify_for_key(&key, value).await);
        assert_eq!(handler.self_signed_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn signature_cache_cannot_bypass_key_binding() {
        let handler = Arc::new(TestHandler::new(true, true).with_key_binding_result(false));
        let protocol = test_protocol(handler.clone(), true).await;
        let key = [18; ID_LEN];
        let value = b"valid record for another key";

        assert!(!protocol.verify_for_key(&key, value).await);
        assert!(!protocol.verify_for_key(&key, value).await);
        assert_eq!(handler.key_binding_calls.load(Ordering::Relaxed), 2);
        assert_eq!(handler.self_signed_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn rpc_find_value_does_not_serve_a_record_bound_to_a_different_key() {
        let key = [19; ID_LEN];
        let storage = Arc::new(ForgetfulStorage::new(-1));
        storage.set(key.to_vec(), b"record for another DID".to_vec());
        let handler = Arc::new(TestHandler::new(true, true).with_key_binding_result(false));
        let protocol = test_protocol_with_storage(handler.clone(), false, storage).await;

        let response = protocol
            .rpc_find_value([20; ID_LEN], ("127.0.0.1".into(), 9015), key)
            .await;

        assert!(matches!(response, FindValueResult::Nodes(_)));
        assert_eq!(handler.key_binding_calls.load(Ordering::Relaxed), 1);
        assert_eq!(handler.self_signed_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn response_from_an_unexpected_endpoint_is_ignored() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let expected_peer: SocketAddr = "127.0.0.1:9200".parse().unwrap();
        let unexpected_peer: SocketAddr = "127.0.0.1:9201".parse().unwrap();
        let (tx, mut rx) = oneshot::channel();
        protocol.pending.lock().await.insert(
            42,
            PendingCall::new(expected_peer, ExpectedResponse::StoreResult, tx),
        );

        let encode_response = || {
            let frame = Frame {
                msg_id: 42,
                is_request: false,
                message: RpcMessage::StoreResult {
                    status: StoreStatus::Stored,
                },
            };
            encode_fragments(1, &bincode::serialize(&frame).unwrap())
                .into_iter()
                .next()
                .unwrap()
        };

        protocol
            .handle_datagram(encode_response(), unexpected_peer)
            .await;
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(protocol.pending.lock().await.contains_key(&42));

        protocol
            .handle_datagram(encode_response(), expected_peer)
            .await;
        assert!(matches!(
            rx.await,
            Ok(RpcMessage::StoreResult {
                status: StoreStatus::Stored
            })
        ));
    }

    #[tokio::test]
    async fn pong_from_unexpected_endpoint_does_not_update_routing_table() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let expected_peer: SocketAddr = "127.0.0.1:9210".parse().unwrap();
        let unexpected_peer: SocketAddr = "127.0.0.1:9211".parse().unwrap();
        let expected_id = [10; ID_LEN];
        let unexpected_id = [11; ID_LEN];
        let (tx, mut rx) = oneshot::channel();
        protocol.pending.lock().await.insert(
            43,
            PendingCall::new(expected_peer, ExpectedResponse::Pong, tx),
        );

        let encode_pong = |sender_id| {
            let frame = Frame {
                msg_id: 43,
                is_request: false,
                message: RpcMessage::Pong { sender_id },
            };
            encode_fragments(1, &bincode::serialize(&frame).unwrap())
                .into_iter()
                .next()
                .unwrap()
        };

        protocol
            .handle_datagram(encode_pong(unexpected_id), unexpected_peer)
            .await;
        let unexpected_added = timeout(Duration::from_millis(50), async {
            loop {
                if protocol
                    .router
                    .read()
                    .await
                    .get_contact(&unexpected_id)
                    .is_some()
                {
                    break true;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            !unexpected_added,
            "an unexpected Pong must not update the routing table"
        );
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(protocol.pending.lock().await.contains_key(&43));

        protocol
            .handle_datagram(encode_pong(expected_id), expected_peer)
            .await;
        assert!(matches!(rx.await, Ok(RpcMessage::Pong { sender_id }) if sender_id == expected_id));
        timeout(Duration::from_millis(250), async {
            loop {
                if protocol
                    .router
                    .read()
                    .await
                    .get_contact(&expected_id)
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a valid Pong from the expected endpoint should refresh routing");
    }

    #[tokio::test]
    async fn pong_for_pending_store_response_does_not_update_routing_table() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let expected_peer: SocketAddr = "127.0.0.1:9220".parse().unwrap();
        let pong_id = [12; ID_LEN];
        let (tx, mut rx) = oneshot::channel();
        protocol.pending.lock().await.insert(
            44,
            PendingCall::new(expected_peer, ExpectedResponse::StoreResult, tx),
        );

        let encode_response = |message| {
            let frame = Frame {
                msg_id: 44,
                is_request: false,
                message,
            };
            encode_fragments(1, &bincode::serialize(&frame).unwrap())
                .into_iter()
                .next()
                .unwrap()
        };

        protocol
            .handle_datagram(
                encode_response(RpcMessage::Pong { sender_id: pong_id }),
                expected_peer,
            )
            .await;
        let pong_added = timeout(Duration::from_millis(50), async {
            loop {
                if protocol.router.read().await.get_contact(&pong_id).is_some() {
                    break true;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            !pong_added,
            "a Pong must not update routing for a non-Ping pending RPC"
        );
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(protocol.pending.lock().await.contains_key(&44));

        protocol
            .handle_datagram(
                encode_response(RpcMessage::StoreResult {
                    status: StoreStatus::Stored,
                }),
                expected_peer,
            )
            .await;
        assert!(matches!(
            rx.await,
            Ok(RpcMessage::StoreResult {
                status: StoreStatus::Stored
            })
        ));
    }

    #[tokio::test]
    async fn leave_requires_the_registered_endpoint() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let contact = Node::new([9; ID_LEN], Some("127.0.0.1".into()), Some(9300));
        protocol.router.write().await.add_contact(contact.clone());

        protocol
            .rpc_leave(contact.id, ("127.0.0.1".into(), 9301))
            .await;
        assert!(protocol
            .router
            .read()
            .await
            .get_contact(&contact.id)
            .is_some());

        protocol
            .rpc_leave(contact.id, ("127.0.0.1".into(), 9300))
            .await;
        assert!(protocol
            .router
            .read()
            .await
            .get_contact(&contact.id)
            .is_none());
    }

    #[tokio::test]
    async fn oversized_fragment_never_enters_reassembly() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let peer: SocketAddr = "127.0.0.1:9600".parse().unwrap();
        let mut fragment = encode_fragments(100, &vec![0; FRAG_CHUNK_SIZE + 1])
            .into_iter()
            .next()
            .unwrap();
        fragment.push(0);

        protocol.handle_datagram(fragment, peer).await;
        assert!(protocol.reassembly.lock().await.is_empty());
    }

    #[tokio::test]
    async fn reassembly_limits_entries_and_discards_inconsistent_totals() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let incomplete = encode_fragments(0, &vec![0; FRAG_CHUNK_SIZE + 1]);
        for port in 9400..(9400 + MAX_REASSEMBLY_ENTRIES as u16 + 1) {
            let peer: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            protocol.handle_datagram(incomplete[0].clone(), peer).await;
        }
        assert_eq!(
            protocol.reassembly.lock().await.len(),
            MAX_REASSEMBLY_ENTRIES,
            "the global in-flight reassembly limit must be enforced"
        );

        let fresh_protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let peer: SocketAddr = "127.0.0.1:9500".parse().unwrap();
        let two_fragments = encode_fragments(99, &vec![0; FRAG_CHUNK_SIZE + 1]);
        let three_fragments = encode_fragments(99, &vec![0; FRAG_CHUNK_SIZE * 2 + 1]);
        fresh_protocol
            .handle_datagram(two_fragments[0].clone(), peer)
            .await;
        fresh_protocol
            .handle_datagram(three_fragments[0].clone(), peer)
            .await;
        assert!(
            fresh_protocol.reassembly.lock().await.is_empty(),
            "an inconsistent fragment total must not poison the reassembly slot"
        );
    }

    /// Key of the record used by the welcome tests. This node (`[1; ID_LEN]`)
    /// is at XOR distance 1 from it, closer than any `id_at_distance`.
    fn welcome_key() -> [u8; ID_LEN] {
        let mut key = [1; ID_LEN];
        key[ID_LEN - 1] = 0;
        key
    }

    fn id_at_distance(distance: u8) -> [u8; ID_LEN] {
        assert!(distance > 1);
        let mut id = welcome_key();
        id[ID_LEN - 1] = distance;
        id
    }

    /// A node that holds the record of `welcome_key`, serving.
    async fn node_with_record() -> Arc<KademliaProtocol> {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        protocol
            .storage
            .set(welcome_key().to_vec(), b"record".to_vec());
        serve(&protocol);
        protocol
    }

    /// A peer at `distance` from the key makes contact and is sent the record,
    /// which it never acknowledges: sending it records lasts until the RPC
    /// timeout.
    async fn start_slow_replication(protocol: &Arc<KademliaProtocol>, distance: u8) -> UdpSocket {
        let (peer, contact) = raw_peer(id_at_distance(distance)).await;
        let to = protocol.socket.local_addr().unwrap();
        send_raw(
            &peer,
            to,
            1,
            true,
            RpcMessage::Ping {
                sender_id: contact.id,
            },
        )
        .await;
        let (store, _) = read_frame_of_kind(&peer, true).await;
        assert!(matches!(store.message, RpcMessage::Store { .. }));
        peer
    }

    /// A peer at `distance` from the key pings `protocol` and gets its Pong.
    async fn meet(protocol: &Arc<KademliaProtocol>, distance: u8) -> (UdpSocket, Node) {
        let (peer, contact) = raw_peer(id_at_distance(distance)).await;
        let to = protocol.socket.local_addr().unwrap();
        send_raw(
            &peer,
            to,
            1,
            true,
            RpcMessage::Ping {
                sender_id: contact.id,
            },
        )
        .await;
        let (pong, _) = read_frame(&peer).await;
        assert!(matches!(pong.message, RpcMessage::Pong { .. }));
        (peer, contact)
    }

    /// Nodes that make contact while this node is sending records to another
    /// one all enter its routing table at once (Kademlia §2.2).
    #[tokio::test]
    async fn nodes_met_during_a_replication_enter_the_table_at_once() {
        let protocol = node_with_record().await;
        let _slow = start_slow_replication(&protocol, 0x40).await;

        let mut met = Vec::new();
        for distance in [0x10, 0x20, 0x30, 0x50] {
            met.push(meet(&protocol, distance).await);
        }

        let router = protocol.router.read().await;
        for (_, contact) in &met {
            assert!(
                router.get_contact(&contact.id).is_some(),
                "{} is not in the routing table",
                contact
            );
        }
    }

    /// A node met while this node is sending records to another one still
    /// receives the records it should hold, once that replication is over
    /// (Kademlia §2.5).
    #[tokio::test]
    async fn a_node_met_during_a_replication_still_receives_its_records() {
        let protocol = node_with_record().await;
        let _slow = start_slow_replication(&protocol, 0x40).await;

        // Closer to the key than the slow peer, so the record is due to it.
        let (peer, _) = meet(&protocol, 0x10).await;
        let store = loop {
            let (frame, _) = try_read_frame(&peer, RPC_TIMEOUT * 2)
                .await
                .expect("the record never arrived");
            if frame.is_request {
                break frame;
            }
        };
        match store.message {
            RpcMessage::Store { key, value, .. } => {
                assert_eq!(key, welcome_key());
                assert_eq!(value, b"record");
            }
            other => panic!("expected a Store, got {}", rpc_message_name(&other)),
        }
    }

    /// Nodes met while a replication is under way wait for their records in
    /// a queue, up to its bound; beyond it they are not queued.
    #[tokio::test]
    async fn nodes_met_in_a_flood_wait_in_a_bounded_queue() {
        let protocol = node_with_record().await;
        let _slow = start_slow_replication(&protocol, 0x40).await;

        let (flood, _) = raw_peer([0; ID_LEN]).await;
        let to = protocol.socket.local_addr().unwrap();
        for i in 0..(MAX_WELCOME_QUEUE + 50) as u32 {
            let mut id = [0xAA; ID_LEN];
            id[..4].copy_from_slice(&i.to_be_bytes());
            send_raw(&flood, to, i, true, RpcMessage::Ping { sender_id: id }).await;
            read_frame_of_kind(&flood, false).await;
        }

        // The slow replication is still under way: the queue is full.
        assert_eq!(protocol.welcome_in_flight.len(), MAX_WELCOME_QUEUE);
    }

    /// New nodes falling into a full bucket ping its oldest contact once at a
    /// time, not once each (Kademlia §2.2).
    #[tokio::test]
    async fn a_full_bucket_pings_its_oldest_contact_once_at_a_time() {
        // k = 1: one contact fills the bucket away from this node's id.
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let protocol = Arc::new(KademliaProtocol::new(
            Node::from_id([1; ID_LEN]),
            socket,
            Arc::new(ForgetfulStorage::new(-1)),
            1,
            3,
            Arc::new(TestHandler::new(true, true)),
            None,
        ));
        serve(&protocol);
        let (oldest, contact) = raw_peer([0xF0; ID_LEN]).await;
        protocol.router.write().await.add_contact(contact);

        let (newcomers, _) = raw_peer([0; ID_LEN]).await;
        let to = protocol.socket.local_addr().unwrap();
        for i in 1..=10u8 {
            let mut id = [0xF0; ID_LEN];
            id[ID_LEN - 1] = i;
            send_raw(
                &newcomers,
                to,
                i as u32,
                true,
                RpcMessage::Ping { sender_id: id },
            )
            .await;
            let (pong, _) = read_frame_of_kind(&newcomers, false).await;
            assert!(matches!(pong.message, RpcMessage::Pong { .. }));
        }

        let mut pings = HashSet::new();
        while let Some((frame, _)) = try_read_frame(&oldest, Duration::from_millis(1000)).await {
            if matches!(frame.message, RpcMessage::Ping { .. }) {
                pings.insert(frame.msg_id);
            }
        }
        assert_eq!(
            pings.len(),
            1,
            "the oldest contact was pinged {} times",
            pings.len()
        );
    }
}
