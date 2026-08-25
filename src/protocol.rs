/// Kademlia protocol layer with a real UDP transport.
///
/// `KademliaProtocol` owns the UDP socket, serialises/deserialises messages
/// with `bincode`, dispatches incoming RPCs to the appropriate handler, and
/// exposes `call_*` methods for sending outbound RPCs to remote peers.
///
/// Message framing: every datagram is a `bincode`-encoded `(u32 msg_id, RpcEnvelope)`.
/// Responses are correlated by `msg_id` via a `PendingMap`.
///
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use log;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, RwLock, Semaphore};
use tokio::time::timeout;

use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{FindPayload, RawResponse, SpiderProtocol};
use crate::fragmentation::{
    encode_fragments, parse_fragment, ReassemblyEntry, ReassemblyMap, FRAG_CHUNK_SIZE,
    MAX_MESSAGE_SIZE, MAX_REASSEMBLY_ENTRIES, MAX_REASSEMBLY_ENTRIES_PER_PEER,
    REASSEMBLY_GC_INTERVAL, REASSEMBLY_TTL,
};
use crate::node::Node;
use crate::routing::RoutingTable;
use crate::signature_cache::{SignatureCache, VerificationDomain};
use crate::storage::{ForgetfulStorage, IStorage};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

/// Timeout for a single RPC call.
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

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
        ok: bool,
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
    Delete {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    },
    DeleteResult {
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
    DeleteResult,
    FindNodeResult,
    FindValueResult,
    NoResponse,
}

impl ExpectedResponse {
    fn for_request(message: &RpcMessage) -> Self {
        match message {
            RpcMessage::Ping { .. } => Self::Pong,
            RpcMessage::Store { .. } => Self::StoreResult,
            RpcMessage::Update { .. } => Self::UpdateResult,
            RpcMessage::UpdateStatusList { .. } => Self::UpdateStatusListResult,
            RpcMessage::Delete { .. } => Self::DeleteResult,
            RpcMessage::FindNode { .. } => Self::FindNodeResult,
            RpcMessage::FindValue { .. } => Self::FindValueResult,
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
            Self::DeleteResult => matches!(message, RpcMessage::DeleteResult { .. }),
            Self::FindNodeResult => matches!(message, RpcMessage::FindNodeResult { .. }),
            Self::FindValueResult => matches!(
                message,
                RpcMessage::FindValueHit { .. } | RpcMessage::FindValueNodes { .. }
            ),
            Self::NoResponse => false,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pong => "Pong",
            Self::StoreResult => "StoreResult",
            Self::UpdateResult => "UpdateResult",
            Self::UpdateStatusListResult => "UpdateStatusListResult",
            Self::DeleteResult => "DeleteResult",
            Self::FindNodeResult => "FindNodeResult",
            Self::FindValueResult => "FindValueHit|FindValueNodes",
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
        RpcMessage::Delete { .. } => "Delete",
        RpcMessage::DeleteResult { .. } => "DeleteResult",
        RpcMessage::FindNode { .. } => "FindNode",
        RpcMessage::FindNodeResult { .. } => "FindNodeResult",
        RpcMessage::FindValue { .. } => "FindValue",
        RpcMessage::FindValueHit { .. } => "FindValueHit",
        RpcMessage::FindValueNodes { .. } => "FindValueNodes",
        RpcMessage::Leave { .. } => "Leave",
    }
}

type PendingMap =
    Arc<Mutex<HashMap<u32, (SocketAddr, ExpectedResponse, oneshot::Sender<RpcMessage>)>>>;

const INVALID_SIG_BAN_THRESHOLD: u32 = 3;
const WELCOME_CONCURRENCY: usize = 1;
const REPLICATION_CONCURRENCY: usize = 4;

pub struct KademliaProtocol {
    pub router: Arc<RwLock<RoutingTable>>,
    pub storage: Arc<ForgetfulStorage>,
    pub source_node: Node,
    pub socket: Arc<UdpSocket>,
    pub signature_handler: Arc<dyn SignatureVerifierHandler>,
    /// Shared with `Server` so a verification result cached in one layer is
    /// immediately reused by the other. `None` when the cache is disabled.
    sig_cache: Option<Arc<SignatureCache>>,
    /// Counts invalid-signature Store attempts per sender. A peer is removed
    /// from the routing table once it reaches INVALID_SIG_BAN_THRESHOLD.
    invalid_sig_strikes: DashMap<[u8; ID_LEN], u32>,
    /// Peer IDs already scheduled for discovery and replica evaluation.
    welcome_in_flight: DashMap<[u8; ID_LEN], ()>,
    /// Bounds whole-storage scans caused by newly discovered peers.
    welcome_permits: Arc<Semaphore>,
    pending: PendingMap,
    next_msg_id: AtomicU32,
    next_frag_id: AtomicU32,
    reassembly: ReassemblyMap,
    last_reassembly_gc: Mutex<Instant>,
}

impl KademliaProtocol {
    pub fn new(
        source_node: Node,
        socket: Arc<UdpSocket>,
        storage: Arc<ForgetfulStorage>,
        ksize: usize,
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
            sig_cache,
            invalid_sig_strikes: DashMap::new(),
            welcome_in_flight: DashMap::new(),
            welcome_permits: Arc::new(Semaphore::new(WELCOME_CONCURRENCY)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_msg_id: AtomicU32::new(0),
            next_frag_id: AtomicU32::new(0),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
            last_reassembly_gc: Mutex::new(Instant::now()),
        }
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

    /// Schedule the expensive new-peer work without blocking an RPC handler.
    /// Duplicate discoveries coalesce by node ID, and capacity is deliberately
    /// bounded because each accepted peer may require a full storage scan.
    async fn schedule_welcome_if_new(self: &Arc<Self>, node: Node) {
        if !self.router.read().await.is_new_node(&node) {
            return;
        }
        if self.welcome_in_flight.insert(node.id, ()).is_some() {
            return;
        }

        let permit = match Arc::clone(&self.welcome_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.welcome_in_flight.remove(&node.id);
                log::debug!(
                    "Discovery capacity exhausted for {}; it will be retried on a later RPC",
                    node
                );
                return;
            }
        };

        let p = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            p.welcome_if_new(node.clone()).await;
            p.welcome_in_flight.remove(&node.id);
        });
    }

    /// Serialize, fragment, and send a frame to `addr`. Returns false if any
    /// fragment fails to be transmitted.
    async fn send_frame(&self, addr: SocketAddr, frame: &Frame) -> bool {
        let bytes = match bincode::serialize(frame) {
            Ok(b) => b,
            Err(e) => {
                log::error!("Serialization error: {}", e);
                return false;
            }
        };

        if bytes.len() > MAX_MESSAGE_SIZE {
            log::error!(
                "Refusing to send {} byte message (limit {})",
                bytes.len(),
                MAX_MESSAGE_SIZE
            );
            return false;
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

        for dg in &datagrams {
            if let Err(e) = self.socket.send_to(dg, addr).await {
                log::warn!("UDP send to {} failed: {}", addr, e);
                return false;
            }
        }
        true
    }

    /// Send an RPC request to `addr` and wait for the matching response.
    async fn call(&self, addr: SocketAddr, message: RpcMessage) -> Option<RpcMessage> {
        let msg_id = self.next_id();
        let frame = Frame {
            msg_id,
            is_request: true,
            message,
        };

        let expected_response = ExpectedResponse::for_request(&frame.message);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(msg_id, (addr, expected_response, tx));

        if !self.send_frame(addr, &frame).await {
            self.pending.lock().await.remove(&msg_id);
            return None;
        }

        match timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(response)) => Some(response),
            Ok(Err(_)) => {
                log::debug!("Response channel closed for msg_id={}", msg_id);
                self.pending.lock().await.remove(&msg_id);
                None
            }
            Err(_) => {
                log::debug!("RPC timeout for msg_id={}", msg_id);
                self.pending.lock().await.remove(&msg_id);
                None
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
            let tx = {
                let mut pending = self.pending.lock().await;
                match pending
                    .get(&frame.msg_id)
                    .map(|(expected_peer, expected_response, _)| {
                        (*expected_peer, *expected_response)
                    }) {
                    Some((expected_peer, expected_response))
                        if expected_peer == peer && expected_response.accepts(&message) =>
                    {
                        pending.remove(&frame.msg_id).map(|(_, _, tx)| tx)
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

        let response = self.dispatch_request(frame.message, peer).await;
        if let Some(resp) = response {
            let resp_frame = Frame {
                msg_id: frame.msg_id,
                is_request: false,
                message: resp,
            };
            self.send_frame(peer, &resp_frame).await;
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
            } => {
                let ok = self.rpc_store(sender_id, sender_addr, key, value).await;
                Some(RpcMessage::StoreResult { ok })
            }
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
            RpcMessage::Delete {
                sender_id,
                key,
                auth_signature,
                delete_msg,
            } => {
                let ok = self
                    .rpc_delete(sender_id, sender_addr, key, auth_signature, delete_msg)
                    .await;
                Some(RpcMessage::DeleteResult { ok })
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

    pub async fn rpc_store(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        // Peer Ban Mechanism
        if !self.verify_for_key(&key, &value).await {
            let strikes = {
                let mut n = self.invalid_sig_strikes.entry(sender_id).or_insert(0);
                *n += 1;
                *n
            };
            let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
            if strikes >= INVALID_SIG_BAN_THRESHOLD {
                log::warn!(
                    "rpc_store: {} invalid-sig strikes from {} — removing from routing table",
                    strikes,
                    sender_addr.0
                );
                self.router.write().await.remove_contact(&source);
            } else {
                log::warn!(
                    "rpc_store: invalid signature for {} from {} (strike {}/{})",
                    hex::encode(key),
                    sender_addr.0,
                    strikes,
                    INVALID_SIG_BAN_THRESHOLD
                );
                self.schedule_welcome_if_new(source).await;
            }
            return false;
        }

        // Atomic insert: rejects duplicate keys without a TOCTOU race window.
        if !self.storage.insert_if_absent(key.to_vec(), value) {
            log::error!("rpc_store: record {} already exists", hex::encode(key));
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        true
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
        let handler = Arc::clone(&self.signature_handler);
        let v = value.clone();
        let ok = tokio::task::spawn_blocking(move || {
            handler
                .handle_update_verification(&v, &old_value, &auth_signature)
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if !ok {
            log::error!(
                "rpc_update: unauthenticated update for {}",
                hex::encode(key)
            );
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        self.storage.set(key.to_vec(), value);
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
        self.storage.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_delete(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        let value = match self.storage.get(&key) {
            Some(v) => v,
            None => {
                log::error!("rpc_delete: record {} not found", hex::encode(key));
                return false;
            }
        };
        let handler = Arc::clone(&self.signature_handler);
        let ok = tokio::task::spawn_blocking(move || {
            handler
                .handle_signature_delete_operation(&value, &auth_signature, &delete_msg)
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if !ok {
            log::error!("rpc_delete: invalid signature for {}", hex::encode(key));
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        self.storage.delete(&key);
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
            .find_neighbors(&target, Some(&source))
    }

    pub async fn rpc_find_value(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> FindValueResult {
        let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
        self.schedule_welcome_if_new(source.clone()).await;
        match self.storage.get(&key) {
            Some(v) => FindValueResult::Value(v),
            None => {
                let target = Node::from_id(key);
                let neighbors = self
                    .router
                    .read()
                    .await
                    .find_neighbors(&target, Some(&source));
                FindValueResult::Nodes(neighbors)
            }
        }
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

    pub async fn call_store_rpc(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
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
                RpcMessage::Store {
                    sender_id: self.source_node.id,
                    key,
                    value,
                },
            )
            .await
        {
            Some(RpcMessage::StoreResult { ok }) => ok,
            _ => {
                log::warn!("no response from {}, removing from router", peer);
                self.router.write().await.remove_contact(peer);
                false
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
                RpcMessage::Update {
                    sender_id: self.source_node.id,
                    key,
                    value,
                    auth_signature,
                },
            )
            .await
        {
            Some(RpcMessage::UpdateResult { ok }) => ok,
            _ => {
                log::warn!("no response from {}, removing from router", peer);
                self.router.write().await.remove_contact(peer);
                false
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
            Some(RpcMessage::UpdateStatusListResult { ok }) => ok,
            _ => {
                log::warn!("no response from {}, removing from router", peer);
                self.router.write().await.remove_contact(peer);
                false
            }
        }
    }

    pub async fn call_delete_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
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
                RpcMessage::Delete {
                    sender_id: self.source_node.id,
                    key,
                    auth_signature,
                    delete_msg,
                },
            )
            .await
        {
            Some(RpcMessage::DeleteResult { ok }) => ok,
            _ => {
                log::warn!("no response from {}, removing from router", peer);
                self.router.write().await.remove_contact(peer);
                false
            }
        }
    }

    pub async fn call_leave_rpc(&self, peer: &Node) {
        let addr = match peer.address() {
            Some(a) => a,
            None => return,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let _ = self
            .call(
                sock_addr,
                RpcMessage::Leave {
                    sender_id: self.source_node.id,
                },
            )
            .await;
    }

    /// Verify `value` for `key`, using the signature cache to skip redundant
    /// PQ crypto on repeated calls with the same record bytes.
    async fn verify_for_key(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
        let is_status = *key == digest(STATUS_LIST_KEY);
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

    /// Add `node` to the routing table and replicate keys that belong to it
    /// (Kademlia §2.5). Replication fires only when `new_node_close` AND
    /// `this_closest` are both true. Neighbors are sampled before `add_contact`
    /// to exclude the new node from distance comparisons.
    pub async fn welcome_if_new(self: &Arc<Self>, node: Node) {
        if !self.router.read().await.is_new_node(&node) {
            return;
        }
        log::info!("New node discovered: {}", node);

        let all_entries = self.storage.iter_all();
        let self_node = self.source_node.clone();

        let keys_to_replicate: Vec<([u8; ID_LEN], Vec<u8>)> = {
            let router = self.router.read().await;
            all_entries
                .into_iter()
                .filter_map(|(key_vec, value)| {
                    if key_vec.len() != ID_LEN {
                        return None;
                    }
                    let mut key = [0u8; ID_LEN];
                    key.copy_from_slice(&key_vec);
                    let key_node = Node::from_id(key);

                    let neighbors = router.find_neighbors(&key_node, None);

                    let new_node_close = match neighbors.last() {
                        Some(last) => node.distance_to(&key_node) < last.distance_to(&key_node),
                        None => true,
                    };
                    let this_closest = match neighbors.first() {
                        Some(first) => {
                            self_node.distance_to(&key_node) < first.distance_to(&key_node)
                        }
                        None => true,
                    };

                    if new_node_close && this_closest {
                        Some((key, value))
                    } else {
                        None
                    }
                })
                .collect()
        }; // router read lock released here

        let lru = self.router.write().await.add_contact(node.clone());
        if let Some(lru_node) = lru {
            let p = Arc::clone(self);
            tokio::spawn(async move { p.call_ping_node(&lru_node).await });
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
    /// On failure the node is removed and its replacement (if any) is promoted
    /// automatically by `remove_node`. On success the Pong response triggers
    /// `welcome_if_new` in `handle_datagram`, refreshing the routing table.
    pub async fn call_ping_node(self: &Arc<Self>, node: &Node) {
        let addr = match node.address() {
            Some(a) => a,
            None => return,
        };
        let (ok, _) = self.call_ping_addr(&addr).await;
        if !ok {
            log::warn!("LRU ping: no response from {}, evicting", node);
            self.router.write().await.remove_contact(node);
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
                log::warn!("no response from {}, removing from router", peer);
                self.router.write().await.remove_contact(&peer);
                RawResponse(false, FindPayload::Empty)
            }
        }
    }

    async fn call_find_value(self: Arc<Self>, peer: Node, target: Node) -> RawResponse {
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
                RpcMessage::FindValue {
                    sender_id: self.source_node.id,
                    key: target.id,
                },
            )
            .await
        {
            Some(RpcMessage::FindValueHit { value }) => {
                self.schedule_welcome_if_new(peer).await;
                RawResponse(true, FindPayload::Value(value))
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
                log::warn!("no response from {}, removing from router", peer);
                self.router.write().await.remove_contact(&peer);
                RawResponse(false, FindPayload::Empty)
            }
        }
    }

    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
        self.call_store_rpc(peer, key, value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::auth_handler::AuthHandlerError;
    use crate::signature_cache::VerificationDomain;

    struct TestHandler {
        self_signed_result: bool,
        issuer_signed_result: bool,
        self_signed_calls: AtomicUsize,
        issuer_signed_calls: AtomicUsize,
    }

    impl TestHandler {
        fn new(self_signed_result: bool, issuer_signed_result: bool) -> Self {
            Self {
                self_signed_result,
                issuer_signed_result,
                self_signed_calls: AtomicUsize::new(0),
                issuer_signed_calls: AtomicUsize::new(0),
            }
        }
    }

    impl SignatureVerifierHandler for TestHandler {
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

        fn handle_signature_delete_operation(
            &self,
            _value: &[u8],
            _auth_signature: &[u8],
            _delete_msg: &[u8],
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
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let storage = Arc::new(ForgetfulStorage::new(-1));
        Arc::new(KademliaProtocol::new(
            Node::from_id([1; ID_LEN]),
            socket,
            storage,
            20,
            handler,
            use_cache.then(|| Arc::new(SignatureCache::new(32))),
        ))
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
    async fn response_from_an_unexpected_endpoint_is_ignored() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let expected_peer: SocketAddr = "127.0.0.1:9200".parse().unwrap();
        let unexpected_peer: SocketAddr = "127.0.0.1:9201".parse().unwrap();
        let (tx, mut rx) = oneshot::channel();
        protocol
            .pending
            .lock()
            .await
            .insert(42, (expected_peer, ExpectedResponse::StoreResult, tx));

        let encode_response = || {
            let frame = Frame {
                msg_id: 42,
                is_request: false,
                message: RpcMessage::StoreResult { ok: true },
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
        assert!(matches!(rx.await, Ok(RpcMessage::StoreResult { ok: true })));
    }

    #[tokio::test]
    async fn pong_from_unexpected_endpoint_does_not_update_routing_table() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let expected_peer: SocketAddr = "127.0.0.1:9210".parse().unwrap();
        let unexpected_peer: SocketAddr = "127.0.0.1:9211".parse().unwrap();
        let expected_id = [10; ID_LEN];
        let unexpected_id = [11; ID_LEN];
        let (tx, mut rx) = oneshot::channel();
        protocol
            .pending
            .lock()
            .await
            .insert(43, (expected_peer, ExpectedResponse::Pong, tx));

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
        protocol
            .pending
            .lock()
            .await
            .insert(44, (expected_peer, ExpectedResponse::StoreResult, tx));

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
                encode_response(RpcMessage::StoreResult { ok: true }),
                expected_peer,
            )
            .await;
        assert!(matches!(rx.await, Ok(RpcMessage::StoreResult { ok: true })));
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
}
