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
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use log;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::time::timeout;

use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{FindPayload, RawResponse, SpiderProtocol};
use crate::fragmentation::{
    encode_fragments, parse_fragment, ReassemblyEntry, ReassemblyMap, FRAG_CHUNK_SIZE,
    MAX_MESSAGE_SIZE, REASSEMBLY_TTL,
};
use crate::node::Node;
use crate::routing::RoutingTable;
use crate::signature_cache::SignatureCache;
use crate::storage::{ForgetfulStorage, IStorage};
use crate::utils::{digest, STATUS_LIST_KEY, ID_LEN};

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

type PendingMap = Arc<Mutex<HashMap<u32, oneshot::Sender<RpcMessage>>>>;

const INVALID_SIG_BAN_THRESHOLD: u32 = 3;

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
    pending: PendingMap,
    next_msg_id: AtomicU32,
    next_frag_id: AtomicU32,
    reassembly: ReassemblyMap,
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
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_msg_id: AtomicU32::new(0),
            next_frag_id: AtomicU32::new(0),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn next_id(&self) -> u32 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_frag_id_val(&self) -> u32 {
        self.next_frag_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Drop reassembly buffers older than `REASSEMBLY_TTL`. Called opportunistically
    /// to bound memory usage in the face of lost fragments.
    async fn gc_reassembly(&self) {
        let now = Instant::now();
        let mut map = self.reassembly.lock().await;
        map.retain(|_, entry| now.duration_since(entry.created_at) < REASSEMBLY_TTL);
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

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(msg_id, tx);

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

            let key = (peer, header.frag_id);
            let mut map = self.reassembly.lock().await;

            // Scope releases the `map` &mut borrow before `map.remove()` below.
            let complete = {
                let entry = map
                    .entry(key)
                    .or_insert_with(|| ReassemblyEntry::new(header.total));

                if entry.total != header.total {
                    log::warn!(
                        "Inconsistent total for frag_id={} from {} (got {}, expected {})",
                        header.frag_id,
                        peer,
                        header.total,
                        entry.total
                    );
                    return;
                }
                entry.insert(header.index, chunk.to_vec())
            };

            if !complete {
                drop(map);
                self.gc_reassembly().await;
                return;
            }

            let entry = map.remove(&key).expect("entry checked above");
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
            if let RpcMessage::Pong { sender_id } = &frame.message {
                let source = Node::new(*sender_id, Some(peer.ip().to_string()), Some(peer.port()));
                let p = Arc::clone(self);
                tokio::spawn(async move { p.welcome_if_new(source).await });
            }
            if let Some(tx) = self.pending.lock().await.remove(&frame.msg_id) {
                let _ = tx.send(frame.message);
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
        let p = Arc::clone(self);
        tokio::spawn(async move { p.welcome_if_new(source).await });
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
                let p = Arc::clone(self);
                tokio::spawn(async move { p.welcome_if_new(source).await });
            }
            return false;
        }

        // Atomic insert: rejects duplicate keys without a TOCTOU race window.
        if !self.storage.insert_if_absent(key.to_vec(), value) {
            log::error!("rpc_store: record {} already exists", hex::encode(key));
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        let p = Arc::clone(self);
        tokio::spawn(async move { p.welcome_if_new(source).await });
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
        let p = Arc::clone(self);
        tokio::spawn(async move { p.welcome_if_new(source).await });
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
        let p = Arc::clone(self);
        tokio::spawn(async move { p.welcome_if_new(source).await });
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
        let p = Arc::clone(self);
        tokio::spawn(async move { p.welcome_if_new(source).await });
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
        let p = Arc::clone(self);
        let src_clone = source.clone();
        tokio::spawn(async move { p.welcome_if_new(src_clone).await });
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
        self.welcome_if_new(source.clone()).await;
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
        log::info!("Node {} is leaving the network", hex::encode(sender_id));
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.router.write().await.remove_contact(&source);
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
        let cache_key = self
            .sig_cache
            .as_ref()
            .map(|_| SignatureCache::compute_key(value));
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
        if result {
            if let (Some(cache), Some(ck)) = (&self.sig_cache, cache_key) {
                cache.insert_by_key(ck, result);
            }
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

        for (key, value) in keys_to_replicate {
            let p = Arc::clone(self);
            let n = node.clone();
            tokio::spawn(async move { p.call_store_rpc(&n, key, value).await });
        }
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
                let p = Arc::clone(&self);
                tokio::spawn(async move { p.welcome_if_new(peer).await });
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
                let p = Arc::clone(&self);
                tokio::spawn(async move { p.welcome_if_new(peer).await });
                RawResponse(true, FindPayload::Value(value))
            }
            Some(RpcMessage::FindValueNodes { nodes }) => {
                let p = Arc::clone(&self);
                tokio::spawn(async move { p.welcome_if_new(peer).await });
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
