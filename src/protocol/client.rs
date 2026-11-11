//! The requests this node sends: `call_*`, and the requests of the lookups
//! (`SpiderProtocol`, used by `crawling.rs`).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::crawling::{FindPayload, RawResponse, SpiderProtocol};
use crate::node::Node;
use crate::protocol::messages::{Frame, RpcMessage, StoreStatus, UpdateStatus, RECORD_HASH_LEN};
use crate::utils::ID_LEN;

use super::KademliaProtocol;

#[async_trait]
impl SpiderProtocol for KademliaProtocol {
    async fn call_find_node(self: Arc<Self>, peer: Node, target: Node) -> RawResponse {
        let Some(sock_addr) = socket_addr_of(&peer) else {
            return RawResponse(false, FindPayload::Empty);
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

impl KademliaProtocol {
    pub async fn call_ping_addr(&self, addr: &(String, u16)) -> (bool, Vec<u8>) {
        let Some(sock_addr) = socket_addr(addr) else {
            return (false, vec![]);
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
        let sock_addr = socket_addr_of(peer)?;
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

    /// Whether `peer` holds `value` after an UPDATE: it applied it, or held it.
    pub async fn call_update_rpc(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
        matches!(
            self.call_update_rpc_answer(peer, key, value).await,
            Some(UpdateStatus::Updated | UpdateStatus::AlreadyStored)
        )
    }

    /// The answer of `peer` to an UPDATE, or `None` when it gave none.
    pub async fn call_update_rpc_answer(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Option<UpdateStatus> {
        let sock_addr = socket_addr_of(peer)?;
        match self
            .call(
                sock_addr,
                RpcMessage::Update {
                    sender_id: self.source_node.id,
                    key,
                    value,
                },
            )
            .await
        {
            Some(RpcMessage::UpdateResult { status }) => {
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

    pub async fn call_status_list_update_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        let Some(sock_addr) = socket_addr_of(peer) else {
            return false;
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
        let Some(sock_addr) = socket_addr_of(peer) else {
            return;
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

    /// Ask `peer` whether it holds a record for `target`, receiving its
    /// version and SHA-256 (`FindHash`) instead of the record. A hit is
    /// returned as `FindPayload::Value` holding both (`hash_hit_bytes`).
    pub(crate) async fn call_find_hash(self: Arc<Self>, peer: Node, target: Node) -> RawResponse {
        let request = RpcMessage::FindHash {
            sender_id: self.source_node.id,
            key: target.id,
        };
        self.call_find(peer, request).await
    }

    /// Send a `FindValue` or `FindHash` request and translate the answer.
    async fn call_find(self: Arc<Self>, peer: Node, request: RpcMessage) -> RawResponse {
        let Some(sock_addr) = socket_addr_of(&peer) else {
            return RawResponse(false, FindPayload::Empty);
        };
        match self.call(sock_addr, request).await {
            Some(RpcMessage::FindValueHit { value }) => {
                self.schedule_welcome_if_new(peer).await;
                RawResponse(true, FindPayload::Value(value))
            }
            Some(RpcMessage::FindHashHit { seq, hash }) => {
                self.schedule_welcome_if_new(peer).await;
                RawResponse(true, FindPayload::Value(hash_hit_bytes(seq, &hash)))
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

/// A `FindHashHit` as a lookup carries it: the version, 8 bytes big-endian,
/// then the SHA-256 of the record.
pub(crate) fn hash_hit_bytes(seq: u64, hash: &[u8; RECORD_HASH_LEN]) -> Vec<u8> {
    let mut bytes = seq.to_be_bytes().to_vec();
    bytes.extend_from_slice(hash);
    bytes
}

/// The version and hash of a `FindHashHit`, from `hash_hit_bytes`.
pub(crate) fn parse_hash_hit(bytes: &[u8]) -> Option<(u64, [u8; RECORD_HASH_LEN])> {
    let (seq, hash) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*seq), hash.try_into().ok()?))
}

/// The socket address of `addr`. `None` if its IP does not parse.
fn socket_addr(addr: &(String, u16)) -> Option<SocketAddr> {
    format!("{}:{}", addr.0, addr.1).parse().ok()
}

/// The socket address of `peer`. `None` for a node without an address (a
/// target in the key space), or one whose IP does not parse.
fn socket_addr_of(peer: &Node) -> Option<SocketAddr> {
    socket_addr(&peer.address()?)
}
