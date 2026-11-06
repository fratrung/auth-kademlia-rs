//! What a node does with each request, except STORE.
//!
//! `dispatch_request` routes a request to its handler. STORE has its own file,
//! `store_check.rs`, because an empty replica checks the network first. The
//! verification of a record for a key is here, used by both.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::node::Node;
use crate::protocol::messages::{record_hash, RpcMessage, WireNode};
use crate::signature_cache::{SignatureCache, VerificationDomain};
use crate::storage::{IStorage, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::KademliaProtocol;

pub enum FindValueResult {
    Nodes(Vec<Node>),
    Value(Vec<u8>),
}

impl KademliaProtocol {
    pub(super) async fn dispatch_request(
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

    /// Verify `value` for `key`, using the signature cache to skip redundant
    /// PQ crypto on repeated calls with the same record bytes.
    pub(super) async fn verify_for_key(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
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

    pub(super) fn key_binding_is_valid(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
        *key == digest(STATUS_LIST_KEY)
            || self
                .signature_handler
                .handle_key_binding_verification(key, value)
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use crate::fragmentation::FRAG_CHUNK_SIZE;
    use crate::protocol::messages::{record_hash, Frame, RpcMessage};
    use crate::protocol::test_support::*;
    use crate::signature_cache::VerificationDomain;
    use crate::storage::ForgetfulStorage;

    use super::*;

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
}
