//! What a node does with each request, except STORE.
//!
//! `dispatch_request` routes a request to its handler. STORE has its own file,
//! `store_check.rs`, because an empty replica checks the network first. The
//! verification of a record for a key is here, used by both.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth_handler::rules::Conflict;
use crate::auth_handler::tree::tree_form;
use crate::auth_handler::{is_bound_to_key, verify_issuer_signed, verify_record};
use crate::node::Node;
use crate::protocol::messages::{record_hash, RpcMessage, WireNode};
use crate::storage::{IStorage, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::KademliaProtocol;

pub enum FindValueResult {
    Nodes(Vec<Node>),
    Value(Vec<u8>),
}

/// Log a valid record refused at the position of the stored one, with both
/// hashes for diagnosis. Two documents signed by one key at one position is
/// proven duplicity; the same document signed again is only a repeated
/// signing.
pub(super) fn log_conflict(
    key: &[u8; ID_LEN],
    kind: Conflict,
    stored: Option<&[u8]>,
    incoming: &[u8],
) {
    let (stored_hash, incoming_hash) = (
        stored
            .map(|s| hex::encode(record_hash(s)))
            .unwrap_or_default(),
        hex::encode(record_hash(incoming)),
    );
    match kind {
        Conflict::RepeatedSigning => log::info!(
            "{}: the same document signed again (stored {stored_hash}, sent {incoming_hash})",
            hex::encode(key)
        ),
        Conflict::Duplicity => log::warn!(
            "{}: proven duplicity, two documents at one position signed by its key (stored {stored_hash}, sent {incoming_hash})",
            hex::encode(key)
        ),
    }
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
                Some(self.rpc_find_hash(sender_id, sender_addr, key).await)
            }
            RpcMessage::ListKeys { sender_id, after } => {
                self.rpc_list_keys(sender_id, sender_addr, after).await
            }
            RpcMessage::Leave { sender_id } => {
                self.rpc_leave(sender_id, sender_addr).await;
                None
            }
            RpcMessage::Pong { .. }
            | RpcMessage::StoreResult { .. }
            | RpcMessage::UpdateStatusListResult { .. }
            | RpcMessage::FindNodeResult { .. }
            | RpcMessage::FindValueNodes { .. }
            | RpcMessage::FindValueHit { .. }
            | RpcMessage::FindHashHit { .. }
            | RpcMessage::Received
            | RpcMessage::KeyList { .. } => {
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
        let ok = verify_issuer_signed(&self.signature_handler, &value).await;
        if !ok {
            log::error!("rpc_update_status_list: unauthenticated update");
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source).await;
        if matches!(
            self.storage.set(key.to_vec(), value),
            StorageWriteStatus::CapacityExceeded | StorageWriteStatus::WriteFailed
        ) {
            log::warn!(
                "rpc_update_status_list: the list of {} was not stored",
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

    /// Answer `FindHash`: the position and SHA-256 of the record held for
    /// `key` (`FindHashHit`), or else the nodes closest to it, as
    /// `rpc_find_value` chooses them.
    async fn rpc_find_hash(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> RpcMessage {
        let found = self.rpc_find_value(sender_id, sender_addr, key).await;
        #[cfg(feature = "testbed")]
        match self.lie() {
            super::Lie::Honest => {}
            super::Lie::LaterVersion => {
                return RpcMessage::FindHashHit {
                    seq: crate::auth_handler::did::MAX_INTEGER,
                    hash: rand::random(),
                };
            }
            super::Lie::OtherVersionZero => {
                return RpcMessage::FindHashHit {
                    seq: 0,
                    hash: rand::random(),
                };
            }
        }
        match found {
            // The Status List has no position: it answers 0.
            FindValueResult::Value(v) => RpcMessage::FindHashHit {
                seq: tree_form(&key, &v).map_or(0, |form| form.seq),
                hash: record_hash(&v),
            },
            FindValueResult::Nodes(ns) => RpcMessage::FindValueNodes {
                nodes: ns.iter().map(WireNode::from).collect(),
            },
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

    /// Verify `value` for `key` (`auth_handler::verify_record`).
    pub(super) async fn verify_for_key(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
        verify_record(
            &self.signature_handler,
            self.sig_cache.as_deref(),
            key,
            value,
        )
        .await
    }

    /// Whether `value` belongs to `key` (`auth_handler::is_bound_to_key`).
    pub(super) fn key_binding_is_valid(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
        is_bound_to_key(self.signature_handler.as_ref(), key, value)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use crate::fragmentation::FRAG_CHUNK_SIZE;
    use crate::protocol::messages::{record_hash, Frame, RpcMessage};
    use crate::protocol::test_support::*;
    use crate::signature_cache::{SignatureCache, VerificationDomain};
    use crate::storage::ForgetfulStorage;

    use super::*;

    /// The testbed switch: a lying node claims a position far ahead, or
    /// position 0, for a key it does not hold, and answers honestly again
    /// once it is switched off.
    #[cfg(feature = "testbed")]
    #[tokio::test]
    async fn a_lying_node_claims_a_version_for_any_key() {
        use super::super::Lie;
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let ask = || protocol.rpc_find_hash([2; ID_LEN], ("127.0.0.1".into(), 9000), [7; ID_LEN]);

        assert!(matches!(ask().await, RpcMessage::FindValueNodes { .. }));
        protocol.set_lying(Lie::LaterVersion);
        assert!(matches!(
            ask().await,
            RpcMessage::FindHashHit { seq, .. } if seq == crate::auth_handler::did::MAX_INTEGER
        ));
        protocol.set_lying(Lie::OtherVersionZero);
        assert!(matches!(
            ask().await,
            RpcMessage::FindHashHit { seq: 0, .. }
        ));
        protocol.set_lying(Lie::Honest);
        assert!(matches!(ask().await, RpcMessage::FindValueNodes { .. }));
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
        let Some(RpcMessage::FindHashHit { seq, hash }) = answer else {
            panic!("expected the record's hash, got {answer:?}");
        };
        assert_eq!(hash, record_hash(&record));
        let frame = Frame {
            msg_id: 1,
            is_request: false,
            message: RpcMessage::FindHashHit { seq, hash },
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

    /// A higher position that does not fit the storage budget leaves the
    /// stored record in place.
    #[tokio::test]
    async fn a_higher_position_beyond_the_budget_leaves_the_stored_one() {
        use crate::auth_handler::test_tree::{body, TreeOwner, PLACEHOLDER};
        let owner = TreeOwner::new(1);
        let v3 = owner.record(3, Some(b"2"));
        let mut larger = body(PLACEHOLDER, owner.keys[5].public_key(), 5, Some(&v3));
        larger["alsoKnownAs"] = serde_json::json!(["https://example.com/a-longer-document"]);
        let v5 = owner.record_from(&larger, 5);
        assert!(v5.len() > v3.len());
        let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
            -1,
            ID_LEN + v3.len(),
        ));
        assert_eq!(
            storage.set(owner.key.to_vec(), v3.clone()),
            StorageWriteStatus::Stored
        );
        let protocol =
            test_protocol_with_storage(Arc::new(TestHandler::new(true, true)), false, storage)
                .await;
        let status = protocol
            .rpc_store([4; ID_LEN], ("127.0.0.1".to_string(), 9012), owner.key, v5)
            .await;
        assert_eq!(status, Some(crate::protocol::StoreStatus::CapacityExceeded));
        assert_eq!(protocol.storage.get(&owner.key), Some(v3));
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
