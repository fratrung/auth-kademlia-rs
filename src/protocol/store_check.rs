//! STORE, and the network check of an empty replica.
//!
//! A replica that does not hold the key asks the nodes closest to it for the
//! hash of their record (`FindHash`) before storing (`DESIGN.md` section 7).
//! It refuses when a node holds another record or does not answer.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::counters::CheckEnd;
use crate::crawling::{ValueSearch, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::messages::{record_hash, StoreStatus};
use crate::storage::IStorage;
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::KademliaProtocol;

/// How long an empty replica asks the network about a record it was sent,
/// below `RPC_TIMEOUT` so that its answer reaches the sender in time.
const STORE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2000);

/// STOREs waiting for that lookup at once. Beyond this a STORE is dropped
/// without an answer, as an overloaded node drops datagrams.
pub(super) const MAX_STORE_LOOKUPS: usize = 256;

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
pub(super) struct StoreLookupSlot(Arc<AtomicUsize>);

impl StoreLookupSlot {
    pub(super) fn take(count: &Arc<AtomicUsize>) -> Option<Self> {
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

impl KademliaProtocol {
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
                self.counters.check(CheckEnd::Unbound, 0, Duration::ZERO);
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
    pub(super) fn store_needs_lookup(&self, key: &[u8; ID_LEN]) -> bool {
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
        let started = Instant::now();
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
            self.counters
                .check(CheckEnd::NobodyToAsk, 0, started.elapsed());
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
        let (copy, end) = match search {
            ValueSearch::Found(_) => (NetworkCopy::Other, CheckEnd::Other),
            ValueSearch::NotFound => (NetworkCopy::NoneOrSame, CheckEnd::NoneOrSame),
            ValueSearch::Incomplete => (NetworkCopy::Unknown, CheckEnd::NoAnswer),
        };
        self.counters.check(end, crawl.rounds(), started.elapsed());
        copy
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use tokio::net::UdpSocket;

    use crate::protocol::messages::{record_hash, RpcMessage, StoreStatus, WireNode};
    use crate::protocol::test_support::*;
    use crate::storage::ForgetfulStorage;

    use super::*;

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
        #[cfg(feature = "counters")]
        assert_eq!(protocol.counters().checks.nobody_to_ask, 1);
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
        #[cfg(feature = "counters")]
        assert_eq!(protocol.counters().checks.unbound, 1);
    }

    /// The counters of a STORE check: the question and its copy, sent to a
    /// peer never measured, the lookup's single round, and how it ended.
    #[cfg(feature = "counters")]
    #[tokio::test]
    async fn counters_record_a_store_check_and_its_resend() {
        use crate::fragmentation::encode_fragments;
        use crate::protocol::messages::Frame;

        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        serve(&protocol);
        let (peer, contact) = raw_peer([5; ID_LEN]).await;
        protocol.router.write().await.add_contact(contact);
        let replica = Arc::clone(&protocol);
        let store = tokio::spawn(async move {
            replica
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9020),
                    [7; ID_LEN],
                    b"one".to_vec(),
                )
                .await
        });

        let (lost, _) = read_frame_of_kind(&peer, true).await;
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

        let counters = protocol.counters();
        let find_hash = counters.sent["FindHash"];
        assert_eq!(find_hash.datagrams, 2);
        let question = Frame {
            msg_id: lost.msg_id,
            is_request: true,
            message: lost.message,
        };
        let one_copy = encode_fragments(0, &bincode::serialize(&question).unwrap())[0].len();
        assert_eq!(find_hash.bytes, 2 * one_copy as u64);
        assert_eq!(counters.sent.len(), 1, "{:?}", counters.sent);
        assert_eq!(counters.resends_to_unmeasured_peers, 1);
        assert_eq!(counters.resends_to_measured_peers, 0);
        assert_eq!(counters.checks.none_or_same, 1);
        assert_eq!(counters.checks.rounds, vec![1, 0, 0, 0, 0]);
        assert_eq!(counters.checks.duration_ms.iter().sum::<u64>(), 1);
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
}
