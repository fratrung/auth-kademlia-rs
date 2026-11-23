//! STORE, and the network check of a replica that holds nothing.
//!
//! A replica decides first with what it holds (`rules::decide_locally`). One
//! that holds nothing asks the nodes closest to the key for the position and
//! hash of their record (`FindHash`) and fetches the records claimed at a
//! higher position. It refuses as stale only on one it verifies, and stores
//! that one instead. Otherwise it stores the record it was sent, whether or
//! not every node answered: the record proves its own key, so the check only
//! looks for proof that it has been superseded, and a claim or a silence is
//! no such proof.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth_handler::rules::{
    claims_to_fetch, decide_locally, shows_higher, Answer, Held, Local,
};
use crate::counters::CheckEnd;
use crate::crawling::{RPCFindResponse, SpiderProtocol, ValueSearch, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::client::parse_hash_hit;
use crate::protocol::handlers::log_conflict;
use crate::protocol::messages::StoreStatus;
use crate::storage::{IStorage, ReplaceStatus, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::KademliaProtocol;

/// How long an empty replica checks the network for a record it was sent,
/// fetches included: below `RPC_TIMEOUT`, so that its answer reaches the
/// sender in time.
const STORE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2000);

/// STOREs waiting for that check at once. Beyond this a STORE is dropped
/// without an answer, as an overloaded node drops datagrams.
pub(super) const MAX_STORE_LOOKUPS: usize = 256;

/// One of the `MAX_STORE_LOOKUPS` places for a STORE waiting for a check,
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

/// What the network check found for a record sent to an empty replica.
enum CheckOutcome {
    /// Nobody showed a higher position: store the record.
    Store,
    /// A verified record at a higher position, to store instead.
    Superseded(Vec<u8>),
}

impl KademliaProtocol {
    /// Store a DID record, or the Status List under its own rule. `None`
    /// means no answer: the stored record changed twice while this one was
    /// decided, or emptied during the check. The sender then counts the
    /// replica as unavailable.
    pub async fn rpc_store(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Option<StoreStatus> {
        if key == digest(STATUS_LIST_KEY) {
            return self
                .store_status_list(sender_id, sender_addr, key, value)
                .await;
        }
        let mut asked_network = false;
        // Writes are compare-and-swap: when the stored record changes while
        // this one is decided, it is decided once more against the new one.
        for _ in 0..2 {
            let (stored, marker) = self.storage.record_or_marker(&key);
            let status = match decide_locally(&key, Held::of(stored.as_deref(), marker), &value) {
                Local::Invalid(error) => {
                    log::warn!(
                        "rpc_store: invalid record for {} from {}: {error}",
                        hex::encode(key),
                        sender_addr.0
                    );
                    if stored.is_none() {
                        self.counters
                            .check(CheckEnd::Invalid, 0, Duration::ZERO, false);
                    }
                    StoreStatus::InvalidRecord
                }
                // The same bytes refresh the expiry, so that republication
                // keeps a record alive. They were verified when stored.
                Local::AlreadyStored => {
                    match self.storage.replace_if(&key, &value, value.clone()) {
                        ReplaceStatus::Replaced => StoreStatus::AlreadyStored,
                        _ => continue,
                    }
                }
                Local::AskNetwork(form) => {
                    // A check never runs twice for one STORE.
                    if asked_network {
                        log::warn!(
                            "rpc_store: {} emptied while it was checked",
                            hex::encode(key)
                        );
                        return None;
                    }
                    asked_network = true;
                    match self.network_check(key, form.seq).await {
                        CheckOutcome::Superseded(newer) => {
                            log::info!(
                                "rpc_store: position {} of {} from {} is superseded",
                                form.seq,
                                hex::encode(key),
                                sender_addr.0
                            );
                            if self.storage.insert_if_absent(key.to_vec(), newer)
                                == StorageWriteStatus::Conflict
                            {
                                continue;
                            }
                            return Some(StoreStatus::Stale);
                        }
                        CheckOutcome::Store => {}
                    }
                    if !self.verify_for_key(&key, &value).await {
                        return Some(StoreStatus::InvalidRecord);
                    }
                    match self.storage.insert_if_absent(key.to_vec(), value.clone()) {
                        StorageWriteStatus::Stored => StoreStatus::Stored,
                        StorageWriteStatus::AlreadyStored => StoreStatus::AlreadyStored,
                        StorageWriteStatus::CapacityExceeded => StoreStatus::CapacityExceeded,
                        StorageWriteStatus::Conflict => continue,
                        StorageWriteStatus::WriteFailed => return None,
                    }
                }
                Local::VerifyAndReplace => {
                    if !self.verify_for_key(&key, &value).await {
                        return Some(StoreStatus::InvalidRecord);
                    }
                    let Some(expected) = stored else {
                        continue;
                    };
                    match self.storage.replace_if(&key, &expected, value.clone()) {
                        ReplaceStatus::Replaced => StoreStatus::Stored,
                        ReplaceStatus::CapacityExceeded => StoreStatus::CapacityExceeded,
                        ReplaceStatus::Changed => continue,
                        ReplaceStatus::WriteFailed => return None,
                    }
                }
                Local::Stale { .. } => StoreStatus::Stale,
                // The stored record stays. Only a valid second signature is
                // evidence of a conflict.
                Local::VerifyConflict(kind) => {
                    if !self.verify_for_key(&key, &value).await {
                        return Some(StoreStatus::InvalidRecord);
                    }
                    log_conflict(&key, kind, stored.as_deref(), &value);
                    StoreStatus::Conflict
                }
            };
            if matches!(status, StoreStatus::Stored | StoreStatus::AlreadyStored) {
                // The bytes are those of a verified record: the sender enters
                // the routing table, never after a refusal.
                let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
                self.schedule_welcome_if_new(source).await;
            }
            return Some(status);
        }
        log::warn!(
            "rpc_store: the record of {} changed twice, no answer",
            hex::encode(key)
        );
        None
    }

    /// The Status List: signed by the issuer, first writer wins.
    async fn store_status_list(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Option<StoreStatus> {
        if !self.verify_for_key(&key, &value).await {
            log::warn!("rpc_store: invalid status list from {}", sender_addr.0);
            return Some(StoreStatus::InvalidRecord);
        }
        let status = StoreStatus::of_write(self.storage.insert_if_absent(key.to_vec(), value))?;
        if matches!(status, StoreStatus::Stored | StoreStatus::AlreadyStored) {
            let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
            self.schedule_welcome_if_new(source).await;
        }
        Some(status)
    }

    /// A STORE for a DID this node does not hold, which runs the network
    /// check. The Status List has rules of its own.
    pub(super) fn store_needs_lookup(&self, key: &[u8; ID_LEN]) -> bool {
        *key != digest(STATUS_LIST_KEY) && self.storage.get(key).is_none()
    }

    /// Whether a record at `seq` for `key`, sent to this replica while it
    /// holds nothing, has been superseded. The lookup asks the nodes closest
    /// to the key for the position and SHA-256 of their record (`FindHash`),
    /// one datagram each instead of a whole record, and gives up after
    /// `STORE_LOOKUP_TIMEOUT`.
    async fn network_check(self: &Arc<Self>, key: [u8; ID_LEN], seq: u64) -> CheckOutcome {
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
        if nearest.is_empty() {
            self.counters
                .check(CheckEnd::NobodyToAsk, 0, started.elapsed(), false);
            return CheckOutcome::Store;
        }
        let deadline = tokio::time::Instant::now() + STORE_LOOKUP_TIMEOUT;
        let find_hash = |protocol: Arc<Self>, peer, target| protocol.call_find_hash(peer, target);
        let mut crawl = ValueSpiderCrawl::new(
            Arc::clone(self),
            target.clone(),
            nearest,
            self.ksize,
            self.alpha,
        );
        // A replica asks the nodes it knows at once, so that an answer full
        // of made-up nodes closer to the key cannot push a known holder out
        // of the lookup before it is asked. A node far from the key keeps
        // asking `alpha` at a time: the nodes it knows are replaced at each
        // hop, and asking all of them would ask k per hop.
        if among_closest {
            crawl = crawl.asking_everyone();
        }
        // Every answer is kept and none ends the lookup.
        let hits: Arc<Mutex<Vec<(Node, Answer)>>> = Arc::default();
        let collected = Arc::clone(&hits);
        let search = crawl
            .search(Some(deadline), find_hash, move |peer, payload| {
                if let Some((seq, hash)) = parse_hash_hit(&payload) {
                    if let Ok(mut hits) = collected.lock() {
                        hits.push((peer, Answer { seq, hash }));
                    }
                }
                async { None }
            })
            .await;
        let everyone_answered = search == ValueSearch::NotFound;
        let mut hits = hits.lock().map(|hits| hits.clone()).unwrap_or_default();
        hits.sort_by_key(|(peer, _)| peer.distance_to(&target));
        let (peers, answers): (Vec<Node>, Vec<Answer>) = hits.into_iter().unzip();

        // Only the k replicas hold the DID: the k - 1 others are enough.
        let claims = claims_to_fetch(seq, &answers, self.ksize.saturating_sub(1));
        let newer = if claims.is_empty() {
            None
        } else {
            self.fetch_higher(key, seq, &peers, &answers, &claims, deadline)
                .await
        };
        let end = match (&newer, everyone_answered) {
            (Some(_), _) => CheckEnd::Superseded,
            (None, true) => CheckEnd::Accepted,
            (None, false) => CheckEnd::AcceptedWithSilence,
        };
        self.counters
            .check(end, crawl.rounds(), started.elapsed(), !claims.is_empty());
        newer.map_or(CheckOutcome::Store, CheckOutcome::Superseded)
    }

    /// Fetch the records claimed above `seq` (`claims`, indices into `peers`
    /// and `answers`), all at once within the deadline of the check, and
    /// return the highest that hashes to its claim, binds to the key and
    /// verifies. A claim not shown in time, or shown with another record, is
    /// dropped. `join_all` polls every fetch, so none waits for the router
    /// while unpolled.
    async fn fetch_higher(
        self: &Arc<Self>,
        key: [u8; ID_LEN],
        seq: u64,
        peers: &[Node],
        answers: &[Answer],
        claims: &[usize],
        deadline: tokio::time::Instant,
    ) -> Option<Vec<u8>> {
        let fetches = claims.iter().filter_map(|&index| {
            let peer = peers.get(index)?.clone();
            let claimed = answers.get(index)?.hash;
            let call = Arc::clone(self).call_find_value(peer, Node::from_id(key));
            Some(async move {
                let raw = tokio::time::timeout_at(deadline, call).await.ok()?;
                let record = RPCFindResponse::new(raw).get_value()?;
                let form = shows_higher(&key, seq, &claimed, &record)?;
                Some((form.seq, record))
            })
        });
        let mut shown: Vec<(u64, Vec<u8>)> = futures::future::join_all(fetches)
            .await
            .into_iter()
            .flatten()
            .collect();
        shown.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));
        for (_, record) in shown {
            if self.verify_for_key(&key, &record).await {
                return Some(record);
            }
        }
        log::warn!(
            "rpc_store: {} claims of a later position of {} not shown, dropped",
            claims.len(),
            hex::encode(key)
        );
        self.counters.unshown_claims(claims.len());
        None
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    use crate::auth_handler::test_tree::TreeOwner;
    use crate::protocol::messages::{record_hash, RpcMessage, StoreStatus, WireNode};
    use crate::protocol::test_support::*;
    use crate::storage::ForgetfulStorage;

    use super::*;

    /// An id at XOR distance `distance` from `key`, in its first byte.
    fn id_at(key: [u8; ID_LEN], distance: u8) -> [u8; ID_LEN] {
        let mut id = key;
        id[0] ^= distance;
        id
    }

    async fn real_protocol() -> (Arc<KademliaProtocol>, Arc<CountingDidHandler>) {
        real_protocol_with(Arc::new(ForgetfulStorage::new(-1))).await
    }

    async fn real_protocol_with(
        storage: Arc<ForgetfulStorage>,
    ) -> (Arc<KademliaProtocol>, Arc<CountingDidHandler>) {
        let handler = Arc::new(CountingDidHandler::new());
        (
            test_protocol_with_storage(handler.clone(), false, storage).await,
            handler,
        )
    }

    /// The network check of a STORE survives a lost question: the node asked
    /// gets it again, and the STORE is decided well before the check's
    /// deadline.
    #[tokio::test]
    async fn the_store_check_survives_a_lost_question() {
        let (protocol, _) = real_protocol().await;
        serve(&protocol);
        let owner = TreeOwner::new(1);
        let (peer, contact) = raw_peer(id_at(owner.key, 1)).await;
        protocol.router.write().await.add_contact(contact);
        let started = Instant::now();
        let replica = Arc::clone(&protocol);
        let (key, record) = (owner.key, owner.record(0, None));
        let store = tokio::spawn(async move {
            replica
                .rpc_store([2; ID_LEN], ("127.0.0.1".to_string(), 9015), key, record)
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
        let owner = TreeOwner::new(1);
        let v0 = owner.record(0, None);
        let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
            -1,
            ID_LEN + v0.len(),
        ));
        let (protocol, _) = real_protocol_with(storage).await;
        give_answering_contact(&protocol, id_at(owner.key, 1)).await;
        let sender = [2; ID_LEN];
        let address = ("127.0.0.1".to_string(), 9010);

        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), owner.key, v0.clone())
                .await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), owner.key, v0)
                .await,
            Some(StoreStatus::AlreadyStored)
        );
        // The same document signed again.
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), owner.key, owner.record(0, None))
                .await,
            Some(StoreStatus::Conflict)
        );
        // The first STORE added the sender as a contact. The key below is new,
        // so the node would ask that contact, which does not exist here.
        let contact = Node::new(sender, Some(address.0.clone()), Some(address.1));
        protocol.router.write().await.remove_contact(&contact);
        let other = TreeOwner::new(2);
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), other.key, other.record(0, None))
                .await,
            Some(StoreStatus::CapacityExceeded)
        );

        let third = TreeOwner::new(3);
        let mut bad = third.record(0, None);
        bad[20] ^= 1;
        let (invalid_protocol, _) = real_protocol().await;
        give_answering_contact(&invalid_protocol, id_at(third.key, 1)).await;
        assert_eq!(
            invalid_protocol
                .rpc_store([3; ID_LEN], ("127.0.0.1".to_string(), 9011), third.key, bad)
                .await,
            Some(StoreStatus::InvalidRecord)
        );
    }

    /// A node that knows nobody, as one that has just restarted, has nobody
    /// to show it a higher position: it stores the verified record.
    #[tokio::test]
    async fn a_node_that_knows_nobody_stores_a_verified_record() {
        let (protocol, _) = real_protocol().await;
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9012),
                    owner.key,
                    v5.clone()
                )
                .await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(protocol.storage.get(&owner.key), Some(v5));
        #[cfg(feature = "counters")]
        assert_eq!(protocol.counters().checks.nobody_to_ask, 1);
    }

    /// An empty replica refuses a record that does not have the form of a
    /// record of the key before asking the network: the form costs a JSON
    /// parse, the lookup a message to every node close to the key. The
    /// signature is not checked either.
    #[tokio::test]
    async fn a_record_bound_to_another_key_is_refused_before_the_network_check() {
        let (protocol, handler) = real_protocol().await;
        let (owner, other) = (TreeOwner::new(1), TreeOwner::new(2));
        let (peer, contact) = raw_peer(id_at(other.key, 1)).await;
        protocol.router.write().await.add_contact(contact);
        let started = Instant::now();

        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9016),
                    other.key,
                    owner.record(0, None),
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
        assert_eq!(handler.verified(), 0);
        assert_eq!(protocol.storage.get(&other.key), None);
        #[cfg(feature = "counters")]
        assert_eq!(protocol.counters().checks.invalid, 1);
    }

    /// The counters of a STORE check: the question and its copy, sent to a
    /// peer never measured, the lookup's single round, and how it ended.
    #[cfg(feature = "counters")]
    #[tokio::test]
    async fn counters_record_a_store_check_and_its_resend() {
        use crate::fragmentation::encode_fragments;
        use crate::protocol::messages::Frame;

        let (protocol, _) = real_protocol().await;
        serve(&protocol);
        let owner = TreeOwner::new(1);
        let (peer, contact) = raw_peer(id_at(owner.key, 1)).await;
        protocol.router.write().await.add_contact(contact);
        let replica = Arc::clone(&protocol);
        let (key, record) = (owner.key, owner.record(0, None));
        let store = tokio::spawn(async move {
            replica
                .rpc_store([2; ID_LEN], ("127.0.0.1".to_string(), 9020), key, record)
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
        assert_eq!(counters.checks.accepted, 1);
        assert_eq!(counters.checks.rounds, vec![1, 0, 0, 0, 0]);
        assert_eq!(counters.checks.duration_ms.iter().sum::<u64>(), 1);
        assert_eq!(counters.checks.fetches, 0);
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

    /// Serve `record`, at position `seq`, as a holder does: its hash to
    /// `FindHash`, the record to `FindValue`.
    fn hold(socket: UdpSocket, seq: u64, record: Vec<u8>) {
        tokio::spawn(async move {
            while let Some((frame, from)) = try_read_frame(&socket, Duration::from_secs(5)).await {
                let answer = match frame.message {
                    RpcMessage::FindHash { .. } => RpcMessage::FindHashHit {
                        seq,
                        hash: record_hash(&record),
                    },
                    RpcMessage::FindValue { .. } => RpcMessage::FindValueHit {
                        value: record.clone(),
                    },
                    _ => continue,
                };
                send_raw(&socket, from, frame.msg_id, false, answer).await;
            }
        });
    }

    /// A replica among the nodes closest to the key, by its own table, asks
    /// them all at once rather than `alpha` at a time. None of them answers:
    /// the replica stores the record at the deadline.
    #[tokio::test]
    async fn an_empty_replica_asks_every_known_neighbour_at_once() {
        let (protocol, _) = real_protocol().await;
        serve(&protocol);
        let owner = TreeOwner::new(1);
        let mut peers = vec![];
        for distance in [1u8, 2, 3, 4, 7] {
            let (peer, contact) = raw_peer(id_at(owner.key, distance)).await;
            protocol.router.write().await.add_contact(contact);
            peers.push((distance, peer));
        }
        let started = tokio::time::Instant::now();
        let replica = Arc::clone(&protocol);
        let (key, record) = (owner.key, owner.record(0, None));
        let store = tokio::spawn(async move {
            replica
                .rpc_store([2; ID_LEN], ("127.0.0.1".to_string(), 9017), key, record)
                .await
        });

        let asked_by = started + Duration::from_millis(300);
        let mut not_asked = vec![];
        for (distance, peer) in &peers {
            let wait = asked_by.saturating_duration_since(tokio::time::Instant::now());
            match try_read_frame(peer, wait).await {
                Some((frame, _)) => assert!(
                    matches!(frame.message, RpcMessage::FindHash { key: asked, .. } if asked == owner.key),
                    "{:?}",
                    frame.message
                ),
                None => not_asked.push(*distance),
            }
        }
        assert!(
            not_asked.is_empty(),
            "neighbours not asked within 300 ms: {not_asked:?}"
        );
        assert_eq!(store.await.unwrap(), Some(StoreStatus::Stored));
        assert!(protocol.storage.get(&owner.key).is_some());
        #[cfg(feature = "counters")]
        assert_eq!(protocol.counters().checks.accepted_with_silence, 1);
    }

    /// A node that knows k nodes closer to the key than itself is not among the
    /// replicas by its own table: it keeps asking `alpha` at a time, since the
    /// nodes it knows would be replaced at the next hop.
    #[tokio::test]
    async fn a_node_far_from_the_key_asks_alpha_neighbours_at_a_time() {
        let owner = TreeOwner::new(1);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let protocol = Arc::new(KademliaProtocol::new(
            Node::from_id(id_at(owner.key, 0x80)),
            socket,
            Arc::new(ForgetfulStorage::new(-1)),
            5,
            3,
            Arc::new(CountingDidHandler::new()),
            None,
        ));
        serve(&protocol);
        // Five nodes, all closer to the key than this node, from the closest.
        let mut peers = vec![];
        for distance in [1u8, 2, 3, 4, 5] {
            let (peer, contact) = raw_peer(id_at(owner.key, distance)).await;
            protocol.router.write().await.add_contact(contact);
            peers.push((distance, peer));
        }
        let started = tokio::time::Instant::now();
        let replica = Arc::clone(&protocol);
        let (key, record) = (owner.key, owner.record(0, None));
        let store = tokio::spawn(async move {
            replica
                .rpc_store([2; ID_LEN], ("127.0.0.1".to_string(), 9019), key, record)
                .await
        });

        let asked_by = started + Duration::from_millis(300);
        let mut asked = vec![];
        for (distance, peer) in &peers {
            let wait = asked_by.saturating_duration_since(tokio::time::Instant::now());
            if try_read_frame(peer, wait).await.is_some() {
                asked.push(*distance);
            }
        }
        assert_eq!(asked, vec![1, 2, 3]);
        assert_eq!(store.await.unwrap(), Some(StoreStatus::Stored));
    }

    /// A neighbour answers the check with made-up nodes closer to the key,
    /// all at its own address, that hold nothing. They must not push out of
    /// the check a node the replica already knows, which holds a higher
    /// position: the replica still asks it, verifies its record, refuses the
    /// lower one as stale and stores the higher one.
    #[tokio::test]
    async fn a_neighbour_cannot_push_a_known_holder_out_of_the_store_check() {
        let (protocol, handler) = real_protocol().await;
        serve(&protocol);
        let owner = TreeOwner::new(1);
        let key = owner.key;
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));

        // From the closest to the key: an empty node, the liar, another empty
        // node, the holder, a third empty node.
        let (liar, liar_contact) = raw_peer(id_at(key, 2)).await;
        let (holder, holder_contact) = raw_peer(id_at(key, 4)).await;
        let mut contacts = vec![liar_contact.clone(), holder_contact];
        for distance in [1u8, 3, 7] {
            let (empty, contact) = raw_peer(id_at(key, distance)).await;
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
        hold(holder, 6, v6.clone());

        assert_eq!(
            protocol
                .rpc_store([2; ID_LEN], ("127.0.0.1".to_string(), 9018), key, v5)
                .await,
            Some(StoreStatus::Stale)
        );
        assert_eq!(protocol.storage.get(&key), Some(v6));
        assert_eq!(handler.verified(), 1);
    }

    #[tokio::test]
    async fn invalid_store_does_not_remove_spoofed_sender_from_routing_table() {
        let (protocol, _) = real_protocol().await;
        let sender_id = [14; ID_LEN];
        let registered = Node::new(sender_id, Some("127.0.0.1".into()), Some(9013));
        protocol
            .router
            .write()
            .await
            .add_contact(registered.clone());
        // The node holds position 0, so each STORE of position 1 is decided
        // locally, without asking the network, whose contact never answers.
        let owner = TreeOwner::new(1);
        let v0 = owner.record(0, None);
        protocol.storage.set(owner.key.to_vec(), v0.clone());
        let mut invalid = owner.record(1, Some(&v0));
        invalid[20] ^= 1;

        for _ in 0..3 {
            assert_eq!(
                protocol
                    .rpc_store(
                        sender_id,
                        ("127.0.0.1".into(), 9999),
                        owner.key,
                        invalid.clone()
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
