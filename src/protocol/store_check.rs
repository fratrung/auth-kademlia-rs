//! STORE, and the network check of a replica that holds nothing (ADR 0005,
//! section 3).
//!
//! A replica decides first with what it holds (`rules::decide_locally`): the
//! same bytes, a verified successor, an older version, another record at the
//! same place, or a version too far ahead. A replica that holds nothing asks
//! the nodes closest to the key for the version and hash of their record
//! (`FindHash`) and applies R2 to a version 0 and R5 to a later one, fetching
//! the version before from a node that voted for it when R5 says so. It never
//! accepts on silence.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth_handler::did::RecordForm;
use crate::auth_handler::rules::{
    check_fetched, decide_locally, decide_successor, decide_version_zero, Answer, Fetch,
    FetchCheck, Local, LocalConflict, Refusal, Request, Verdict,
};
use crate::counters::CheckEnd;
use crate::crawling::{RPCFindResponse, SpiderProtocol, ValueSearch, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::client::parse_hash_hit;
use crate::protocol::handlers::log_conflict;
use crate::protocol::messages::{record_hash, StoreStatus};
use crate::storage::{IStorage, ReplaceStatus, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::KademliaProtocol;

/// How long an empty replica asks the network about a record it was sent,
/// the fetch of the version before included, below `RPC_TIMEOUT` so that its
/// answer reaches the sender in time.
const STORE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2000);

/// STOREs waiting for that lookup at once. Beyond this a STORE is dropped
/// without an answer, as an overloaded node drops datagrams.
pub(super) const MAX_STORE_LOOKUPS: usize = 256;

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

/// The STORE status of a refusal by the network check.
fn refused(refusal: Refusal) -> StoreStatus {
    match refusal {
        Refusal::NewerClaimed { .. } => StoreStatus::NewerClaimed,
        Refusal::OtherVersion { .. }
        | Refusal::NotFollowing { .. }
        | Refusal::HolderBehind { .. }
        | Refusal::FetchedDoesNotHold => StoreStatus::Conflict,
    }
}

impl KademliaProtocol {
    /// Store a DID record by the rules of ADR 0005, section 3, or the Status
    /// List as before. `None` means no answer: the network check had nobody
    /// to ask, did not hear from every node it asked, found fewer votes than
    /// the quorum, or the stored record changed twice while this one was
    /// checked. The sender then counts the replica as unavailable.
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
        // Decided again once if the stored record changes while this one is
        // checked (optimistic concurrency, open point 14).
        for _ in 0..2 {
            let stored = self.storage.get(&key);
            let status = match decide_locally(Request::Store, &key, stored.as_deref(), &value) {
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
                // R1: the same bytes. The STORE refreshes the expiry, so that
                // republication keeps the record alive; nothing is verified.
                Local::AlreadyStored => {
                    match self.storage.replace_if(&key, &value, value.clone()) {
                        ReplaceStatus::Replaced => StoreStatus::AlreadyStored,
                        ReplaceStatus::Changed | ReplaceStatus::CapacityExceeded => continue,
                    }
                }
                Local::AskNetwork(form) => {
                    // A check that would run again after the record changed
                    // gives no answer: it never loops.
                    if asked_network {
                        log::warn!(
                            "rpc_store: {} emptied while it was checked",
                            hex::encode(key)
                        );
                        return None;
                    }
                    asked_network = true;
                    match self.network_check(key, &value, &form).await {
                        Verdict::Accept => {}
                        Verdict::Refuse(refusal) => {
                            log::warn!(
                                "rpc_store: the network refuses version {} of {} from {}: {refusal:?}",
                                form.seq,
                                hex::encode(key),
                                sender_addr.0
                            );
                            return Some(refused(refusal));
                        }
                        Verdict::NoAnswer | Verdict::Fetch(_) => {
                            log::warn!(
                                "rpc_store: no answer for version {} of {} from {}",
                                form.seq,
                                hex::encode(key),
                                sender_addr.0
                            );
                            return None;
                        }
                    }
                    if !self.verify_for_key(&key, &value).await {
                        return Some(StoreStatus::InvalidRecord);
                    }
                    match self.storage.insert_if_absent(key.to_vec(), value.clone()) {
                        StorageWriteStatus::Stored => StoreStatus::Stored,
                        StorageWriteStatus::AlreadyStored => StoreStatus::AlreadyStored,
                        StorageWriteStatus::CapacityExceeded => StoreStatus::CapacityExceeded,
                        // Another record arrived meanwhile: decide against it.
                        StorageWriteStatus::Conflict => continue,
                    }
                }
                // R3: the successor of the stored version, decided locally.
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
                    }
                }
                Local::VerifyDuplicity => {
                    if !self.verify_for_key(&key, &value).await {
                        return Some(StoreStatus::InvalidRecord);
                    }
                    log_conflict(
                        &key,
                        LocalConflict::ProvenDuplicity,
                        stored.as_deref(),
                        &value,
                    );
                    StoreStatus::Conflict
                }
                Local::Stale { .. } => StoreStatus::Stale,
                Local::Conflict(kind) => {
                    log_conflict(&key, kind, stored.as_deref(), &value);
                    StoreStatus::Conflict
                }
                Local::MissingPrevious(seq) => StoreStatus::MissingPrevious {
                    seq: seq.unwrap_or_default(),
                },
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

    /// The Status List, outside ADR 0005: signed by the issuer, first writer
    /// wins.
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
        let status = StoreStatus::from(self.storage.insert_if_absent(key.to_vec(), value));
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

    /// R2 or R5 for `value`, of form `form`, at this replica, which holds
    /// nothing for `key`. The lookup asks the nodes closest to the key for the
    /// version and SHA-256 of their record (`FindHash`) rather than the
    /// record, asks all of them, leaves no copy on any node, and gives up
    /// after `STORE_LOOKUP_TIMEOUT`. The rules decide once every node asked
    /// has answered or the deadline has passed, refusals first.
    async fn network_check(
        self: &Arc<Self>,
        key: [u8; ID_LEN],
        value: &[u8],
        form: &RecordForm,
    ) -> Verdict {
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
                .check(CheckEnd::NobodyToAsk, 0, started.elapsed(), false);
            return Verdict::NoAnswer;
        }
        let deadline = tokio::time::Instant::now() + STORE_LOOKUP_TIMEOUT;
        let own = record_hash(value);
        let find_hash = |protocol: Arc<Self>, peer, target| protocol.call_find_hash(peer, target);
        let mut crawl = ValueSpiderCrawl::new(
            Arc::clone(self),
            target.clone(),
            nearest,
            self.ksize,
            self.alpha,
        );
        // A replica has to hear all of them anyway, so it asks them at once:
        // one round instead of several, and a node it knows cannot be pushed
        // out of the lookup by an earlier answer before it is asked. A node far
        // from the key keeps asking `alpha` at a time: the nodes it knows are
        // replaced at each hop, and asking all of them would ask k per hop.
        if among_closest {
            crawl = crawl.asking_everyone();
        }
        // Every answer is kept, none ends the lookup: the rules decide at the
        // end, refusals first.
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
        let asked = crawl.asked();
        let mut hits = hits.lock().map(|hits| hits.clone()).unwrap_or_default();
        hits.sort_by_key(|(peer, _)| peer.distance_to(&target));
        let (voters, answers): (Vec<Node>, Vec<Answer>) = hits.into_iter().unzip();

        let mut fetched = false;
        let verdict = if form.seq == 0 {
            decide_version_zero(self.ksize, asked, &own, &answers, everyone_answered)
        } else {
            let first = decide_successor(
                self.ksize,
                asked,
                form,
                &own,
                &answers,
                everyone_answered,
                &Fetch::NotYet,
            );
            match first {
                Verdict::Fetch(order) => {
                    fetched = true;
                    match self
                        .fetch_previous(key, form, &voters, &order, deadline)
                        .await
                    {
                        Ok(fetch) => decide_successor(
                            self.ksize,
                            asked,
                            form,
                            &own,
                            &answers,
                            everyone_answered,
                            &fetch,
                        ),
                        Err(verdict) => verdict,
                    }
                }
                other => other,
            }
        };
        let end = match &verdict {
            Verdict::Accept => CheckEnd::Accepted,
            Verdict::Refuse(Refusal::NewerClaimed { .. }) => CheckEnd::NewerClaimed,
            Verdict::Refuse(Refusal::OtherVersion { .. }) => CheckEnd::OtherVersion,
            Verdict::Refuse(Refusal::NotFollowing { .. }) => CheckEnd::NotFollowing,
            Verdict::Refuse(Refusal::HolderBehind { .. }) => CheckEnd::HolderBehind,
            Verdict::Refuse(Refusal::FetchedDoesNotHold) => CheckEnd::FetchRefused,
            Verdict::NoAnswer | Verdict::Fetch(_) if everyone_answered && !fetched => {
                CheckEnd::TooFewVotes
            }
            Verdict::NoAnswer | Verdict::Fetch(_) => CheckEnd::NoAnswer,
        };
        self.counters
            .check(end, crawl.rounds(), started.elapsed(), fetched);
        verdict
    }

    /// Fetch version N−1 from the nodes that voted for it, in `order` (the
    /// closest to the key first), until one gives a record that hashes to
    /// `prev`, within the deadline of the whole check. A node that gives no
    /// record, or another one, is no vote; the next one is asked.
    async fn fetch_previous(
        self: &Arc<Self>,
        key: [u8; ID_LEN],
        form: &RecordForm,
        voters: &[Node],
        order: &[usize],
        deadline: tokio::time::Instant,
    ) -> Result<Fetch, Verdict> {
        let mut dropped = vec![];
        for &index in order {
            let Some(peer) = voters.get(index) else {
                continue;
            };
            let call = Arc::clone(self).call_find_value(peer.clone(), Node::from_id(key));
            let Ok(raw) = tokio::time::timeout_at(deadline, call).await else {
                return Err(Verdict::NoAnswer);
            };
            let Some(record) = RPCFindResponse::new(raw).get_value() else {
                dropped.push(index);
                continue;
            };
            match check_fetched(&key, form, &record) {
                FetchCheck::NotPrev => dropped.push(index),
                FetchCheck::DoesNotHold => {
                    log::warn!(
                        "rpc_store: the version before, from {peer}, does not commit to version {} of {}",
                        form.seq,
                        hex::encode(key)
                    );
                    return Err(Verdict::Refuse(Refusal::FetchedDoesNotHold));
                }
                FetchCheck::Confirmed {
                    verify_version_zero,
                } => {
                    // Version 0 binds by its own signature too (section 1).
                    if verify_version_zero && !self.verify_for_key(&key, &record).await {
                        return Err(Verdict::Refuse(Refusal::FetchedDoesNotHold));
                    }
                    return Ok(Fetch::Confirmed { dropped });
                }
            }
        }
        Ok(Fetch::NoneConfirmed)
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    use crate::auth_handler::test_chain::{new_key, sign, Chain};
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
        let chain = Chain::new();
        let (peer, contact) = raw_peer(id_at(chain.key, 1)).await;
        protocol.router.write().await.add_contact(contact);
        let started = Instant::now();
        let replica = Arc::clone(&protocol);
        let (key, record) = (chain.key, chain.version(0).to_vec());
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
        let chain = Chain::new();
        let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
            -1,
            ID_LEN + chain.version(0).len(),
        ));
        let (protocol, _) = real_protocol_with(storage).await;
        give_answering_contact(&protocol, id_at(chain.key, 1)).await;
        let sender = [2; ID_LEN];
        let address = ("127.0.0.1".to_string(), 9010);
        let v0 = chain.version(0).to_vec();
        let again = sign(
            &chain.doc(
                0,
                None,
                chain.keys[0].public_key(),
                chain.keys[1].public_key(),
            ),
            &chain.keys[0],
        );

        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), chain.key, v0.clone())
                .await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), chain.key, v0)
                .await,
            Some(StoreStatus::AlreadyStored)
        );
        assert_eq!(
            protocol
                .rpc_store(sender, address.clone(), chain.key, again)
                .await,
            Some(StoreStatus::Conflict)
        );
        // The first STORE added the sender as a contact. The key below is new,
        // so the node would ask that contact, which does not exist here.
        let contact = Node::new(sender, Some(address.0.clone()), Some(address.1));
        protocol.router.write().await.remove_contact(&contact);
        let other = Chain::new();
        assert_eq!(
            protocol
                .rpc_store(
                    sender,
                    address.clone(),
                    other.key,
                    other.version(0).to_vec()
                )
                .await,
            Some(StoreStatus::CapacityExceeded)
        );

        let bad_chain = Chain::new();
        let mut bad = bad_chain.version(0).to_vec();
        bad[20] ^= 1;
        let (invalid_protocol, _) = real_protocol().await;
        give_answering_contact(&invalid_protocol, id_at(bad_chain.key, 1)).await;
        assert_eq!(
            invalid_protocol
                .rpc_store(
                    [3; ID_LEN],
                    ("127.0.0.1".to_string(), 9011),
                    bad_chain.key,
                    bad
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
        let (protocol, _) = real_protocol().await;
        let chain = Chain::new();
        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9012),
                    chain.key,
                    chain.version(0).to_vec()
                )
                .await,
            None
        );
        assert_eq!(protocol.storage.get(&chain.key), None);
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
        let (chain, other) = (Chain::new(), Chain::new());
        let (peer, contact) = raw_peer(id_at(other.key, 1)).await;
        protocol.router.write().await.add_contact(contact);
        let started = Instant::now();

        assert_eq!(
            protocol
                .rpc_store(
                    [2; ID_LEN],
                    ("127.0.0.1".to_string(), 9016),
                    other.key,
                    chain.version(0).to_vec(),
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
        let chain = Chain::new();
        let (peer, contact) = raw_peer(id_at(chain.key, 1)).await;
        protocol.router.write().await.add_contact(contact);
        let replica = Arc::clone(&protocol);
        let (key, record) = (chain.key, chain.version(0).to_vec());
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

    /// A replica among the nodes closest to the key, by its own table, must
    /// hear all of them anyway: it asks them all at once rather than α at a
    /// time. None of them answers, so the STORE gets no answer.
    #[tokio::test]
    async fn an_empty_replica_asks_every_known_neighbour_at_once() {
        let (protocol, _) = real_protocol().await;
        serve(&protocol);
        let chain = Chain::new();
        let mut peers = vec![];
        for distance in [1u8, 2, 3, 4, 7] {
            let (peer, contact) = raw_peer(id_at(chain.key, distance)).await;
            protocol.router.write().await.add_contact(contact);
            peers.push((distance, peer));
        }
        let started = tokio::time::Instant::now();
        let replica = Arc::clone(&protocol);
        let (key, record) = (chain.key, chain.version(0).to_vec());
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
                    matches!(frame.message, RpcMessage::FindHash { key: asked, .. } if asked == chain.key),
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
        assert_eq!(store.await.unwrap(), None);
        assert_eq!(protocol.storage.get(&chain.key), None);
    }

    /// A node that knows k nodes closer to the key than itself is not among the
    /// replicas by its own table: it keeps asking `alpha` at a time, since the
    /// nodes it knows would be replaced at the next hop.
    #[tokio::test]
    async fn a_node_far_from_the_key_asks_alpha_neighbours_at_a_time() {
        let chain = Chain::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let protocol = Arc::new(KademliaProtocol::new(
            Node::from_id(id_at(chain.key, 0x80)),
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
            let (peer, contact) = raw_peer(id_at(chain.key, distance)).await;
            protocol.router.write().await.add_contact(contact);
            peers.push((distance, peer));
        }
        let started = tokio::time::Instant::now();
        let replica = Arc::clone(&protocol);
        let (key, record) = (chain.key, chain.version(0).to_vec());
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
        assert_eq!(store.await.unwrap(), None);
        assert_eq!(protocol.storage.get(&chain.key), None);
    }

    /// A neighbour answers the STORE check with made-up nodes closer to the key,
    /// all at its own address, that hold nothing. They must not push out of the
    /// check a node the replica already knows, which holds another version 1.
    #[tokio::test]
    async fn a_neighbour_cannot_push_a_known_holder_out_of_the_store_check() {
        let (protocol, handler) = real_protocol().await;
        serve(&protocol);
        let chain = Chain::with_versions(1);
        let key = chain.key;

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
        answer_every_request(
            holder,
            RpcMessage::FindHashHit {
                seq: 1,
                hash: record_hash(chain.version(1)),
            },
        );

        let attacker = new_key();
        let forged = sign(
            &chain.doc(
                1,
                Some(chain.version(0)),
                attacker.public_key(),
                new_key().public_key(),
            ),
            &attacker,
        );
        assert_eq!(
            protocol
                .rpc_store([2; ID_LEN], ("127.0.0.1".to_string(), 9018), key, forged)
                .await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(handler.verified(), 0);
        assert_eq!(protocol.storage.get(&key), None);
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
        // The node holds version 0, so each STORE of version 1 is decided
        // locally, without asking the network, whose contact never answers.
        let chain = Chain::with_versions(1);
        protocol
            .storage
            .set(chain.key.to_vec(), chain.version(0).to_vec());
        let mut invalid = chain.version(1).to_vec();
        invalid[20] ^= 1;

        for _ in 0..3 {
            assert_eq!(
                protocol
                    .rpc_store(
                        sender_id,
                        ("127.0.0.1".into(), 9999),
                        chain.key,
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
