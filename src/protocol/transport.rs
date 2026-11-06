//! Sending requests and receiving datagrams.
//!
//! Encoding into KADF fragments, sending, `call` with its resends (lost
//! datagrams, `retransmit.rs`), and the receive path: `handle_datagram`
//! reassembles fragments, matches answers to pending calls, and hands
//! requests to `dispatch_request` (`handlers.rs`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::protocol::messages::{
    carried_record, record_hash, rpc_message_name, ExpectedResponse, Frame, RpcMessage,
    RECORD_HASH_LEN,
};
use tokio::sync::{oneshot, Mutex, Notify};

use crate::protocol::store_check::{StoreLookupSlot, MAX_STORE_LOOKUPS};

use crate::fragmentation::{
    encode_fragments, parse_fragment, ReassemblyEntry, FRAG_CHUNK_SIZE, MAX_MESSAGE_SIZE,
    MAX_REASSEMBLY_ENTRIES, MAX_REASSEMBLY_ENTRIES_PER_PEER, REASSEMBLY_GC_INTERVAL,
    REASSEMBLY_TTL,
};
use crate::node::Node;
use crate::retransmit::MAX_RESENDS;

use super::KademliaProtocol;

/// Timeout for a single RPC call. A lookup pays it once for a contact that does
/// not respond: after that the contact is marked as failing and skipped.
pub(super) const RPC_TIMEOUT: Duration = Duration::from_millis(2500);

/// A request waiting for its answer.
pub(super) struct PendingCall {
    peer: SocketAddr,
    expected: ExpectedResponse,
    reply: oneshot::Sender<RpcMessage>,
    /// Signalled for each receipt (`Received`) the peer sends.
    received: Arc<Notify>,
}

pub(super) type PendingMap = Arc<Mutex<HashMap<u32, PendingCall>>>;

/// A request that carries a record, being handled: its sender's address and
/// the SHA-256 of the whole request. A copy of it, sent again because the
/// receipt or the answer was late, is identical, so it is recognised and not
/// handled twice. Another request under the same msg_id is not a copy.
pub(super) type RequestKey = (SocketAddr, [u8; RECORD_HASH_LEN]);

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

impl KademliaProtocol {
    pub(super) fn next_id(&self) -> u32 {
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

    /// Send the datagrams of one frame, a message of type `kind`. Returns
    /// false if any fails to be transmitted.
    async fn send_datagrams(
        &self,
        addr: SocketAddr,
        kind: &'static str,
        datagrams: &[Vec<u8>],
    ) -> bool {
        for dg in datagrams {
            if let Err(e) = self.socket.send_to(dg, addr).await {
                log::warn!("UDP send to {} failed: {}", addr, e);
                return false;
            }
            self.counters.sent(kind, dg.len());
        }
        true
    }

    /// Serialize, fragment, and send a frame to `addr`. Returns false if any
    /// fragment fails to be transmitted.
    pub(super) async fn send_frame(&self, addr: SocketAddr, frame: &Frame) -> bool {
        match self.encode_frame(addr, frame) {
            Some(datagrams) => {
                self.send_datagrams(addr, rpc_message_name(&frame.message), &datagrams)
                    .await
            }
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
    pub(super) async fn call(&self, addr: SocketAddr, message: RpcMessage) -> Option<RpcMessage> {
        let msg_id = self.next_id();
        let frame = Frame {
            msg_id,
            is_request: true,
            message,
        };
        // The answer to a request carrying a record comes after the record is
        // handled, so it does not measure the round trip; its receipt does.
        let answer_measures = carried_record(&frame.message).is_none();
        let kind = rpc_message_name(&frame.message);
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
        if !self.send_datagrams(addr, kind, &datagrams).await {
            return None;
        }
        let measured = self.round_trips.is_measured(addr);
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
                    self.counters.resent(measured);
                    if !self.send_datagrams(addr, kind, &datagrams).await {
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
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use tokio::time::timeout;

    use crate::protocol::messages::{ExpectedResponse, Frame, RpcMessage, StoreStatus};
    use crate::protocol::test_support::*;
    use crate::utils::ID_LEN;

    use super::*;

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
