//! Nodes met through a message (Kademlia §2.2, §2.5). They enter the routing
//! table at once; sending them the records they should hold waits in a
//! bounded queue that runs one replication at a time.

use std::sync::Arc;

use futures::stream::{self, StreamExt};

use crate::node::Node;
use crate::protocol::contacts::RETURNED_AFTER;
use crate::storage::IStorage;
use crate::utils::ID_LEN;

use super::KademliaProtocol;

/// Replications to new nodes that run at once. Each one scans the whole
/// storage.
pub(super) const WELCOME_CONCURRENCY: usize = 1;

/// Nodes waiting for, or receiving, the records they should hold. A node met
/// beyond this still enters the routing table, and gets its records from the
/// hourly republication.
const MAX_WELCOME_QUEUE: usize = 256;

/// Records whose neighbours are computed under one read lock of the routing
/// table, while scanning the storage for a new node.
const WELCOME_SCAN_CHUNK: usize = 256;

const REPLICATION_CONCURRENCY: usize = 4;

impl KademliaProtocol {
    /// A node made contact: add it to the routing table at once (Kademlia
    /// §2.2), and queue the records it should hold (§2.5). Only the records
    /// are bounded, because finding them scans the whole storage: one scan
    /// runs at a time and at most `MAX_WELCOME_QUEUE` nodes wait for it.
    pub(super) async fn schedule_welcome_if_new(self: &Arc<Self>, node: Node) {
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
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use crate::protocol::messages::{rpc_message_name, RpcMessage};
    use crate::protocol::test_support::*;
    use crate::protocol::transport::RPC_TIMEOUT;
    use crate::storage::ForgetfulStorage;

    use super::*;

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
