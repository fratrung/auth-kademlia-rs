//! Republication of a held record to the nodes closest to its key (Kademlia
//! §2.5), and the repair of the holder from a replica that refuses it as
//! stale.

use std::sync::Arc;

use rand::seq::SliceRandom;

use crate::auth_handler::rules::{decide_locally, Held, Local};
use crate::crawling::{NodeSpiderCrawl, RPCFindResponse, SpiderProtocol};
use crate::node::Node;
use crate::protocol::messages::StoreStatus;
use crate::storage::{IStorage, ReplaceStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::KademliaProtocol;

impl KademliaProtocol {
    /// Send `value`, the record this node holds under `key`, to the `k` nodes
    /// closest to the key, and return their answers, as `republish_to`.
    pub async fn republish(
        self: &Arc<Self>,
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Vec<Option<StoreStatus>> {
        let target = Node::from_id(key);
        let neighbours = self.router.read().await.find_neighbors(&target, None);
        if neighbours.is_empty() {
            return vec![];
        }
        let nodes =
            NodeSpiderCrawl::new(Arc::clone(self), target, neighbours, self.ksize, self.alpha)
                .find()
                .await;
        self.republish_to(key, value, &nodes).await
    }

    /// Send `value`, the record this node holds under `key`, to `nodes`.
    /// When replicas answer `Stale`, ask one of them, drawn at random, for its
    /// record, and take it as a replica holding `value` would: a higher
    /// position of the same DID with a valid signature. One fetch per call
    /// bounds what made-up refusals cost; the random draw keeps one node that
    /// always refuses without showing anything from blocking every repair.
    pub(crate) async fn republish_to(
        self: &Arc<Self>,
        key: [u8; ID_LEN],
        value: Vec<u8>,
        nodes: &[Node],
    ) -> Vec<Option<StoreStatus>> {
        let answers = futures::future::join_all(
            nodes
                .iter()
                .map(|node| self.call_store_rpc(node, key, value.clone())),
        )
        .await;
        if key == digest(STATUS_LIST_KEY) {
            return answers;
        }
        let stale: Vec<&Node> = nodes
            .iter()
            .zip(&answers)
            .filter(|(_, answer)| **answer == Some(StoreStatus::Stale))
            .map(|(node, _)| node)
            .collect();
        let Some(&replica) = stale.choose(&mut rand::thread_rng()) else {
            return answers;
        };
        let call = Arc::clone(self).call_find_value(replica.clone(), Node::from_id(key));
        let taken = match RPCFindResponse::new(call.await).get_value() {
            Some(record) => self.take_higher(&key, &value, record).await,
            None => false,
        };
        if taken {
            log::info!(
                "republish {}: took the higher record {} showed",
                hex::encode(key),
                replica
            );
        } else {
            log::warn!(
                "republish {}: {} refused as stale without showing a higher record",
                hex::encode(key),
                replica
            );
        }
        answers
    }

    /// Replace `held`, the record stored under `key`, with `record` if a
    /// replica holding `held` would take it: a higher position, whose
    /// signature verifies, while `held` is still the stored record.
    async fn take_higher(&self, key: &[u8; ID_LEN], held: &[u8], record: Vec<u8>) -> bool {
        if decide_locally(key, Held::Record(held), &record) != Local::VerifyAndReplace {
            return false;
        }
        if !self.verify_for_key(key, &record).await {
            return false;
        }
        self.storage.replace_if(key, held, record) == ReplaceStatus::Replaced
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use crate::auth_handler::test_tree::{body, TreeOwner, PLACEHOLDER};
    use crate::protocol::messages::RpcMessage;
    use crate::protocol::test_support::*;
    use crate::storage::ForgetfulStorage;

    use super::*;

    async fn holder_of(key: [u8; ID_LEN], record: &[u8]) -> Arc<KademliaProtocol> {
        let storage = Arc::new(ForgetfulStorage::new(-1));
        storage.set(key.to_vec(), record.to_vec());
        let protocol =
            test_protocol_with_storage(Arc::new(CountingDidHandler::new()), false, storage).await;
        serve(&protocol);
        protocol
    }

    /// A replica that refuses every STORE as stale and answers `FindValue`
    /// with `shown`, counting the fetches.
    fn stale_replica(socket: UdpSocket, shown: RpcMessage, fetches: Arc<AtomicUsize>) {
        tokio::spawn(async move {
            while let Some((frame, from)) = try_read_message(&socket, Duration::from_secs(5)).await
            {
                let answer = match frame.message {
                    RpcMessage::Store { .. } => RpcMessage::StoreResult {
                        status: StoreStatus::Stale,
                    },
                    RpcMessage::FindValue { .. } => {
                        fetches.fetch_add(1, Ordering::Relaxed);
                        shown.clone()
                    }
                    _ => continue,
                };
                send_raw(&socket, from, frame.msg_id, false, answer).await;
            }
        });
    }

    #[tokio::test]
    async fn a_holder_takes_the_higher_record_a_stale_replica_shows() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let holder = holder_of(owner.key, &v5).await;

        let storage = Arc::new(ForgetfulStorage::new(-1));
        storage.set(owner.key.to_vec(), v6.clone());
        let replica =
            test_protocol_with_storage(Arc::new(CountingDidHandler::new()), false, storage).await;
        serve(&replica);
        let port = replica.socket.local_addr().unwrap().port();

        let answers = holder
            .republish_to(owner.key, v5, &[contact_at([9; ID_LEN], port)])
            .await;
        assert_eq!(answers, vec![Some(StoreStatus::Stale)]);
        assert_eq!(holder.storage.get(&owner.key), Some(v6));
    }

    /// Nothing, another DID's record, a lower one, the same position signed
    /// again, or a record whose key is not the tree's: the holder keeps 5.
    #[tokio::test]
    async fn a_stale_replica_that_shows_no_valid_higher_record_changes_nothing() {
        let owner = TreeOwner::new(1);
        let v4 = owner.record(4, Some(b"3"));
        let v5 = owner.record(5, Some(&v4));
        let forged = owner.record_from(
            &body(PLACEHOLDER, owner.keys[5].public_key(), 6, Some(&v5)),
            6,
        );
        // The record of 6 with one bit of its signature flipped.
        let unsigned = {
            let mut record = owner.record(6, Some(&v5));
            record[20] ^= 1;
            record
        };
        let shown = [
            RpcMessage::FindValueNodes { nodes: vec![] },
            RpcMessage::FindValueHit {
                value: TreeOwner::new(2).record(6, Some(b"5")),
            },
            RpcMessage::FindValueHit { value: v4 },
            RpcMessage::FindValueHit {
                value: owner.record(5, Some(b"4")),
            },
            RpcMessage::FindValueHit { value: forged },
            RpcMessage::FindValueHit { value: unsigned },
        ];
        for message in shown {
            let holder = holder_of(owner.key, &v5).await;
            let (socket, contact) = raw_peer([9; ID_LEN]).await;
            let fetches = Arc::new(AtomicUsize::new(0));
            stale_replica(socket, message.clone(), Arc::clone(&fetches));
            holder.republish_to(owner.key, v5.clone(), &[contact]).await;
            assert_eq!(fetches.load(Ordering::Relaxed), 1, "{message:?}");
            assert_eq!(
                holder.storage.get(&owner.key),
                Some(v5.clone()),
                "{message:?}"
            );
        }
    }

    #[tokio::test]
    async fn one_republication_fetches_from_one_stale_replica() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let holder = holder_of(owner.key, &v5).await;
        let fetches = Arc::new(AtomicUsize::new(0));
        let mut replicas = vec![];
        for tag in 2..6u8 {
            let (socket, contact) = raw_peer([tag; ID_LEN]).await;
            stale_replica(
                socket,
                RpcMessage::FindValueNodes { nodes: vec![] },
                Arc::clone(&fetches),
            );
            replicas.push(contact);
        }
        let answers = holder.republish_to(owner.key, v5, &replicas).await;
        assert_eq!(answers, vec![Some(StoreStatus::Stale); 4]);
        assert_eq!(fetches.load(Ordering::Relaxed), 1);
    }

    /// A writer stores 7 while the holder of 5 fetches 6: 7 stays.
    #[tokio::test]
    async fn a_higher_record_stored_meanwhile_is_kept() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let v7 = owner.record(7, Some(&v6));
        let holder = holder_of(owner.key, &v7).await;
        assert!(!holder.take_higher(&owner.key, &v5, v6).await);
        assert_eq!(holder.storage.get(&owner.key), Some(v7));
    }
}
