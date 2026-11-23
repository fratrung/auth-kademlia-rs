//! GET: the first copy that passes the DID binding and signature checks, or
//! for the Status List a quorum of identical copies.

use std::sync::Arc;

use crate::auth_handler::tree::tree_form;
use crate::crawling::ValueSpiderCrawl;
use crate::node::Node;
use crate::storage::IStorage;
use crate::utils::STATUS_LIST_KEY;

use super::{dht_key, Server};

/// Byte-identical responses a Status List GET needs, derived from `alpha`.
pub(super) fn read_quorum(alpha: usize) -> usize {
    alpha.max(1) / 2 + 1
}

impl Server {
    /// Look up `key` in the DHT. A DID record comes from local storage if
    /// this node holds one, without asking the network, otherwise from the
    /// first remote record whose key is the tree's at its position and whose
    /// signature verifies. It is the owner's record, not necessarily its
    /// current position: the caller compares its key with the credential, and
    /// `repair` fetches the one the credential names. The Status List is read
    /// through a quorum. Returns `None` if no record is found or none passes
    /// verification.
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        log::info!("get({})", key);
        let dkey = dht_key(key)?;
        let is_status_list = key == STATUS_LIST_KEY;
        let local_value = self.storage.get(&dkey);

        // DID Documents keep the low-latency local fast path. The frequently
        // updated status list instead uses the local copy as one quorum vote.
        if !is_status_list {
            if let Some(result) = local_value.as_ref() {
                return if self.verify_value(key, result).await {
                    Some(result.clone())
                } else {
                    None
                };
            }
        }

        let proto = self.protocol.as_ref()?;
        let nearest: Vec<Node> = proto
            .router
            .read()
            .await
            .find_neighbors(&Node::from_id(dkey), None);

        if nearest.is_empty() {
            log::warn!("get({}): no known neighbours", key);
            return None;
        }

        let crawl = ValueSpiderCrawl::new(
            Arc::clone(proto),
            Node::from_id(dkey),
            nearest,
            self.ksize,
            self.alpha,
        );

        if !is_status_list {
            // A position below one this node remembers is superseded.
            let floor = self.storage.marker(&dkey);
            return crawl
                .find_first_valid(|value| async move {
                    let above_floor = floor.is_none_or(|floor| {
                        tree_form(&dkey, &value).is_ok_and(|form| form.seq >= floor)
                    });
                    (above_floor && self.verify_value(key, &value).await).then_some(value)
                })
                .await;
        }

        let initial_values = local_value.into_iter().collect::<Vec<_>>();
        let result = crawl
            .find_quorum(initial_values, read_quorum(self.alpha), self.alpha.max(1))
            .await;

        match result {
            Some(v) if self.verify_value(key, &v).await => Some(v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::auth_handler::test_tree::TreeOwner;
    use crate::auth_handler::DIDSignatureVerifierHandler;
    use crate::storage::{ForgetfulStorage, IStorage, DEFAULT_MAX_STORAGE_BYTES};
    use crate::utils::ID_LEN;

    use super::*;

    /// A reader whose 6 expired returns nothing for the 5 a node serves, and
    /// the 7 it serves next. Ports 16040-16041.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_get_returns_nothing_below_the_position_remembered() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let v7 = owner.record(7, Some(&v6));
        let time = Arc::new(AtomicU64::new(0));
        let now = Arc::clone(&time);
        let storage = ForgetfulStorage::in_memory(
            100,
            DEFAULT_MAX_STORAGE_BYTES,
            Arc::new(move || now.load(Ordering::Relaxed)),
        );
        storage.set(owner.key.to_vec(), v6);
        time.store(100_000, Ordering::Relaxed);

        let handler = Arc::new(DIDSignatureVerifierHandler::new("unused"));
        let mut reader = Server::new(
            handler.clone(),
            20,
            3,
            Some([1; ID_LEN]),
            Some(Arc::new(storage)),
            false,
        );
        reader.listen(16040, "127.0.0.1").await.unwrap();
        let mut peer = Server::new(handler, 20, 3, Some([2; ID_LEN]), None, false);
        peer.listen(16041, "127.0.0.1").await.unwrap();
        assert!(!reader
            .bootstrap(vec![("127.0.0.1".to_string(), 16041)])
            .await
            .is_empty());

        peer.storage.set(owner.key.to_vec(), v5);
        assert_eq!(reader.get(&owner.did).await, None);
        peer.storage.set(owner.key.to_vec(), v7.clone());
        assert_eq!(reader.get(&owner.did).await, Some(v7));
        reader.stop().await;
        peer.stop().await;
    }
}
