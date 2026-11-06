//! GET: the first copy that passes the DID binding and signature checks, or
//! for the Status List a quorum of identical copies.

use std::sync::Arc;

use crate::crawling::ValueSpiderCrawl;
use crate::node::Node;
use crate::storage::IStorage;
use crate::utils::{digest, STATUS_LIST_KEY};

use super::Server;

/// Byte-identical responses a Status List GET needs, derived from `alpha`.
pub(super) fn read_quorum(alpha: usize) -> usize {
    alpha.max(1) / 2 + 1
}

impl Server {
    /// Look up `key` in the DHT. A DID Document comes from local storage if
    /// present, otherwise from the first remote record that passes verification.
    /// This does not prove it is current or authentic: a forged, correctly
    /// self-signed record passes too, and the caller must compare its public key
    /// with the VC. The Status List is read through a quorum.
    /// Returns `None` if no record is found or none passes verification.
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        log::info!("get({})", key);
        let dkey = digest(key);
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
            return crawl
                .find_first_valid(|value| async move {
                    self.verify_value(key, &value).await.then_some(value)
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
