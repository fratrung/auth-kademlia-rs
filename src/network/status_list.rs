//! UPDATE of the Status List: a new list signed by the issuer replaces the
//! one the replicas hold. DID records have no update: a later position is
//! published like any other, with `set`.

use std::sync::Arc;

use crate::auth_handler::verify_issuer_signed;
use crate::crawling::NodeSpiderCrawl;
use crate::node::Node;
use crate::protocol::KademliaProtocol;
use crate::storage::{IStorage, StorageWriteStatus};
use crate::utils::{ID_LEN, STATUS_LIST_KEY};

use super::publish::select_responsible_nodes;
use super::{dht_key, Server};

impl Server {
    /// Replace the Status List with `value`, signed by the issuer. `None`
    /// when no list is published yet or the signature fails; otherwise
    /// whether a strict majority of the consistency group, at most `alpha`
    /// replicas with this node first, took it.
    pub async fn update_status_list(&self, value: Vec<u8>) -> Option<bool> {
        let dkey = dht_key(STATUS_LIST_KEY)?;
        self.get(STATUS_LIST_KEY).await?;
        if !verify_issuer_signed(&self.signature_handler, &value).await {
            log::error!("update_status_list: invalid issuer signature");
            return None;
        }
        let proto = self.protocol.as_ref()?;
        let Some((store_local, nodes)) = self.replicas(proto, dkey).await else {
            log::warn!("update_status_list: no neighbours");
            return Some(false);
        };
        let results = futures::future::join_all(
            nodes
                .iter()
                .map(|node| proto.call_status_list_update_rpc(node, dkey, value.clone())),
        )
        .await;
        let local_vote = usize::from(store_local);
        let primary_remote_count = self.alpha.saturating_sub(local_vote).min(results.len());
        let group_size = local_vote + primary_remote_count;
        if group_size == 0 {
            return Some(false);
        }
        let required = group_size / 2 + 1;
        let acknowledgements = local_vote
            + results
                .iter()
                .take(primary_remote_count)
                .filter(|ok| **ok)
                .count();
        if acknowledgements < required {
            log::warn!(
                "update_status_list: quorum not reached ({}/{})",
                acknowledgements,
                required
            );
            return Some(false);
        }
        if store_local
            && matches!(
                self.storage.set(dkey.to_vec(), value),
                StorageWriteStatus::CapacityExceeded | StorageWriteStatus::WriteFailed
            )
        {
            log::warn!("update_status_list: the local copy was not stored");
            return Some(false);
        }
        Some(true)
    }

    /// The `k` replicas of `dkey`: whether this node is one, and the others.
    async fn replicas(
        &self,
        proto: &Arc<KademliaProtocol>,
        dkey: [u8; ID_LEN],
    ) -> Option<(bool, Vec<Node>)> {
        let target = Node::from_id(dkey);
        let nearest = proto.router.read().await.find_neighbors(&target, None);
        if nearest.is_empty() {
            return None;
        }
        let nodes = NodeSpiderCrawl::new(
            Arc::clone(proto),
            target.clone(),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find()
        .await;
        Some(select_responsible_nodes(
            &self.node, &target, nodes, self.ksize,
        ))
    }
}
