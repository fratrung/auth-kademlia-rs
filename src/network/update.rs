//! UPDATE: replace a record with a new one authorised by the old key (a key
//! rotation) on the replicas that hold it, and send it as a STORE to those
//! that do not.

use std::sync::Arc;

use crate::auth_handler::{verify_issuer_signed, verify_rotation};
use crate::crawling::NodeSpiderCrawl;
use crate::node::Node;
use crate::protocol::StoreStatus;
use crate::storage::{IStorage, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::publish::select_responsible_nodes;
use super::Server;

impl Server {
    /// Update an existing record. For regular DID Documents `auth_signature`
    /// must be produced with the private key of the current stored document.
    /// For the status-list key `auth_signature` may be `None` (the issuer
    /// node signature embedded in `value` is used instead).
    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> Option<bool> {
        let dkey = digest(key);
        let old_value = self.get(key).await?;

        let is_status = key == STATUS_LIST_KEY && auth_signature.is_none();
        // A retry of an update that already reached this copy: the copy is the
        // new record itself, verified when it was read, and the old key's
        // signature no longer verifies against it. Publish it again so the
        // replicas that missed it are completed.
        let already_applied = key != STATUS_LIST_KEY && old_value == value;
        let ok = already_applied
            || if is_status {
                verify_issuer_signed(&self.signature_handler, &value).await
            } else {
                verify_rotation(
                    &self.signature_handler,
                    &dkey,
                    &value,
                    &old_value,
                    auth_signature.as_deref().unwrap_or_default(),
                )
                .await
            };

        if !ok {
            log::error!("update({}): invalid record or authorization", key);
            return None;
        }
        log::info!("update({}): authenticated, publishing", key);
        Some(self.update_digest(key, dkey, value, auth_signature).await)
    }

    async fn update_digest(
        &self,
        key: &str,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> bool {
        let proto = match &self.protocol {
            Some(p) => p,
            None => return false,
        };
        let node = Node::from_id(dkey);
        let nearest = proto.router.read().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!("update_digest {}: no neighbours", key);
            return false;
        }

        let nodes = NodeSpiderCrawl::new(
            Arc::clone(proto),
            node.clone(),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find()
        .await;
        let (should_store_local, nodes) =
            select_responsible_nodes(&self.node, &node, nodes, self.ksize);

        let is_status_list = key == STATUS_LIST_KEY;
        let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>> =
            vec![];

        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let v = value.clone();
            if is_status_list {
                futs.push(Box::pin(async move {
                    p.call_status_list_update_rpc(&n, dkey, v).await
                }));
            } else {
                let sig = auth_signature.clone().unwrap_or_default();
                futs.push(Box::pin(async move {
                    match p.call_update_rpc_answer(&n, dkey, v.clone(), sig).await {
                        Some(true) => true,
                        // A replica without the record cannot verify the
                        // rotation and refuses it. It can take the record
                        // through STORE, under the same first-writer-wins rule
                        // as any publication; a replica holding another record
                        // answers Conflict and is not changed.
                        Some(false) => matches!(
                            p.call_store_rpc(&n, dkey, v).await,
                            Some(StoreStatus::Stored | StoreStatus::AlreadyStored)
                        ),
                        // No answer: a STORE would only wait for another timeout.
                        None => false,
                    }
                }));
            }
        }

        let results = futures::future::join_all(futs).await;

        // The consistency group is the local replica (when applicable) plus
        // the closest remote peers, capped at alpha. Remaining replicas are
        // still updated best-effort but do not affect the quorum decision.
        let local_vote = usize::from(should_store_local);
        let primary_remote_count = self.alpha.saturating_sub(local_vote).min(results.len());
        let group_size = local_vote + primary_remote_count;
        if group_size == 0 {
            return false;
        }
        let required = group_size / 2 + 1;
        let acknowledgements = local_vote
            + results
                .iter()
                .take(primary_remote_count)
                .filter(|&&ok| ok)
                .count();
        let quorum_met = acknowledgements >= required;

        if quorum_met {
            if should_store_local
                && self.storage.set(dkey.to_vec(), value) == StorageWriteStatus::CapacityExceeded
            {
                log::warn!("update_digest {}: local storage capacity exceeded", key);
                return false;
            }
        } else {
            log::warn!(
                "update_digest {}: quorum not reached ({}/{})",
                key,
                acknowledgements,
                required
            );
        }

        quorum_met
    }
}
