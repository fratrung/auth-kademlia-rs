//! SET: publish a record on the `k` nodes closest to its key, and report how
//! many of them hold it (`SetReport`, `SetOutcome`).

use std::sync::Arc;

use crate::crawling::{LookupNodes, NodeSpiderCrawl, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::StoreStatus;
use crate::storage::IStorage;
use crate::utils::{digest, ID_LEN};

use super::Server;

/// Detailed result of a DHT publication attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetReport {
    pub expected_replicas: usize,
    pub stored_replicas: usize,
    pub already_present: usize,
    pub capacity_rejections: usize,
    /// Replicas that did not acknowledge, plus nodes the lookup knew were not
    /// responding. Those are not replicas: they do not count in `expected_replicas`
    /// and do not prevent a `Complete` outcome.
    pub unavailable_nodes: usize,
    pub conflict_rejections: usize,
    pub invalid_rejections: usize,
}

impl SetReport {
    pub fn acknowledged_replicas(&self) -> usize {
        self.stored_replicas + self.already_present
    }

    fn record_status(&mut self, status: Option<StoreStatus>) {
        match status {
            Some(StoreStatus::Stored) => self.stored_replicas += 1,
            Some(StoreStatus::AlreadyStored) => self.already_present += 1,
            Some(StoreStatus::CapacityExceeded) => self.capacity_rejections += 1,
            Some(StoreStatus::Conflict) => self.conflict_rejections += 1,
            Some(StoreStatus::InvalidRecord) => self.invalid_rejections += 1,
            None => self.unavailable_nodes += 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetRejection {
    ExistingRecord,
    InvalidRecord,
    ReplicaConflict,
    CapacityExceeded,
    Unavailable,
    NoResponsibleNodes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOutcome {
    Complete(SetReport),
    Degraded(SetReport),
    Rejected {
        reason: SetRejection,
        report: SetReport,
    },
}

impl SetOutcome {
    pub fn report(&self) -> &SetReport {
        match self {
            Self::Complete(report) | Self::Degraded(report) | Self::Rejected { report, .. } => {
                report
            }
        }
    }
}

enum PublishLookup {
    Missing(LookupNodes),
    Identical,
    Conflict,
}

pub(super) fn select_responsible_nodes(
    local_node: &Node,
    target: &Node,
    mut remote_nodes: Vec<Node>,
    ksize: usize,
) -> (bool, Vec<Node>) {
    remote_nodes.push(local_node.clone());
    remote_nodes.sort_by_key(|node| node.distance_to(target));
    remote_nodes.dedup_by_key(|node| node.id);
    remote_nodes.truncate(ksize);

    let store_local = remote_nodes.iter().any(|node| node.id == local_node.id);
    remote_nodes.retain(|node| node.id != local_node.id);
    (store_local, remote_nodes)
}

fn classify_set_report(report: SetReport) -> SetOutcome {
    if report.conflict_rejections > 0 {
        return SetOutcome::Rejected {
            reason: SetRejection::ReplicaConflict,
            report,
        };
    }
    if report.invalid_rejections > 0 {
        return SetOutcome::Rejected {
            reason: SetRejection::InvalidRecord,
            report,
        };
    }
    if report.expected_replicas == 0 {
        return SetOutcome::Rejected {
            reason: SetRejection::NoResponsibleNodes,
            report,
        };
    }

    let acknowledged = report.acknowledged_replicas();
    if acknowledged == report.expected_replicas {
        SetOutcome::Complete(report)
    } else if acknowledged > 0 {
        SetOutcome::Degraded(report)
    } else {
        let reason = if report.capacity_rejections > 0 {
            SetRejection::CapacityExceeded
        } else {
            SetRejection::Unavailable
        };
        SetOutcome::Rejected { reason, report }
    }
}

impl Server {
    /// Look for an existing value while retaining the closest nodes discovered
    /// on a miss for the subsequent STORE phase.
    async fn check_publish_state(&self, key: &str, value: &[u8]) -> PublishLookup {
        let dkey = digest(key);

        if let Some(existing) = self.storage.get(&dkey) {
            return if existing == value {
                PublishLookup::Identical
            } else {
                PublishLookup::Conflict
            };
        }

        let proto = match self.protocol.as_ref() {
            Some(protocol) => protocol,
            None => return PublishLookup::Missing(LookupNodes::default()),
        };

        let nearest = proto
            .router
            .read()
            .await
            .find_neighbors(&Node::from_id(dkey), None);
        if nearest.is_empty() {
            log::warn!("set({}): no known neighbours", key);
            return PublishLookup::Missing(LookupNodes::default());
        }

        let (result, lookup) = ValueSpiderCrawl::new(
            Arc::clone(proto),
            Node::from_id(dkey),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find()
        .await;

        match result {
            Some(found) if self.verify_value(key, &found).await => {
                if found == value {
                    PublishLookup::Identical
                } else {
                    PublishLookup::Conflict
                }
            }
            Some(_) => {
                // A malformed remote candidate does not own the key, but a
                // value-hit crawl does not return its node shortlist.
                PublishLookup::Missing(self.discover_publish_nodes(dkey).await)
            }
            None => PublishLookup::Missing(lookup),
        }
    }

    async fn discover_publish_nodes(&self, dkey: [u8; ID_LEN]) -> LookupNodes {
        let proto = match self.protocol.as_ref() {
            Some(protocol) => protocol,
            None => return LookupNodes::default(),
        };
        let target = Node::from_id(dkey);
        let nearest = proto.router.read().await.find_neighbors(&target, None);
        if nearest.is_empty() {
            return LookupNodes::default();
        }
        NodeSpiderCrawl::new(Arc::clone(proto), target, nearest, self.ksize, self.alpha)
            .find_lookup_nodes()
            .await
    }

    /// Store value under key and report the exact replica outcome.
    ///
    /// Re-publishing byte-identical data is idempotent and can complete a
    /// previously degraded publication. A different value remains a conflict.
    pub async fn set_detailed(&self, key: &str, value: Vec<u8>) -> SetOutcome {
        if !self.verify_value(key, &value).await {
            log::error!("set({}): invalid record or DID-key binding", key);
            return SetOutcome::Rejected {
                reason: SetRejection::InvalidRecord,
                report: SetReport::default(),
            };
        }
        if self.protocol.is_none() {
            log::error!("set({}): server is not listening", key);
            return SetOutcome::Rejected {
                reason: SetRejection::Unavailable,
                report: SetReport::default(),
            };
        }

        let dkey = digest(key);
        let lookup = match self.check_publish_state(key, &value).await {
            PublishLookup::Missing(lookup) => lookup,
            PublishLookup::Identical => self.discover_publish_nodes(dkey).await,
            PublishLookup::Conflict => {
                log::error!("set({}): a different record already exists", key);
                return SetOutcome::Rejected {
                    reason: SetRejection::ExistingRecord,
                    report: SetReport::default(),
                };
            }
        };

        log::info!("set({}): publishing to responsible replicas", key);
        self.set_digest_detailed(dkey, value, lookup).await
    }

    /// Compatibility wrapper around set_detailed.
    ///
    /// Complete publications return Some(true); degraded or unavailable
    /// publications return Some(false); invalid or conflicting records retain
    /// the historical None result.
    pub async fn set(&self, key: &str, value: Vec<u8>) -> Option<bool> {
        match self.set_detailed(key, value).await {
            SetOutcome::Complete(_) => Some(true),
            SetOutcome::Degraded(_) => Some(false),
            SetOutcome::Rejected { reason, .. } => match reason {
                SetRejection::ExistingRecord
                | SetRejection::InvalidRecord
                | SetRejection::ReplicaConflict => None,
                SetRejection::CapacityExceeded
                | SetRejection::Unavailable
                | SetRejection::NoResponsibleNodes => Some(false),
            },
        }
    }

    async fn set_digest_detailed(
        &self,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
        lookup: LookupNodes,
    ) -> SetOutcome {
        let proto = match &self.protocol {
            Some(protocol) => protocol,
            None => {
                return SetOutcome::Rejected {
                    reason: SetRejection::Unavailable,
                    report: SetReport::default(),
                };
            }
        };

        let target = Node::from_id(dkey);
        let (store_local, remote_nodes) =
            select_responsible_nodes(&self.node, &target, lookup.nodes, self.ksize);
        // A node with no reachable peer but with known contacts or seeds is cut
        // off, not alone: it holds at most one copy of a wider set of replicas.
        let cut_off = remote_nodes.is_empty()
            && (proto.router.read().await.has_contacts() || !proto.seeds().is_empty());
        let mut report = SetReport {
            expected_replicas: remote_nodes.len() + usize::from(store_local) + usize::from(cut_off),
            unavailable_nodes: lookup.unresponsive.max(usize::from(cut_off)),
            ..SetReport::default()
        };

        log::info!(
            "set_digest {}: storing on {} responsible replicas",
            hex::encode(dkey),
            report.expected_replicas
        );

        if store_local {
            let status =
                StoreStatus::from(self.storage.insert_if_absent(dkey.to_vec(), value.clone()));
            report.record_status(Some(status));
        }

        let mut futures = Vec::with_capacity(remote_nodes.len());
        for node in remote_nodes {
            let protocol = Arc::clone(proto);
            let value = value.clone();
            futures.push(async move { protocol.call_store_rpc(&node, dkey, value).await });
        }
        for status in futures::future::join_all(futures).await {
            report.record_status(status);
        }

        let acknowledged = report.acknowledged_replicas();
        log::info!(
            "set_digest {}: {}/{} replicas acknowledged",
            hex::encode(dkey),
            acknowledged,
            report.expected_replicas
        );
        classify_set_report(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_with_last_byte(last: u8) -> Node {
        let mut id = [0u8; ID_LEN];
        id[ID_LEN - 1] = last;
        Node::from_id(id)
    }

    #[test]
    fn responsible_replica_selection_is_xor_sorted_and_never_exceeds_k() {
        let target = Node::from_id([0; ID_LEN]);
        let local = Node::from_id([0xff; ID_LEN]);
        let remotes = vec![
            node_with_last_byte(3),
            node_with_last_byte(1),
            node_with_last_byte(2),
        ];

        let (store_local, selected) = select_responsible_nodes(&local, &target, remotes, 2);
        assert!(!store_local);
        assert_eq!(
            selected.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![node_with_last_byte(1).id, node_with_last_byte(2).id]
        );

        let local = node_with_last_byte(1);
        let remotes = vec![
            node_with_last_byte(4),
            node_with_last_byte(2),
            node_with_last_byte(3),
        ];
        let (store_local, selected) = select_responsible_nodes(&local, &target, remotes, 3);
        assert!(store_local);
        assert_eq!(selected.len() + usize::from(store_local), 3);
        assert_eq!(
            selected.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![node_with_last_byte(2).id, node_with_last_byte(3).id]
        );
    }

    #[test]
    fn set_report_classification_is_explicit() {
        let complete = SetReport {
            expected_replicas: 2,
            stored_replicas: 1,
            already_present: 1,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(complete),
            SetOutcome::Complete(_)
        ));

        let degraded = SetReport {
            expected_replicas: 2,
            stored_replicas: 1,
            capacity_rejections: 1,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(degraded),
            SetOutcome::Degraded(_)
        ));

        let rejected = SetReport {
            expected_replicas: 2,
            capacity_rejections: 2,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(rejected),
            SetOutcome::Rejected {
                reason: SetRejection::CapacityExceeded,
                ..
            }
        ));

        let conflict = SetReport {
            expected_replicas: 2,
            stored_replicas: 1,
            conflict_rejections: 1,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(conflict),
            SetOutcome::Rejected {
                reason: SetRejection::ReplicaConflict,
                ..
            }
        ));
    }
}
