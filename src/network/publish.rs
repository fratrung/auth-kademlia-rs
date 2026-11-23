//! SET: publish a record of any position on the `k` nodes closest to its
//! key, and report how many of them hold it (`SetReport`, `SetOutcome`).
//!
//! `set` reads no copy first: it finds the closest nodes and sends them the
//! record (Kademlia, section 2.3). A replica that refuses counts only once it
//! shows a record that proves why, a higher position or another record at
//! the same position, with a valid signature. Any other refusal, and any
//! number of them, is a replica that did not store.

use std::sync::Arc;

use crate::auth_handler::rules::{decide_locally, shown_against, Held, Local, Proof};
use crate::crawling::{LookupNodes, NodeSpiderCrawl, RPCFindResponse, SpiderProtocol};
use crate::node::Node;
use crate::protocol::StoreStatus;
use crate::storage::{IStorage, ReplaceStatus, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::{dht_key, Server};

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
    /// Replicas that answered `Conflict`: they hold another record at the
    /// same position.
    pub conflict_rejections: usize,
    pub invalid_rejections: usize,
    /// Replicas that answered `Stale`: they hold, or verified, a higher
    /// position.
    pub stale_rejections: usize,
    /// Replicas that refused without showing a record that proves it: they
    /// count as replicas that did not store.
    pub unproven_refusals: usize,
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
            Some(StoreStatus::Stale) => self.stale_rejections += 1,
            None => self.unavailable_nodes += 1,
        }
    }
}

/// A refusal that counts only once the replica shows why.
fn is_refusal(status: Option<StoreStatus>) -> bool {
    matches!(status, Some(StoreStatus::Conflict | StoreStatus::Stale))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetRejection {
    /// A replica showed another valid record at the same position.
    ExistingRecord,
    InvalidRecord,
    ReplicaConflict,
    CapacityExceeded,
    Unavailable,
    NoResponsibleNodes,
    /// A replica showed a valid record at a higher position: the record is
    /// superseded.
    NewerVersion,
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

/// The outcome of a publication from what the replicas answered and what
/// those that refused showed. A refusal shown decides; the others weigh only
/// as replicas that did not store.
fn classify_set_report(report: SetReport, proven: Proof) -> SetOutcome {
    match proven {
        Proof::Conflict(_) => {
            return SetOutcome::Rejected {
                reason: SetRejection::ExistingRecord,
                report,
            };
        }
        Proof::Superseded => {
            return SetOutcome::Rejected {
                reason: SetRejection::NewerVersion,
                report,
            };
        }
        Proof::Nothing => {}
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
        let reason = if report.unproven_refusals > 0 {
            SetRejection::ReplicaConflict
        } else if report.invalid_rejections > 0 {
            SetRejection::InvalidRecord
        } else if report.capacity_rejections > 0 {
            SetRejection::CapacityExceeded
        } else {
            SetRejection::Unavailable
        };
        SetOutcome::Rejected { reason, report }
    }
}

impl Server {
    /// What `record`, a copy of the DID `key` held by a replica, proves
    /// against `value`, the record being published: only what a replica
    /// holding it would decide, and only with a valid signature.
    async fn prove(&self, key: &str, dkey: &[u8; ID_LEN], value: &[u8], record: &[u8]) -> Proof {
        match shown_against(dkey, value, record) {
            Proof::Nothing => Proof::Nothing,
            proof if self.verify_value(key, record).await => proof,
            _ => Proof::Nothing,
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

    /// Publish a record of the DID `key`, at any position, and report the
    /// exact replica outcome.
    ///
    /// Re-publishing byte-identical data is idempotent and can complete a
    /// previously degraded publication. A replica that holds a lower position
    /// takes this one directly. The publication is rejected once a replica
    /// shows a higher position, or another record at this position.
    pub async fn set_detailed(&self, key: &str, value: Vec<u8>) -> SetOutcome {
        let Some(dkey) = dht_key(key) else {
            log::error!("set({}): not a DID", key);
            return SetOutcome::Rejected {
                reason: SetRejection::InvalidRecord,
                report: SetReport::default(),
            };
        };
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

        // This node's own copy is evidence like any replica's.
        if let Some(held) = self.storage.get(&dkey).filter(|held| *held != value) {
            match self.prove(key, &dkey, &value, &held).await {
                Proof::Conflict(_) => {
                    log::error!(
                        "set({}): this node holds another record at this position",
                        key
                    );
                    return SetOutcome::Rejected {
                        reason: SetRejection::ExistingRecord,
                        report: SetReport::default(),
                    };
                }
                Proof::Superseded => {
                    log::error!("set({}): this node holds a higher position", key);
                    return SetOutcome::Rejected {
                        reason: SetRejection::NewerVersion,
                        report: SetReport::default(),
                    };
                }
                Proof::Nothing => {}
            }
        }

        let lookup = self.discover_publish_nodes(dkey).await;
        log::info!("set({}): publishing to responsible replicas", key);
        self.set_digest_detailed(key, dkey, value, lookup).await
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
                | SetRejection::ReplicaConflict
                | SetRejection::NewerVersion => None,
                SetRejection::CapacityExceeded
                | SetRejection::Unavailable
                | SetRejection::NoResponsibleNodes => Some(false),
            },
        }
    }

    /// Write the owner's verified `value` to this node's storage by the rules
    /// a replica follows, without the network check: the owner knows its own
    /// record. The Status List keeps its own rule, first writer wins. `None`
    /// when the stored record changed twice meanwhile, or the record could
    /// not be made durable.
    fn store_locally(&self, dkey: &[u8; ID_LEN], value: &[u8]) -> Option<StoreStatus> {
        if *dkey == digest(STATUS_LIST_KEY) {
            let status = self.storage.insert_if_absent(dkey.to_vec(), value.to_vec());
            return StoreStatus::of_write(status);
        }
        for _ in 0..2 {
            let (stored, marker) = self.storage.record_or_marker(dkey);
            let status = match decide_locally(dkey, Held::of(stored.as_deref(), marker), value) {
                Local::Invalid(_) => StoreStatus::InvalidRecord,
                Local::AskNetwork(_) => {
                    match self.storage.insert_if_absent(dkey.to_vec(), value.to_vec()) {
                        StorageWriteStatus::Conflict => continue,
                        status => StoreStatus::of_write(status)?,
                    }
                }
                Local::AlreadyStored => {
                    match self.storage.replace_if(dkey, value, value.to_vec()) {
                        ReplaceStatus::Replaced => StoreStatus::AlreadyStored,
                        ReplaceStatus::CapacityExceeded => StoreStatus::CapacityExceeded,
                        ReplaceStatus::Changed | ReplaceStatus::WriteFailed => continue,
                    }
                }
                Local::VerifyAndReplace => {
                    let Some(expected) = stored else {
                        continue;
                    };
                    match self.storage.replace_if(dkey, &expected, value.to_vec()) {
                        ReplaceStatus::Replaced => StoreStatus::Stored,
                        ReplaceStatus::CapacityExceeded => StoreStatus::CapacityExceeded,
                        ReplaceStatus::Changed => continue,
                        ReplaceStatus::WriteFailed => return None,
                    }
                }
                Local::Stale { .. } => StoreStatus::Stale,
                Local::VerifyConflict(_) => StoreStatus::Conflict,
            };
            return Some(status);
        }
        None
    }

    async fn set_digest_detailed(
        &self,
        key: &str,
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

        // What the replicas that refused show: this node's copy as it is, the
        // others' fetched by `FindValue`, all at once.
        let mut shown: Vec<Option<Vec<u8>>> = vec![];
        if store_local {
            let status = self.store_locally(&dkey, &value);
            report.record_status(status);
            if is_refusal(status) {
                shown.push(self.storage.get(&dkey));
            }
        }

        let stores = remote_nodes.iter().map(|node| {
            let protocol = Arc::clone(proto);
            let value = value.clone();
            async move { protocol.call_store_rpc(node, dkey, value).await }
        });
        let statuses = futures::future::join_all(stores).await;
        let refusing: Vec<&Node> = remote_nodes
            .iter()
            .zip(&statuses)
            .filter(|(_, status)| is_refusal(**status))
            .map(|(node, _)| node)
            .collect();
        for status in statuses {
            report.record_status(status);
        }
        let fetches = refusing.iter().map(|node| {
            let call = Arc::clone(proto).call_find_value((*node).clone(), target.clone());
            async move { RPCFindResponse::new(call.await).get_value() }
        });
        shown.extend(futures::future::join_all(fetches).await);

        let mut proven = Proof::Nothing;
        for record in shown {
            let shows = match record {
                Some(record) => self.prove(key, &dkey, &value, &record).await,
                None => Proof::Nothing,
            };
            match shows {
                Proof::Nothing => report.unproven_refusals += 1,
                // Another record at this position is the owner's own doing:
                // it decides over a higher position.
                Proof::Conflict(_) => proven = shows,
                Proof::Superseded if proven == Proof::Nothing => proven = shows,
                Proof::Superseded => {}
            }
        }
        if report.unproven_refusals > 0 {
            log::warn!(
                "set_digest {}: {} replicas refused without showing why",
                hex::encode(dkey),
                report.unproven_refusals
            );
        }

        let acknowledged = report.acknowledged_replicas();
        log::info!(
            "set_digest {}: {}/{} replicas acknowledged",
            hex::encode(dkey),
            acknowledged,
            report.expected_replicas
        );
        classify_set_report(report, proven)
    }
}

#[cfg(test)]
mod tests {
    use crate::auth_handler::rules::Conflict;

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

    fn reason(outcome: SetOutcome) -> Option<SetRejection> {
        match outcome {
            SetOutcome::Rejected { reason, .. } => Some(reason),
            _ => None,
        }
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
            classify_set_report(complete, Proof::Nothing),
            SetOutcome::Complete(_)
        ));

        let degraded = SetReport {
            expected_replicas: 2,
            stored_replicas: 1,
            capacity_rejections: 1,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(degraded, Proof::Nothing),
            SetOutcome::Degraded(_)
        ));

        let rejected = SetReport {
            expected_replicas: 2,
            capacity_rejections: 2,
            ..SetReport::default()
        };
        assert_eq!(
            reason(classify_set_report(rejected, Proof::Nothing)),
            Some(SetRejection::CapacityExceeded)
        );
    }

    /// A refusal decides only once shown: unshown, a replica that refused or
    /// called the record invalid is one that did not store, however many.
    #[test]
    fn a_refusal_decides_only_once_shown() {
        let refused = |field: fn(&mut SetReport)| {
            let mut report = SetReport {
                expected_replicas: 4,
                stored_replicas: 3,
                unproven_refusals: 1,
                ..SetReport::default()
            };
            field(&mut report);
            report
        };
        for field in [
            (|r: &mut SetReport| r.conflict_rejections = 1) as fn(&mut SetReport),
            |r| r.stale_rejections = 1,
            |r| {
                r.unproven_refusals = 0;
                r.invalid_rejections = 1;
            },
        ] {
            assert!(matches!(
                classify_set_report(refused(field), Proof::Nothing),
                SetOutcome::Degraded(_)
            ));
            for kind in [Conflict::RepeatedSigning, Conflict::Duplicity] {
                assert_eq!(
                    reason(classify_set_report(refused(field), Proof::Conflict(kind))),
                    Some(SetRejection::ExistingRecord)
                );
            }
            assert_eq!(
                reason(classify_set_report(refused(field), Proof::Superseded)),
                Some(SetRejection::NewerVersion)
            );
        }

        // 13 of 19 replicas answer `Stale` and show nothing: the publication
        // stands on the 6 that stored it.
        let unshown = SetReport {
            expected_replicas: 19,
            stored_replicas: 6,
            stale_rejections: 13,
            unproven_refusals: 13,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(unshown, Proof::Nothing),
            SetOutcome::Degraded(_)
        ));

        // Nothing stored: refusals not shown are a replica conflict, before
        // an invalid record or capacity.
        let nothing_stored = SetReport {
            expected_replicas: 3,
            conflict_rejections: 1,
            invalid_rejections: 1,
            capacity_rejections: 1,
            unproven_refusals: 1,
            ..SetReport::default()
        };
        assert_eq!(
            reason(classify_set_report(nothing_stored, Proof::Nothing)),
            Some(SetRejection::ReplicaConflict)
        );
        let invalid = SetReport {
            expected_replicas: 2,
            invalid_rejections: 2,
            ..SetReport::default()
        };
        assert_eq!(
            reason(classify_set_report(invalid, Proof::Nothing)),
            Some(SetRejection::InvalidRecord)
        );
    }
}
