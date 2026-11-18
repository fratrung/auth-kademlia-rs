//! SET: publish a record on the `k` nodes closest to its key, and report how
//! many of them hold it (`SetReport`, `SetOutcome`).
//!
//! `set` reads no copy first: it finds the closest nodes and sends them the
//! record (Kademlia, section 2.3), as `update` does (ADR 0005, open point 16).
//! A replica that refuses it counts only once it shows a record that the
//! owner's version 0 proves to be another version 0 or its successor (open
//! point 27); a refusal it does not show is a replica that did not store.

use std::sync::Arc;

use crate::auth_handler::did::record_form;
use crate::auth_handler::rules::{shown_against, store_quorum, Shown};
use crate::crawling::{LookupNodes, NodeSpiderCrawl, RPCFindResponse, SpiderProtocol};
use crate::node::Node;
use crate::protocol::StoreStatus;
use crate::storage::IStorage;
use crate::utils::ID_LEN;

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
    /// Replicas that answered `Conflict`: they hold, or were shown, another
    /// record at the place of version 0.
    pub conflict_rejections: usize,
    pub invalid_rejections: usize,
    /// Replicas that answered `Stale`: they hold a later version of the DID.
    /// Apart from `conflict_rejections`, where another record competes with
    /// it.
    pub stale_rejections: usize,
    /// Empty replicas that refused because nodes near the key claim a newer
    /// version, which they do not prove (ADR 0005).
    pub newer_claimed: usize,
    /// Replicas that refused (`Conflict`, `Stale`, `NewerClaimed`) without
    /// showing a record that version 0 proves to be another version 0 or its
    /// successor (open point 27): they count as replicas that did not store.
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
            Some(StoreStatus::NewerClaimed) => self.newer_claimed += 1,
            // A replica answers it only to a version N ≥ 2, which `set` never
            // sends.
            Some(StoreStatus::MissingPrevious { .. }) => self.conflict_rejections += 1,
            None => self.unavailable_nodes += 1,
        }
    }
}

/// A refusal of version 0 by a replica, which counts only once shown.
fn is_refusal(status: Option<StoreStatus>) -> bool {
    matches!(
        status,
        Some(
            StoreStatus::Conflict
                | StoreStatus::Stale
                | StoreStatus::NewerClaimed
                | StoreStatus::MissingPrevious { .. }
        )
    )
}

/// What the replicas that refused version 0 showed (open point 27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proven {
    /// Nothing: their refusals weigh only as replicas that did not store.
    Nothing,
    /// Another version 0 of the DID with a valid signature: it was signed
    /// twice.
    OtherVersionZero,
    /// The successor of version 0, signed by the key version 0 commits to:
    /// the DID has moved on.
    Successor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetRejection {
    ExistingRecord,
    InvalidRecord,
    ReplicaConflict,
    CapacityExceeded,
    Unavailable,
    NoResponsibleNodes,
    /// A replica showed the version after version 0, or at least
    /// `store_quorum` of the replicas claim a later version: publish it with
    /// `update` (ADR 0005).
    NewerVersion,
    /// The record is a version N ≥ 1: `set` creates a DID, `update` publishes
    /// its later versions (ADR 0005).
    UseUpdate,
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
/// those that refused showed. A refusal shown decides; the others weigh as
/// replicas that did not store, and claims of a later version weigh only by
/// the quorum's word, as in R2 (open point 27).
fn classify_set_report(report: SetReport, proven: Proven) -> SetOutcome {
    match proven {
        Proven::OtherVersionZero => {
            return SetOutcome::Rejected {
                reason: SetRejection::ExistingRecord,
                report,
            };
        }
        Proven::Successor => {
            return SetOutcome::Rejected {
                reason: SetRejection::NewerVersion,
                report,
            };
        }
        Proven::Nothing => {}
    }
    if report.expected_replicas == 0 {
        return SetOutcome::Rejected {
            reason: SetRejection::NoResponsibleNodes,
            report,
        };
    }
    let newer = report.stale_rejections + report.newer_claimed;
    if newer > 0 && newer >= store_quorum(report.expected_replicas) {
        return SetOutcome::Rejected {
            reason: SetRejection::NewerVersion,
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
    /// against `value`, the version 0 being published: only what that version
    /// 0 shows it to be, with a valid signature (open point 27).
    async fn prove(&self, key: &str, dkey: &[u8; ID_LEN], value: &[u8], record: &[u8]) -> Proven {
        match shown_against(dkey, value, record) {
            Shown::OtherVersionZero if self.verify_value(key, record).await => {
                Proven::OtherVersionZero
            }
            Shown::Successor if self.verify_value(key, record).await => Proven::Successor,
            _ => Proven::Nothing,
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

    /// Publish version 0 of the DID `key` and report the exact replica
    /// outcome (ADR 0005: later versions go through `update`).
    ///
    /// Re-publishing byte-identical data is idempotent and can complete a
    /// previously degraded publication. Another version 0, signed again, is
    /// refused once a replica shows it; a later version once a replica shows
    /// version 1 or the quorum claims one (open point 27).
    pub async fn set_detailed(&self, key: &str, value: Vec<u8>) -> SetOutcome {
        let Some(dkey) = dht_key(key) else {
            log::error!("set({}): not a DID", key);
            return SetOutcome::Rejected {
                reason: SetRejection::InvalidRecord,
                report: SetReport::default(),
            };
        };
        // `set` creates a DID: a later version is published with `update`
        // (ADR 0005, open point 16), and nothing is sent.
        if record_form(&dkey, &value).is_ok_and(|form| form.seq >= 1) {
            log::error!("set({}): a version after 0 is published with update", key);
            return SetOutcome::Rejected {
                reason: SetRejection::UseUpdate,
                report: SetReport::default(),
            };
        }
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

        // This node's own copy, if any, is a proof like any replica's.
        if let Some(held) = self.storage.get(&dkey).filter(|held| *held != value) {
            match self.prove(key, &dkey, &value, &held).await {
                Proven::OtherVersionZero => {
                    log::error!("set({}): version 0 was signed twice", key);
                    return SetOutcome::Rejected {
                        reason: SetRejection::ExistingRecord,
                        report: SetReport::default(),
                    };
                }
                Proven::Successor => {
                    log::error!("set({}): this node holds version 1", key);
                    return SetOutcome::Rejected {
                        reason: SetRejection::NewerVersion,
                        report: SetReport::default(),
                    };
                }
                Proven::Nothing => log::warn!(
                    "set({}): this node holds a record version 0 does not prove",
                    key
                ),
            }
        }

        // No copy is read from the network first: one served by any node
        // would decide nothing (open point 27).
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
                | SetRejection::NewerVersion
                | SetRejection::UseUpdate => None,
                SetRejection::CapacityExceeded
                | SetRejection::Unavailable
                | SetRejection::NoResponsibleNodes => Some(false),
            },
        }
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
            let status =
                StoreStatus::from(self.storage.insert_if_absent(dkey.to_vec(), value.clone()));
            report.record_status(Some(status));
            if is_refusal(Some(status)) {
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

        let mut proven = Proven::Nothing;
        for record in shown {
            let shows = match record {
                Some(record) => self.prove(key, &dkey, &value, &record).await,
                None => Proven::Nothing,
            };
            match shows {
                Proven::Nothing => report.unproven_refusals += 1,
                // Another version 0 is the owner's own error: it decides.
                Proven::OtherVersionZero => proven = shows,
                Proven::Successor if proven == Proven::Nothing => proven = shows,
                Proven::Successor => {}
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
            classify_set_report(complete, Proven::Nothing),
            SetOutcome::Complete(_)
        ));

        let degraded = SetReport {
            expected_replicas: 2,
            stored_replicas: 1,
            capacity_rejections: 1,
            ..SetReport::default()
        };
        assert!(matches!(
            classify_set_report(degraded, Proven::Nothing),
            SetOutcome::Degraded(_)
        ));

        let rejected = SetReport {
            expected_replicas: 2,
            capacity_rejections: 2,
            ..SetReport::default()
        };
        assert_eq!(
            reason(classify_set_report(rejected, Proven::Nothing)),
            Some(SetRejection::CapacityExceeded)
        );
    }

    /// A refusal decides only once shown (open point 27): unshown, a replica
    /// that refused or called the record invalid is one that did not store,
    /// and claims of a later version weigh by the quorum's word.
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
            |r| r.newer_claimed = 1,
            |r| {
                r.unproven_refusals = 0;
                r.invalid_rejections = 1;
            },
        ] {
            assert!(matches!(
                classify_set_report(refused(field), Proven::Nothing),
                SetOutcome::Degraded(_)
            ));
            assert_eq!(
                reason(classify_set_report(
                    refused(field),
                    Proven::OtherVersionZero
                )),
                Some(SetRejection::ExistingRecord)
            );
            assert_eq!(
                reason(classify_set_report(refused(field), Proven::Successor)),
                Some(SetRejection::NewerVersion)
            );
        }

        // 4 replicas: 3 claims of a later version are the quorum, 2 are not.
        let claims = |stale, newer_claimed| SetReport {
            expected_replicas: 4,
            stored_replicas: 4 - stale - newer_claimed,
            stale_rejections: stale,
            newer_claimed,
            unproven_refusals: stale + newer_claimed,
            ..SetReport::default()
        };
        assert_eq!(
            reason(classify_set_report(claims(1, 2), Proven::Nothing)),
            Some(SetRejection::NewerVersion)
        );
        assert!(matches!(
            classify_set_report(claims(1, 1), Proven::Nothing),
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
            reason(classify_set_report(nothing_stored, Proven::Nothing)),
            Some(SetRejection::ReplicaConflict)
        );
        let invalid = SetReport {
            expected_replicas: 2,
            invalid_rejections: 2,
            ..SetReport::default()
        };
        assert_eq!(
            reason(classify_set_report(invalid, Proven::Nothing)),
            Some(SetRejection::InvalidRecord)
        );
    }
}
