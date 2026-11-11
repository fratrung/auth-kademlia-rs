//! UPDATE: publish version N ≥ 1 of a DID record (ADR 0005) on the `k`
//! replicas. Each replica decides with what it holds: a replica holding
//! version N−1 takes it (R3), one that lacks versions says so, and the owner
//! replays its chain to it, the replicas behind first and the empty ones
//! after. The Status List keeps its own path: the issuer's signature.

use std::sync::Arc;

use crate::auth_handler::did::{record_form, RecordForm};
use crate::auth_handler::rules::{decide_locally, Local, Request};
use crate::auth_handler::verify_issuer_signed;
use crate::crawling::NodeSpiderCrawl;
use crate::node::Node;
use crate::protocol::{KademliaProtocol, StoreStatus, UpdateStatus};
use crate::storage::{IStorage, ReplaceStatus, StorageWriteStatus};
use crate::utils::{digest_bytes, ID_LEN, STATUS_LIST_KEY};

use super::publish::select_responsible_nodes;
use super::{dht_key, Server};

/// The versions the owner can send: version `first` and the ones after it, up
/// to the new version N, the last.
struct OwnerChain {
    first: u64,
    records: Vec<Vec<u8>>,
}

impl OwnerChain {
    /// The new version `value` (of form `form`) after `earlier`, if they make
    /// a chain: consecutive versions, each followed by the next through its
    /// `prev`, the last one committing to the key of `value`. `earlier` may
    /// be empty, or start at any version: the replay uses what is there.
    fn new(
        key: &[u8; ID_LEN],
        form: &RecordForm,
        value: Vec<u8>,
        earlier: Vec<Vec<u8>>,
    ) -> Option<Self> {
        let first = form.seq.checked_sub(earlier.len() as u64)?;
        let mut before: Option<(&Vec<u8>, RecordForm)> = None;
        for (offset, record) in earlier.iter().enumerate() {
            let this = record_form(key, record).ok()?;
            if this.seq != first + offset as u64 {
                return None;
            }
            if let Some((previous, _)) = &before {
                if this.prev != Some(digest_bytes(previous)) {
                    return None;
                }
            }
            before = Some((record, this));
        }
        if let Some((last, last_form)) = &before {
            if form.prev != Some(digest_bytes(last)) || last_form.next_key_hash != form.key_hash {
                return None;
            }
        }
        let mut records = earlier;
        records.push(value);
        Some(Self { first, records })
    }

    /// The seq of the new version.
    fn seq(&self) -> u64 {
        self.first + self.records.len() as u64 - 1
    }

    fn version(&self, seq: u64) -> Option<&[u8]> {
        let offset = seq.checked_sub(self.first)?;
        self.records.get(offset as usize).map(Vec::as_slice)
    }

    fn current(&self) -> &[u8] {
        self.records.last().map(Vec::as_slice).unwrap_or_default()
    }
}

/// How the replay of the chain to one replica ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayEnd {
    /// The replica took every version, the new one included.
    Done,
    /// Version 0 was refused because nodes near the key claim a later
    /// version: the network check can now take the new version.
    NewerOnVersionZero,
    /// A version was refused, not answered, or not given to `update`.
    Stopped,
}

/// The vote of the owner's own copy, when the owner is a replica.
enum LocalVote {
    /// It holds the new version, or will once it is written after the
    /// quorum over `expected`.
    Yes {
        expected: Option<Vec<u8>>,
    },
    No,
}

impl Server {
    /// Publish `value`, version N ≥ 1 of the DID `key`, with `earlier`, the
    /// owner's saved versions just before it (from any version up to N−1,
    /// possibly none), used only to replay the chain to replicas that miss
    /// versions (ADR 0005). Reads no copy from the network first.
    ///
    /// `None` when the record is refused before anything is sent: a version 0
    /// (published with `set`), a record that does not bind to `key` or whose
    /// signature fails, or earlier versions that are not its chain. Otherwise
    /// whether the quorum of replicas holds it.
    ///
    /// On the Status List key, `value` is the issuer-signed list, and
    /// `earlier` is not used.
    pub async fn update(&self, key: &str, value: Vec<u8>, earlier: Vec<Vec<u8>>) -> Option<bool> {
        let dkey = dht_key(key)?;
        if key == STATUS_LIST_KEY {
            return self.update_status_list(key, dkey, value).await;
        }
        let form = match record_form(&dkey, &value) {
            Ok(form) => form,
            Err(error) => {
                log::error!("update({}): invalid record: {error}", key);
                return None;
            }
        };
        if form.seq == 0 {
            log::error!("update({}): version 0 is published with set", key);
            return None;
        }
        if !self.verify_value(key, &value).await {
            log::error!("update({}): the signature does not verify", key);
            return None;
        }
        let Some(chain) = OwnerChain::new(&dkey, &form, value, earlier) else {
            log::error!(
                "update({}): the earlier versions are not the chain of version {}",
                key,
                form.seq
            );
            return None;
        };
        log::info!("update({}): publishing version {}", key, form.seq);
        Some(self.update_digest(key, dkey, &chain).await)
    }

    async fn update_digest(&self, key: &str, dkey: [u8; ID_LEN], chain: &OwnerChain) -> bool {
        let Some(proto) = &self.protocol else {
            return false;
        };
        let Some((store_local, nodes)) = self.replicas(proto, dkey).await else {
            log::warn!("update_digest {}: no neighbours", key);
            return false;
        };
        // The owner's copy votes as any replica's, by the rules. When it lacks
        // version N−1 it first writes the owner's chain up to N−1, without
        // asking the network: the chain is the owner's own.
        let local = if store_local {
            Some(self.prepare_local_copy(dkey, chain))
        } else {
            None
        };

        // The UPDATE to every replica at once.
        let first_answers = futures::future::join_all(
            nodes
                .iter()
                .map(|node| proto.call_update_rpc_answer(node, dkey, chain.current().to_vec())),
        )
        .await;
        let mut votes = vec![false; nodes.len()];
        let (mut behind, mut empty) = (vec![], vec![]);
        for (index, answer) in first_answers.into_iter().enumerate() {
            match answer {
                Some(UpdateStatus::Updated | UpdateStatus::AlreadyStored) => votes[index] = true,
                Some(UpdateStatus::MissingPrevious { seq: Some(seq) }) => behind.push((index, seq)),
                Some(UpdateStatus::MissingPrevious { seq: None }) => empty.push(index),
                Some(status) => log::info!(
                    "update_digest {}: {} answered {status:?}",
                    key,
                    nodes[index]
                ),
                None => {}
            }
        }

        // The replicas behind first, so that the empty ones count them once
        // repaired (open point 23).
        let repaired = futures::future::join_all(
            behind
                .iter()
                .map(|(index, seq)| replay(proto, &nodes[*index], dkey, chain, seq + 1)),
        )
        .await;
        for ((index, _), end) in behind.iter().zip(repaired) {
            votes[*index] = end == ReplayEnd::Done;
        }
        let filled = futures::future::join_all(
            empty
                .iter()
                .map(|index| fill_empty_replica(proto, &nodes[*index], dkey, chain)),
        )
        .await;
        for (index, stored) in empty.iter().zip(filled) {
            votes[*index] = stored;
        }

        // The consistency group is the local replica (when applicable) plus
        // the closest remote peers, capped at alpha. Remaining replicas are
        // still updated best-effort but do not affect the quorum decision.
        let local_member = usize::from(local.is_some());
        let primary_remote_count = self.alpha.saturating_sub(local_member).min(votes.len());
        let group_size = local_member + primary_remote_count;
        if group_size == 0 {
            return false;
        }
        let required = group_size / 2 + 1;
        let local_yes = usize::from(matches!(local, Some(LocalVote::Yes { .. })));
        let acknowledgements = local_yes
            + votes
                .iter()
                .take(primary_remote_count)
                .filter(|ok| **ok)
                .count();
        if acknowledgements < required {
            log::warn!(
                "update_digest {}: quorum not reached ({}/{})",
                key,
                acknowledgements,
                required
            );
            return false;
        }
        if let Some(LocalVote::Yes {
            expected: Some(expected),
        }) = local
        {
            match self
                .storage
                .replace_if(&dkey, &expected, chain.current().to_vec())
            {
                ReplaceStatus::Replaced => {}
                ReplaceStatus::CapacityExceeded => {
                    log::warn!("update_digest {}: local storage capacity exceeded", key);
                    return false;
                }
                ReplaceStatus::Changed => {
                    if self.storage.get(&dkey).as_deref() != Some(chain.current()) {
                        log::warn!("update_digest {}: the local copy changed meanwhile", key);
                    }
                }
            }
        }
        true
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

    /// The vote of the owner's copy for the new version, by the rules of any
    /// replica. The signature of the new version was verified by `update`.
    fn prepare_local_copy(&self, dkey: [u8; ID_LEN], chain: &OwnerChain) -> LocalVote {
        let stored = self.storage.get(&dkey);
        let start = match decide_locally(Request::Update, &dkey, stored.as_deref(), chain.current())
        {
            Local::AlreadyStored => return LocalVote::Yes { expected: None },
            Local::VerifyAndReplace => return LocalVote::Yes { expected: stored },
            Local::MissingPrevious(None) => 0,
            Local::MissingPrevious(Some(seq)) => seq + 1,
            other => {
                log::warn!("update_digest: the local copy refuses the new version: {other:?}");
                return LocalVote::No;
            }
        };
        let mut held = stored;
        for seq in start..chain.seq() {
            let Some(record) = chain.version(seq) else {
                log::warn!(
                    "update_digest: version {seq} was not given, the local copy stays behind"
                );
                return LocalVote::No;
            };
            let written = match &held {
                None => matches!(
                    self.storage
                        .insert_if_absent(dkey.to_vec(), record.to_vec()),
                    StorageWriteStatus::Stored | StorageWriteStatus::AlreadyStored
                ),
                Some(previous) => {
                    self.storage.replace_if(&dkey, previous, record.to_vec())
                        == ReplaceStatus::Replaced
                }
            };
            if !written {
                log::warn!("update_digest: could not write version {seq} locally");
                return LocalVote::No;
            }
            held = Some(record.to_vec());
        }
        LocalVote::Yes { expected: held }
    }

    /// The Status List: verified against the issuer's key, as before ADR 0005.
    async fn update_status_list(
        &self,
        key: &str,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> Option<bool> {
        self.get(key).await?;
        if !verify_issuer_signed(&self.signature_handler, &value).await {
            log::error!("update({}): invalid issuer signature", key);
            return None;
        }
        let proto = self.protocol.as_ref()?;
        let Some((store_local, nodes)) = self.replicas(proto, dkey).await else {
            log::warn!("update_digest {}: no neighbours", key);
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
                "update_digest {}: quorum not reached ({}/{})",
                key,
                acknowledgements,
                required
            );
            return Some(false);
        }
        if store_local
            && self.storage.set(dkey.to_vec(), value) == StorageWriteStatus::CapacityExceeded
        {
            log::warn!("update_digest {}: local storage capacity exceeded", key);
            return Some(false);
        }
        Some(true)
    }
}

/// Send `node` the owner's versions from `from` to the new one, each after
/// the answer to the one before (stop-and-wait): version 0 by STORE, since
/// only a STORE runs the network check of a version 0, the others by UPDATE.
async fn replay(
    proto: &Arc<KademliaProtocol>,
    node: &Node,
    dkey: [u8; ID_LEN],
    chain: &OwnerChain,
    from: u64,
) -> ReplayEnd {
    for seq in from..=chain.seq() {
        let Some(record) = chain.version(seq) else {
            log::warn!(
                "replay to {node}: version {seq} was not given to update, the replica stays behind"
            );
            return ReplayEnd::Stopped;
        };
        let taken = if seq == 0 {
            match proto.call_store_rpc(node, dkey, record.to_vec()).await {
                Some(StoreStatus::Stored | StoreStatus::AlreadyStored) => true,
                Some(StoreStatus::NewerClaimed) => return ReplayEnd::NewerOnVersionZero,
                _ => false,
            }
        } else {
            matches!(
                proto
                    .call_update_rpc_answer(node, dkey, record.to_vec())
                    .await,
                Some(UpdateStatus::Updated | UpdateStatus::AlreadyStored)
            )
        };
        if !taken {
            log::info!("replay to {node}: version {seq} not taken, the replay stops");
            return ReplayEnd::Stopped;
        }
    }
    ReplayEnd::Done
}

/// A replica that holds nothing: the new version by STORE, which its network
/// check decides; if it does not take it, the chain from version 0. When
/// version 0 is refused because the quorum near the key now claims a later
/// version (a replica just repaired, for instance), the new version once more
/// by STORE: the network check can take it now (a decision taken with the
/// user, beside ADR 0005's "The replay").
async fn fill_empty_replica(
    proto: &Arc<KademliaProtocol>,
    node: &Node,
    dkey: [u8; ID_LEN],
    chain: &OwnerChain,
) -> bool {
    let current = chain.current().to_vec();
    let from = match proto.call_store_rpc(node, dkey, current.clone()).await {
        Some(StoreStatus::Stored | StoreStatus::AlreadyStored) => return true,
        Some(StoreStatus::MissingPrevious { seq }) => seq + 1,
        None | Some(StoreStatus::Conflict | StoreStatus::NewerClaimed) => 0,
        Some(StoreStatus::Stale | StoreStatus::InvalidRecord | StoreStatus::CapacityExceeded) => {
            return false;
        }
    };
    match replay(proto, node, dkey, chain, from).await {
        ReplayEnd::Done => true,
        ReplayEnd::Stopped => false,
        ReplayEnd::NewerOnVersionZero => matches!(
            proto.call_store_rpc(node, dkey, current).await,
            Some(StoreStatus::Stored | StoreStatus::AlreadyStored)
        ),
    }
}
