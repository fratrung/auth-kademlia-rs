use std::sync::Arc;
use std::time::Duration;

use log;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;

use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{NodeSpiderCrawl, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::{KademliaProtocol, StoreStatus};
use crate::signature_cache::{SignatureCache, VerificationDomain};
use crate::storage::{ForgetfulStorage, IStorage, StorageWriteStatus, DEFAULT_TTL};
use crate::utils::{digest, digest_bytes, ID_LEN, STATUS_LIST_KEY};

/// Detailed result of a DHT publication attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetReport {
    pub expected_replicas: usize,
    pub stored_replicas: usize,
    pub already_present: usize,
    pub capacity_rejections: usize,
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

/// Operational snapshot suitable for monitoring and language bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStats {
    pub node_id: [u8; ID_LEN],
    pub listening: bool,
    pub routing_nodes: usize,
    pub storage_records: usize,
    pub storage_bytes: usize,
    pub max_storage_bytes: usize,
    pub signature_cache_entries: Option<u64>,
}

enum PublishLookup {
    Missing(Vec<Node>),
    Identical,
    Conflict,
}

fn select_responsible_nodes(
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

pub struct Server {
    pub ksize: usize,
    pub alpha: usize,
    pub storage: Arc<ForgetfulStorage>,
    pub node: Node,
    pub protocol: Option<Arc<KademliaProtocol>>,
    refresh_loop: Option<tokio::task::JoinHandle<()>>,
    save_state_loop: Option<tokio::task::JoinHandle<()>>,
    signature_handler: Arc<dyn SignatureVerifierHandler>,
    /// Shared with `KademliaProtocol` so a cache hit at the network layer
    /// (rpc_store) is visible at the API layer (get/set) and vice versa.
    /// `None` when the cache is disabled.
    sig_cache: Option<Arc<SignatureCache>>,
}

impl Server {
    /// Create a new server instance.
    ///
    /// - `signature_handler` — pluggable signature verification strategy.
    /// - `ksize`             — Kademlia k parameter (bucket size).
    /// - `alpha`             — lookup concurrency factor.
    /// - `node_id`           — fixed node ID; `None` picks one at random.
    /// - `storage`           — custom storage; `None` uses the default TTL store.
    /// - `use_cache`         — enable the Dilithium verification cache
    pub fn new(
        signature_handler: Arc<dyn SignatureVerifierHandler>,
        ksize: usize,
        alpha: usize,
        node_id: Option<[u8; ID_LEN]>,
        storage: Option<Arc<ForgetfulStorage>>,
        use_cache: bool,
    ) -> Self {
        let storage = storage.unwrap_or_else(|| Arc::new(ForgetfulStorage::new(DEFAULT_TTL)));

        let node = match node_id {
            Some(id) => Node::from_id(id),
            None => {
                use rand::RngCore;
                let mut b = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut b);
                Node::from_id(digest_bytes(&b))
            }
        };

        let sig_cache = use_cache.then(|| Arc::new(SignatureCache::new(4096)));

        Self {
            ksize,
            alpha,
            storage,
            node,
            protocol: None,
            refresh_loop: None,
            save_state_loop: None,
            signature_handler,
            sig_cache,
        }
    }

    /// Bind to `interface:port` and start the receive loop.
    ///
    /// Datagrams are round-robin dispatched to `available_parallelism()` workers,
    /// each backed by a dedicated `mpsc::channel(256)`. When all channels are
    /// full the receive loop blocks on the base worker rather than dropping.
    pub async fn listen(&mut self, port: u16, interface: &str) -> tokio::io::Result<()> {
        let addr = format!("{}:{}", interface, port);
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        log::info!("Node {} listening on {}", self.node.long_id, addr);

        let protocol = Arc::new(KademliaProtocol::new(
            self.node.clone(),
            Arc::clone(&socket),
            Arc::clone(&self.storage),
            self.ksize,
            Arc::clone(&self.signature_handler),
            self.sig_cache.clone(),
        ));
        self.protocol = Some(Arc::clone(&protocol));

        const WORKER_QUEUE_DEPTH: usize = 256;
        let num_workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);

        let mut senders = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(WORKER_QUEUE_DEPTH);
            senders.push(tx);
            let proto = Arc::clone(&protocol);
            tokio::spawn(async move {
                while let Some((data, peer)) = rx.recv().await {
                    proto.handle_datagram(data, peer).await;
                }
            });
        }

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            let mut idx = 0usize;
            'receive: loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let mut job = (buf[..len].to_vec(), peer);
                        let base = idx;
                        for i in 0..num_workers {
                            let w = (base + i) % num_workers;
                            match senders[w].try_send(job) {
                                Ok(()) => {
                                    idx = (w + 1) % num_workers;
                                    continue 'receive;
                                }
                                Err(TrySendError::Full(returned))
                                | Err(TrySendError::Closed(returned)) => {
                                    job = returned;
                                }
                            }
                        }
                        let w = base % num_workers;
                        let _ = senders[w].send(job).await;
                        idx = (w + 1) % num_workers;
                    }
                    Err(e) => log::error!("UDP recv error: {}", e),
                }
            }
        });

        self.schedule_refresh();
        self.schedule_stats_log();
        Ok(())
    }

    /// Notify neighbours of departure and cancel background tasks.
    pub async fn stop(&mut self) {
        if let Some(proto) = &self.protocol {
            let neighbors = proto.router.read().await.find_neighbors(&self.node, None);
            log::info!("Notifying {} neighbours of departure", neighbors.len());
            let mut tasks = vec![];
            for neighbor in neighbors {
                let p = Arc::clone(proto);
                tasks.push(tokio::spawn(async move {
                    p.call_leave_rpc(&neighbor).await;
                }));
            }
            futures::future::join_all(tasks).await;
        }
        if let Some(h) = self.refresh_loop.take() {
            h.abort();
        }
        if let Some(h) = self.save_state_loop.take() {
            h.abort();
        }
    }

    /// Ping each address in `addrs`, then run a `NodeSpiderCrawl` to populate
    /// the routing table. Returns the k-closest nodes discovered.
    pub async fn bootstrap(&self, addrs: Vec<(String, u16)>) -> Vec<Node> {
        log::debug!("Bootstrapping with {} initial contacts", addrs.len());
        let mut futs = vec![];
        for addr in addrs {
            futs.push(self.bootstrap_node(addr));
        }
        let nodes: Vec<Node> = futures::future::join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect();

        match &self.protocol {
            Some(proto) => {
                NodeSpiderCrawl::new(
                    Arc::clone(proto),
                    self.node.clone(),
                    nodes,
                    self.ksize,
                    self.alpha,
                )
                .find()
                .await
            }
            None => vec![],
        }
    }

    async fn bootstrap_node(&self, addr: (String, u16)) -> Option<Node> {
        let proto = self.protocol.as_ref()?;
        let (ok, id_bytes) = proto.call_ping_addr(&addr).await;
        if !ok || id_bytes.len() != ID_LEN {
            return None;
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_bytes);
        Some(Node::new(id, Some(addr.0), Some(addr.1)))
    }

    /// Look up `key` in the DHT. Checks local storage first, then performs an
    /// iterative FIND_VALUE. Verifies the Dilithium signature on every hit.
    /// Returns `None` if the key is absent or the signature is invalid.
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

        let sample_size = self.alpha.max(1);
        let minimum_votes = sample_size / 2 + 1;
        let initial_values = if is_status_list {
            local_value.into_iter().collect::<Vec<_>>()
        } else {
            vec![]
        };

        if nearest.is_empty() {
            log::warn!("get({}): insufficient neighbours for quorum", key);
            return None;
        }

        let result = ValueSpiderCrawl::new(
            Arc::clone(proto),
            Node::from_id(dkey),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find_quorum(initial_values, minimum_votes, sample_size)
        .await;

        match result {
            Some(v) if self.verify_value(key, &v).await => Some(v),
            _ => None,
        }
    }

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
            None => return PublishLookup::Missing(vec![]),
        };

        let nearest = proto
            .router
            .read()
            .await
            .find_neighbors(&Node::from_id(dkey), None);
        if nearest.is_empty() {
            log::warn!("set({}): no known neighbours", key);
            return PublishLookup::Missing(vec![]);
        }

        let (result, nodes) = ValueSpiderCrawl::new(
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
            None => PublishLookup::Missing(nodes),
        }
    }

    async fn discover_publish_nodes(&self, dkey: [u8; ID_LEN]) -> Vec<Node> {
        let proto = match self.protocol.as_ref() {
            Some(protocol) => protocol,
            None => return vec![],
        };
        let target = Node::from_id(dkey);
        let nearest = proto.router.read().await.find_neighbors(&target, None);
        if nearest.is_empty() {
            return vec![];
        }
        NodeSpiderCrawl::new(Arc::clone(proto), target, nearest, self.ksize, self.alpha)
            .find()
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
        let nodes = match self.check_publish_state(key, &value).await {
            PublishLookup::Missing(nodes) => nodes,
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
        self.set_digest_detailed(dkey, value, nodes).await
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

        let handler = Arc::clone(&self.signature_handler);
        let is_status = key == STATUS_LIST_KEY && auth_signature.is_none();
        let v = value.clone();
        let auth = auth_signature.clone();
        let ok = tokio::task::spawn_blocking(move || {
            if is_status {
                handler
                    .handle_issuer_node_signature_verification(&v)
                    .unwrap_or(false)
            } else {
                handler
                    .handle_key_binding_verification(&dkey, &v)
                    .unwrap_or(false)
                    && handler
                        .handle_update_verification(
                            &v,
                            &old_value,
                            auth.as_deref().unwrap_or_default(),
                        )
                        .unwrap_or(false)
            }
        })
        .await
        .unwrap_or(false);

        if !ok {
            log::error!("update({}): invalid record or authorization", key);
            return None;
        }
        log::info!("update({}): authenticated, publishing", key);
        Some(self.update_digest(key, dkey, value, auth_signature).await)
    }

    async fn set_digest_detailed(
        &self,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
        nodes: Vec<Node>,
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
            select_responsible_nodes(&self.node, &target, nodes, self.ksize);
        let mut report = SetReport {
            expected_replicas: remote_nodes.len() + usize::from(store_local),
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
                    p.call_update_rpc(&n, dkey, v, sig).await
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

    async fn verify_value(&self, key: &str, value: &[u8]) -> bool {
        let is_status = key == STATUS_LIST_KEY;
        if !is_status
            && !self
                .signature_handler
                .handle_key_binding_verification(&digest(key), value)
                .unwrap_or(false)
        {
            return false;
        }
        let domain = if is_status {
            VerificationDomain::IssuerSigned
        } else {
            VerificationDomain::SelfSigned
        };
        let cache_key = self
            .sig_cache
            .as_ref()
            .map(|_| SignatureCache::compute_key(domain, value));
        if let (Some(cache), Some(ck)) = (&self.sig_cache, &cache_key) {
            if let Some(cached) = cache.get_by_key(ck) {
                return cached;
            }
        }
        let handler = Arc::clone(&self.signature_handler);
        let v = value.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            if is_status {
                handler
                    .handle_issuer_node_signature_verification(&v)
                    .unwrap_or(false)
            } else {
                handler.handle_signature_verification(&v).unwrap_or(false)
            }
        })
        .await
        .unwrap_or(false);
        if result && is_status {
            log::info!("Status-list signature verified");
        }
        if let (Some(cache), Some(ck)) = (&self.sig_cache, cache_key) {
            cache.insert_by_key(ck, result);
        }
        result
    }

    /// Return the addresses of known neighbours suitable for bootstrapping.
    pub async fn bootstrappable_neighbors(&self) -> Vec<(String, u16)> {
        match &self.protocol {
            Some(proto) => proto
                .router
                .read()
                .await
                .find_neighbors(&self.node, None)
                .into_iter()
                .filter_map(|n| n.address())
                .collect(),
            None => vec![],
        }
    }

    /// Return a point-in-time operational snapshot without changing node state.
    pub async fn stats(&self) -> ServerStats {
        let routing_nodes = match &self.protocol {
            Some(proto) => proto
                .router
                .read()
                .await
                .buckets()
                .iter()
                .map(|bucket| bucket.len())
                .sum(),
            None => 0,
        };

        ServerStats {
            node_id: self.node.id,
            listening: self.protocol.is_some(),
            routing_nodes,
            storage_records: self.storage.iter_all().len(),
            storage_bytes: self.storage.current_storage_bytes(),
            max_storage_bytes: self.storage.max_storage_bytes(),
            signature_cache_entries: self.sig_cache.as_ref().map(|cache| cache.entry_count()),
        }
    }

    /// Persist node state (ksize, alpha, id, neighbours) to a JSON file.
    pub async fn save_state(&self, fname: &str) {
        let neighbors = self.bootstrappable_neighbors().await;
        if neighbors.is_empty() {
            log::warn!("save_state: no neighbours, skipping");
            return;
        }
        let data = serde_json::json!({
            "ksize": self.ksize,
            "alpha": self.alpha,
            "id": hex::encode(self.node.id),
            "neighbors": neighbors,
        });
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if let Err(e) = std::fs::write(fname, json) {
                log::error!("save_state: failed to write {}: {}", fname, e);
            }
        }
    }

    /// Spawn a background task that writes node state every `frequency_secs` seconds.
    pub fn save_state_regularly(&mut self, fname: String, frequency_secs: u64) {
        let node = self.node.clone();
        let ksize = self.ksize;
        let alpha = self.alpha;
        if let Some(proto) = &self.protocol {
            let proto = Arc::clone(proto);
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(frequency_secs)).await;
                    let neighbors: Vec<_> = proto
                        .router
                        .read()
                        .await
                        .find_neighbors(&node, None)
                        .into_iter()
                        .filter_map(|n| n.address())
                        .collect();
                    if !neighbors.is_empty() {
                        let data = serde_json::json!({
                            "ksize": ksize,
                            "alpha": alpha,
                            "id": hex::encode(node.id),
                            "neighbors": neighbors,
                        });
                        if let Ok(json) = serde_json::to_string_pretty(&data) {
                            let _ = std::fs::write(&fname, json);
                        }
                    }
                }
            });
            self.save_state_loop = Some(handle);
        }
    }

    fn schedule_stats_log(&self) {
        let proto = match &self.protocol {
            Some(p) => Arc::clone(p),
            None => return,
        };
        let storage = Arc::clone(&self.storage);
        let sig_cache = self.sig_cache.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let reclaimed = storage.prune_expired();
                if reclaimed > 0 {
                    log::debug!("Pruned {} expired storage records", reclaimed);
                }

                let routing_size: usize = proto
                    .router
                    .read()
                    .await
                    .buckets()
                    .iter()
                    .map(|b| b.len())
                    .sum();

                let storage_size = storage.iter_all().len();

                match &sig_cache {
                    Some(cache) => log::info!(
                        "[stats] routing_table={} nodes  storage={} records  storage_bytes={}/{}  sig_cache={} entries",
                        routing_size,
                        storage_size,
                        storage.current_storage_bytes(),
                        storage.max_storage_bytes(),
                        cache.entry_count(),
                    ),
                    None => log::info!(
                        "[stats] routing_table={} nodes  storage={} records  storage_bytes={}/{}",
                        routing_size,
                        storage_size,
                        storage.current_storage_bytes(),
                        storage.max_storage_bytes(),
                    ),
                }
            }
        });
    }

    fn schedule_refresh(&mut self) {
        let proto = match &self.protocol {
            Some(p) => Arc::clone(p),
            None => return,
        };
        let storage = Arc::clone(&self.storage);
        let ksize = self.ksize;
        let alpha = self.alpha;

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                log::debug!("Routing table refresh triggered");

                let refresh_ids = proto.get_refresh_ids().await;
                let mut futs = vec![];
                for rid in refresh_ids {
                    let rnode = Node::from_id(rid);
                    let neighbors = proto.router.read().await.find_neighbors(&rnode, None);
                    let spider =
                        NodeSpiderCrawl::new(Arc::clone(&proto), rnode, neighbors, ksize, alpha);
                    futs.push(spider.find());
                }
                futures::future::join_all(futs).await;

                let old_entries = storage.iter_older_than(3600);
                for (key_vec, value) in old_entries {
                    if key_vec.len() != ID_LEN {
                        continue;
                    }
                    let mut dkey = [0u8; ID_LEN];
                    dkey.copy_from_slice(&key_vec);
                    let target = Node::from_id(dkey);
                    let neighbors = proto.router.read().await.find_neighbors(&target, None);
                    if neighbors.is_empty() {
                        continue;
                    }
                    let nodes =
                        NodeSpiderCrawl::new(Arc::clone(&proto), target, neighbors, ksize, alpha)
                            .find()
                            .await;

                    let mut store_futs = vec![];
                    for n in &nodes {
                        let p = Arc::clone(&proto);
                        let n = n.clone();
                        let v = value.clone();
                        store_futs.push(async move { p.call_store_rpc(&n, dkey, v).await });
                    }
                    futures::future::join_all(store_futs).await;
                }
            }
        });
        self.refresh_loop = Some(handle);
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
