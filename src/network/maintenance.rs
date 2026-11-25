//! The node's background work: hourly bucket refresh and daily
//! republication, recovery of failing contacts and seeds, the stats log,
//! and the saved state.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crawling::NodeSpiderCrawl;
use crate::node::Node;
use crate::routing::with_jitter;
use crate::storage::IStorage;
use crate::utils::ID_LEN;

use super::Server;

const MAINTENANCE_TICK: Duration = Duration::from_secs(1);

const REJOIN_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How often the buckets no lookup touched are refreshed (Kademlia §2.3).
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// How often a node sends the records it holds to the nodes closest to
/// their keys, those that nobody sent it meanwhile: once a day, well within
/// the 14-day TTL, so that each record, and its renewal on disk, costs one
/// round a day rather than one an hour.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Operational snapshot suitable for monitoring and language bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStats {
    pub node_id: [u8; ID_LEN],
    pub listening: bool,
    pub routing_nodes: usize,
    /// Routing contacts with no failure since their last response.
    pub live_routing_nodes: usize,
    pub storage_records: usize,
    pub storage_bytes: usize,
    pub max_storage_bytes: usize,
    pub signature_cache_entries: Option<u64>,
}

impl Server {
    /// Return a point-in-time operational snapshot without changing node state.
    pub async fn stats(&self) -> ServerStats {
        let (routing_nodes, live_routing_nodes) = match &self.protocol {
            Some(proto) => {
                let router = proto.router.read().await;
                (
                    router.buckets().iter().map(|bucket| bucket.len()).sum(),
                    router.live_contacts(),
                )
            }
            None => (0, 0),
        };

        ServerStats {
            node_id: self.node.id,
            listening: self.protocol.is_some(),
            routing_nodes,
            live_routing_nodes,
            storage_records: self.storage.iter_all().len(),
            storage_bytes: self.storage.current_storage_bytes(),
            max_storage_bytes: self.storage.max_storage_bytes(),
            signature_cache_entries: self.sig_cache.as_ref().map(|cache| cache.entry_count()),
        }
    }

    /// What this node has sent since it started listening (feature
    /// `counters`), or `None` before `listen`. See `src/counters.rs`.
    #[cfg(feature = "counters")]
    pub fn counters(&self) -> Option<crate::counters::CounterSnapshot> {
        self.protocol.as_ref().map(|protocol| protocol.counters())
    }

    /// Testbed only: make this node lie in `FindHash`, or stop
    /// (`KademliaProtocol::set_lying`). False when it is not listening.
    #[cfg(feature = "testbed")]
    pub fn set_lying(&self, lie: crate::protocol::Lie) -> bool {
        self.protocol
            .as_ref()
            .map(|protocol| protocol.set_lying(lie))
            .is_some()
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
        if let Some(owner) = &self.protocol {
            let proto = Arc::clone(owner);
            owner.spawn_task(async move {
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
        }
    }

    pub(super) fn schedule_stats_log(&self) {
        let Some(owner) = &self.protocol else {
            return;
        };
        let proto = Arc::clone(owner);
        let storage = Arc::clone(&self.storage);
        let sig_cache = self.sig_cache.clone();

        owner.spawn_task(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                // Expiry writes the files of a persistent store.
                let pruning = Arc::clone(&storage);
                match tokio::task::spawn_blocking(move || pruning.prune_expired()).await {
                    Ok(0) => {}
                    Ok(reclaimed) => log::debug!("Pruned {} expired storage records", reclaimed),
                    Err(error) => log::error!("prune: {error}"),
                }

                let (routing_size, live_size): (usize, usize) = {
                    let router = proto.router.read().await;
                    (
                        router.buckets().iter().map(|b| b.len()).sum(),
                        router.live_contacts(),
                    )
                };

                let storage_size = storage.iter_all().len();

                match &sig_cache {
                    Some(cache) => log::info!(
                        "[stats] routing_table={} nodes ({} live)  storage={} records  storage_bytes={}/{}  sig_cache={} entries",
                        routing_size,
                        live_size,
                        storage_size,
                        storage.current_storage_bytes(),
                        storage.max_storage_bytes(),
                        cache.entry_count(),
                    ),
                    None => log::info!(
                        "[stats] routing_table={} nodes ({} live)  storage={} records  storage_bytes={}/{}",
                        routing_size,
                        live_size,
                        storage_size,
                        storage.current_storage_bytes(),
                        storage.max_storage_bytes(),
                    ),
                }
            }
        });
    }

    /// Probe failing contacts and, while no contact is responding, retry the
    /// bootstrap seeds. Once a contact answers again, or first answers a node
    /// that started with records and has not looked up its own id, look it
    /// up. Does no network work while the routing table is healthy.
    pub(super) fn schedule_maintenance(&self) {
        let Some(owner) = &self.protocol else {
            return;
        };
        let proto = Arc::clone(owner);
        let node = self.node.clone();
        let ksize = self.ksize;
        let alpha = self.alpha;

        owner.spawn_task(async move {
            let mut isolated = false;
            let mut seed_delay = MAINTENANCE_TICK;
            let mut next_seed_attempt = Instant::now();
            loop {
                tokio::time::sleep(MAINTENANCE_TICK).await;
                proto.probe_failing_contacts(alpha).await;

                if proto.router.read().await.live_contacts() > 0 {
                    seed_delay = MAINTENANCE_TICK;
                    // A node that started with records and was contacted
                    // before it looked up its own id, such as a seed with
                    // no seeds of its own, joins here.
                    if isolated || !proto.has_joined() {
                        if isolated {
                            log::info!("Reconnected, refreshing the routing table");
                        }
                        isolated = false;
                        let neighbors = proto.router.read().await.find_neighbors(&node, None);
                        NodeSpiderCrawl::new(
                            Arc::clone(&proto),
                            node.clone(),
                            neighbors,
                            ksize,
                            alpha,
                        )
                        .find()
                        .await;
                        proto.note_joined();
                    }
                    continue;
                }

                isolated = true;
                let seeds = proto.seeds();
                if !seeds.is_empty() && Instant::now() >= next_seed_attempt {
                    futures::future::join_all(seeds.iter().map(|seed| proto.call_ping_addr(seed)))
                        .await;
                    seed_delay = (seed_delay * 2).min(REJOIN_BACKOFF_MAX);
                    next_seed_attempt = Instant::now() + with_jitter(seed_delay);
                }
            }
        });
    }

    /// Write the renewals of a persistent store every `flush_interval`, on
    /// the blocking pool: they wait for the device.
    pub(super) fn schedule_flush(&self) {
        let (Some(owner), true) = (&self.protocol, self.storage.is_persistent()) else {
            return;
        };
        let storage = Arc::clone(&self.storage);
        owner.spawn_task(async move {
            loop {
                tokio::time::sleep(storage.flush_interval()).await;
                let flushing = Arc::clone(&storage);
                match tokio::task::spawn_blocking(move || flushing.flush_renewals()).await {
                    Ok(0) => {}
                    Ok(written) => log::debug!("Wrote {} renewed records", written),
                    Err(error) => log::error!("flush: {error}"),
                }
            }
        });
    }

    pub(super) fn schedule_refresh(&self) {
        let Some(owner) = &self.protocol else {
            return;
        };
        let proto = Arc::clone(owner);
        let ksize = self.ksize;
        let alpha = self.alpha;

        owner.spawn_task(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
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
            }
        });
    }

    /// Republish, once a day, the records that no other node sent this one
    /// during the day (Kademlia §2.5): a record a holder republished reached
    /// the others, which then skip it.
    pub(super) fn schedule_republish(&self) {
        let Some(owner) = &self.protocol else {
            return;
        };
        let proto = Arc::clone(owner);
        let storage = Arc::clone(&self.storage);

        owner.spawn_task(async move {
            loop {
                tokio::time::sleep(REPUBLISH_INTERVAL).await;
                let old_entries = storage.iter_older_than(REPUBLISH_INTERVAL.as_secs());
                for (key_vec, value) in old_entries {
                    if key_vec.len() != ID_LEN {
                        continue;
                    }
                    let mut dkey = [0u8; ID_LEN];
                    dkey.copy_from_slice(&key_vec);
                    proto.republish(dkey, value).await;
                }
            }
        });
    }
}
