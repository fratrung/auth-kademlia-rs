/// Kademlia routing table with binary bucket splitting.
///
/// Follows the Python AuthKademlia implementation strictly:
/// - KBucket has a primary `nodes` list and a `replacement_nodes` list (§4.1).
/// - Bucket splits when full AND (covers local node OR depth % 5 != 0) (§4.2).
/// - When split is not possible, the LRU head is returned to the caller for pinging.
/// - `remove_node` promotes from replacement_nodes automatically.
/// - Lonely buckets = not updated in the last hour (time-based, §2.3).
/// - `last_updated` is touched ONLY by `find_neighbors` on the bucket containing
///   the lookup target (only lookups reset the timer, not node additions).
/// - `find_neighbors` evaluates every known primary contact before truncating to
///   `k`, so the result is the exact local top-k under the full 256-bit XOR metric.
/// - Unlike Python, a contact that stops responding is not removed at the first
///   timeout. It follows Kademlia §4.1: stale after 5 failures in a row, removed
///   only if a replacement can take its place, and locked out with a backoff.
use std::collections::{HashMap, VecDeque};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use primitive_types::U256;
use rand::Rng;

use crate::node::Node;
use crate::utils::ID_LEN;

/// Consecutive failures after which a contact is stale (Kademlia §4.1).
pub const STALE_AFTER_FAILURES: u32 = 5;
/// Backoff after the first failure. Failures inside the window are not counted,
/// so a burst of concurrent timeouts counts as one.
const BACKOFF_BASE: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Below this many healthy contacts a lookup also uses failing ones: a Status
/// List GET needs that many votes, and a contact that just lost a packet is
/// usually alive. The default matches `alpha = 3`; `Server` sets it from `alpha`.
const DEFAULT_MIN_LOOKUP_CONTACTS: usize = 2;

/// Spread retries so that nodes that lost the same peer do not probe in step.
pub(crate) fn with_jitter(delay: Duration) -> Duration {
    delay + delay.mul_f64(rand::thread_rng().gen_range(0.0..0.25))
}

fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    with_jitter(BACKOFF_BASE.saturating_mul(1 << doublings).min(BACKOFF_MAX))
}

/// Present only for primary contacts that have failed since their last response.
struct ContactHealth {
    failures: u32,
    first_failure: Instant,
    retry_after: Instant,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The whole key space `[0, 2^256 - 1]`, the Python `KBucket(0, 2**256)`.
/// Python's upper bound is exclusive; here it is inclusive, because 2^256
/// is not a `U256` (ADR 0004).
fn full_keyspace() -> RangeInclusive<U256> {
    U256::zero()..=U256::MAX
}

/// A uniform random id in `range`, for the refresh of a bucket (§2.3).
pub(crate) fn random_id_in(range: &RangeInclusive<U256>) -> [u8; ID_LEN] {
    use rand::RngCore;
    let (lo, hi) = (*range.start(), *range.end());
    let mut random = [0u8; ID_LEN];
    rand::thread_rng().fill_bytes(&mut random);
    let r = U256::from_big_endian(&random);
    // The width of the whole space, 2^256, is not a `U256`: any id is in it.
    let value = match (hi - lo).checked_add(U256::one()) {
        Some(width) => lo + r % width,
        None => r,
    };
    let mut id = [0u8; ID_LEN];
    value.to_big_endian(&mut id);
    id
}

/// A single K-bucket covering a contiguous range of the XOR keyspace.
pub struct KBucket {
    /// The inclusive range `[lo, hi]` of `long_id` values this bucket covers.
    pub range: RangeInclusive<U256>,
    /// Primary node list in LRU order (least-recently-seen at front).
    nodes: VecDeque<Node>,
    /// Overflow list: nodes that arrived when the bucket was full (§4.1).
    replacement_nodes: VecDeque<Node>,
    /// Maximum number of primary nodes (`k`).
    ksize: usize,
    /// Cap on replacement list size (`k * 5`, matching Python default).
    max_replacement_nodes: usize,
    /// Timestamp of last lookup that touched this bucket (seconds since UNIX_EPOCH).
    /// AtomicU64 allows touch_last_updated() with &self — required because
    /// find_neighbors() holds only a read lock on RoutingTable.
    /// Updated ONLY by `find_neighbors` for the bucket containing the lookup target.
    last_updated: AtomicU64,
}

impl KBucket {
    pub fn new(range: RangeInclusive<U256>, ksize: usize) -> Self {
        Self {
            range,
            nodes: VecDeque::new(),
            replacement_nodes: VecDeque::new(),
            ksize,
            max_replacement_nodes: ksize * 5,
            last_updated: AtomicU64::new(now_secs()),
        }
    }

    /// Mark the bucket as recently used — called by `find_neighbors` on the bucket
    /// containing the lookup target.
    /// Takes `&self` so it works under a read lock on `RoutingTable`.
    pub fn touch_last_updated(&self) {
        self.last_updated.store(now_secs(), Ordering::Relaxed);
    }

    /// Insert or refresh `node`.
    ///
    /// - Already known → move to MRU tail, return `true`.
    /// - Bucket has capacity → append, return `true`.
    /// - Bucket full → add to replacement list (capped), return `false`.
    ///
    /// Does NOT touch `last_updated` — matches Python's `add_node` which never calls
    /// `touch_last_updated()`. Only `find_neighbors` (i.e., lookups) resets the timer.
    pub fn add_node(&mut self, node: Node) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push_back(node);
            return true;
        }
        if self.nodes.len() < self.ksize {
            self.nodes.push_back(node);
            return true;
        }
        // Bucket full: refresh position in replacement list if already there,
        // otherwise append. Cap at max_replacement_nodes (evict oldest).
        if let Some(pos) = self.replacement_nodes.iter().position(|n| n.id == node.id) {
            self.replacement_nodes.remove(pos);
        }
        self.replacement_nodes.push_back(node);
        while self.replacement_nodes.len() > self.max_replacement_nodes {
            self.replacement_nodes.pop_front();
        }
        false
    }

    /// Remove `node` from the primary list. If a replacement node is available,
    /// it is promoted automatically (§4.1).
    /// Promotes the most-recently-seen replacement node (pop_back = LIFO),
    /// matching Python's `replacement_nodes.popitem()` (last=True default).
    pub fn remove_node(&mut self, node: &Node) {
        self.replacement_nodes.retain(|n| n.id != node.id);
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            if let Some(replacement) = self.replacement_nodes.pop_back() {
                self.nodes.push_back(replacement);
            }
        }
    }

    /// Return `true` if `node` is in the primary list.
    pub fn contains(&self, node: &Node) -> bool {
        self.nodes.iter().any(|n| n.id == node.id)
    }

    /// Split this bucket at its midpoint into two new buckets.
    /// Both primary nodes and replacement nodes are redistributed (matches Python).
    pub fn split(self) -> (KBucket, KBucket) {
        let lo = *self.range.start();
        let hi = *self.range.end();
        // `lo + (hi - lo) / 2` avoids any overflow concern and matches the
        // Python midpoint `(lo + hi) // 2` for lo <= hi.
        let mid = lo + (hi - lo) / 2;

        let mut low = KBucket::new(lo..=mid, self.ksize);
        let mut high = KBucket::new(mid + U256::one()..=hi, self.ksize);

        for n in self.nodes.into_iter().chain(self.replacement_nodes) {
            if n.long_id <= mid {
                low.add_node(n);
            } else {
                high.add_node(n);
            }
        }
        (low, high)
    }

    /// Length of the shared binary prefix (in bits) of all primary node IDs.
    /// Used by the §4.2 split condition: also split when depth % 5 != 0.
    pub fn depth(&self) -> usize {
        if self.nodes.len() < 2 {
            return if self.nodes.is_empty() {
                0
            } else {
                self.nodes[0].id.len() * 8
            };
        }
        let first = &self.nodes[0].id;
        let mut prefix_len = 0;
        'outer: for (byte_idx, &byte) in first.iter().enumerate() {
            for shift in (0..8).rev() {
                let bit = (byte >> shift) & 1;
                for node in self.nodes.iter().skip(1) {
                    if ((node.id[byte_idx] >> shift) & 1) != bit {
                        break 'outer;
                    }
                }
                prefix_len += 1;
            }
        }
        prefix_len
    }

    /// A bucket is "lonely" if it hasn't been touched by a lookup in the last hour (§2.3).
    pub fn is_lonely(&self) -> bool {
        let updated = self.last_updated.load(Ordering::Relaxed);
        now_secs().saturating_sub(updated) > 3600
    }

    /// Least-recently-seen node (LRU head). Caller should ping it when the
    /// bucket is full and cannot be split (§4.2).
    pub fn head(&self) -> Option<&Node> {
        self.nodes.front()
    }

    /// Immutable view of the primary node list (LRU order).
    pub fn nodes(&self) -> &VecDeque<Node> {
        &self.nodes
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn has_replacement(&self) -> bool {
        !self.replacement_nodes.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn covers(&self, long_id: U256) -> bool {
        self.range.contains(&long_id)
    }
}

/// Maintains a list of K-buckets that together partition the entire 256-bit
/// XOR keyspace.
pub struct RoutingTable {
    pub node: Node,
    ksize: usize,
    buckets: Vec<KBucket>,
    health: HashMap<[u8; ID_LEN], ContactHealth>,
    min_lookup_contacts: usize,
}

impl RoutingTable {
    pub fn new(node: Node, ksize: usize) -> Self {
        let bucket = KBucket::new(full_keyspace(), ksize);
        Self {
            node,
            ksize,
            buckets: vec![bucket],
            health: HashMap::new(),
            min_lookup_contacts: DEFAULT_MIN_LOOKUP_CONTACTS,
        }
    }

    pub fn set_min_lookup_contacts(&mut self, count: usize) {
        self.min_lookup_contacts = count;
    }

    /// Add a contact to the routing table.
    ///
    /// Returns `Some(lru_node)` when the target bucket is full and cannot be
    /// split. The caller is responsible for pinging `lru_node` and calling
    /// `record_failure` if it does not respond (§4.2).
    pub fn add_contact(&mut self, node: Node) -> Option<Node> {
        if node.id == self.node.id {
            return None;
        }
        self.insert(node)
    }

    fn insert(&mut self, node: Node) -> Option<Node> {
        let idx = self.bucket_index_for(node.long_id);
        self.replace_stale_if_full(idx, &node);
        if self.buckets[idx].add_node(node.clone()) {
            return None;
        }
        // §4.2: split if bucket covers local node OR if depth % 5 != 0.
        if self.buckets[idx].covers(self.node.long_id)
            || !self.buckets[idx].depth().is_multiple_of(5)
        {
            self.split_bucket(idx);
            return self.insert(node);
        }
        // Cannot split: return LRU head so the caller can ping it.
        self.buckets[idx].head().cloned()
    }

    /// A full bucket gives up a stale contact for a node that is responding.
    fn replace_stale_if_full(&mut self, idx: usize, node: &Node) {
        let bucket = &self.buckets[idx];
        if bucket.len() < self.ksize || bucket.contains(node) {
            return;
        }
        let stale = bucket
            .nodes()
            .iter()
            .find(|n| self.is_stale(&n.id))
            .cloned();
        if let Some(stale) = stale {
            self.remove_contact(&stale);
        }
    }

    pub fn remove_contact(&mut self, node: &Node) {
        let idx = self.bucket_index_for(node.long_id);
        self.buckets[idx].remove_node(node);
        self.health.remove(&node.id);
    }

    /// Count a contact's failure to respond (Kademlia §4.1). A stale contact is
    /// removed only if a replacement can take its place, so a node that lost its
    /// own connection does not void its table.
    pub fn record_failure(&mut self, node: &Node) {
        self.record_failure_at(node, Instant::now());
    }

    pub(crate) fn record_failure_at(&mut self, node: &Node, now: Instant) {
        let idx = self.bucket_index_for(node.long_id);
        if !self.buckets[idx].contains(node) {
            self.buckets[idx].remove_node(node);
            return;
        }
        let failures = match self.health.get_mut(&node.id) {
            Some(health) if now < health.retry_after => return,
            Some(health) => {
                health.failures += 1;
                health.retry_after = now + backoff(health.failures);
                health.failures
            }
            None => {
                self.health.insert(
                    node.id,
                    ContactHealth {
                        failures: 1,
                        first_failure: now,
                        retry_after: now + backoff(1),
                    },
                );
                1
            }
        };
        if failures >= STALE_AFTER_FAILURES && self.buckets[idx].has_replacement() {
            self.remove_contact(node);
        }
    }

    /// Clear a contact's failures. Returns how long it had been failing, or
    /// `None` if it was healthy.
    pub fn record_success(&mut self, id: &[u8; ID_LEN]) -> Option<Duration> {
        self.health
            .remove(id)
            .map(|health| health.first_failure.elapsed())
    }

    pub fn has_failures(&self, id: &[u8; ID_LEN]) -> bool {
        self.health.contains_key(id)
    }

    pub fn is_stale(&self, id: &[u8; ID_LEN]) -> bool {
        self.health
            .get(id)
            .is_some_and(|health| health.failures >= STALE_AFTER_FAILURES)
    }

    /// Failing contacts whose backoff has elapsed, the longest overdue first.
    pub fn contacts_due_for_probe(&self, limit: usize) -> Vec<Node> {
        let now = Instant::now();
        let mut due: Vec<(Instant, Node)> = self
            .buckets
            .iter()
            .flat_map(|bucket| bucket.nodes().iter())
            .filter_map(|node| {
                let health = self.health.get(&node.id)?;
                (now >= health.retry_after).then(|| (health.retry_after, node.clone()))
            })
            .collect();
        due.sort_unstable_by_key(|(retry_after, _)| *retry_after);
        due.truncate(limit);
        due.into_iter().map(|(_, node)| node).collect()
    }

    /// Primary contacts with no failure since their last response.
    pub fn live_contacts(&self) -> usize {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.nodes().iter())
            .filter(|node| !self.has_failures(&node.id))
            .count()
    }

    pub fn has_contacts(&self) -> bool {
        self.buckets.iter().any(|bucket| !bucket.is_empty())
    }

    pub fn is_new_node(&self, node: &Node) -> bool {
        let idx = self.bucket_index_for(node.long_id);
        !self.buckets[idx].contains(node)
    }

    /// Return the registered contact for `id`, including replacement entries.
    ///
    /// Control messages must use the endpoint already associated with an ID;
    /// callers must not trust a fresh endpoint claimed inside the message.
    pub fn get_contact(&self, id: &[u8; ID_LEN]) -> Option<Node> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.nodes.iter().chain(bucket.replacement_nodes.iter()))
            .find(|node| node.id == *id)
            .cloned()
    }

    /// Return the exact `k` known primary contacts closest to `target`, optionally
    /// excluding one node. Candidate selection uses the full 256-bit XOR distance
    /// before truncation; otherwise bucket traversal order could omit a closer node.
    ///
    /// Failing contacts are skipped, so a lookup does not pay their timeout, unless
    /// too few healthy ones remain. Stale contacts are the last resort.
    pub fn find_neighbors(&self, target: &Node, exclude: Option<&Node>) -> Vec<Node> {
        let healthy = self.closest(target, exclude, |node| !self.has_failures(&node.id));
        if healthy.len() >= self.min_lookup_contacts {
            return healthy;
        }
        let not_stale = self.closest(target, exclude, |node| !self.is_stale(&node.id));
        if not_stale.is_empty() {
            self.closest(target, exclude, |_| true)
        } else {
            not_stale
        }
    }

    /// Contacts to report to other nodes. Stale contacts are not passed on.
    pub fn find_neighbors_to_advertise(&self, target: &Node, exclude: Option<&Node>) -> Vec<Node> {
        self.closest(target, exclude, |node| !self.is_stale(&node.id))
    }

    fn closest(
        &self,
        target: &Node,
        exclude: Option<&Node>,
        keep: impl Fn(&Node) -> bool,
    ) -> Vec<Node> {
        let target_bucket = self.bucket_index_for(target.long_id);
        self.buckets[target_bucket].touch_last_updated();

        let mut nodes: Vec<(U256, Node)> = self
            .buckets
            .iter()
            .flat_map(|bucket| bucket.nodes().iter())
            .filter(|neighbor| {
                neighbor.id != target.id
                    && exclude
                        .map(|excluded| neighbor.id != excluded.id)
                        .unwrap_or(true)
                    && keep(neighbor)
            })
            .map(|neighbor| (neighbor.distance_to(target), neighbor.clone()))
            .collect();

        nodes.sort_unstable_by_key(|(dist, _)| *dist);
        nodes.truncate(self.ksize);
        nodes.into_iter().map(|(_, n)| n).collect()
    }

    pub fn lonely_buckets(&self) -> Vec<&KBucket> {
        self.buckets.iter().filter(|b| b.is_lonely()).collect()
    }

    /// Split the bucket at `idx` using `KBucket::split()`, which distributes
    /// both primary nodes and replacement nodes into the two halves.
    fn split_bucket(&mut self, idx: usize) {
        let bucket = self.buckets.remove(idx);
        let (low, high) = bucket.split();
        self.buckets.insert(idx, high);
        self.buckets.insert(idx, low);
    }

    fn bucket_index_for(&self, long_id: U256) -> usize {
        self.buckets
            .iter()
            .position(|b| b.covers(long_id))
            .unwrap_or(self.buckets.len() - 1)
    }

    pub fn buckets(&self) -> &Vec<KBucket> {
        &self.buckets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::digest;

    fn make_node(key: &str) -> Node {
        Node::from_id(digest(key))
    }

    fn node_with_first_byte(first: u8) -> Node {
        let mut id = [0u8; ID_LEN];
        id[0] = first;
        Node::from_id(id)
    }

    /// k=2 table whose far bucket holds two contacts, cannot split, and keeps a
    /// third node in its replacement list.
    fn table_with_replacement() -> (RoutingTable, Node, Node) {
        let mut rt = RoutingTable::new(Node::from_id([0u8; ID_LEN]), 2);
        let (oldest, other) = (node_with_first_byte(0x80), node_with_first_byte(0x84));
        rt.add_contact(oldest.clone());
        rt.add_contact(other);
        let waiting = node_with_first_byte(0x86);
        assert!(rt.add_contact(waiting.clone()).is_some());
        (rt, oldest, waiting)
    }

    fn fail_until_stale(rt: &mut RoutingTable, node: &Node) {
        let mut now = Instant::now();
        for _ in 0..STALE_AFTER_FAILURES {
            rt.record_failure_at(node, now);
            now += Duration::from_secs(10_000);
        }
    }

    #[test]
    fn one_failure_keeps_the_contact() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        rt.record_failure(&peer);
        assert!(!rt.is_new_node(&peer));
        assert!(rt.has_failures(&peer.id));
    }

    #[test]
    fn failures_inside_the_backoff_window_count_once() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        for _ in 0..100 {
            rt.record_failure(&peer);
        }
        assert_eq!(rt.health[&peer.id].failures, 1);
        assert!(!rt.is_stale(&peer.id));
    }

    #[test]
    fn stale_contact_without_replacement_is_kept_and_not_advertised() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        let (peer, other) = (make_node("peer"), make_node("other"));
        rt.add_contact(peer.clone());
        rt.add_contact(other.clone());
        fail_until_stale(&mut rt, &peer);
        assert!(rt.is_stale(&peer.id));
        assert!(!rt.is_new_node(&peer));
        let target = make_node("target");
        let advertised = rt.find_neighbors_to_advertise(&target, None);
        assert!(advertised.iter().all(|n| n.id != peer.id));
        assert!(advertised.iter().any(|n| n.id == other.id));
    }

    #[test]
    fn stale_contact_with_replacement_is_replaced() {
        let (mut rt, oldest, waiting) = table_with_replacement();
        fail_until_stale(&mut rt, &oldest);
        assert!(rt.is_new_node(&oldest));
        assert!(!rt.is_new_node(&waiting));
        assert!(!rt.has_failures(&oldest.id));
    }

    #[test]
    fn response_clears_the_failures() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        rt.record_failure(&peer);
        assert!(rt.record_success(&peer.id).is_some());
        assert!(!rt.has_failures(&peer.id));
        assert!(rt.record_success(&peer.id).is_none());
    }

    #[test]
    fn lookups_skip_failing_contacts_while_two_healthy_ones_remain() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        let (a, b, c) = (make_node("a"), make_node("b"), make_node("c"));
        for peer in [&a, &b, &c] {
            rt.add_contact(peer.clone());
        }
        let target = make_node("target");

        rt.record_failure(&a);
        let found = rt.find_neighbors(&target, None);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|n| n.id != a.id));
        assert_eq!(rt.live_contacts(), 2);

        rt.record_failure(&b);
        assert_eq!(rt.find_neighbors(&target, None).len(), 3);
        assert_eq!(rt.live_contacts(), 1);
    }

    #[test]
    fn min_lookup_contacts_follows_the_configured_quorum() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        rt.set_min_lookup_contacts(3);
        let (a, b, c) = (make_node("a"), make_node("b"), make_node("c"));
        for peer in [&a, &b, &c] {
            rt.add_contact(peer.clone());
        }
        rt.record_failure(&a);
        assert_eq!(rt.find_neighbors(&make_node("target"), None).len(), 3);
    }

    #[test]
    fn stale_contacts_are_the_last_resort_for_lookups() {
        let mut rt = RoutingTable::new(make_node("local"), 20);
        let (stale, healthy) = (make_node("stale"), make_node("healthy"));
        rt.add_contact(stale.clone());
        rt.add_contact(healthy.clone());
        fail_until_stale(&mut rt, &stale);
        let target = make_node("target");
        let found = rt.find_neighbors(&target, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, healthy.id);

        rt.remove_contact(&healthy);
        let found = rt.find_neighbors(&target, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, stale.id);
    }

    #[test]
    fn add_and_find() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 3);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        // Search for a different target: peer must appear in results.
        let found = rt.find_neighbors(&make_node("target"), None);
        assert!(!found.is_empty());
        assert!(found.iter().any(|n| n.id == peer.id));
    }

    #[test]
    fn ignores_self() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 3);
        rt.add_contact(local.clone());
        let found = rt.find_neighbors(&local, None);
        assert!(!found.iter().any(|n| n.id == local.id));
    }

    #[test]
    fn remove_contact() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 20);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        rt.remove_contact(&peer);
        assert!(rt.find_neighbors(&peer, None).is_empty());
    }

    #[test]
    fn replacement_node_promoted_on_eviction() {
        let local = make_node("local");
        let ksize = 1;
        let mut rt = RoutingTable::new(local.clone(), ksize);
        let peer_a = make_node("peer_a");
        let peer_b = make_node("peer_b");
        rt.add_contact(peer_a.clone());
        rt.add_contact(peer_b.clone());
        rt.remove_contact(&peer_a);
        let found = rt.find_neighbors(&make_node("target"), None);
        assert!(found.iter().any(|n| n.id == peer_b.id));
    }

    #[test]
    fn bucket_splits_on_overflow() {
        let local = make_node("local");
        let ksize = 2;
        let mut rt = RoutingTable::new(local.clone(), ksize);
        for i in 0..20 {
            rt.add_contact(make_node(&format!("peer{}", i)));
        }
        let found = rt.find_neighbors(&make_node("target"), None);
        assert!(found.len() <= ksize);
    }

    #[test]
    fn find_neighbors_excludes_target() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 20);
        let target = make_node("target");
        rt.add_contact(target.clone());
        for i in 0..5 {
            rt.add_contact(make_node(&format!("peer{}", i)));
        }
        let found = rt.find_neighbors(&target, None);
        assert!(!found.iter().any(|n| n.id == target.id));
    }

    #[test]
    fn touch_last_updated_prevents_lonely() {
        let local = make_node("local");
        let rt = RoutingTable::new(local.clone(), 3);
        // Appena creato non deve essere lonely (last_updated = now).
        assert!(rt.lonely_buckets().is_empty());
    }

    #[test]
    fn add_node_does_not_reset_lonely_timer() {
        // last_updated è toccato SOLO da find_neighbors, non da add_node.
        // Verifichiamo che dopo add_contact il bucket risulti ancora non-lonely
        // (perché è appena stato creato), ma che add_contact non possa mai
        // "ringiovanire" un bucket che fosse già vecchio.
        // In questo test costruiamo un KBucket direttamente e misuriamo che
        // last_updated non cambi dopo add_node.
        let mut b = KBucket::new(full_keyspace(), 20);
        let t_before = b.last_updated.load(Ordering::Relaxed);
        b.add_node(make_node("x"));
        let t_after = b.last_updated.load(Ordering::Relaxed);
        assert_eq!(
            t_before, t_after,
            "add_node non deve aggiornare last_updated"
        );
    }

    #[test]
    fn touch_last_updated_resets_timer() {
        let b = KBucket::new(full_keyspace(), 20);
        let t_before = b.last_updated.load(Ordering::Relaxed);
        // Simula il passaggio di un secondo.
        std::thread::sleep(std::time::Duration::from_secs(1));
        b.touch_last_updated();
        let t_after = b.last_updated.load(Ordering::Relaxed);
        assert!(
            t_after > t_before,
            "touch_last_updated deve aggiornare last_updated"
        );
    }

    #[test]
    fn find_neighbors_visits_all_buckets() {
        let local = make_node("local");
        let ksize = 20;
        let mut rt = RoutingTable::new(local.clone(), ksize);
        for i in 0..15 {
            rt.add_contact(make_node(&format!("peer{}", i)));
        }
        let target = make_node("target");
        let found = rt.find_neighbors(&target, None);
        assert!(!found.is_empty());
        assert!(found.len() <= ksize);
    }

    /// The first bucket covers the whole key space, up to 2^256 - 1, the
    /// largest `U256` (ADR 0004); it splits into two halves that meet without
    /// a gap.
    #[test]
    fn the_whole_key_space_splits_into_two_halves() {
        let whole = full_keyspace();
        assert_eq!((*whole.start(), *whole.end()), (U256::zero(), U256::MAX));
        let (low, high) = KBucket::new(whole, 20).split();
        assert_eq!(*low.range.start(), U256::zero());
        assert_eq!(*low.range.end() + U256::one(), *high.range.start());
        assert_eq!(*high.range.start(), U256::one() << 255);
        assert_eq!(*high.range.end(), U256::MAX);
    }

    /// An id at the top of the space, all bytes 0xFF, lies in one bucket of
    /// the table, and its distance from the id of all zeros is the largest.
    #[test]
    fn an_id_at_the_top_of_the_space_finds_its_bucket() {
        let bottom = Node::from_id([0; ID_LEN]);
        let top = Node::from_id([0xFF; ID_LEN]);
        assert_eq!(top.long_id, U256::MAX);
        assert_eq!(bottom.distance_to(&top), U256::MAX);

        // k = 2: the third contact splits the first bucket.
        let mut rt = RoutingTable::new(bottom, 2);
        rt.add_contact(top.clone());
        rt.add_contact(node_with_first_byte(0x80));
        rt.add_contact(node_with_first_byte(0x40));
        assert!(rt.buckets().len() > 1);
        let covering: Vec<_> = rt
            .buckets()
            .iter()
            .filter(|b| b.covers(top.long_id))
            .collect();
        assert_eq!(covering.len(), 1);
        assert!(covering[0].contains(&top));
        assert_eq!(*covering[0].range.end(), U256::MAX);
    }

    /// A refresh id lies in its bucket, also in the bucket that covers the
    /// whole space, whose width, 2^256, is not a `U256`, and at the top.
    #[test]
    fn a_refresh_id_lies_in_its_bucket() {
        let max = U256::MAX;
        for range in [
            U256::zero()..=max,
            (U256::one() << 255)..=max,
            (max - U256::one())..=max,
            U256::from(7)..=U256::from(7),
            U256::zero()..=U256::from(255),
        ] {
            for _ in 0..200 {
                let id = Node::from_id(random_id_in(&range)).long_id;
                assert!(range.contains(&id), "{id} outside {range:?}");
            }
        }
    }
}
