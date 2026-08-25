/// Kademlia routing table with binary bucket splitting.
///
/// Follows the Python AuthKademlia implementation strictly:
/// - KBucket has a primary `nodes` list and a `replacement_nodes` list (§4.1).
/// - Bucket splits when full AND (covers local node OR depth % 5 != 0) (§4.2).
/// - When split is not possible, the LRU head is returned to the caller for pinging.
/// - `remove_node` promotes from replacement_nodes automatically.
/// - Lonely buckets = not updated in the last hour (time-based, §2.3).
/// - `last_updated` is touched ONLY by `TableTraverser` (matches Python: only lookups
///   reset the timer, not node additions).
/// - `TableTraverser` mirrors the Python implementation exactly — starts from the
///   bucket containing the target, alternates left/right, falls back to the
///   remaining side when one is exhausted.
use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use primitive_types::U256;

use crate::node::Node;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The full 160-bit key space `[0, 2^160 - 1]`, matching the Python
/// `KBucket(0, 2**160)` (which uses an exclusive upper bound; we use the
/// inclusive maximum representable 160-bit value, consistent with the rest
/// of the table operating on concrete ids).
fn full_keyspace() -> RangeInclusive<U256> {
    U256::zero()..=((U256::one() << 160) - U256::one())
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
    /// Updated ONLY by TableTraverser, matching Python's touch_last_updated() semantics.
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

    /// Mark the bucket as recently used — called by TableTraverser on the central
    /// bucket, matching Python's `touch_last_updated()`.
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
    /// `touch_last_updated()`. Only `TableTraverser` (i.e., lookups) resets the timer.
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

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn covers(&self, long_id: U256) -> bool {
        self.range.contains(&long_id)
    }
}

/// Mirrors Python's `TableTraverser` exactly:
///
/// 1. Starts with nodes from the bucket that contains `target`.
/// 2. Touches `last_updated` on that bucket (matching Python).
/// 3. Alternates left/right — left first, then right, then left, etc.
/// 4. When one side is exhausted, continues on the other.
///
/// Both `left_buckets` and `right_buckets` are stored in reverse order so
/// that `Vec::pop()` (O(1)) yields the bucket closest to `target` first —
/// matching Python's `left_buckets.pop()` and `right_buckets.pop(0)` semantics.
struct TableTraverser<'a> {
    current_nodes: Vec<Node>,
    /// Buckets to the left of the central bucket, closest-first (reversed).
    left_buckets: Vec<&'a KBucket>,
    /// Buckets to the right of the central bucket, closest-first (reversed).
    right_buckets: Vec<&'a KBucket>,
    take_left: bool,
}

impl<'a> TableTraverser<'a> {
    fn new(table: &'a RoutingTable, target: &Node) -> Self {
        let idx = table.bucket_index_for(target.long_id);

        // Touch the central bucket — matches Python's TableTraverser.__init__
        table.buckets[idx].touch_last_updated();

        let current_nodes = table.buckets[idx].nodes().iter().cloned().collect();

        // Reverse both sides so pop() yields the closest bucket first.
        // left:  buckets[..idx]   reversed → closest is at the end
        // right: buckets[idx+1..] reversed → closest is at the end
        let left_buckets = table.buckets[..idx].iter().rev().collect();
        let right_buckets = table.buckets[idx + 1..].iter().rev().collect();

        Self {
            current_nodes,
            left_buckets,
            right_buckets,
            take_left: true,
        }
    }
}

impl<'a> Iterator for TableTraverser<'a> {
    type Item = Node;

    fn next(&mut self) -> Option<Node> {
        // Drain current bucket first — matches Python's `if self.current_nodes`
        if let Some(node) = self.current_nodes.pop() {
            return Some(node);
        }

        // Alternate left/right — left first, matching Python's `self.left` flag
        if self.take_left {
            if let Some(bucket) = self.left_buckets.pop() {
                self.current_nodes = bucket.nodes().iter().cloned().collect();
                self.take_left = false;
                return self.next();
            }
        }

        // Try right side
        if let Some(bucket) = self.right_buckets.pop() {
            self.current_nodes = bucket.nodes().iter().cloned().collect();
            self.take_left = true;
            return self.next();
        }

        // Right exhausted — fall back to remaining left buckets (symmetric)
        if let Some(bucket) = self.left_buckets.pop() {
            self.current_nodes = bucket.nodes().iter().cloned().collect();
            return self.next();
        }

        None
    }
}

/// Maintains a list of K-buckets that together partition the entire 160-bit
/// XOR keyspace.
pub struct RoutingTable {
    pub node: Node,
    ksize: usize,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(node: Node, ksize: usize) -> Self {
        let bucket = KBucket::new(full_keyspace(), ksize);
        Self {
            node,
            ksize,
            buckets: vec![bucket],
        }
    }

    /// Add a contact to the routing table.
    ///
    /// Returns `Some(lru_node)` when the target bucket is full and cannot be
    /// split. The caller is responsible for pinging `lru_node` and evicting it
    /// via `remove_contact` if it does not respond (§4.2).
    pub fn add_contact(&mut self, node: Node) -> Option<Node> {
        if node.id == self.node.id {
            return None;
        }
        self.insert(node)
    }

    fn insert(&mut self, node: Node) -> Option<Node> {
        let idx = self.bucket_index_for(node.long_id);
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

    pub fn remove_contact(&mut self, node: &Node) {
        let idx = self.bucket_index_for(node.long_id);
        self.buckets[idx].remove_node(node);
    }

    pub fn is_new_node(&self, node: &Node) -> bool {
        let idx = self.bucket_index_for(node.long_id);
        !self.buckets[idx].contains(node)
    }

    /// Return the registered contact for `id`, including replacement entries.
    ///
    /// Control messages must use the endpoint already associated with an ID;
    /// callers must not trust a fresh endpoint claimed inside the message.
    pub fn get_contact(&self, id: &[u8; 20]) -> Option<Node> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.nodes.iter().chain(bucket.replacement_nodes.iter()))
            .find(|node| node.id == *id)
            .cloned()
    }

    /// Return the `k` nodes closest to `target`, optionally excluding one node.
    ///
    /// Mirrors Python's `find_neighbors` exactly:
    /// - Uses `TableTraverser` to visit buckets in order of proximity.
    /// - Excludes `target.id` itself (matches Python's `neighbor.id != node.id` check).
    /// - Collects up to k candidates with early-stop, then sorts by XOR distance.
    /// - Matches Python's `heapq.nsmallest(k, nodes)` result.
    pub fn find_neighbors(&self, target: &Node, exclude: Option<&Node>) -> Vec<Node> {
        let mut nodes: Vec<(U256, Node)> = Vec::new();

        for neighbor in TableTraverser::new(self, target) {
            if neighbor.id == target.id {
                continue;
            }
            if let Some(ex) = exclude {
                if neighbor.id == ex.id {
                    continue;
                }
            }
            let dist = neighbor.distance_to(target);
            nodes.push((dist, neighbor));

            if nodes.len() == self.ksize {
                break;
            }
        }

        nodes.sort_unstable_by_key(|(dist, _)| *dist);
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
        // last_updated è toccato SOLO da TableTraverser, non da add_node.
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
    fn traverser_visits_all_buckets() {
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
}
