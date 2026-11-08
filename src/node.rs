/// Node and NodeHeap — core Kademlia data structures.
///
/// `Node` represents a single peer identified by a 20-byte SHA-1 ID.
/// `NodeHeap` holds the nodes met during an iterative lookup, ordered by XOR
/// distance from a pivot node; reads see the closest `maxsize`.
use std::collections::HashSet;
use std::fmt;

use primitive_types::U256;

use crate::utils::ID_LEN;

/// A Kademlia peer node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Node {
    /// Raw 20-byte node ID.
    pub id: [u8; ID_LEN],
    pub ip: Option<String>,
    pub port: Option<u16>,
    /// The node ID interpreted as a full 160-bit unsigned integer for XOR
    /// distance calculations. Stored in a `U256` (the smallest fixed-width
    /// integer that holds 160 bits without loss), matching the Python
    /// AuthKademlia `int(node_id.hex(), 16)`. All 20 bytes are preserved, so
    /// the XOR metric and bucket ordering are canonical (no folding).
    pub long_id: U256,
}

impl Node {
    /// Create a node with a known address.
    pub fn new(id: [u8; ID_LEN], ip: Option<String>, port: Option<u16>) -> Self {
        let long_id = Self::id_to_u256(&id);
        Self {
            id,
            ip,
            port,
            long_id,
        }
    }

    /// Create a node without an address (used as a lookup key).
    pub fn from_id(id: [u8; ID_LEN]) -> Self {
        Self::new(id, None, None)
    }

    /// Interpret a 20-byte ID as a big-endian 160-bit integer (held in a
    /// `U256`). No bits are discarded — the top 12 bytes of the `U256` are
    /// always zero, so the value lies in `[0, 2^160)`.
    fn id_to_u256(id: &[u8; ID_LEN]) -> U256 {
        U256::from_big_endian(id)
    }

    /// XOR distance to another node (used for Kademlia routing).
    pub fn distance_to(&self, other: &Node) -> U256 {
        self.long_id ^ other.long_id
    }

    /// Returns `true` if both nodes share the same IP and port.
    pub fn same_home_as(&self, other: &Node) -> bool {
        self.ip == other.ip && self.port == other.port
    }

    /// Return the node's address as `(ip, port)` if both are known.
    pub fn address(&self) -> Option<(String, u16)> {
        match (&self.ip, self.port) {
            (Some(ip), Some(port)) => Some((ip.clone(), port)),
            _ => None,
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.ip, self.port) {
            (Some(ip), Some(port)) => write!(f, "{}:{}", ip, port),
            _ => {
                // Key-space target node (no address) — show first 8 bytes of ID as hex.
                let hex: String = self.id[..8].iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "<key:{}>", hex)
            }
        }
    }
}

/// An entry paired with its XOR distance from the heap's pivot node.
#[derive(Debug, Clone)]
struct HeapEntry {
    distance: U256,
    node: Node,
}

/// The nodes met during a lookup, ordered by XOR distance from a pivot; reads
/// see the `maxsize` closest.
///
/// Every node pushed is kept, not only the closest `maxsize`: when a lookup
/// removes a peer that did not answer, the next node takes its place, so the
/// lookup still ends with `k` nodes if it met more (Python's `heapq` +
/// `nsmallest`). `iter`, `to_vec`, `get_ids`, `get_uncontacted`,
/// `have_contacted_all` and `len` see the closest `maxsize`; `contains`,
/// `get_node`, `remove` and `popleft` see every node. Backed by a `Vec` kept
/// sorted by ascending distance, which every read needs. With the full
/// 160-bit metric the distance order is total (distinct ids never tie).
#[derive(Debug, Clone)]
pub struct NodeHeap {
    /// The pivot node — all distances are relative to this.
    pub node: Node,
    /// Every node pushed and not removed, sorted by ascending XOR distance.
    entries: Vec<HeapEntry>,
    /// The ids in `entries`.
    ids: HashSet<[u8; ID_LEN]>,
    /// IDs of nodes that have been marked as contacted.
    pub contacted: HashSet<[u8; ID_LEN]>,
    /// How many of the closest nodes the reads see.
    pub maxsize: usize,
}

impl NodeHeap {
    /// Create an empty heap with the given pivot and capacity.
    pub fn new(node: Node, maxsize: usize) -> Self {
        Self {
            node,
            entries: Vec::new(),
            ids: HashSet::new(),
            contacted: HashSet::new(),
            maxsize,
        }
    }

    /// Insert a batch of nodes, ignoring duplicates, and keep the order.
    pub fn push(&mut self, nodes: Vec<Node>) {
        let mut added = false;
        for node in nodes {
            if self.ids.insert(node.id) {
                let distance = self.node.distance_to(&node);
                self.entries.push(HeapEntry { distance, node });
                added = true;
            }
        }
        if added {
            self.entries.sort_unstable_by_key(|e| e.distance);
        }
    }

    /// Insert a single node.
    pub fn push_one(&mut self, node: Node) {
        self.push(vec![node]);
    }

    /// Remove nodes by ID. Preserves the ascending-distance ordering.
    pub fn remove(&mut self, peers: &[[u8; ID_LEN]]) {
        if peers.is_empty() {
            return;
        }
        let peer_set: HashSet<[u8; ID_LEN]> = peers.iter().cloned().collect();
        self.entries.retain(|e| !peer_set.contains(&e.node.id));
        self.ids.retain(|id| !peer_set.contains(id));
    }

    /// Pop and return the single closest node.
    pub fn popleft(&mut self) -> Option<Node> {
        if self.entries.is_empty() {
            None
        } else {
            let node = self.entries.remove(0).node;
            self.ids.remove(&node.id);
            Some(node)
        }
    }

    /// Return `true` if the node is in the heap, among the closest `maxsize`
    /// or beyond.
    pub fn contains(&self, node: &Node) -> bool {
        self.ids.contains(&node.id)
    }

    /// Look up a node by its raw ID.
    pub fn get_node(&self, node_id: &[u8; ID_LEN]) -> Option<Node> {
        self.entries
            .iter()
            .find(|e| &e.node.id == node_id)
            .map(|e| e.node.clone())
    }

    /// Return `true` if every node in the heap has been contacted.
    pub fn have_contacted_all(&self) -> bool {
        self.get_uncontacted().is_empty()
    }

    /// Return the IDs of the closest `maxsize` nodes (closest first).
    pub fn get_ids(&self) -> Vec<[u8; ID_LEN]> {
        self.iter().map(|n| n.id).collect()
    }

    /// Number of nodes the reads see (at most `maxsize`).
    pub fn len(&self) -> usize {
        self.entries.len().min(self.maxsize)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mark a node as contacted so it is excluded from future crawl rounds.
    pub fn mark_contacted(&mut self, node: &Node) {
        self.contacted.insert(node.id);
    }

    /// Return nodes that have not yet been contacted, in ascending distance order.
    pub fn get_uncontacted(&self) -> Vec<Node> {
        self.iter()
            .filter(|n| !self.contacted.contains(&n.id))
            .collect()
    }

    /// Iterate over nodes in ascending XOR-distance order, limited to `maxsize`.
    /// `entries` is maintained sorted, so this is a direct view.
    pub fn iter(&self) -> impl Iterator<Item = Node> + '_ {
        self.entries
            .iter()
            .take(self.maxsize)
            .map(|e| e.node.clone())
    }

    /// Collect the closest `maxsize` nodes into a `Vec` (closest first).
    pub fn to_vec(&self) -> Vec<Node> {
        self.iter().collect()
    }
}

impl fmt::Display for NodeHeap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nodes: Vec<String> = self.iter().map(|n| n.to_string()).collect();
        write!(f, "[{}]", nodes.join(", "))
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
    fn heap_respects_maxsize() {
        let pivot = make_node("pivot");
        let mut heap = NodeHeap::new(pivot, 3);
        for i in 0..10 {
            heap.push_one(make_node(&i.to_string()));
        }
        assert_eq!(heap.len(), 3);
        assert_eq!(heap.to_vec().len(), 3);
    }

    /// The node at `distance` from the pivot `[0; ID_LEN]`.
    fn node_at(distance: u8) -> Node {
        let mut id = [0u8; ID_LEN];
        id[ID_LEN - 1] = distance;
        Node::from_id(id)
    }

    /// A node beyond `maxsize` is kept, and comes back when a closer one is
    /// removed: a lookup that drops a peer that did not answer still has `k`
    /// nodes if it met more than `k`.
    #[test]
    fn a_node_beyond_maxsize_comes_back_when_a_closer_one_is_removed() {
        let mut heap = NodeHeap::new(node_at(0), 3);
        heap.push((1..=4).map(node_at).collect());
        let ids = |distances: &[u8]| -> Vec<[u8; ID_LEN]> {
            distances.iter().map(|d| node_at(*d).id).collect()
        };
        assert_eq!(heap.get_ids(), ids(&[1, 2, 3]));
        heap.remove(&[node_at(1).id]);
        assert_eq!(heap.get_ids(), ids(&[2, 3, 4]));
        assert!(heap.contains(&node_at(4)));
    }

    #[test]
    fn heap_no_duplicates() {
        let pivot = make_node("pivot");
        let mut heap = NodeHeap::new(pivot, 10);
        let node = make_node("a");
        heap.push_one(node.clone());
        heap.push_one(node);
        assert_eq!(heap.entries.len(), 1);
    }

    #[test]
    fn contacted_tracking() {
        let pivot = make_node("pivot");
        let mut heap = NodeHeap::new(pivot, 10);
        let node = make_node("peer");
        heap.push_one(node.clone());
        assert!(!heap.have_contacted_all());
        heap.mark_contacted(&node);
        assert!(heap.have_contacted_all());
    }

    // --- Regression tests for the full 160-bit XOR metric (PORTING_REVIEW §1) ---
    //
    // The previous implementation folded the 20-byte (160-bit) id into a u128 by
    // XOR-ing bytes [16..20] into the high 32 bits. That fold is lossy: it both
    // inverts distance ordering and lets distinct ids collide. These two tests
    // pin the canonical behaviour (matching the Python AuthKademlia 160-bit int).

    #[test]
    fn xor_metric_respects_full_160bit_order() {
        // `a` differs from the zero pivot only in a low-significance byte
        // (true XOR distance 2^31); `b` only in the most-significant byte
        // (true XOR distance 2^152). `a` must rank far closer than `b`.
        let pivot = Node::from_id([0u8; ID_LEN]);
        let mut a_id = [0u8; ID_LEN];
        a_id[16] = 0x80;
        let mut b_id = [0u8; ID_LEN];
        b_id[0] = 0x01;
        let a = Node::from_id(a_id);
        let b = Node::from_id(b_id);
        assert!(
            pivot.distance_to(&a) < pivot.distance_to(&b),
            "XOR metric must follow the full 160-bit order (u128 folding inverted it)"
        );
    }

    #[test]
    fn distinct_ids_keep_distinct_long_id() {
        // These two ids differ only in bytes that the old u128 fold collapsed
        // onto each other (byte[0] vs byte[16] in the high 32 bits).
        let mut c1 = [0u8; ID_LEN];
        c1[0] = 0xAA;
        c1[16] = 0x55;
        let mut c2 = [0u8; ID_LEN];
        c2[0] = 0xAA ^ 0x55;
        assert_ne!(
            Node::from_id(c1).long_id,
            Node::from_id(c2).long_id,
            "distinct 160-bit ids must not collide in long_id"
        );
    }
}
