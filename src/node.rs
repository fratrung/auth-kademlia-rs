/// Node and NodeHeap — core Kademlia data structures.
///
/// `Node` represents a single peer identified by a 20-byte SHA-1 ID.
/// `NodeHeap` is a bounded min-heap ordered by XOR distance from a pivot node,
/// used during iterative lookups.
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

    /// Create a node with a random ID.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; ID_LEN];
        rand::thread_rng().fill_bytes(&mut id);
        Self::from_id(id)
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

/// A bounded set of the `k` nodes closest to a pivot, ordered by XOR distance.
///
/// Kademlia lookups maintain the `k` closest known nodes. Backed by a `Vec`
/// kept sorted by ascending distance: every consumer (`iter`, `popleft`,
/// `to_vec`) needs the closest-first order, so maintaining the invariant on
/// mutation is both simpler and cheaper than a `BinaryHeap` that gets
/// drained and re-sorted on each access. With the full 160-bit metric the
/// distance order is total (distinct ids never tie), so the ordering is
/// unambiguous. Mirrors Python's `heapq` + `nsmallest` semantics.
#[derive(Debug, Clone)]
pub struct NodeHeap {
    /// The pivot node — all distances are relative to this.
    pub node: Node,
    /// The k closest known nodes, sorted by ascending XOR distance.
    entries: Vec<HeapEntry>,
    /// IDs of nodes that have been marked as contacted.
    pub contacted: HashSet<[u8; ID_LEN]>,
    /// Maximum number of nodes the heap may hold.
    pub maxsize: usize,
}

impl NodeHeap {
    /// Create an empty heap with the given pivot and capacity.
    pub fn new(node: Node, maxsize: usize) -> Self {
        Self {
            node,
            entries: Vec::new(),
            contacted: HashSet::new(),
            maxsize,
        }
    }

    /// Insert a batch of nodes, ignoring duplicates.
    ///
    /// After insertion the set is re-sorted and trimmed to `maxsize`, keeping
    /// the closest nodes.
    pub fn push(&mut self, nodes: Vec<Node>) {
        let mut added = false;
        for node in nodes {
            if !self.contains(&node) {
                let distance = self.node.distance_to(&node);
                self.entries.push(HeapEntry { distance, node });
                added = true;
            }
        }
        if added {
            self.entries.sort_unstable_by_key(|e| e.distance);
            self.entries.truncate(self.maxsize);
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
    }

    /// Pop and return the single closest node.
    pub fn popleft(&mut self) -> Option<Node> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.entries.remove(0).node)
        }
    }

    /// Return `true` if the node is already in the heap.
    pub fn contains(&self, node: &Node) -> bool {
        self.entries.iter().any(|e| e.node.id == node.id)
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

    /// Return the IDs of all nodes currently in the heap (closest first).
    pub fn get_ids(&self) -> Vec<[u8; ID_LEN]> {
        self.iter().map(|n| n.id).collect()
    }

    /// Number of nodes in the heap (capped at `maxsize`).
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

    /// Collect all nodes into a `Vec` (closest first).
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
        assert!(heap.entries.len() <= 3);
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
