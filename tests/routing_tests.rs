//! Integration tests for the Kademlia routing table and node data structures.
//!
//! Context: the routing table is the core peer-discovery mechanism.  It
//! partitions the 160-bit XOR keyspace into K-buckets and uses XOR distance to
//! find the k nodes closest to any given target.  `NodeHeap` is the bounded
//! priority queue used during iterative lookups (SpiderCrawl).
//!
//! These tests exercise routing in isolation (no UDP sockets) to verify
//! bucket splitting, neighbour ordering, exclusion filters, and contact
//! tracking — all critical to correct DHT behaviour.

use auth_kademlia_rs::node::{Node, NodeHeap};
use primitive_types::U256;
use auth_kademlia_rs::routing::RoutingTable;
use auth_kademlia_rs::utils::digest;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_node(label: &str) -> Node {
    Node::from_id(digest(label))
}

fn make_node_with_addr(label: &str, ip: &str, port: u16) -> Node {
    Node::new(digest(label), Some(ip.to_string()), Some(port))
}

// ─────────────────────────────────────────────────────────────────────────────
// RoutingTable — basic contact management
// ─────────────────────────────────────────────────────────────────────────────

/// A newly added peer is returned by `find_neighbors`.
#[test]
fn test_add_single_peer_and_find() {
    let local = make_node("local");
    let mut rt = RoutingTable::new(local.clone(), 20);
    let peer = make_node("peer_a");
    rt.add_contact(peer.clone());

    // Search for a different target: find_neighbors excludes the target itself
    // (matches Python's `neighbor.id != node.id` check).
    let found = rt.find_neighbors(&make_node("target"), None);
    assert!(!found.is_empty(), "peer should be in the routing table");
    assert!(found.iter().any(|n| n.id == peer.id));
}

/// The local node ID is never inserted into its own routing table.
#[test]
fn test_local_node_never_added() {
    let local = make_node("local");
    let mut rt = RoutingTable::new(local.clone(), 20);
    rt.add_contact(local.clone());

    let found = rt.find_neighbors(&local, None);
    assert!(
        !found.iter().any(|n| n.id == local.id),
        "local node must not appear in its own routing table"
    );
}

/// `find_neighbors` returns at most k nodes.
#[test]
fn test_find_neighbors_capped_at_k() {
    let ksize = 5;
    let local = make_node("local");
    let mut rt = RoutingTable::new(local.clone(), ksize);

    for i in 0..50 {
        rt.add_contact(make_node(&format!("p{}", i)));
    }

    let found = rt.find_neighbors(&make_node("target"), None);
    assert!(
        found.len() <= ksize,
        "find_neighbors must return at most k={} nodes, got {}",
        ksize,
        found.len()
    );
}

/// Results are sorted by ascending XOR distance to the target.
#[test]
fn test_find_neighbors_sorted_by_xor_distance() {
    let local = make_node("local");
    let target = make_node("target");
    let mut rt = RoutingTable::new(local.clone(), 20);

    for i in 0..10 {
        rt.add_contact(make_node(&format!("node{}", i)));
    }

    let found = rt.find_neighbors(&target, None);
    let distances: Vec<U256> = found.iter().map(|n| n.distance_to(&target)).collect();
    let mut sorted = distances.clone();
    sorted.sort_unstable();
    assert_eq!(
        distances, sorted,
        "results must be in ascending XOR-distance order"
    );
}

/// A peer passed as `exclude` is absent from the result list.
#[test]
fn test_find_neighbors_exclusion_filter() {
    let local = make_node("local");
    let mut rt = RoutingTable::new(local.clone(), 20);
    let excluded = make_node("excluded");
    rt.add_contact(excluded.clone());
    rt.add_contact(make_node("other1"));
    rt.add_contact(make_node("other2"));

    let found = rt.find_neighbors(&make_node("target"), Some(&excluded));
    assert!(
        !found.iter().any(|n| n.id == excluded.id),
        "excluded peer must not appear in results"
    );
}

/// A removed contact no longer appears in `find_neighbors`.
#[test]
fn test_remove_contact() {
    let local = make_node("local");
    let mut rt = RoutingTable::new(local.clone(), 20);
    let peer = make_node("remove_me");
    rt.add_contact(peer.clone());
    rt.remove_contact(&peer);

    let found = rt.find_neighbors(&peer, None);
    assert!(
        !found.iter().any(|n| n.id == peer.id),
        "removed peer must not appear in routing table"
    );
}

/// `is_new_node` correctly distinguishes new from known contacts.
#[test]
fn test_is_new_node_detection() {
    let local = make_node("local");
    let mut rt = RoutingTable::new(local.clone(), 20);
    let peer = make_node("known");

    assert!(rt.is_new_node(&peer), "peer should be new before insertion");
    rt.add_contact(peer.clone());
    assert!(
        !rt.is_new_node(&peer),
        "peer should be known after insertion"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RoutingTable — bucket splitting
// ─────────────────────────────────────────────────────────────────────────────

/// Inserting more nodes than ksize into the bucket covering the local node
/// triggers splits, and the table still returns at most k neighbours.
#[test]
fn test_bucket_splits_on_overflow() {
    let ksize = 3;
    let local = make_node("local_split");
    let mut rt = RoutingTable::new(local.clone(), ksize);

    for i in 0..30 {
        rt.add_contact(make_node(&format!("s{}", i)));
    }

    let found = rt.find_neighbors(&make_node("any_target"), None);
    assert!(
        found.len() <= ksize,
        "after splits, find_neighbors must still return at most k={} nodes",
        ksize
    );
    // After many splits the table should have more than one bucket.
    assert!(
        rt.buckets().len() > 1,
        "overflow near local node should trigger at least one bucket split"
    );
}

/// Per §2.3, a bucket is lonely if it hasn't been updated in over an hour.
/// A freshly created routing table has just-touched buckets — none are lonely.
#[test]
fn test_fresh_table_has_no_lonely_buckets() {
    let local = make_node("lonely");
    let rt = RoutingTable::new(local, 20);
    assert!(
        rt.lonely_buckets().is_empty(),
        "a freshly created routing table should have no lonely buckets (time-based §2.3)"
    );
}

/// Adding nodes touches the bucket's last_updated timestamp, so it remains
/// non-lonely regardless of node count.
#[test]
fn test_bucket_not_lonely_after_add() {
    let ksize = 4;
    let local = make_node("local_full");
    let mut rt = RoutingTable::new(local.clone(), ksize);

    rt.add_contact(make_node("p1"));
    rt.add_contact(make_node("p2"));

    // Bucket was just updated — not lonely.
    assert!(rt.lonely_buckets().is_empty());
    // And the nodes are actually present.
    let found = rt.find_neighbors(&make_node("any"), None);
    assert!(found.len() >= 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Node — distance calculation
// ─────────────────────────────────────────────────────────────────────────────

/// XOR distance to self is always zero.
#[test]
fn test_distance_to_self_is_zero() {
    let n = make_node("x");
    assert_eq!(n.distance_to(&n), U256::zero());
}

/// XOR distance is symmetric: d(a, b) == d(b, a).
#[test]
fn test_distance_is_symmetric() {
    let a = make_node("alpha");
    let b = make_node("beta");
    assert_eq!(a.distance_to(&b), b.distance_to(&a));
}

/// Two distinct nodes have a non-zero distance.
#[test]
fn test_distinct_nodes_have_nonzero_distance() {
    let a = make_node("node_a");
    let b = make_node("node_b");
    assert_ne!(
        a.distance_to(&b),
        U256::zero(),
        "distinct nodes should have non-zero XOR distance"
    );
}

/// `address()` returns Some only when both ip and port are set.
#[test]
fn test_node_address() {
    let with_addr = make_node_with_addr("n", "10.0.0.1", 1234);
    assert_eq!(with_addr.address(), Some(("10.0.0.1".to_string(), 1234)));

    let no_addr = make_node("no_addr");
    assert_eq!(no_addr.address(), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeHeap — bounded priority queue for iterative lookups
// ─────────────────────────────────────────────────────────────────────────────

/// Inserting more nodes than maxsize keeps only the closest ones.
#[test]
fn test_nodeheap_maxsize_enforced() {
    let pivot = make_node("pivot");
    let mut heap = NodeHeap::new(pivot.clone(), 3);

    for i in 0..20 {
        heap.push_one(make_node(&format!("h{}", i)));
    }

    assert!(
        heap.len() <= 3,
        "heap must not exceed maxsize, got {} nodes",
        heap.len()
    );
}

/// Inserting the same node twice does not create duplicates.
#[test]
fn test_nodeheap_no_duplicates() {
    let pivot = make_node("pivot");
    let mut heap = NodeHeap::new(pivot, 10);
    let node = make_node("dup");
    heap.push_one(node.clone());
    heap.push_one(node);
    assert_eq!(heap.len(), 1, "duplicate insertion must be ignored");
}

/// `iter()` returns nodes in ascending XOR-distance order from the pivot.
#[test]
fn test_nodeheap_iter_distance_order() {
    let pivot = make_node("pivot_ord");
    let mut heap = NodeHeap::new(pivot.clone(), 10);
    for i in 0..5 {
        heap.push_one(make_node(&format!("ord{}", i)));
    }

    let nodes = heap.to_vec();
    let distances: Vec<U256> = nodes.iter().map(|n| n.distance_to(&pivot)).collect();
    let mut sorted = distances.clone();
    sorted.sort_unstable();
    assert_eq!(
        distances, sorted,
        "heap iteration must yield nodes in ascending distance order"
    );
}

/// `mark_contacted` moves a node out of `get_uncontacted`.
#[test]
fn test_nodeheap_contact_tracking() {
    let pivot = make_node("pivot_ct");
    let mut heap = NodeHeap::new(pivot, 10);
    let peer = make_node("ct_peer");
    heap.push_one(peer.clone());

    assert!(
        !heap.have_contacted_all(),
        "should have at least one uncontacted node"
    );
    heap.mark_contacted(&peer);
    assert!(
        heap.have_contacted_all(),
        "after marking, all nodes should be contacted"
    );
}

/// `get_uncontacted` returns only nodes not yet contacted.
#[test]
fn test_nodeheap_get_uncontacted_filters_correctly() {
    let pivot = make_node("pivot_uc");
    let mut heap = NodeHeap::new(pivot, 10);
    let a = make_node("uc_a");
    let b = make_node("uc_b");
    heap.push_one(a.clone());
    heap.push_one(b.clone());

    heap.mark_contacted(&a);
    let uncontacted = heap.get_uncontacted();
    assert_eq!(uncontacted.len(), 1);
    assert_eq!(uncontacted[0].id, b.id);
}

/// `remove` eliminates the specified nodes from the heap.
#[test]
fn test_nodeheap_remove() {
    let pivot = make_node("pivot_rm");
    let mut heap = NodeHeap::new(pivot, 10);
    let a = make_node("rm_a");
    let b = make_node("rm_b");
    heap.push_one(a.clone());
    heap.push_one(b.clone());

    heap.remove(&[a.id]);
    assert!(!heap.contains(&a), "removed node must not be in heap");
    assert!(heap.contains(&b), "non-removed node must still be in heap");
}
