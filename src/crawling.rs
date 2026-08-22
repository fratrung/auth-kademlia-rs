/// Iterative Kademlia lookup (spider crawl).
///
/// Implements the three-class crawl hierarchy from the original Python:
///
/// - `SpiderCrawl`       — shared crawl state and the `find_round` driver
/// - `ValueSpiderCrawl`  — lookup terminating when a value is found
/// - `NodeSpiderCrawl`   — lookup terminating when the k-closest nodes are found
use std::collections::HashMap;
use std::sync::Arc;

use log;

use crate::node::{Node, NodeHeap};
use crate::utils::ID_LEN;

/// Raw tuple returned by a protocol `call_find_*` method:
/// `(response_received, payload)`.
#[derive(Debug, Clone)]
pub struct RawResponse(pub bool, pub FindPayload);

/// The payload half of a `RawResponse`.
#[derive(Debug, Clone)]
pub enum FindPayload {
    /// A list of `(id_bytes, ip, port)` triples (find_node result or value miss).
    Nodes(Vec<(Vec<u8>, Option<String>, Option<u16>)>),
    /// A found value (find_value hit).
    Value(Vec<u8>),
    /// No response or a timeout.
    Empty,
}

pub struct RPCFindResponse {
    response: RawResponse,
}

impl RPCFindResponse {
    pub fn new(response: RawResponse) -> Self {
        Self { response }
    }

    pub fn happened(&self) -> bool {
        self.response.0
    }

    /// Did the response contain a value?
    pub fn has_value(&self) -> bool {
        matches!(self.response.1, FindPayload::Value(_))
    }

    /// Return the value, or `None` if the response did not contain one.
    pub fn get_value(&self) -> Option<Vec<u8>> {
        match &self.response.1 {
            FindPayload::Value(v) => Some(v.clone()),
            _ => None,
        }
    }

    /// Decode the node list from the payload.
    pub fn get_node_list(&self) -> Vec<Node> {
        match &self.response.1 {
            FindPayload::Nodes(tuples) => tuples
                .iter()
                .filter_map(|(id_bytes, ip, port)| {
                    if id_bytes.len() != ID_LEN {
                        return None;
                    }
                    let mut id = [0u8; ID_LEN];
                    id.copy_from_slice(id_bytes);
                    Some(Node::new(id, ip.clone(), *port))
                })
                .collect(),
            _ => vec![],
        }
    }
}

/// The subset of the Kademlia protocol needed by the spider crawl.
///
/// This trait is implemented by `KademliaProtocol` and can be mocked in tests.
#[async_trait::async_trait]
pub trait SpiderProtocol: Send + Sync {
    /// `Arc<Self>` receiver so implementations can spawn `welcome_if_new` tasks.
    async fn call_find_node(self: Arc<Self>, peer: Node, target: Node) -> RawResponse;
    async fn call_find_value(self: Arc<Self>, peer: Node, target: Node) -> RawResponse;
    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool;
}

/// Shared state for iterative Kademlia lookups.
pub struct SpiderCrawl<P: SpiderProtocol> {
    pub protocol: Arc<P>,
    pub ksize: usize,
    pub alpha: usize,
    /// The target key we are searching for.
    pub node: Node,
    /// The k closest known nodes to `node`, with contact tracking.
    pub nearest: NodeHeap,
    /// IDs seen in the previous round, used to detect convergence.
    pub last_ids_crawled: Vec<[u8; ID_LEN]>,
}

impl<P: SpiderProtocol> SpiderCrawl<P> {
    pub fn new(protocol: Arc<P>, node: Node, peers: Vec<Node>, ksize: usize, alpha: usize) -> Self {
        let mut nearest = NodeHeap::new(node.clone(), ksize);
        log::info!(
            "Starting lookup for key {} with {} initial peers",
            node,
            peers.len()
        );
        nearest.push(peers);
        Self {
            protocol,
            ksize,
            alpha,
            node,
            nearest,
            last_ids_crawled: vec![],
        }
    }

    /// Execute one round of the iterative lookup.
    ///
    /// Contacts up to `alpha` uncontacted nearest nodes concurrently using
    /// `rpcmethod`. Returns a map from peer ID to raw response.
    ///
    /// When the nearest set has not changed since the last round (convergence),
    /// *all* remaining uncontacted nodes are queried instead of just `alpha`.
    pub async fn find_round<F, Fut>(&mut self, rpcmethod: F) -> HashMap<[u8; ID_LEN], RawResponse>
    where
        F: Fn(Arc<P>, Node, Node) -> Fut + Clone,
        Fut: std::future::Future<Output = RawResponse> + Send,
    {
        self.find_round_limited(usize::MAX, rpcmethod).await
    }

    /// Execute one crawl round while contacting no more than `limit` peers.
    /// A value-quorum lookup uses this to cap record-bearing responses without
    /// limiting how many closer nodes it may discover over successive rounds.
    pub async fn find_round_limited<F, Fut>(
        &mut self,
        limit: usize,
        rpcmethod: F,
    ) -> HashMap<[u8; ID_LEN], RawResponse>
    where
        F: Fn(Arc<P>, Node, Node) -> Fut + Clone,
        Fut: std::future::Future<Output = RawResponse> + Send,
    {
        log::info!("Crawling with nearest: {}", self.nearest);

        let current_ids = self.nearest.get_ids();
        let count = if current_ids == self.last_ids_crawled {
            self.nearest.len()
        } else {
            self.alpha
        }
        .min(limit);
        self.last_ids_crawled = current_ids;

        let uncontacted: Vec<Node> = self
            .nearest
            .get_uncontacted()
            .into_iter()
            .take(count)
            .collect();

        let mut futs: Vec<_> = Vec::with_capacity(uncontacted.len());
        for peer in &uncontacted {
            self.nearest.mark_contacted(peer);
            let proto = Arc::clone(&self.protocol);
            let peer_clone = peer.clone();
            let node_clone = self.node.clone();
            let f = rpcmethod.clone();
            let id = peer.id;
            futs.push(async move { (id, f(proto, peer_clone, node_clone).await) });
        }

        futures::future::join_all(futs).await.into_iter().collect()
    }
}

/// Iterative lookup that terminates when a value is found or the network is
/// exhausted.
pub struct ValueSpiderCrawl<P: SpiderProtocol> {
    pub base: SpiderCrawl<P>,
    /// The single nearest node that did *not* have the value (used for
    /// post-lookup caching).
    pub nearest_without_value: NodeHeap,
}

/// Return the unique value that has a strict majority, provided it also meets
/// `minimum_votes`. Values are compared byte-for-byte, so no signature work is
/// performed until the caller verifies the selected winner.
fn strict_quorum_value(values: &[Vec<u8>], minimum_votes: usize) -> Option<Vec<u8>> {
    let mut counts: HashMap<&[u8], usize> = HashMap::new();
    for value in values {
        *counts.entry(value.as_slice()).or_insert(0) += 1;
    }

    let required = minimum_votes.max(values.len() / 2 + 1);
    let highest = counts.values().copied().max()?;
    if highest < required {
        return None;
    }

    let mut winners = counts
        .into_iter()
        .filter(|(_, count)| *count == highest)
        .map(|(value, _)| value.to_vec());
    let winner = winners.next()?;
    if winners.next().is_some() {
        return None;
    }
    Some(winner)
}

impl<P: SpiderProtocol + 'static> ValueSpiderCrawl<P> {
    pub fn new(protocol: Arc<P>, node: Node, peers: Vec<Node>, ksize: usize, alpha: usize) -> Self {
        let nearest_without_value = NodeHeap::new(node.clone(), 1);
        Self {
            base: SpiderCrawl::new(protocol, node, peers, ksize, alpha),
            nearest_without_value,
        }
    }

    /// Run the lookup. Returns the found value and the k-closest nodes discovered.
    ///
    /// On a value hit: `(Some(value), vec![])`.
    /// On a miss: `(None, k_closest)` — the caller can use the nodes directly
    /// for a subsequent STORE without a second traversal (Kademlia §2.3).
    pub async fn find(mut self) -> (Option<Vec<u8>>, Vec<Node>) {
        loop {
            let responses = self
                .base
                .find_round(
                    |proto, peer, node| async move { proto.call_find_value(peer, node).await },
                )
                .await;

            let mut to_remove: Vec<[u8; ID_LEN]> = vec![];
            let mut found_values: Vec<Vec<u8>> = vec![];

            for (peer_id, raw) in &responses {
                let r = RPCFindResponse::new(raw.clone());
                if !r.happened() {
                    to_remove.push(*peer_id);
                } else if r.has_value() {
                    if let Some(v) = r.get_value() {
                        found_values.push(v);
                    }
                } else {
                    if let Some(peer) = self.base.nearest.get_node(peer_id) {
                        self.nearest_without_value.push_one(peer);
                    }
                    self.base.nearest.push(r.get_node_list());
                }
            }
            self.base.nearest.remove(&to_remove);

            if !found_values.is_empty() {
                let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
                for v in &found_values {
                    *counts.entry(v.clone()).or_insert(0) += 1;
                }
                if counts.len() > 1 {
                    log::warn!(
                        "Multiple distinct values found for key {:?} — returning majority",
                        self.base.node.long_id
                    );
                }
                let value = counts.into_iter().max_by_key(|(_, c)| *c).map(|(v, _)| v);
                if let Some(ref v) = value {
                    if let Some(peer) = self.nearest_without_value.popleft() {
                        self.base
                            .protocol
                            .call_store(&peer, self.base.node.id, v.clone())
                            .await;
                    }
                }
                return (value, vec![]);
            }

            if self.base.nearest.have_contacted_all() {
                return (None, self.base.nearest.to_vec());
            }
        }
    }

    /// Iteratively discover closer peers and return a byte-identical value only
    /// when it has a strict quorum. At most `maximum_votes` record responses are
    /// collected; peers returning only closer-node lists do not consume a vote.
    /// `initial_values` lets the caller include a local status-list copy. Only
    /// the selected winner is returned for signature checking.
    pub async fn find_quorum(
        mut self,
        initial_values: Vec<Vec<u8>>,
        minimum_votes: usize,
        maximum_votes: usize,
    ) -> Option<Vec<u8>> {
        let mut found_values = initial_values;

        loop {
            if let Some(value) = strict_quorum_value(&found_values, minimum_votes) {
                return Some(value);
            }

            let remaining_votes = maximum_votes.saturating_sub(found_values.len());
            if remaining_votes == 0 || self.base.nearest.have_contacted_all() {
                break;
            }

            let responses = self
                .base
                .find_round_limited(remaining_votes, |proto, peer, node| async move {
                    proto.call_find_value(peer, node).await
                })
                .await;

            let mut to_remove: Vec<[u8; ID_LEN]> = vec![];
            for (peer_id, raw) in &responses {
                let response = RPCFindResponse::new(raw.clone());
                if !response.happened() {
                    to_remove.push(*peer_id);
                } else if let Some(value) = response.get_value() {
                    found_values.push(value);
                } else {
                    self.base.nearest.push(response.get_node_list());
                }
            }
            self.base.nearest.remove(&to_remove);
        }

        if !found_values.is_empty() {
            log::warn!(
                "No strict value quorum for key {:?} after {} record responses",
                self.base.node.long_id,
                found_values.len()
            );
        }
        None
    }
}

/// Iterative lookup that returns the k closest nodes to a target.
pub struct NodeSpiderCrawl<P: SpiderProtocol> {
    pub base: SpiderCrawl<P>,
}

impl<P: SpiderProtocol + 'static> NodeSpiderCrawl<P> {
    pub fn new(protocol: Arc<P>, node: Node, peers: Vec<Node>, ksize: usize, alpha: usize) -> Self {
        Self {
            base: SpiderCrawl::new(protocol, node, peers, ksize, alpha),
        }
    }

    /// Run the lookup and return the k closest nodes found.
    pub async fn find(mut self) -> Vec<Node> {
        loop {
            let responses = self
                .base
                .find_round(
                    |proto, peer, node| async move { proto.call_find_node(peer, node).await },
                )
                .await;

            let mut to_remove: Vec<[u8; ID_LEN]> = vec![];
            for (peer_id, raw) in &responses {
                let r = RPCFindResponse::new(raw.clone());
                if !r.happened() {
                    to_remove.push(*peer_id);
                } else {
                    self.base.nearest.push(r.get_node_list());
                }
            }
            self.base.nearest.remove(&to_remove);

            if self.base.nearest.have_contacted_all() {
                return self.base.nearest.to_vec();
            }
        }
    }
}

#[cfg(test)]
mod quorum_tests {
    use std::sync::{Arc, Mutex};

    use super::{
        strict_quorum_value, FindPayload, Node, RawResponse, SpiderCrawl, SpiderProtocol, ID_LEN,
    };

    struct RecordingProtocol {
        contacted: Mutex<Vec<[u8; ID_LEN]>>,
    }

    #[async_trait::async_trait]
    impl SpiderProtocol for RecordingProtocol {
        async fn call_find_node(self: Arc<Self>, peer: Node, _target: Node) -> RawResponse {
            self.contacted.lock().unwrap().push(peer.id);
            RawResponse(true, FindPayload::Empty)
        }

        async fn call_find_value(self: Arc<Self>, peer: Node, _target: Node) -> RawResponse {
            self.contacted.lock().unwrap().push(peer.id);
            RawResponse(true, FindPayload::Empty)
        }

        async fn call_store(&self, _peer: &Node, _key: [u8; ID_LEN], _value: Vec<u8>) -> bool {
            false
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn two_of_three_selects_the_majority() {
        let values = vec![b"v1".to_vec(), b"v2".to_vec(), b"v2".to_vec()];
        assert_eq!(strict_quorum_value(&values, 2), Some(b"v2".to_vec()));
    }

    #[test]
    fn three_distinct_values_have_no_quorum() {
        let values = vec![b"v1".to_vec(), b"v2".to_vec(), b"v3".to_vec()];
        assert_eq!(strict_quorum_value(&values, 2), None);
    }

    #[test]
    fn one_response_cannot_satisfy_two_vote_quorum() {
        let values = vec![b"v1".to_vec()];
        assert_eq!(strict_quorum_value(&values, 2), None);
    }

    #[test]
    fn tied_groups_are_not_selected() {
        let values = vec![
            b"v1".to_vec(),
            b"v1".to_vec(),
            b"v2".to_vec(),
            b"v2".to_vec(),
        ];
        assert_eq!(strict_quorum_value(&values, 2), None);
    }

    #[test]
    fn converged_standard_crawl_contacts_all_remaining_peers() {
        test_runtime().block_on(async {
            let protocol = Arc::new(RecordingProtocol {
                contacted: Mutex::new(vec![]),
            });
            let target = Node::from_id([0; ID_LEN]);
            let peers = (1_u8..=5)
                .map(|marker| Node::from_id([marker; ID_LEN]))
                .collect();
            let mut crawl = SpiderCrawl::new(protocol.clone(), target, peers, 20, 2);

            crawl
                .find_round(|proto, peer, node| async move {
                    proto.call_find_node(peer, node).await
                })
                .await;
            assert_eq!(protocol.contacted.lock().unwrap().len(), 2);

            crawl
                .find_round(|proto, peer, node| async move {
                    proto.call_find_node(peer, node).await
                })
                .await;
            assert_eq!(
                protocol.contacted.lock().unwrap().len(),
                5,
                "a converged normal Kademlia crawl must contact all three remaining peers"
            );
        });
    }
}
