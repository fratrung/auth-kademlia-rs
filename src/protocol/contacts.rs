//! Upkeep of the routing table's contacts: failures and their backoff, nodes
//! seen alive again, new contacts, pings of failing contacts, and the ids of
//! the buckets to refresh.

use std::sync::Arc;
use std::time::Duration;

use crate::node::Node;
use crate::protocol::transport::RPC_TIMEOUT;
use crate::utils::ID_LEN;

use super::KademliaProtocol;

/// A contact silent for this long may have missed records when it comes back.
pub(super) const RETURNED_AFTER: Duration = RPC_TIMEOUT;

impl KademliaProtocol {
    pub(super) async fn note_failure(&self, peer: &Node) {
        self.router.write().await.record_failure(peer);
    }

    /// Returns how long the contact had been failing, if it was. The read lock
    /// keeps the common case, a healthy contact, off the write lock.
    ///
    /// Only the registered endpoint can vouch for a failing contact, so a forged
    /// message cannot redirect it. A stale contact also accepts a new endpoint,
    /// otherwise a peer that changed address could never be reached again.
    pub(super) async fn note_alive(&self, node: &Node) -> Option<Duration> {
        {
            let router = self.router.read().await;
            if !router.has_failures(&node.id) {
                return None;
            }
            let from_registered_endpoint = router
                .get_contact(&node.id)
                .is_some_and(|contact| contact.same_home_as(node));
            if !from_registered_endpoint && !router.is_stale(&node.id) {
                return None;
            }
        }
        self.router.write().await.record_success(&node.id)
    }

    /// Ping up to `limit` failing contacts whose backoff has elapsed. Probing
    /// here keeps the cost of a dead contact out of user lookups.
    pub(crate) async fn probe_failing_contacts(self: &Arc<Self>, limit: usize) {
        let due = self.router.read().await.contacts_due_for_probe(limit);
        futures::future::join_all(due.iter().map(|node| self.call_ping_node(node))).await;
    }

    /// Add `node` to the routing table. A full bucket that cannot split gives
    /// its oldest contact, which is pinged to learn whether it is still there
    /// (§2.2): at most one ping per contact at a time, however many new nodes
    /// fall into that bucket.
    pub(super) async fn add_contact(self: &Arc<Self>, node: Node) {
        let oldest = self.router.write().await.add_contact(node);
        let Some(oldest) = oldest else {
            return;
        };
        if self.oldest_pings_in_flight.insert(oldest.id, ()).is_some() {
            return;
        }
        let p = Arc::clone(self);
        self.spawn_task(async move {
            p.call_ping_node(&oldest).await;
            p.oldest_pings_in_flight.remove(&oldest.id);
        });
    }

    /// Ping `node` to check liveness (§4.2 LRU eviction).
    ///
    /// A failure is counted, and the node is replaced once stale if a replacement
    /// is available (`record_failure`). On success the Pong response triggers
    /// `welcome_if_new` in `handle_datagram`, refreshing the routing table.
    pub async fn call_ping_node(self: &Arc<Self>, node: &Node) {
        let addr = match node.address() {
            Some(a) => a,
            None => return,
        };
        let (ok, _) = self.call_ping_addr(&addr).await;
        if !ok {
            log::warn!("ping: no response from {}", node);
            self.note_failure(node).await;
        }
        // On success: Pong received in handle_datagram already calls welcome_if_new.
    }

    /// Return a random ID for each lonely bucket, constrained to that bucket's
    /// keyspace range (§2.3). Matches Python: `random.randint(*bucket.range).to_bytes(20, 'big')`.
    pub async fn get_refresh_ids(&self) -> Vec<[u8; ID_LEN]> {
        use rand::RngCore;
        self.router
            .read()
            .await
            .lonely_buckets()
            .iter()
            .map(|b| {
                let lo = *b.range.start();
                let hi = *b.range.end();
                // Uniform id in [lo, hi] over the full 160-bit space.
                let span = hi - lo + primitive_types::U256::one();
                let mut rand_bytes = [0u8; ID_LEN];
                rand::thread_rng().fill_bytes(&mut rand_bytes);
                let r = primitive_types::U256::from_big_endian(&rand_bytes); // in [0, 2^160)
                let val = lo + (r % span);
                // `val <= hi < 2^160`, so the top 12 bytes are zero.
                let mut buf = [0u8; 32];
                val.to_big_endian(&mut buf);
                let mut id = [0u8; ID_LEN];
                id.copy_from_slice(&buf[12..32]);
                id
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::protocol::test_support::*;

    use super::*;

    #[tokio::test]
    async fn forged_endpoint_cannot_clear_a_failing_contact() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let registered = contact_at([9; ID_LEN], 7000);
        {
            let mut router = protocol.router.write().await;
            router.add_contact(registered.clone());
            router.record_failure(&registered);
        }

        let forged = contact_at([9; ID_LEN], 7001);
        assert!(protocol.note_alive(&forged).await.is_none());
        assert!(protocol.router.read().await.has_failures(&registered.id));

        assert!(protocol.note_alive(&registered).await.is_some());
        assert!(!protocol.router.read().await.has_failures(&registered.id));
    }

    #[tokio::test]
    async fn stale_contact_accepts_a_new_endpoint() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let registered = contact_at([9; ID_LEN], 7000);
        {
            let mut router = protocol.router.write().await;
            router.add_contact(registered.clone());
            let mut now = Instant::now();
            for _ in 0..crate::routing::STALE_AFTER_FAILURES {
                router.record_failure_at(&registered, now);
                now += Duration::from_secs(10_000);
            }
            assert!(router.is_stale(&registered.id));
        }

        let moved = contact_at([9; ID_LEN], 7001);
        assert!(protocol.note_alive(&moved).await.is_some());
        assert!(!protocol.router.read().await.has_failures(&registered.id));
    }
}
