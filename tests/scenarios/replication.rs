//! Scenario: welcome_if_new replication.
//!
//! When a new node C bootstraps into a network where A and B already hold a
//! record, A's `welcome_if_new` must replicate that record to C.
//!
//! Topology:
//!   A (seed, stores the record together with B)
//!   B (joins first, receives the record via STORE RPC)
//!   C (joins last, must receive the record via welcome_if_new from A or B)
//!
//! Ports: A=15787, B=15788, C=15789.

#[path = "common.rs"]
mod common;

use std::time::Duration;

use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::digest;

use common::{make_record, poll_until, rt, start_node_with_id};

#[test]
fn welcome_if_new_replicates_to_joining_node() {
    rt().block_on(async {
        let (key, record) = make_record();
        let dkey = digest(&key);
        let mut node_b_id = dkey;
        node_b_id[0] ^= 0x80;
        let mut node_c_id = dkey;
        node_c_id[0] ^= 0x40;

        // A is closest to the key and C is closer than B, satisfying both
        // Kademlia §2.5 conditions checked by welcome_if_new.
        let node_a = start_node_with_id(15787, dkey).await;
        let node_b = start_node_with_id(15788, node_b_id).await;

        node_b
            .bootstrap(vec![("127.0.0.1".to_string(), 15787)])
            .await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // A stores the record with B as a known peer — set() succeeds.
        let stored = node_a.set(&key, record.clone()).await;
        assert_eq!(stored, Some(true), "node A must store the record");

        // Wait for the STORE RPC to land on B.
        let on_b = poll_until(
            Duration::from_secs(3),
            Duration::from_millis(100),
            || async { node_b.storage.get(&dkey) },
        )
        .await;
        assert!(on_b.is_some(), "node B must hold the record before C joins");

        // C joins — welcome_if_new fires asynchronously on A (and B) toward C.
        let node_c = start_node_with_id(15789, node_c_id).await;
        node_c
            .bootstrap(vec![("127.0.0.1".to_string(), 15787)])
            .await;

        let result = poll_until(
            Duration::from_secs(5),
            Duration::from_millis(200),
            || async { node_c.storage.get(&dkey) },
        )
        .await;

        assert!(
            result.is_some(),
            "node C must receive the record via welcome_if_new replication"
        );
        assert_eq!(
            result.unwrap(),
            record,
            "replicated bytes must be identical"
        );
    });
}
