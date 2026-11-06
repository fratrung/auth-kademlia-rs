//! Scenario: node churn survivability.
//!
//! Simulates the IoT scenario where the node that published a record restarts.
//! The record must remain retrievable via the nodes that received it through
//! replication to a new node (`schedule_welcome_if_new`).
//!
//! Topology:
//!   A (seed, stays online)
//!   B (publisher, then leaves)
//!   C (stays online, receives replication)
//!   D (new joiner, must find the record)
//!
//! Ports: A=15792, B=15793, C=15794, D=15795.

#[path = "common.rs"]
mod common;

use std::time::Duration;

use common::{make_record, poll_until, rt, start_node};

#[test]
fn record_survives_publisher_leaving_network() {
    rt().block_on(async {
        let node_a = start_node(15792).await; // seed
        let mut node_b = start_node(15793).await; // publisher — will leave
        let node_c = start_node(15794).await; // stays

        node_b
            .bootstrap(vec![("127.0.0.1".to_string(), 15792)])
            .await;
        node_c
            .bootstrap(vec![("127.0.0.1".to_string(), 15792)])
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        // B publishes the record; schedule_welcome_if_new replicates to A and C.
        let (key, record) = make_record();
        assert_eq!(
            node_b.set(&key, record.clone()).await,
            Some(true),
            "B must store the record"
        );

        // Wait for replication to propagate to A and C.
        let replicated = poll_until(
            Duration::from_secs(5),
            Duration::from_millis(200),
            || async { node_a.get(&key).await },
        )
        .await;
        assert!(
            replicated.is_some(),
            "record must reach A via the replication to new nodes before B leaves"
        );

        // B leaves the network.
        node_b.stop().await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // D is a brand new node that never saw the record.
        let node_d = start_node(15795).await;
        node_d
            .bootstrap(vec![("127.0.0.1".to_string(), 15792)])
            .await;

        let result = poll_until(
            Duration::from_secs(5),
            Duration::from_millis(300),
            || async { node_d.get(&key).await },
        )
        .await;

        assert!(
            result.is_some(),
            "record must be retrievable by D after B left the network"
        );
        assert_eq!(
            result.unwrap(),
            record,
            "retrieved bytes must match the original record"
        );
    });
}
