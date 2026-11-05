//! What a node sends, counted for measurements (Cargo feature `counters`,
//! off by default). Without the feature `Counters` holds nothing and its
//! methods do nothing.
//!
//! Counted:
//! - every datagram the node sends and its bytes (UDP payload, KADF header
//!   included), by message type, first copies and resends together. Each
//!   datagram is counted once, by its sender, so the sum over every node of a
//!   network is its traffic;
//! - the resends of a request, split by whether the round trip of its peer was
//!   measured when the request was first sent (`RoundTrips::is_measured`);
//! - the network check of a STORE to an empty replica (`rpc_store`,
//!   `network_copy`): how it ended, how many rounds its lookup took, and how
//!   long it lasted.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

/// Message types, as `rpc_message_name` names them.
pub const MESSAGE_TYPES: [&str; 17] = [
    "Ping",
    "Pong",
    "Store",
    "StoreResult",
    "Update",
    "UpdateResult",
    "UpdateStatusList",
    "UpdateStatusListResult",
    "FindNode",
    "FindNodeResult",
    "FindValue",
    "FindValueHit",
    "FindValueNodes",
    "Leave",
    "FindHash",
    "FindHashHit",
    "Received",
];

/// Lookups of the check by rounds: 1, 2, 3, 4, 5 or more.
pub const CHECK_ROUND_BUCKETS: usize = 5;

/// Upper bounds, in ms, of the buckets of check durations; one more bucket
/// holds the longer ones.
pub const CHECK_DURATION_BOUNDS_MS: [u64; 8] = [10, 25, 50, 100, 200, 500, 1000, 2000];

/// How the check of a STORE to an empty replica ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckEnd {
    /// The record does not belong to the key: refused before any lookup.
    Unbound,
    /// The node knew nobody to ask: refused without a lookup.
    NobodyToAsk,
    /// Every node asked answered, none with another hash.
    NoneOrSame,
    /// A node answered with another hash.
    Other,
    /// A node asked did not answer by the deadline.
    NoAnswer,
}

/// Datagrams and bytes of one message type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Sent {
    pub datagrams: u64,
    pub bytes: u64,
}

/// The checks of STOREs to an empty replica.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CheckCounts {
    pub unbound: u64,
    pub nobody_to_ask: u64,
    pub none_or_same: u64,
    pub other: u64,
    pub no_answer: u64,
    /// Lookups by rounds (`CHECK_ROUND_BUCKETS`).
    pub rounds: Vec<u64>,
    /// Lookups by duration (`CHECK_DURATION_BOUNDS_MS`, then longer).
    pub duration_ms: Vec<u64>,
    /// Sum of the lookup durations, in µs.
    pub duration_total_us: u64,
}

/// The counters of a node at one moment. They only grow: what happened
/// between two moments is the difference of their snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CounterSnapshot {
    /// By message type; types never sent are left out.
    pub sent: BTreeMap<&'static str, Sent>,
    pub resends_to_measured_peers: u64,
    pub resends_to_unmeasured_peers: u64,
    pub checks: CheckCounts,
}

#[derive(Default)]
pub(crate) struct Counters {
    #[cfg(feature = "counters")]
    inner: enabled::Inner,
}

impl Counters {
    /// One datagram of `bytes` bytes sent, part of a message of type `kind`.
    #[inline]
    pub(crate) fn sent(&self, kind: &'static str, bytes: usize) {
        #[cfg(feature = "counters")]
        self.inner.sent(kind, bytes);
        #[cfg(not(feature = "counters"))]
        let _ = (kind, bytes);
    }

    /// A request sent again; `measured` tells whether its peer's round trip
    /// was known when the request was first sent.
    #[inline]
    pub(crate) fn resent(&self, measured: bool) {
        #[cfg(feature = "counters")]
        self.inner.resent(measured);
        #[cfg(not(feature = "counters"))]
        let _ = measured;
    }

    /// A check ended after a lookup of `rounds` rounds lasting `elapsed`;
    /// `rounds` is 0 when no lookup ran.
    #[inline]
    pub(crate) fn check(&self, end: CheckEnd, rounds: usize, elapsed: Duration) {
        #[cfg(feature = "counters")]
        self.inner.check(end, rounds, elapsed);
        #[cfg(not(feature = "counters"))]
        let _ = (end, rounds, elapsed);
    }

    #[cfg(feature = "counters")]
    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        self.inner.snapshot()
    }
}

#[cfg(feature = "counters")]
mod enabled {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    pub(super) struct Inner {
        datagrams: [AtomicU64; MESSAGE_TYPES.len()],
        bytes: [AtomicU64; MESSAGE_TYPES.len()],
        resends_measured: AtomicU64,
        resends_unmeasured: AtomicU64,
        unbound: AtomicU64,
        nobody_to_ask: AtomicU64,
        none_or_same: AtomicU64,
        other: AtomicU64,
        no_answer: AtomicU64,
        rounds: [AtomicU64; CHECK_ROUND_BUCKETS],
        durations: [AtomicU64; CHECK_DURATION_BOUNDS_MS.len() + 1],
        duration_total_us: AtomicU64,
    }

    impl Inner {
        pub(super) fn sent(&self, kind: &'static str, bytes: usize) {
            let Some(index) = MESSAGE_TYPES.iter().position(|name| *name == kind) else {
                return;
            };
            self.datagrams[index].fetch_add(1, Relaxed);
            self.bytes[index].fetch_add(bytes as u64, Relaxed);
        }

        pub(super) fn resent(&self, measured: bool) {
            if measured {
                self.resends_measured.fetch_add(1, Relaxed);
            } else {
                self.resends_unmeasured.fetch_add(1, Relaxed);
            }
        }

        pub(super) fn check(&self, end: CheckEnd, rounds: usize, elapsed: Duration) {
            let outcome = match end {
                CheckEnd::Unbound => &self.unbound,
                CheckEnd::NobodyToAsk => &self.nobody_to_ask,
                CheckEnd::NoneOrSame => &self.none_or_same,
                CheckEnd::Other => &self.other,
                CheckEnd::NoAnswer => &self.no_answer,
            };
            outcome.fetch_add(1, Relaxed);
            if rounds == 0 {
                return;
            }
            self.rounds[rounds.min(CHECK_ROUND_BUCKETS) - 1].fetch_add(1, Relaxed);
            let ms = elapsed.as_millis() as u64;
            let bucket = CHECK_DURATION_BOUNDS_MS
                .iter()
                .position(|bound| ms <= *bound)
                .unwrap_or(CHECK_DURATION_BOUNDS_MS.len());
            self.durations[bucket].fetch_add(1, Relaxed);
            self.duration_total_us
                .fetch_add(elapsed.as_micros() as u64, Relaxed);
        }

        pub(super) fn snapshot(&self) -> CounterSnapshot {
            let load = |counter: &AtomicU64| counter.load(Relaxed);
            let sent = MESSAGE_TYPES
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    let sent = Sent {
                        datagrams: load(&self.datagrams[index]),
                        bytes: load(&self.bytes[index]),
                    };
                    (*name, sent)
                })
                .filter(|(_, sent)| sent.datagrams > 0)
                .collect();
            CounterSnapshot {
                sent,
                resends_to_measured_peers: load(&self.resends_measured),
                resends_to_unmeasured_peers: load(&self.resends_unmeasured),
                checks: CheckCounts {
                    unbound: load(&self.unbound),
                    nobody_to_ask: load(&self.nobody_to_ask),
                    none_or_same: load(&self.none_or_same),
                    other: load(&self.other),
                    no_answer: load(&self.no_answer),
                    rounds: self.rounds.iter().map(load).collect(),
                    duration_ms: self.durations.iter().map(load).collect(),
                    duration_total_us: load(&self.duration_total_us),
                },
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use crate::counters::{CheckEnd, Counters, Sent, MESSAGE_TYPES};

        #[test]
        fn every_message_type_has_a_counter() {
            let counters = Counters::default();
            for name in MESSAGE_TYPES {
                counters.sent(name, 10);
            }
            let snapshot = counters.snapshot();
            assert_eq!(snapshot.sent.len(), MESSAGE_TYPES.len());
            assert!(snapshot.sent.values().all(|sent| *sent
                == Sent {
                    datagrams: 1,
                    bytes: 10
                }));
        }

        #[test]
        fn a_check_is_counted_by_outcome_rounds_and_duration() {
            let counters = Counters::default();
            counters.check(CheckEnd::Unbound, 0, Duration::ZERO);
            counters.check(CheckEnd::NoneOrSame, 1, Duration::from_millis(40));
            counters.check(CheckEnd::NoAnswer, 7, Duration::from_millis(2001));
            let checks = counters.snapshot().checks;
            assert_eq!(
                (checks.unbound, checks.none_or_same, checks.no_answer),
                (1, 1, 1)
            );
            assert_eq!(checks.rounds, vec![1, 0, 0, 0, 1]);
            assert_eq!(checks.duration_ms, vec![0, 0, 1, 0, 0, 0, 0, 0, 1]);
            assert_eq!(checks.duration_total_us, 2_041_000);
        }
    }
}
