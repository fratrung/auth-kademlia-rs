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
//!   `network_check`): how it ended, how many rounds its lookup took, and how
//!   long it lasted, apart for the checks that fetched claimed records.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

/// Message types, as `rpc_message_name` names them.
pub const MESSAGE_TYPES: [&str; 15] = [
    "Ping",
    "Pong",
    "Store",
    "StoreResult",
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
    /// The record fails the form: refused before any lookup.
    Invalid,
    /// The node knew nobody to ask: accepted without a lookup.
    NobodyToAsk,
    /// Every node asked answered, and none showed a higher position.
    Accepted,
    /// Some node did not answer by the deadline, and none showed a higher
    /// position: accepted all the same.
    AcceptedWithSilence,
    /// A node showed a verified record at a higher position: refused as
    /// stale, and that record stored instead.
    Superseded,
}

/// Ends of a check, one counter each.
#[cfg(feature = "counters")]
const CHECK_ENDS: usize = CheckEnd::Superseded as usize + 1;

/// Datagrams and bytes of one message type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Sent {
    pub datagrams: u64,
    pub bytes: u64,
}

/// The checks of STOREs to an empty replica.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CheckCounts {
    pub invalid: u64,
    pub nobody_to_ask: u64,
    pub accepted: u64,
    pub accepted_with_silence: u64,
    pub superseded: u64,
    /// Claims of a higher position dropped: the node did not show a valid
    /// record for its claim when asked for it.
    pub unshown_claims: u64,
    /// Checks that fetched claimed records.
    pub fetches: u64,
    /// Durations of those checks, whole check included
    /// (`CHECK_DURATION_BOUNDS_MS`, then longer).
    pub fetch_duration_ms: Vec<u64>,
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
    /// `rounds` is 0 when no lookup ran. `fetched` when it fetched claimed
    /// records.
    #[inline]
    pub(crate) fn check(&self, end: CheckEnd, rounds: usize, elapsed: Duration, fetched: bool) {
        #[cfg(feature = "counters")]
        self.inner.check(end, rounds, elapsed, fetched);
        #[cfg(not(feature = "counters"))]
        let _ = (end, rounds, elapsed, fetched);
    }

    /// `claims` claims of a higher position dropped, not shown.
    #[inline]
    pub(crate) fn unshown_claims(&self, claims: usize) {
        #[cfg(feature = "counters")]
        self.inner.unshown_claims(claims);
        #[cfg(not(feature = "counters"))]
        let _ = claims;
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
        ends: [AtomicU64; CHECK_ENDS],
        rounds: [AtomicU64; CHECK_ROUND_BUCKETS],
        durations: [AtomicU64; CHECK_DURATION_BOUNDS_MS.len() + 1],
        unshown_claims: AtomicU64,
        fetches: AtomicU64,
        fetch_durations: [AtomicU64; CHECK_DURATION_BOUNDS_MS.len() + 1],
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

        pub(super) fn check(&self, end: CheckEnd, rounds: usize, elapsed: Duration, fetched: bool) {
            self.ends[end as usize].fetch_add(1, Relaxed);
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
            if fetched {
                self.fetches.fetch_add(1, Relaxed);
                self.fetch_durations[bucket].fetch_add(1, Relaxed);
            }
            self.duration_total_us
                .fetch_add(elapsed.as_micros() as u64, Relaxed);
        }

        pub(super) fn unshown_claims(&self, claims: usize) {
            self.unshown_claims.fetch_add(claims as u64, Relaxed);
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
                    invalid: load(&self.ends[CheckEnd::Invalid as usize]),
                    nobody_to_ask: load(&self.ends[CheckEnd::NobodyToAsk as usize]),
                    accepted: load(&self.ends[CheckEnd::Accepted as usize]),
                    accepted_with_silence: load(&self.ends[CheckEnd::AcceptedWithSilence as usize]),
                    superseded: load(&self.ends[CheckEnd::Superseded as usize]),
                    unshown_claims: load(&self.unshown_claims),
                    fetches: load(&self.fetches),
                    fetch_duration_ms: self.fetch_durations.iter().map(load).collect(),
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
            counters.check(CheckEnd::Invalid, 0, Duration::ZERO, false);
            counters.check(CheckEnd::Accepted, 1, Duration::from_millis(40), false);
            counters.check(CheckEnd::Superseded, 2, Duration::from_millis(20), false);
            counters.check(
                CheckEnd::AcceptedWithSilence,
                7,
                Duration::from_millis(2001),
                true,
            );
            let checks = counters.snapshot().checks;
            assert_eq!(
                (
                    checks.invalid,
                    checks.accepted,
                    checks.superseded,
                    checks.accepted_with_silence
                ),
                (1, 1, 1, 1)
            );
            assert_eq!(checks.rounds, vec![1, 1, 0, 0, 1]);
            assert_eq!(checks.duration_ms, vec![0, 1, 1, 0, 0, 0, 0, 0, 1]);
            assert_eq!(checks.duration_total_us, 2_061_000);
            assert_eq!(checks.fetches, 1);
            assert_eq!(checks.fetch_duration_ms, vec![0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }
    }
}
