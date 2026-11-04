//! When to send a request again over UDP.
//!
//! A request or its answer can be lost. The sender then waits a few times the
//! peer's usual round trip and sends the same request again, at most
//! `MAX_RESENDS` times, doubling the wait each time. The round trip is a
//! smoothed estimate per peer address (RFC 6298, §2). Only requests sent once
//! are measured, because the answer to a resent request could belong to
//! either copy (Karn's algorithm, RFC 6298, §3).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Copies of a request sent after the first, when no answer arrives.
pub(crate) const MAX_RESENDS: u32 = 2;
/// Wait before the first resend to a peer never measured.
pub(crate) const INITIAL_RESEND_AFTER: Duration = Duration::from_millis(500);
/// Bounds of the wait before a resend. The lower one absorbs a peer that is
/// briefly busy, the upper one a slow link.
pub(crate) const MIN_RESEND_AFTER: Duration = Duration::from_millis(20);
pub(crate) const MAX_RESEND_AFTER: Duration = Duration::from_secs(1);
/// Peers whose round trip is remembered.
const MAX_PEERS: usize = 4096;
/// A peer not heard from for this long is forgotten first when the table is full.
const FORGET_AFTER: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy)]
struct RoundTrip {
    smoothed: Duration,
    variation: Duration,
    updated: Instant,
}

/// Round-trip estimates of the peers this node sends requests to.
pub(crate) struct RoundTrips {
    peers: DashMap<SocketAddr, RoundTrip>,
    capacity: usize,
}

impl Default for RoundTrips {
    fn default() -> Self {
        Self::with_capacity(MAX_PEERS)
    }
}

impl RoundTrips {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            peers: DashMap::new(),
            capacity,
        }
    }

    /// How long to wait for an answer from `peer` before sending the request
    /// again: three round trips, or more if its round trips vary a lot.
    pub(crate) fn resend_after(&self, peer: SocketAddr) -> Duration {
        let Some(round_trip) = self.peers.get(&peer).map(|entry| *entry) else {
            return INITIAL_RESEND_AFTER;
        };
        // RFC 6298 waits smoothed + 4 * variation. On a steady link the
        // variation shrinks to nothing, so a peer briefly slower than usual
        // would get copies it does not need: never wait less than 3 round trips.
        let wait = (round_trip.smoothed * 3).max(round_trip.smoothed + round_trip.variation * 4);
        wait.clamp(MIN_RESEND_AFTER, MAX_RESEND_AFTER)
    }

    /// `peer` answered a request sent once after `sample`.
    pub(crate) fn record(&self, peer: SocketAddr, sample: Duration) {
        let now = Instant::now();
        if let Some(mut round_trip) = self.peers.get_mut(&peer) {
            // RFC 6298, §2.3, with alpha = 1/8 and beta = 1/4.
            let deviation = round_trip.smoothed.abs_diff(sample);
            round_trip.variation = round_trip.variation * 3 / 4 + deviation / 4;
            round_trip.smoothed = round_trip.smoothed * 7 / 8 + sample / 8;
            round_trip.updated = now;
            return;
        }
        if self.peers.len() >= self.capacity {
            self.peers
                .retain(|_, round_trip| now.duration_since(round_trip.updated) < FORGET_AFTER);
            if self.peers.len() >= self.capacity {
                return;
            }
        }
        // RFC 6298, §2.2: the first measurement.
        self.peers.insert(
            peer,
            RoundTrip {
                smoothed: sample,
                variation: sample / 2,
                updated: now,
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn a_peer_never_measured_gets_the_initial_wait() {
        assert_eq!(
            RoundTrips::default().resend_after(peer(1)),
            INITIAL_RESEND_AFTER
        );
    }

    #[test]
    fn the_wait_is_three_round_trips() {
        let round_trips = RoundTrips::default();
        round_trips.record(peer(1), ms(15));
        assert_eq!(round_trips.resend_after(peer(1)), ms(45));
        assert_eq!(round_trips.resend_after(peer(2)), INITIAL_RESEND_AFTER);
    }

    #[test]
    fn the_wait_stays_within_its_bounds() {
        let round_trips = RoundTrips::default();
        round_trips.record(peer(1), Duration::from_micros(100));
        round_trips.record(peer(2), ms(800));
        assert_eq!(round_trips.resend_after(peer(1)), MIN_RESEND_AFTER);
        assert_eq!(round_trips.resend_after(peer(2)), MAX_RESEND_AFTER);
    }

    #[test]
    fn one_fast_answer_does_not_erase_a_slow_history() {
        let round_trips = RoundTrips::default();
        round_trips.record(peer(1), ms(100));
        round_trips.record(peer(1), ms(10));
        // RFC 6298: smoothed = 7/8 * 100 + 1/8 * 10 = 88.75 ms.
        assert!(round_trips.resend_after(peer(1)) >= ms(266));
    }

    #[test]
    fn round_trips_that_vary_widen_the_wait() {
        let steady = RoundTrips::default();
        let varying = RoundTrips::default();
        for _ in 0..20 {
            steady.record(peer(1), ms(30));
            varying.record(peer(1), ms(10));
            varying.record(peer(1), ms(50));
        }
        assert!(varying.resend_after(peer(1)) > steady.resend_after(peer(1)));
    }

    #[test]
    fn the_table_stays_bounded() {
        let round_trips = RoundTrips::with_capacity(4);
        for port in 1..=10 {
            round_trips.record(peer(port), ms(15));
        }
        assert_eq!(round_trips.len(), 4);
        // A peer already known is still updated.
        round_trips.record(peer(1), ms(100));
        assert!(round_trips.resend_after(peer(1)) > ms(45));
    }
}
