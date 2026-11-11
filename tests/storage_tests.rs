//! Integration tests for [`ForgetfulStorage`].
//!
//! Context: `ForgetfulStorage` is the local key-value store used by every DHT
//! node to cache records it is responsible for.  It supports optional TTL-based
//! expiry and insertion-ordered iteration — both critical to Kademlia's
//! republication and caching semantics.
//!
//! These tests exercise the storage layer in isolation (no network) to verify
//! correctness of storage operations, TTL expiry, iteration, and behaviour with
//! realistic large binary payloads (signed DID records).

use std::thread::sleep;
use std::time::Duration;

use auth_kademlia_rs::storage::{ForgetfulStorage, IStorage, ReplaceStatus, DEFAULT_TTL};

// ─────────────────────────────────────────────────────────────────────────────
// Basic storage operations
// ─────────────────────────────────────────────────────────────────────────────

/// A stored value is immediately retrievable.
#[test]
fn test_basic_set_and_get() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"key1".to_vec(), b"value1".to_vec());
    assert_eq!(s.get(b"key1"), Some(b"value1".to_vec()));
}

/// Getting a key that was never stored returns None.
#[test]
fn test_get_missing_key_returns_none() {
    let s = ForgetfulStorage::new(-1);
    assert_eq!(s.get(b"ghost"), None);
}

/// `get_default` returns the provided fallback when the key is absent.
#[test]
fn test_get_default_fallback() {
    let s = ForgetfulStorage::new(-1);
    let fallback = Some(b"default".to_vec());
    assert_eq!(s.get_default(b"missing", fallback.clone()), fallback);
}

/// `get_default` returns the stored value when the key exists, ignoring the fallback.
#[test]
fn test_get_default_prefers_stored_value() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"k".to_vec(), b"real".to_vec());
    assert_eq!(
        s.get_default(b"k", Some(b"fallback".to_vec())),
        Some(b"real".to_vec())
    );
}

/// Re-inserting an existing key replaces the value.
#[test]
fn test_overwrite_replaces_value() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"k".to_vec(), b"first".to_vec());
    s.set(b"k".to_vec(), b"second".to_vec());
    assert_eq!(s.get(b"k"), Some(b"second".to_vec()));
}

// ─────────────────────────────────────────────────────────────────────────────
// TTL / expiry
// ─────────────────────────────────────────────────────────────────────────────

/// Entries with TTL = -1 never expire, regardless of elapsed time.
#[test]
fn test_no_ttl_entries_persist_forever() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"k".to_vec(), b"v".to_vec());
    sleep(Duration::from_millis(50));
    // A spurious write should not evict the entry (ttl=-1 → never expires).
    s.set(b"other".to_vec(), b"x".to_vec());
    assert_eq!(s.get(b"k"), Some(b"v".to_vec()));
}

/// An entry expires after the configured TTL and is culled on the next write.
#[test]
fn test_entry_expires_after_ttl() {
    let s = ForgetfulStorage::new(1); // 1-second TTL
    s.set(b"k".to_vec(), b"v".to_vec());
    sleep(Duration::from_millis(1100));
    s.set(b"trigger_cull".to_vec(), b"x".to_vec());
    assert_eq!(s.get(b"k"), None); // lazy expiry: get sees the entry is past TTL
}

/// A fresh entry survives within the TTL window.
#[test]
fn test_entry_survives_within_ttl() {
    let s = ForgetfulStorage::new(60); // 60-second TTL
    s.set(b"k".to_vec(), b"v".to_vec());
    sleep(Duration::from_millis(50));
    assert_eq!(s.get(b"k"), Some(b"v".to_vec()));
}

/// The DEFAULT_TTL constant is two weeks (1 209 600 s).
#[test]
fn test_default_ttl_constant_is_two_weeks() {
    assert_eq!(DEFAULT_TTL, 1_209_600);
}

// ─────────────────────────────────────────────────────────────────────────────
// Iteration
// ─────────────────────────────────────────────────────────────────────────────

/// `iter_older_than` returns only entries inserted before the threshold.
#[test]
fn test_iter_older_than_returns_stale_entries() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"old".to_vec(), b"1".to_vec());
    sleep(Duration::from_millis(1100));
    s.set(b"new".to_vec(), b"2".to_vec());

    let stale = s.iter_older_than(1);
    assert_eq!(stale.len(), 1, "only the old entry should be returned");
    assert_eq!(stale[0].0, b"old".to_vec());
}

/// `iter_older_than(0)` returns all entries (everything is at least 0 s old).
#[test]
fn test_iter_older_than_zero_returns_all() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"a".to_vec(), b"1".to_vec());
    s.set(b"b".to_vec(), b"2".to_vec());
    // Sleep 1 ms so every entry has age >= 0 s.
    sleep(Duration::from_millis(10));
    let all = s.iter_older_than(0);
    assert_eq!(all.len(), 2);
}

/// `iter_all` returns all non-expired entries.
#[test]
fn test_iter_all_returns_all_entries() {
    let s = ForgetfulStorage::new(-1);
    s.set(b"a".to_vec(), b"1".to_vec());
    s.set(b"b".to_vec(), b"2".to_vec());
    s.set(b"c".to_vec(), b"3".to_vec());
    assert_eq!(s.iter_all().len(), 3);
}

/// `iter_all` excludes entries that have passed the TTL.
#[test]
fn test_iter_all_excludes_expired_entries() {
    let s = ForgetfulStorage::new(1); // 1-second TTL
    s.set(b"will_expire".to_vec(), b"x".to_vec());
    sleep(Duration::from_millis(1100));
    s.set(b"fresh".to_vec(), b"y".to_vec());

    let live = s.iter_all();
    assert_eq!(live.len(), 1, "only the fresh entry should survive");
    assert_eq!(live[0].0, b"fresh".to_vec());
}

// ─────────────────────────────────────────────────────────────────────────────
// Realistic payload
// ─────────────────────────────────────────────────────────────────────────────

/// Storage correctly round-trips large binary payloads representative of
/// real signed DID records (12 B header + 3309 B ML-DSA-65 signature + JSON).
#[test]
fn test_large_binary_value_roundtrip() {
    let s = ForgetfulStorage::new(-1);
    // Simulate a signed DID record: 12-byte alg header + 3309-byte signature + 3200-byte JSON
    let payload: Vec<u8> = (0u8..=255).cycle().take(12 + 3309 + 3200).collect();
    s.set(b"did:iiot:test".to_vec(), payload.clone());
    assert_eq!(s.get(b"did:iiot:test"), Some(payload));
}

/// Multiple keys coexist independently without overwriting each other.
#[test]
fn test_multiple_independent_keys() {
    let s = ForgetfulStorage::new(-1);
    for i in 0u8..20 {
        s.set(vec![i], vec![i * 2]);
    }
    for i in 0u8..20 {
        assert_eq!(s.get(&[i]), Some(vec![i * 2]));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// replace_if: replace only the record that was checked (ADR 0005)
// ─────────────────────────────────────────────────────────────────────────────

/// The expected bytes are replaced, with a fresh expiry, and the byte count
/// follows the new value.
#[test]
fn test_replace_if_replaces_the_expected_bytes() {
    let s = ForgetfulStorage::with_max_storage_bytes(-1, 64);
    s.insert_if_absent(b"k".to_vec(), b"version 1".to_vec());
    sleep(Duration::from_millis(1100));
    assert_eq!(s.iter_older_than(1).len(), 1);

    assert_eq!(
        s.replace_if(b"k", b"version 1", b"version two".to_vec()),
        ReplaceStatus::Replaced
    );
    assert_eq!(s.get(b"k"), Some(b"version two".to_vec()));
    assert!(
        s.iter_older_than(1).is_empty(),
        "the new value gets a fresh expiry"
    );
    assert_eq!(s.current_storage_bytes(), 1 + b"version two".len());

    assert_eq!(
        s.replace_if(b"k", b"version two", b"v3".to_vec()),
        ReplaceStatus::Replaced
    );
    assert_eq!(s.current_storage_bytes(), 1 + 2);
}

/// Another value, or none, under the key: nothing is written.
#[test]
fn test_replace_if_does_not_replace_another_value_or_create_one() {
    let s = ForgetfulStorage::new(-1);
    s.insert_if_absent(b"k".to_vec(), b"stored".to_vec());
    assert_eq!(
        s.replace_if(b"k", b"checked", b"new".to_vec()),
        ReplaceStatus::Changed
    );
    assert_eq!(s.get(b"k"), Some(b"stored".to_vec()));
    assert_eq!(
        s.replace_if(b"absent", b"checked", b"new".to_vec()),
        ReplaceStatus::Changed
    );
    assert_eq!(s.get(b"absent"), None);
}

/// An expired record is not replaced: it is as good as absent, and a record
/// is created only by `insert_if_absent`.
#[test]
fn test_replace_if_does_not_replace_an_expired_record() {
    let s = ForgetfulStorage::new(1);
    s.insert_if_absent(b"k".to_vec(), b"old".to_vec());
    sleep(Duration::from_millis(1100));
    assert_eq!(
        s.replace_if(b"k", b"old", b"new".to_vec()),
        ReplaceStatus::Changed
    );
    assert_eq!(s.get(b"k"), None);
}

/// A new value beyond the budget leaves the stored one and the byte count.
#[test]
fn test_replace_if_beyond_the_budget_keeps_the_stored_value() {
    let s = ForgetfulStorage::with_max_storage_bytes(-1, 1 + 5);
    s.insert_if_absent(b"k".to_vec(), b"small".to_vec());
    assert_eq!(
        s.replace_if(b"k", b"small", b"larger".to_vec()),
        ReplaceStatus::CapacityExceeded
    );
    assert_eq!(s.get(b"k"), Some(b"small".to_vec()));
    assert_eq!(s.current_storage_bytes(), 6);
}

/// Two replacements of the same checked value at once: exactly one wins.
#[test]
fn test_replace_if_lets_one_of_two_concurrent_replacements_win() {
    use std::sync::{Arc, Barrier};
    for _ in 0..50 {
        let s = Arc::new(ForgetfulStorage::new(-1));
        s.insert_if_absent(b"k".to_vec(), b"version 2".to_vec());
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [b"version 3a".to_vec(), b"version 3b".to_vec()]
            .into_iter()
            .map(|new| {
                let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    (s.replace_if(b"k", b"version 2", new.clone()), new)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners: Vec<_> = results
            .iter()
            .filter(|(status, _)| *status == ReplaceStatus::Replaced)
            .collect();
        assert_eq!(winners.len(), 1, "{results:?}");
        assert_eq!(s.get(b"k"), Some(winners[0].1.clone()));
    }
}
