/// Key-value storage with optional TTL-based expiry.
///
/// `IStorage` is the abstract interface used by the protocol layer.
/// `ForgetfulStorage` is the concurrent implementation backed by `DashMap`.
/// TTL expiry is lazy: entries are checked on read rather than culled on write.
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Two weeks in seconds — the default record TTL used by AuthKademlia.
pub const DEFAULT_TTL: i64 = 14 * 24 * 60 * 60;

/// Default per-node storage budget: 512 MiB of keys and values.
pub const DEFAULT_MAX_STORAGE_BYTES: usize = 512 * 1024 * 1024;

/// Result of an atomic storage write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageWriteStatus {
    Stored,
    AlreadyStored,
    Conflict,
    CapacityExceeded,
}

/// Abstract key-value store interface.
///
/// All methods take `&self` — implementations must be internally synchronized
/// (e.g. via `DashMap` or `Mutex`) so they can be shared across async tasks.
pub trait IStorage: Send + Sync {
    /// Insert or replace a key-value pair.
    fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageWriteStatus;

    /// Atomically insert `key → value` only if the key is absent.
    /// An identical live value is idempotent; a different value is a conflict.
    fn insert_if_absent(&self, key: Vec<u8>, value: Vec<u8>) -> StorageWriteStatus;

    /// Retrieve a value, returning `default` if the key is absent.
    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>>;

    /// Retrieve a value, returning `None` if the key is absent.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_default(key, None)
    }

    /// Return all `(key, value)` pairs whose insertion time is older than
    /// `seconds_old` seconds.
    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Return all non-expired `(key, value)` pairs.
    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
}

/// A concurrent store backed by `DashMap` with lazy TTL expiry.
///
/// A `ttl` of `-1` disables expiry entirely (entries are kept forever).
/// Expiry is checked on every read; no eager culling on writes.
pub struct ForgetfulStorage {
    data: DashMap<Vec<u8>, (Vec<u8>, Instant)>,
    ttl: i64,
    current_storage_bytes: AtomicUsize,
    max_storage_bytes: usize,
}

impl ForgetfulStorage {
    /// Create a new store with the given TTL.
    ///
    /// Pass `ttl = -1` to disable expiry.
    pub fn new(ttl: i64) -> Self {
        Self::with_max_storage_bytes(ttl, DEFAULT_MAX_STORAGE_BYTES)
    }

    /// Create a store with a per-node byte budget.
    ///
    /// The budget accounts for key and value bytes. Active entries are never
    /// evicted to make room: writes that would exceed the limit are rejected.
    pub fn with_max_storage_bytes(ttl: i64, max_storage_bytes: usize) -> Self {
        Self {
            data: DashMap::new(),
            ttl,
            current_storage_bytes: AtomicUsize::new(0),
            max_storage_bytes,
        }
    }

    /// Bytes currently charged to the storage budget, including expired
    /// entries that have not yet been pruned.
    pub fn current_storage_bytes(&self) -> usize {
        self.current_storage_bytes.load(Ordering::Acquire)
    }

    pub fn max_storage_bytes(&self) -> usize {
        self.max_storage_bytes
    }

    fn reserve_bytes(&self, additional: usize) -> bool {
        if additional == 0 {
            return true;
        }

        self.current_storage_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(additional)
                    .filter(|next| *next <= self.max_storage_bytes)
            })
            .is_ok()
    }

    fn release_bytes(&self, released: usize) {
        if released == 0 {
            return;
        }
        let previous = self
            .current_storage_bytes
            .fetch_sub(released, Ordering::AcqRel);
        debug_assert!(previous >= released, "storage byte accounting underflow");
    }

    fn replace_value(
        &self,
        old_value_len: usize,
        slot: &mut (Vec<u8>, Instant),
        value: Vec<u8>,
    ) -> StorageWriteStatus {
        if slot.0 == value {
            slot.1 = Instant::now();
            return StorageWriteStatus::AlreadyStored;
        }

        let new_value_len = value.len();
        if new_value_len > old_value_len && !self.reserve_bytes(new_value_len - old_value_len) {
            return StorageWriteStatus::CapacityExceeded;
        }

        slot.0 = value;
        slot.1 = Instant::now();
        if old_value_len > new_value_len {
            self.release_bytes(old_value_len - new_value_len);
        }
        StorageWriteStatus::Stored
    }

    fn is_expired(&self, inserted_at: Instant) -> bool {
        if self.ttl == -1 {
            return false;
        }
        inserted_at.elapsed() > Duration::from_secs(self.ttl as u64)
    }

    /// Remove expired entries and return how many were reclaimed.
    ///
    /// Reads remain lazy, while this explicit maintenance pass prevents expired
    /// records from accumulating indefinitely in the backing `DashMap`.
    pub fn prune_expired(&self) -> usize {
        if self.ttl == -1 {
            return 0;
        }

        let reclaimed_records = AtomicUsize::new(0);
        let reclaimed_bytes = AtomicUsize::new(0);
        self.data.retain(|key, (value, inserted_at)| {
            let keep = !self.is_expired(*inserted_at);
            if !keep {
                reclaimed_records.fetch_add(1, Ordering::Relaxed);
                reclaimed_bytes.fetch_add(key.len() + value.len(), Ordering::Relaxed);
            }
            keep
        });
        self.release_bytes(reclaimed_bytes.into_inner());
        reclaimed_records.into_inner()
    }
}

impl IStorage for ForgetfulStorage {
    fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageWriteStatus {
        use dashmap::mapref::entry::Entry;
        match self.data.entry(key) {
            Entry::Vacant(entry) => {
                let record_bytes = entry.key().len() + value.len();
                if !self.reserve_bytes(record_bytes) {
                    return StorageWriteStatus::CapacityExceeded;
                }
                entry.insert((value, Instant::now()));
                StorageWriteStatus::Stored
            }
            Entry::Occupied(mut entry) => {
                let old_value_len = entry.get().0.len();
                self.replace_value(old_value_len, entry.get_mut(), value)
            }
        }
    }

    fn insert_if_absent(&self, key: Vec<u8>, value: Vec<u8>) -> StorageWriteStatus {
        use dashmap::mapref::entry::Entry;
        match self.data.entry(key) {
            Entry::Vacant(entry) => {
                let record_bytes = entry.key().len() + value.len();
                if !self.reserve_bytes(record_bytes) {
                    return StorageWriteStatus::CapacityExceeded;
                }
                entry.insert((value, Instant::now()));
                StorageWriteStatus::Stored
            }
            Entry::Occupied(mut entry) => {
                // Treat an expired entry as absent and replace it atomically.
                if self.is_expired(entry.get().1) {
                    let old_value_len = entry.get().0.len();
                    self.replace_value(old_value_len, entry.get_mut(), value)
                } else if entry.get().0 == value {
                    entry.get_mut().1 = Instant::now();
                    StorageWriteStatus::AlreadyStored
                } else {
                    StorageWriteStatus::Conflict
                }
            }
        }
    }

    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>> {
        match self.data.get(key) {
            Some(entry) if !self.is_expired(entry.value().1) => Some(entry.value().0.clone()),
            _ => default,
        }
    }

    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let threshold = Duration::from_secs(seconds_old);
        self.data
            .iter()
            .filter(|e| e.value().1.elapsed() >= threshold && !self.is_expired(e.value().1))
            .map(|e| (e.key().clone(), e.value().0.clone()))
            .collect()
    }

    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.data
            .iter()
            .filter(|e| !self.is_expired(e.value().1))
            .map(|e| (e.key().clone(), e.value().0.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn set_and_get() {
        let s = ForgetfulStorage::new(-1);
        s.set(b"key".to_vec(), b"value".to_vec());
        assert_eq!(s.get(b"key"), Some(b"value".to_vec()));
    }

    #[test]
    fn ttl_expiry() {
        let s = ForgetfulStorage::new(1); // 1-second TTL
        s.set(b"k".to_vec(), b"v".to_vec());
        sleep(Duration::from_millis(1100));
        assert_eq!(s.get(b"k"), None);
    }

    #[test]
    fn no_ttl_never_expires() {
        let s = ForgetfulStorage::new(-1);
        s.set(b"k".to_vec(), b"v".to_vec());
        sleep(Duration::from_millis(10));
        assert_eq!(s.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn iter_older_than() {
        let s = ForgetfulStorage::new(-1);
        s.set(b"a".to_vec(), b"1".to_vec());
        sleep(Duration::from_millis(1100));
        s.set(b"b".to_vec(), b"2".to_vec());
        let old = s.iter_older_than(1);
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].0, b"a".to_vec());
    }

    #[test]
    fn insert_if_absent_new_key() {
        let s = ForgetfulStorage::new(-1);
        assert_eq!(
            s.insert_if_absent(b"k".to_vec(), b"v1".to_vec()),
            StorageWriteStatus::Stored
        );
        assert_eq!(s.get(b"k"), Some(b"v1".to_vec()));
    }

    #[test]
    fn insert_if_absent_existing_key() {
        let s = ForgetfulStorage::new(-1);
        s.set(b"k".to_vec(), b"v1".to_vec());
        assert_eq!(
            s.insert_if_absent(b"k".to_vec(), b"v2".to_vec()),
            StorageWriteStatus::Conflict
        );
        assert_eq!(s.get(b"k"), Some(b"v1".to_vec()));
    }

    #[test]
    fn insert_if_absent_replaces_expired() {
        let s = ForgetfulStorage::new(1);
        s.set(b"k".to_vec(), b"old".to_vec());
        sleep(Duration::from_millis(1100));
        assert_eq!(
            s.insert_if_absent(b"k".to_vec(), b"new".to_vec()),
            StorageWriteStatus::Stored
        );
        assert_eq!(s.get(b"k"), Some(b"new".to_vec()));
    }

    #[test]
    fn prune_expired_reclaims_memory() {
        let s = ForgetfulStorage::new(1);
        s.set(b"expired".to_vec(), b"value".to_vec());
        sleep(Duration::from_millis(1100));

        assert_eq!(s.prune_expired(), 1);
        assert!(s.data.is_empty());
    }
    #[test]
    fn default_storage_budget_is_512_mib() {
        let storage = ForgetfulStorage::new(-1);
        assert_eq!(storage.max_storage_bytes(), 512 * 1024 * 1024);
        assert_eq!(storage.max_storage_bytes(), DEFAULT_MAX_STORAGE_BYTES);
    }

    #[test]
    fn capacity_is_atomic_and_exact() {
        let storage = ForgetfulStorage::with_max_storage_bytes(-1, 8);
        assert_eq!(
            storage.insert_if_absent(b"key".to_vec(), b"value".to_vec()),
            StorageWriteStatus::Stored
        );
        assert_eq!(storage.current_storage_bytes(), 8);
        assert_eq!(
            storage.insert_if_absent(b"x".to_vec(), Vec::new()),
            StorageWriteStatus::CapacityExceeded
        );
        assert_eq!(storage.current_storage_bytes(), 8);
        assert_eq!(storage.get(b"x"), None);
    }

    #[test]
    fn identical_insert_is_idempotent_but_different_value_conflicts() {
        let storage = ForgetfulStorage::with_max_storage_bytes(-1, 16);
        assert_eq!(
            storage.insert_if_absent(b"k".to_vec(), b"value".to_vec()),
            StorageWriteStatus::Stored
        );
        assert_eq!(
            storage.insert_if_absent(b"k".to_vec(), b"value".to_vec()),
            StorageWriteStatus::AlreadyStored
        );
        assert_eq!(storage.current_storage_bytes(), 6);
        assert_eq!(
            storage.insert_if_absent(b"k".to_vec(), b"other".to_vec()),
            StorageWriteStatus::Conflict
        );
        assert_eq!(storage.get(b"k"), Some(b"value".to_vec()));
        assert_eq!(storage.current_storage_bytes(), 6);
    }

    #[test]
    fn rejected_growth_preserves_the_existing_value_and_accounting() {
        let storage = ForgetfulStorage::with_max_storage_bytes(-1, 6);
        assert_eq!(
            storage.set(b"k".to_vec(), b"value".to_vec()),
            StorageWriteStatus::Stored
        );
        assert_eq!(
            storage.set(b"k".to_vec(), b"larger".to_vec()),
            StorageWriteStatus::CapacityExceeded
        );
        assert_eq!(storage.get(b"k"), Some(b"value".to_vec()));
        assert_eq!(storage.current_storage_bytes(), 6);
    }

    #[test]
    fn prune_expired_releases_capacity() {
        let storage = ForgetfulStorage::with_max_storage_bytes(0, 4);
        assert_eq!(
            storage.set(b"k".to_vec(), b"123".to_vec()),
            StorageWriteStatus::Stored
        );
        sleep(Duration::from_millis(1));
        assert_eq!(storage.prune_expired(), 1);
        assert_eq!(storage.current_storage_bytes(), 0);
    }

    #[test]
    fn concurrent_writes_never_oversubscribe_the_budget() {
        use std::sync::{Arc, Barrier};

        const RECORDS: usize = 32;
        const RECORD_BYTES: usize = 12;
        const CAPACITY_RECORDS: usize = 4;

        let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
            -1,
            RECORD_BYTES * CAPACITY_RECORDS,
        ));
        let barrier = Arc::new(Barrier::new(RECORDS));
        let handles: Vec<_> = (0..RECORDS)
            .map(|index| {
                let storage = Arc::clone(&storage);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    storage.insert_if_absent((index as u32).to_be_bytes().to_vec(), vec![0; 8])
                })
            })
            .collect();

        let stored = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|status| *status == StorageWriteStatus::Stored)
            .count();
        assert_eq!(stored, CAPACITY_RECORDS);
        assert_eq!(
            storage.current_storage_bytes(),
            RECORD_BYTES * CAPACITY_RECORDS
        );
    }
}
