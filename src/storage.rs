/// Key-value storage with optional TTL-based expiry.
///
/// `IStorage` is the abstract interface used by the protocol layer.
/// `ForgetfulStorage` is the concurrent implementation backed by `DashMap`.
/// TTL expiry is lazy: entries are checked on read rather than culled on write.
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Two weeks in seconds — the default record TTL used by AuthKademlia.
pub const DEFAULT_TTL: i64 = 14 * 24 * 60 * 60;

/// Abstract key-value store interface.
///
/// All methods take `&self` — implementations must be internally synchronized
/// (e.g. via `DashMap` or `Mutex`) so they can be shared across async tasks.
pub trait IStorage: Send + Sync {
    /// Insert or replace a key-value pair.
    fn set(&self, key: Vec<u8>, value: Vec<u8>);

    /// Atomically insert `key → value` only if the key is absent.
    /// Returns `true` if the insertion happened, `false` if the key existed.
    fn insert_if_absent(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Retrieve a value, returning `default` if the key is absent.
    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>>;

    /// Retrieve a value, returning `None` if the key is absent.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_default(key, None)
    }

    /// Remove a key.
    fn delete(&self, key: &[u8]);

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
}

impl ForgetfulStorage {
    /// Create a new store with the given TTL.
    ///
    /// Pass `ttl = -1` to disable expiry.
    pub fn new(ttl: i64) -> Self {
        Self {
            data: DashMap::new(),
            ttl,
        }
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

        let before = self.data.len();
        self.data
            .retain(|_, (_, inserted_at)| !self.is_expired(*inserted_at));
        before.saturating_sub(self.data.len())
    }
}

impl IStorage for ForgetfulStorage {
    fn set(&self, key: Vec<u8>, value: Vec<u8>) {
        self.data.insert(key, (value, Instant::now()));
    }

    fn insert_if_absent(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.data.entry(key) {
            Entry::Vacant(e) => {
                e.insert((value, Instant::now()));
                true
            }
            Entry::Occupied(e) => {
                // Treat an expired entry as absent — replace it.
                if self.is_expired(e.get().1) {
                    e.replace_entry((value, Instant::now()));
                    true
                } else {
                    false
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

    fn delete(&self, key: &[u8]) {
        self.data.remove(key);
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
    fn delete() {
        let s = ForgetfulStorage::new(-1);
        s.set(b"k".to_vec(), b"v".to_vec());
        s.delete(b"k");
        assert_eq!(s.get(b"k"), None);
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
        assert!(s.insert_if_absent(b"k".to_vec(), b"v1".to_vec()));
        assert_eq!(s.get(b"k"), Some(b"v1".to_vec()));
    }

    #[test]
    fn insert_if_absent_existing_key() {
        let s = ForgetfulStorage::new(-1);
        s.set(b"k".to_vec(), b"v1".to_vec());
        assert!(!s.insert_if_absent(b"k".to_vec(), b"v2".to_vec()));
        assert_eq!(s.get(b"k"), Some(b"v1".to_vec()));
    }

    #[test]
    fn insert_if_absent_replaces_expired() {
        let s = ForgetfulStorage::new(1);
        s.set(b"k".to_vec(), b"old".to_vec());
        sleep(Duration::from_millis(1100));
        assert!(s.insert_if_absent(b"k".to_vec(), b"new".to_vec()));
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
}
