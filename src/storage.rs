//! Key-value storage with TTL expiry, in memory or also on disk.
//!
//! `IStorage` is the interface the protocol uses. `ForgetfulStorage` keeps
//! its entries in a `DashMap`. Given a data directory it also keeps each one
//! in a file (`durable`): a new or changed record is on the device before the
//! write returns. A renewal of the same bytes only moves the expiry, in
//! memory; the next `flush_renewals` writes every expiry renewed since the
//! records' files were written, all in one file, and the record files stay
//! as they are. Once a DID record expires, the highest position accepted
//! for its key is remembered for one more TTL (`marker`). Expiry is lazy:
//! reads check it, and `prune_expired` reclaims what expired.
//!
//! Times are milliseconds since the Unix epoch, so that a record keeps the
//! rest of its TTL across a restart.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::mapref::entry::{Entry, VacantEntry};
use dashmap::DashMap;

use crate::auth_handler::tree::tree_form;
use crate::durable::{DurableDir, Renewals, Stored};
use crate::utils::{digest_bytes, ID_LEN};

/// Two weeks in seconds — the default record TTL used by AuthKademlia.
pub const DEFAULT_TTL: i64 = 14 * 24 * 60 * 60;

/// Default per-node storage budget: 512 MiB of keys and values.
pub const DEFAULT_MAX_STORAGE_BYTES: usize = 512 * 1024 * 1024;

/// How often the renewals of a persistent store reach the device: the
/// period of the republication that renews its records, one day. A power
/// cut loses at most that much of a record's TTL, never the record.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// What a marker costs in the storage budget besides its key: its position
/// and its deadline.
const MARKER_BYTES: usize = 16;

/// Result of an atomic storage write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageWriteStatus {
    Stored,
    AlreadyStored,
    Conflict,
    CapacityExceeded,
    /// The record could not be made durable: nothing was written.
    WriteFailed,
}

/// Result of `IStorage::replace_if`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceStatus {
    /// The stored value was the expected one, and is now the new one.
    Replaced,
    /// The key holds another value, an expired one, or none: nothing written.
    Changed,
    /// The new value does not fit in the storage budget: nothing written.
    CapacityExceeded,
    /// The new value could not be made durable: nothing written.
    WriteFailed,
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

    /// Atomically replace `expected` with `new` under `key`, only if `key`
    /// still holds `expected` and it has not expired: a compare-and-swap, so
    /// that a replica replaces only the record it checked. The new value
    /// gets a fresh expiry.
    fn replace_if(&self, key: &[u8], expected: &[u8], new: Vec<u8>) -> ReplaceStatus;

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

/// Milliseconds since the Unix epoch.
pub(crate) type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub(crate) fn system_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The position of `value` if it is a DID record of `key`.
fn position_of(key: &[u8], value: &[u8]) -> Option<u64> {
    let key: &[u8; ID_LEN] = key.try_into().ok()?;
    tree_form(key, value).ok().map(|form| form.seq)
}

/// What the store holds for a key.
#[derive(Debug, Clone)]
enum Slot {
    /// A record, written or last renewed at `renewed_at`. `written_at` is
    /// the time its file was written, the renewal that file holds; a later
    /// renewal reaches the disk in the file of renewals.
    Record {
        value: Vec<u8>,
        renewed_at: u64,
        written_at: u64,
    },
    /// The highest position accepted for the key, remembered until `until`
    /// after its record expired.
    Marker { seq: u64, until: u64 },
}

/// What a slot becomes at a given time.
enum Settled {
    Live,
    Marker { seq: u64, until: u64 },
    Gone,
}

/// A concurrent store backed by `DashMap` with lazy TTL expiry, optionally
/// mirrored in a data directory.
///
/// A `ttl` of `-1` disables expiry entirely (entries are kept forever).
pub struct ForgetfulStorage {
    data: DashMap<Vec<u8>, Slot>,
    ttl: i64,
    current_storage_bytes: AtomicUsize,
    max_storage_bytes: usize,
    clock: Clock,
    durable: Option<DurableDir>,
    flush_interval: Duration,
    /// A record was renewed since the last `flush_renewals`.
    renewed: AtomicBool,
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
        Self::in_memory(ttl, max_storage_bytes, Arc::new(system_clock))
    }

    pub(crate) fn in_memory(ttl: i64, max_storage_bytes: usize, clock: Clock) -> Self {
        Self {
            data: DashMap::new(),
            ttl,
            current_storage_bytes: AtomicUsize::new(0),
            max_storage_bytes,
            clock,
            durable: None,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            renewed: AtomicBool::new(false),
        }
    }

    /// A store that also keeps every entry in a file under `dir`, created if
    /// missing, and starts with what it finds there: live records, and the
    /// markers of expired ones. An entry whose record and marker have both
    /// expired is removed, and an entry beyond the budget is left on disk.
    pub fn persistent(
        dir: impl Into<PathBuf>,
        ttl: i64,
        max_storage_bytes: usize,
    ) -> io::Result<Self> {
        Self::open(dir.into(), ttl, max_storage_bytes, Arc::new(system_clock))
    }

    pub(crate) fn open(
        dir: PathBuf,
        ttl: i64,
        max_storage_bytes: usize,
        clock: Clock,
    ) -> io::Result<Self> {
        let durable = DurableDir::open(dir)?;
        let mut store = Self::in_memory(ttl, max_storage_bytes, clock);
        let now = store.now();
        for (key, stored) in durable.load()? {
            let mut slot = match stored {
                Stored::Record {
                    value,
                    expires,
                    renewed,
                } => {
                    let written_at = store.renewed_at_of(expires, now);
                    Slot::Record {
                        value,
                        renewed_at: renewed
                            .map_or(written_at, |later| store.renewed_at_of(later, now)),
                        written_at,
                    }
                }
                Stored::Marker { seq, until } => Slot::Marker { seq, until },
            };
            match store.settle(&key, &slot, now) {
                Settled::Live => {}
                Settled::Marker { seq, until } => {
                    slot = Slot::Marker { seq, until };
                    report(&key, durable.write_marker(&key, seq, until));
                }
                Settled::Gone => {
                    report(&key, durable.remove(&key));
                    continue;
                }
            }
            if !store.reserve_bytes(charge(&key, &slot)) {
                log::warn!(
                    "storage: {} beyond the budget, left on disk",
                    hex::encode(&key)
                );
                continue;
            }
            store.data.insert(key, slot);
        }
        store.durable = Some(durable);
        Ok(store)
    }

    /// The interval at which `flush_renewals` should run.
    pub fn with_flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    pub fn flush_interval(&self) -> Duration {
        self.flush_interval
    }

    /// Whether entries are kept on disk too.
    pub fn is_persistent(&self) -> bool {
        self.durable.is_some()
    }

    /// Bytes currently charged to the storage budget, including expired
    /// entries that have not yet been pruned.
    pub fn current_storage_bytes(&self) -> usize {
        self.current_storage_bytes.load(Ordering::Acquire)
    }

    pub fn max_storage_bytes(&self) -> usize {
        self.max_storage_bytes
    }

    /// Whether the store holds no entry at all, not even an expired record
    /// that has not yet been pruned or a marker.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The highest position accepted for `key` whose record has expired,
    /// while it is remembered: one more TTL after the record's expiry.
    /// `None` while the record is live, as `get` returns it.
    pub fn marker(&self, key: &[u8]) -> Option<u64> {
        let slot = self.data.get(key)?;
        self.marker_of(key, &slot, self.now())
    }

    /// The live record of `key`, or else the position remembered for it,
    /// read under one lock.
    pub fn record_or_marker(&self, key: &[u8]) -> (Option<Vec<u8>>, Option<u64>) {
        let now = self.now();
        let Some(slot) = self.data.get(key) else {
            return (None, None);
        };
        match self.live_value(&slot, now) {
            Some(value) => (Some(value.clone()), None),
            None => (None, self.marker_of(key, &slot, now)),
        }
    }

    fn marker_of(&self, key: &[u8], slot: &Slot, now: u64) -> Option<u64> {
        match (self.settle(key, slot, now), slot) {
            (Settled::Marker { seq, .. }, _) => Some(seq),
            (Settled::Live, Slot::Marker { seq, .. }) => Some(*seq),
            _ => None,
        }
    }

    /// If a record was renewed since the last flush, write the expiry of
    /// every record renewed since its file was written, with the SHA-256 of
    /// the record it renews, to the file of renewals: one write, whatever
    /// the number of records, and none when nothing was renewed. The record
    /// files are not written, and a renewal applies only to the record it
    /// renewed, never to one that replaced it. Returns how many renewals
    /// were written.
    pub fn flush_renewals(&self) -> usize {
        let Some(durable) = &self.durable else {
            return 0;
        };
        // Cleared first: a renewal made while the file is written is
        // written by the next flush.
        if !self.renewed.swap(false, Ordering::AcqRel) {
            return 0;
        }
        let written = self.renewals().and_then(|renewals| {
            let count = renewals.count();
            durable.write_renewals(renewals).map(|()| count)
        });
        match written {
            Ok(count) => count,
            Err(error) => {
                log::error!("storage: the file of renewals: {error}");
                self.renewed.store(true, Ordering::Release);
                0
            }
        }
    }

    /// The renewals of the records renewed since their files were written,
    /// built straight into the bytes of the file of renewals.
    fn renewals(&self) -> io::Result<Renewals> {
        let mut renewals = Renewals::with_capacity(self.data.len());
        for entry in self.data.iter() {
            if let Slot::Record {
                value,
                renewed_at,
                written_at,
            } = entry.value()
            {
                if renewed_at > written_at {
                    renewals.push(entry.key(), &digest_bytes(value), self.expires(*renewed_at))?;
                }
            }
        }
        Ok(renewals)
    }

    /// Turn the DID records that expired into the markers of their positions,
    /// and drop the other expired records and the expired markers. Returns
    /// how many entries changed.
    pub fn prune_expired(&self) -> usize {
        if self.ttl == -1 {
            return 0;
        }
        let now = self.now();
        let expired: Vec<Vec<u8>> = self
            .data
            .iter()
            .filter(|entry| !matches!(self.settle(entry.key(), entry.value(), now), Settled::Live))
            .map(|entry| entry.key().clone())
            .collect();
        let mut changed = 0;
        for key in expired {
            // Settled again under the entry: it may have been written since.
            let Entry::Occupied(mut entry) = self.data.entry(key) else {
                continue;
            };
            match self.settle(entry.key(), entry.get(), now) {
                Settled::Live => continue,
                Settled::Marker { seq, until } => {
                    let marker = Slot::Marker { seq, until };
                    self.release_bytes(
                        charge(entry.key(), entry.get())
                            .saturating_sub(charge(entry.key(), &marker)),
                    );
                    if let Some(durable) = &self.durable {
                        report(entry.key(), durable.write_marker(entry.key(), seq, until));
                    }
                    *entry.get_mut() = marker;
                }
                Settled::Gone => {
                    self.release_bytes(charge(entry.key(), entry.get()));
                    if let Some(durable) = &self.durable {
                        report(entry.key(), durable.remove(entry.key()));
                    }
                    entry.remove();
                }
            }
            changed += 1;
        }
        changed
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn ttl_ms(&self) -> Option<u64> {
        u64::try_from(self.ttl)
            .ok()
            .map(|ttl| ttl.saturating_mul(1000))
    }

    fn expires(&self, renewed_at: u64) -> u64 {
        self.ttl_ms()
            .map_or(u64::MAX, |ttl| renewed_at.saturating_add(ttl))
    }

    /// The renewal that gives a record the expiry `expires`.
    fn renewed_at_of(&self, expires: u64, now: u64) -> u64 {
        self.ttl_ms().map_or(now, |ttl| expires.saturating_sub(ttl))
    }

    /// The live record of `slot`, if any.
    fn live_value<'a>(&self, slot: &'a Slot, now: u64) -> Option<&'a Vec<u8>> {
        match slot {
            Slot::Record {
                value, renewed_at, ..
            } if now < self.expires(*renewed_at) => Some(value),
            _ => None,
        }
    }

    fn settle(&self, key: &[u8], slot: &Slot, now: u64) -> Settled {
        match slot {
            Slot::Record {
                value, renewed_at, ..
            } => {
                let expires = self.expires(*renewed_at);
                if now < expires {
                    return Settled::Live;
                }
                let until = self.expires(expires);
                match position_of(key, value) {
                    Some(seq) if now < until => Settled::Marker { seq, until },
                    _ => Settled::Gone,
                }
            }
            Slot::Marker { until, .. } if now < *until => Settled::Live,
            Slot::Marker { .. } => Settled::Gone,
        }
    }

    /// Write the record `value`, renewed at `now`, as the file of `key`.
    /// `true` when it is durable, or when this store keeps no files.
    fn persist_record(&self, key: &[u8], value: &[u8], now: u64) -> bool {
        self.durable
            .as_ref()
            .is_none_or(|durable| report(key, durable.write_record(key, value, self.expires(now))))
    }

    /// Insert the record `value`, written at `now`, under a vacant key:
    /// first on disk, then in memory, within the budget.
    fn insert_new(
        &self,
        entry: VacantEntry<'_, Vec<u8>, Slot>,
        value: Vec<u8>,
        now: u64,
    ) -> StorageWriteStatus {
        let cost = entry.key().len() + value.len();
        if !self.reserve_bytes(cost) {
            return StorageWriteStatus::CapacityExceeded;
        }
        if !self.persist_record(entry.key(), &value, now) {
            self.release_bytes(cost);
            return StorageWriteStatus::WriteFailed;
        }
        entry.insert(Slot::Record {
            value,
            renewed_at: now,
            written_at: now,
        });
        StorageWriteStatus::Stored
    }

    /// Make `slot`, of `key`, the record `value` written at `now`: first on
    /// disk, then in memory, within the budget.
    fn write_slot(
        &self,
        key: &[u8],
        slot: &mut Slot,
        value: Vec<u8>,
        now: u64,
    ) -> StorageWriteStatus {
        let (old, new) = (charge(key, slot), key.len() + value.len());
        if new > old && !self.reserve_bytes(new - old) {
            return StorageWriteStatus::CapacityExceeded;
        }
        if !self.persist_record(key, &value, now) {
            self.release_bytes(new.saturating_sub(old));
            return StorageWriteStatus::WriteFailed;
        }
        self.release_bytes(old.saturating_sub(new));
        *slot = Slot::Record {
            value,
            renewed_at: now,
            written_at: now,
        };
        StorageWriteStatus::Stored
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

    /// A renewal of `slot`, a live record: a fresh expiry, in memory until
    /// the next flush.
    fn renew(&self, slot: &mut Slot, now: u64) {
        if let Slot::Record { renewed_at, .. } = slot {
            *renewed_at = now;
            self.renewed.store(true, Ordering::Release);
        }
    }
}

/// `true` when `result`, a file operation for `key`, succeeded; a failure
/// is logged.
fn report(key: &[u8], result: io::Result<()>) -> bool {
    result
        .inspect_err(|error| log::error!("storage: the file of {}: {error}", hex::encode(key)))
        .is_ok()
}

/// What an entry costs in the storage budget.
fn charge(key: &[u8], slot: &Slot) -> usize {
    key.len()
        + match slot {
            Slot::Record { value, .. } => value.len(),
            Slot::Marker { .. } => MARKER_BYTES,
        }
}

impl IStorage for ForgetfulStorage {
    fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageWriteStatus {
        let now = self.now();
        match self.data.entry(key) {
            Entry::Vacant(entry) => self.insert_new(entry, value, now),
            Entry::Occupied(mut entry) => {
                if self.live_value(entry.get(), now) == Some(&value) {
                    self.renew(entry.get_mut(), now);
                    return StorageWriteStatus::AlreadyStored;
                }
                let key = entry.key().clone();
                self.write_slot(&key, entry.get_mut(), value, now)
            }
        }
    }

    fn insert_if_absent(&self, key: Vec<u8>, value: Vec<u8>) -> StorageWriteStatus {
        let now = self.now();
        match self.data.entry(key) {
            Entry::Vacant(entry) => self.insert_new(entry, value, now),
            Entry::Occupied(mut entry) => match self.live_value(entry.get(), now) {
                Some(held) if *held == value => {
                    self.renew(entry.get_mut(), now);
                    StorageWriteStatus::AlreadyStored
                }
                Some(_) => StorageWriteStatus::Conflict,
                // An expired record, or a marker, is as good as absent.
                None => {
                    let key = entry.key().clone();
                    self.write_slot(&key, entry.get_mut(), value, now)
                }
            },
        }
    }

    fn replace_if(&self, key: &[u8], expected: &[u8], new: Vec<u8>) -> ReplaceStatus {
        // Under the lock of this one entry, with no `.await`, as
        // `insert_if_absent`: nothing else writes the key in between.
        let now = self.now();
        let Some(mut entry) = self.data.get_mut(key) else {
            return ReplaceStatus::Changed;
        };
        if self.live_value(&entry, now).map(Vec::as_slice) != Some(expected) {
            return ReplaceStatus::Changed;
        }
        if new == expected {
            self.renew(&mut entry, now);
            return ReplaceStatus::Replaced;
        }
        match self.write_slot(key, &mut entry, new, now) {
            StorageWriteStatus::CapacityExceeded => ReplaceStatus::CapacityExceeded,
            StorageWriteStatus::WriteFailed => ReplaceStatus::WriteFailed,
            _ => ReplaceStatus::Replaced,
        }
    }

    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let now = self.now();
        self.data
            .get(key)
            .and_then(|slot| self.live_value(&slot, now).cloned())
            .or(default)
    }

    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let now = self.now();
        let threshold = seconds_old.saturating_mul(1000);
        self.data
            .iter()
            .filter_map(|entry| match entry.value() {
                Slot::Record { renewed_at, .. } if now.saturating_sub(*renewed_at) >= threshold => {
                    self.live_value(entry.value(), now)
                        .map(|value| (entry.key().clone(), value.clone()))
                }
                _ => None,
            })
            .collect()
    }

    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let now = self.now();
        self.data
            .iter()
            .filter_map(|entry| {
                self.live_value(entry.value(), now)
                    .map(|value| (entry.key().clone(), value.clone()))
            })
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

    // ---- Persistence and markers ---------------------------------------------

    use std::sync::atomic::AtomicU64;

    use crate::auth_handler::test_tree::TreeOwner;
    use crate::durable::test_dir::{set_read_only, TestDir};

    const TTL: i64 = 100;
    const TTL_MS: u64 = 100_000;
    const T0: u64 = 1_700_000_000_000;

    /// A clock the test moves, starting at `T0`.
    fn clock() -> (Arc<AtomicU64>, Clock) {
        let time = Arc::new(AtomicU64::new(T0));
        let read = Arc::clone(&time);
        (time, Arc::new(move || read.load(Ordering::Relaxed)))
    }

    fn reopen(dir: &TestDir, clock: &Clock) -> ForgetfulStorage {
        ForgetfulStorage::open(
            dir.path().to_path_buf(),
            TTL,
            DEFAULT_MAX_STORAGE_BYTES,
            Arc::clone(clock),
        )
        .unwrap()
    }

    /// 6 is acknowledged, then the power goes, with no shutdown and no flush:
    /// the restarted store serves the exact bytes of 6.
    #[test]
    fn a_record_acknowledged_before_a_power_cut_is_served_after_it() {
        let (_, clock) = clock();
        let dir = TestDir::new();
        let store = reopen(&dir, &clock);
        store.set(b"k".to_vec(), b"five".to_vec());
        assert_eq!(
            store.replace_if(b"k", b"five", b"six".to_vec()),
            ReplaceStatus::Replaced
        );
        drop(store);
        assert_eq!(reopen(&dir, &clock).get(b"k"), Some(b"six".to_vec()));
    }

    /// The write of 6 fails while 5 is live: 6 is not confirmed, and the
    /// store holds, and recovers, the whole of 5.
    #[test]
    fn a_record_that_cannot_be_made_durable_is_not_stored() {
        let (_, clock) = clock();
        let dir = TestDir::new();
        let store = reopen(&dir, &clock);
        store.set(b"k".to_vec(), b"five".to_vec());
        if !set_read_only(dir.path(), true) {
            eprintln!("skipped: this process writes to a read-only directory");
            return;
        }
        assert_eq!(
            store.replace_if(b"k", b"five", b"six".to_vec()),
            ReplaceStatus::WriteFailed
        );
        assert_eq!(
            store.insert_if_absent(b"other".to_vec(), b"value".to_vec()),
            StorageWriteStatus::WriteFailed
        );
        assert_eq!(store.get(b"k"), Some(b"five".to_vec()));
        assert_eq!(store.get(b"other"), None);
        assert_eq!(store.current_storage_bytes(), 1 + 4);
        set_read_only(dir.path(), false);
        drop(store);
        assert_eq!(reopen(&dir, &clock).get(b"k"), Some(b"five".to_vec()));
    }

    /// 6 is renewed from expiry E1 to E2. Lost before the flush, the renewal
    /// leaves E1; flushed, 6 lives until E2.
    #[test]
    fn a_renewal_reaches_the_disk_with_the_next_flush() {
        let (time, clock) = clock();
        let (e1, e2) = (T0 + TTL_MS, T0 + 10_000 + TTL_MS);
        for flushed in [false, true] {
            time.store(T0, Ordering::Relaxed);
            let dir = TestDir::new();
            let store = reopen(&dir, &clock);
            store.set(b"k".to_vec(), b"six".to_vec());
            time.store(T0 + 10_000, Ordering::Relaxed);
            assert_eq!(
                store.insert_if_absent(b"k".to_vec(), b"six".to_vec()),
                StorageWriteStatus::AlreadyStored
            );
            if flushed {
                assert_eq!(store.flush_renewals(), 1);
            }
            drop(store);
            let expires = if flushed { e2 } else { e1 };
            time.store(expires - 1, Ordering::Relaxed);
            assert_eq!(reopen(&dir, &clock).get(b"k"), Some(b"six".to_vec()));
            time.store(expires, Ordering::Relaxed);
            assert_eq!(reopen(&dir, &clock).get(b"k"), None);
        }
    }

    /// A renewal of 5 is pending when 6 is committed: the flush leaves 6 and
    /// its expiry as they are, and an idle flush writes nothing.
    #[test]
    fn a_flush_never_brings_back_the_record_it_renewed() {
        let (time, clock) = clock();
        let dir = TestDir::new();
        let store = reopen(&dir, &clock);
        store.set(b"k".to_vec(), b"five".to_vec());
        time.store(T0 + 1_000, Ordering::Relaxed);
        store.set(b"k".to_vec(), b"five".to_vec());
        time.store(T0 + 2_000, Ordering::Relaxed);
        store.replace_if(b"k", b"five", b"six".to_vec());
        assert_eq!(store.flush_renewals(), 0);
        assert_eq!(store.flush_renewals(), 0);
        drop(store);
        time.store(T0 + 2_000 + TTL_MS - 1, Ordering::Relaxed);
        assert_eq!(reopen(&dir, &clock).get(b"k"), Some(b"six".to_vec()));
    }

    /// A flush writes the renewed expiries, all in the file of renewals, and
    /// no record file: those keep the bytes they were written with. A flush
    /// with no renewal since the last one writes nothing.
    #[test]
    fn a_flush_writes_the_renewed_expiries_and_not_the_records() {
        let (time, clock) = clock();
        let dir = TestDir::new();
        let files = || {
            let mut files: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = std::fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect();
            files.sort();
            files
        };
        let store = reopen(&dir, &clock);
        store.set(b"a".to_vec(), b"six".to_vec());
        store.set(b"b".to_vec(), b"seven".to_vec());
        let records = files();
        time.store(T0 + 10_000, Ordering::Relaxed);
        store.set(b"a".to_vec(), b"six".to_vec());
        store.set(b"b".to_vec(), b"seven".to_vec());
        assert_eq!(store.flush_renewals(), 2);
        let flushed = files();
        assert_eq!(flushed.len(), records.len() + 1);
        assert!(records.iter().all(|file| flushed.contains(file)));

        let renewals = dir.path().join("renewals");
        std::fs::remove_file(&renewals).unwrap();
        assert_eq!(store.flush_renewals(), 0);
        assert!(!renewals.exists());
    }

    /// An expired DID record leaves the marker of its position for one more
    /// TTL, charged to the budget; another record leaves nothing.
    #[test]
    fn an_expired_record_leaves_the_marker_of_its_position_for_one_more_ttl() {
        let (time, clock) = clock();
        let owner = TreeOwner::new(1);
        let v6 = owner.record(6, Some(b"5"));
        let store = ForgetfulStorage::in_memory(TTL, DEFAULT_MAX_STORAGE_BYTES, clock);
        store.set(owner.key.to_vec(), v6.clone());
        store.set(b"status".to_vec(), b"list".to_vec());
        assert_eq!(store.marker(&owner.key), None);

        time.store(T0 + TTL_MS, Ordering::Relaxed);
        assert_eq!(store.get(&owner.key), None);
        assert_eq!(store.marker(&owner.key), Some(6));
        assert_eq!(store.record_or_marker(&owner.key), (None, Some(6)));
        assert!(store.iter_all().is_empty());
        assert_eq!(store.prune_expired(), 2);
        assert_eq!(store.marker(&owner.key), Some(6));
        assert_eq!(store.marker(b"status"), None);
        assert_eq!(
            store.current_storage_bytes(),
            owner.key.len() + MARKER_BYTES
        );

        time.store(T0 + 2 * TTL_MS, Ordering::Relaxed);
        assert_eq!(store.marker(&owner.key), None);
        assert_eq!(store.prune_expired(), 1);
        assert_eq!(store.current_storage_bytes(), 0);
    }

    /// A record written over a marker replaces it.
    #[test]
    fn a_record_written_over_a_marker_replaces_it() {
        let (time, clock) = clock();
        let owner = TreeOwner::new(1);
        let v6 = owner.record(6, Some(b"5"));
        let v7 = owner.record(7, Some(&v6));
        let store = ForgetfulStorage::in_memory(TTL, DEFAULT_MAX_STORAGE_BYTES, clock);
        store.set(owner.key.to_vec(), v6);
        time.store(T0 + TTL_MS, Ordering::Relaxed);
        store.prune_expired();
        assert_eq!(
            store.insert_if_absent(owner.key.to_vec(), v7.clone()),
            StorageWriteStatus::Stored
        );
        assert_eq!(store.record_or_marker(&owner.key), (Some(v7.clone()), None));
        assert_eq!(store.current_storage_bytes(), owner.key.len() + v7.len());
    }

    /// The marker outlives a power cut, whether the record expired while the
    /// node ran or while it was off, and goes once its own deadline passed.
    #[test]
    fn a_marker_survives_a_power_cut_until_its_deadline() {
        let (time, clock) = clock();
        let owner = TreeOwner::new(1);
        let v6 = owner.record(6, Some(b"5"));
        for pruned_before_the_cut in [true, false] {
            time.store(T0, Ordering::Relaxed);
            let dir = TestDir::new();
            let store = reopen(&dir, &clock);
            store.set(owner.key.to_vec(), v6.clone());
            time.store(T0 + TTL_MS, Ordering::Relaxed);
            if pruned_before_the_cut {
                store.prune_expired();
            }
            drop(store);

            let restarted = reopen(&dir, &clock);
            assert_eq!(restarted.record_or_marker(&owner.key), (None, Some(6)));
            drop(restarted);

            time.store(T0 + 2 * TTL_MS, Ordering::Relaxed);
            let restarted = reopen(&dir, &clock);
            assert_eq!(restarted.record_or_marker(&owner.key), (None, None));
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }
}
