/// In-memory cache for signature verification results.
///
/// Keyed by a domain-separated SHA-256 of the full record bytes so that any
/// byte-level change (algorithm field, signature bytes, or payload) produces
/// a cache miss and forces a full cryptographic re-verification. The domain is
/// part of the key because identical bytes can be verified under different
/// trust roots (the embedded document key or the issuer key). The cache is
/// bounded in size and entries expire after one hour.
use moka::sync::Cache;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct SignatureCache {
    cache: Cache<[u8; 32], bool>,
}

/// Trust root used while verifying a record.
///
/// A successful verification in one domain must never authorize the same
/// bytes in another domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VerificationDomain {
    SelfSigned = 0,
    IssuerSigned = 1,
}

impl SignatureCache {
    pub fn new(max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(3600))
            .build();
        Self { cache }
    }

    /// Compute the cache key for `value` in `domain`.
    ///
    /// Callers that need to both look up and insert should call this once and
    /// use `get_by_key` / `insert_by_key` to avoid hashing twice.
    pub fn compute_key(domain: VerificationDomain, value: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([domain as u8]);
        hasher.update(value);
        hasher.finalize().into()
    }

    pub fn get_by_key(&self, key: &[u8; 32]) -> Option<bool> {
        self.cache.get(key)
    }

    pub fn insert_by_key(&self, key: [u8; 32], result: bool) {
        self.cache.insert(key, result);
    }

    /// Convenience wrapper — computes the key internally. Use when only
    /// looking up (no subsequent insert in the same call site).
    pub fn get(&self, domain: VerificationDomain, value: &[u8]) -> Option<bool> {
        self.cache.get(&Self::compute_key(domain, value))
    }

    /// Convenience wrapper — computes the key internally. Use when only
    /// inserting (no preceding get in the same call site).
    pub fn insert(&self, domain: VerificationDomain, value: &[u8], result: bool) {
        self.cache.insert(Self::compute_key(domain, value), result);
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}
