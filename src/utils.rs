/// General-purpose utilities.
///
/// Provides SHA-1 digests, concurrent future gathering, and bit-level
/// helpers used across the codebase.
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::future::Future;

/// Byte length of a Kademlia node ID (SHA-1 output = 20 bytes = 160 bits).
pub const ID_LEN: usize = 20;

/// Reserved DHT key for the issuer-signed status list. Operations on this key
/// use issuer-node signature verification instead of DID-owner verification.
pub const STATUS_LIST_KEY: &str = "did:iiot:status-list";

/// Compute the SHA-1 digest of a UTF-8 string.
pub fn digest(s: &str) -> [u8; ID_LEN] {
    digest_bytes(s.as_bytes())
}

/// Compute the SHA-1 digest of raw bytes.
pub fn digest_bytes(data: &[u8]) -> [u8; ID_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Run all futures in `dic` concurrently and return a `HashMap` mapping
/// each key to its future's output.
///
/// Equivalent to Python's `gather_dict`.
pub async fn gather_dict<K, V, Fut>(dic: HashMap<K, Fut>) -> HashMap<K, V>
where
    K: Eq + std::hash::Hash + Clone + Send + 'static,
    V: Send + 'static,
    Fut: Future<Output = V> + Send + 'static,
{
    let (keys, futs): (Vec<K>, Vec<Fut>) = dic.into_iter().unzip();
    let results = futures::future::join_all(futs).await;
    keys.into_iter().zip(results).collect()
}

/// Return the longest common byte prefix shared by all slices in `args`.
pub fn shared_prefix(args: &[&[u8]]) -> Vec<u8> {
    match args.first() {
        None => vec![],
        Some(first) => {
            let min_len = args.iter().map(|a| a.len()).min().unwrap_or(0);
            let prefix_len = (0..min_len)
                .take_while(|&i| args.iter().all(|a| a[i] == first[i]))
                .count();
            first[..prefix_len].to_vec()
        }
    }
}

/// Convert a byte slice into a human-readable binary string (e.g. `"01001101…"`).
pub fn bytes_to_bit_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:08b}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_is_20_bytes() {
        assert_eq!(digest("hello").len(), ID_LEN);
    }

    #[test]
    fn test_shared_prefix_empty() {
        assert!(shared_prefix(&[]).is_empty());
    }

    #[test]
    fn test_shared_prefix_common() {
        let a = b"hello world";
        let b = b"hello rust";
        assert_eq!(shared_prefix(&[a, b]), b"hello ");
    }

    #[test]
    fn test_bytes_to_bit_string() {
        assert_eq!(bytes_to_bit_string(&[0b10110001]), "10110001");
    }
}
