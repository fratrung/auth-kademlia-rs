//! DHT keys and node ids: SHA-1 digests (`digest`, `ID_LEN`), and the fixed
//! key of the Status List.

use sha1::{Digest, Sha1};

/// Byte length of a Kademlia node ID (SHA-1 output = 20 bytes = 160 bits).
pub const ID_LEN: usize = 20;

/// Reserved DHT key for the issuer-signed status list. Operations on this key
/// use issuer-node signature verification instead of DID-owner verification.
pub const STATUS_LIST_KEY: &str = "status-list";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_is_20_bytes() {
        assert_eq!(digest("hello").len(), ID_LEN);
    }
}
