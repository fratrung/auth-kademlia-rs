//! DHT keys and node ids: SHA-256 digests (`digest`, `ID_LEN`), and the fixed
//! key of the Status List (ADR 0004).

use sha2::{Digest, Sha256};

/// Byte length of a node id and of a DHT key: a SHA-256 output, 256 bits.
pub const ID_LEN: usize = 32;

/// Reserved DHT key for the issuer-signed status list. Operations on this key
/// use issuer-node signature verification instead of DID-owner verification.
pub const STATUS_LIST_KEY: &str = "status-list";

/// The SHA-256 digest of a UTF-8 string, such as the key of the Status List
/// (`digest(STATUS_LIST_KEY)`). The key of a DID is its decoded suffix
/// (ADR 0005), not a digest.
pub fn digest(s: &str) -> [u8; ID_LEN] {
    digest_bytes(s.as_bytes())
}

/// The SHA-256 digest of raw bytes.
pub fn digest_bytes(data: &[u8]) -> [u8; ID_LEN] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key is the SHA-256 of its text, all 32 bytes (ADR 0004). The values
    /// come from Python's `hashlib.sha256`, outside the crate.
    #[test]
    fn a_key_is_the_sha_256_of_its_text() {
        assert_eq!(ID_LEN, 32);
        assert_eq!(
            hex::encode(digest("3f2b1c4e-8a6d-4e2b-9c1a-5d7e8f9a0b1c")),
            "6d30f67fd93c228c6caed45affd11cf4a5500d5767beaa344ffb955b4f04739b"
        );
        assert_eq!(
            hex::encode(digest(STATUS_LIST_KEY)),
            "f7977b36607818f277bf1436615c56124f5facaa9a1a92dbe6b6e8db9addab06"
        );
    }
}
