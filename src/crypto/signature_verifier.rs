/// Base traits, error types, and algorithm registry for signature verification.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid key length: {0} bytes")]
    InvalidKeyLength(usize),

    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

/// Stateless signature verifier
pub trait SignatureVerifier: Send + Sync {
    /// Return `true` if `signature` over `message` is valid for `public_key`.
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError>;
}

pub trait Signer: Send + Sync {
    /// Sign `message` with `private_key` and return the raw signature bytes.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError>;
}

/// Resolve a canonical algorithm string (e.g. `"Dilithium-3"`) into
/// `(base_algorithm_name, signature_byte_length)`.
///
/// Record headers must use one of these exact spellings. Accepting whitespace,
/// zero-padded levels, or other aliases would make distinct byte strings
/// authenticate as the same logical record.
pub fn resolve_alg_and_length(algorithm_str: &str) -> Result<(String, usize), VerifierError> {
    match algorithm_str {
        "RSA" => Ok(("RSA".to_string(), 256)),
        "Ed25519" => Ok(("Ed25519".to_string(), 64)),
        "Dilithium-2" => Ok(("Dilithium".to_string(), 2420)),
        "Dilithium-3" => Ok(("Dilithium".to_string(), 3293)),
        "Dilithium-5" => Ok(("Dilithium".to_string(), 4595)),
        other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Infer the Dilithium security level from the public key length.
pub fn dilithium_level_from_pubkey_len(len: usize) -> Option<u8> {
    match len {
        1312 => Some(2),
        1952 => Some(3),
        2592 => Some(5),
        _ => None,
    }
}

/// Infer the Dilithium security level from the private key length.
pub fn dilithium_level_from_privkey_len(len: usize) -> Option<u8> {
    match len {
        2560 => Some(2),
        4032 => Some(3),
        4896 => Some(5),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rsa() {
        let (alg, len) = resolve_alg_and_length("RSA").unwrap();
        assert_eq!(alg, "RSA");
        assert_eq!(len, 256);
    }

    #[test]
    fn resolve_ed25519() {
        let (alg, len) = resolve_alg_and_length("Ed25519").unwrap();
        assert_eq!(alg, "Ed25519");
        assert_eq!(len, 64);
    }

    #[test]
    fn resolve_dilithium_levels() {
        assert_eq!(
            resolve_alg_and_length("Dilithium-2").unwrap(),
            ("Dilithium".into(), 2420)
        );
        assert_eq!(
            resolve_alg_and_length("Dilithium-3").unwrap(),
            ("Dilithium".into(), 3293)
        );
        assert_eq!(
            resolve_alg_and_length("Dilithium-5").unwrap(),
            ("Dilithium".into(), 4595)
        );
    }

    #[test]
    fn resolve_dilithium_no_level_errors() {
        assert!(resolve_alg_and_length("Dilithium").is_err());
    }

    #[test]
    fn resolve_unknown_errors() {
        assert!(resolve_alg_and_length("ECDSA").is_err());
    }

    #[test]
    fn resolve_noncanonical_aliases_errors() {
        for alias in ["RSA ", " RSA", "Ed25519\n", "Dilithium-02", "Dilithium-2\0"] {
            assert!(
                resolve_alg_and_length(alias).is_err(),
                "non-canonical alias {alias:?} must be rejected"
            );
        }
    }
    #[test]
    fn pubkey_level_inference() {
        assert_eq!(dilithium_level_from_pubkey_len(1312), Some(2));
        assert_eq!(dilithium_level_from_pubkey_len(1952), Some(3));
        assert_eq!(dilithium_level_from_pubkey_len(2592), Some(5));
        assert_eq!(dilithium_level_from_pubkey_len(999), None);
    }
}
