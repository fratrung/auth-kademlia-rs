/// Base traits, error types, and algorithm registry for signature verification.
use thiserror::Error;

use crate::crypto::mldsa::{self, ML_DSA_65};

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

/// Resolve a canonical algorithm string (e.g. `"ML-DSA-65"`) into
/// `(algorithm_name, signature_byte_length)`.
///
/// Record headers must use one of these exact spellings. Accepting whitespace,
/// zero-padded levels, or other aliases would make distinct byte strings
/// authenticate as the same logical record. Which of these a DID record may
/// use is decided in `auth_handler.rs`: only ML-DSA-65 (ADR 0003).
pub fn resolve_alg_and_length(algorithm_str: &str) -> Result<(String, usize), VerifierError> {
    match algorithm_str {
        ML_DSA_65 => Ok((ML_DSA_65.to_string(), mldsa::signature_len())),
        "RSA" => Ok(("RSA".to_string(), 256)),
        "Ed25519" => Ok(("Ed25519".to_string(), 64)),
        other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
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
    fn resolve_ml_dsa_65_from_the_crate() {
        assert_eq!(
            resolve_alg_and_length("ML-DSA-65").unwrap(),
            ("ML-DSA-65".into(), mldsa::signature_len())
        );
    }

    #[test]
    fn dilithium_and_other_ml_dsa_sets_are_unknown() {
        for alg in [
            "Dilithium-2",
            "Dilithium-3",
            "Dilithium-5",
            "ML-DSA-44",
            "ML-DSA-87",
        ] {
            assert!(resolve_alg_and_length(alg).is_err(), "{alg}");
        }
    }

    #[test]
    fn resolve_unknown_errors() {
        assert!(resolve_alg_and_length("ECDSA").is_err());
    }

    #[test]
    fn resolve_noncanonical_aliases_errors() {
        for alias in [
            "RSA ",
            " RSA",
            "Ed25519\n",
            "ML-DSA-065",
            "ML-DSA-65\0",
            "ml-dsa-65",
        ] {
            assert!(
                resolve_alg_and_length(alias).is_err(),
                "non-canonical alias {alias:?} must be rejected"
            );
        }
    }
}
