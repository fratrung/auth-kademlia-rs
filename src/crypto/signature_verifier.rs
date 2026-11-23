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

/// Resolve the algorithm name of a record header into
/// `(algorithm_name, signature_byte_length)`. The only algorithm is ML-DSA-65
/// (ADR 0003).
///
/// The header must use the exact spelling. Accepting whitespace, zero-padded
/// levels, or other aliases would make distinct byte strings authenticate as
/// the same logical record.
pub fn resolve_alg_and_length(algorithm_str: &str) -> Result<(String, usize), VerifierError> {
    match algorithm_str {
        ML_DSA_65 => Ok((ML_DSA_65.to_string(), mldsa::signature_len())),
        other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for alg in ["ECDSA", "Ed25519", "RSA"] {
            assert!(resolve_alg_and_length(alg).is_err(), "{alg}");
        }
    }

    #[test]
    fn resolve_noncanonical_aliases_errors() {
        for alias in [
            "ML-DSA-65 ",
            " ML-DSA-65",
            "ML-DSA-65\n",
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
