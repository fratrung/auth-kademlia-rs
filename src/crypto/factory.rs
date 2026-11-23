//! Signature verifier and signer factories: the implementation for an
//! algorithm name, as `resolve_alg_and_length` spells it. Only ML-DSA-65
//! exists, and only its exact name is accepted.

use crate::crypto::mldsa::{MlDsa65SignatureVerifier, MlDsa65Signer, ML_DSA_65};
use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

pub struct SignatureVerifierFactory;
pub struct SignerFactory;

impl SignatureVerifierFactory {
    /// Return the `SignatureVerifier` for `algorithm`.
    pub fn get_verifier(algorithm: &str) -> Result<Box<dyn SignatureVerifier>, VerifierError> {
        match algorithm {
            ML_DSA_65 => Ok(Box::new(MlDsa65SignatureVerifier)),
            other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl SignerFactory {
    /// Return the `Signer` for `algorithm`.
    pub fn get_signer(algorithm: &str) -> Result<Box<dyn Signer>, VerifierError> {
        match algorithm {
            ML_DSA_65 => Ok(Box::new(MlDsa65Signer)),
            other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mldsa::MlDsa65KeyPair;

    #[test]
    fn factories_return_ml_dsa_65() {
        let key = MlDsa65KeyPair::generate().unwrap();
        let msg = b"factory test";
        let sig = SignerFactory::get_signer("ML-DSA-65")
            .unwrap()
            .sign(&key.private_key().unwrap(), msg)
            .unwrap();
        let verifier = SignatureVerifierFactory::get_verifier("ML-DSA-65").unwrap();
        assert!(verifier.verify(key.public_key(), &sig, msg).unwrap());
    }

    #[test]
    fn factory_unknown_algorithm_errors() {
        for alg in [
            "ECDSA",
            "Ed25519",
            "RSA",
            "Dilithium-2",
            "ML-DSA-44",
            "ML",
            "ML-DSA-65 ",
        ] {
            assert!(
                SignatureVerifierFactory::get_verifier(alg).is_err(),
                "{alg}"
            );
            assert!(SignerFactory::get_signer(alg).is_err(), "{alg}");
        }
    }
}
