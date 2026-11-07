//! ML-DSA-65 (FIPS 204), the signature of every record (ADR 0003), from
//! `aws-lc-rs`: AWS-LC, whose ML-DSA is `mldsa-native`.
//!
//! Pure ML-DSA with an empty context string: `aws-lc-rs` signs and verifies
//! only with the empty context. A public key is the raw FIPS 204 encoding;
//! `aws-lc-rs` would also take a DER `SubjectPublicKeyInfo`, which is refused
//! here so that a document holds its key in one form. A private key is the
//! expanded FIPS 204 encoding, as the key manager stores it.

use aws_lc_rs::encoding::AsRawBytes;
use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_65 as ML_DSA_65_VERIFICATION,
    ML_DSA_65_SIGNING,
};

use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

/// The name of ML-DSA-65 in a record's algorithm field and in the `alg` of its
/// key (RFC 9964).
pub const ML_DSA_65: &str = "ML-DSA-65";

/// Length of an ML-DSA-65 signature, from the crate.
pub fn signature_len() -> usize {
    ML_DSA_65_SIGNING.signature_len()
}

/// Length of a raw ML-DSA-65 public key, from the crate.
pub fn public_key_len() -> usize {
    ML_DSA_65_SIGNING.public_key_len()
}

/// An ML-DSA-65 key pair.
#[derive(Clone, Debug)]
pub struct MlDsa65KeyPair(PqdsaKeyPair);

impl MlDsa65KeyPair {
    /// A new random key pair.
    pub fn generate() -> Result<Self, VerifierError> {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map(Self)
            .map_err(|_| VerifierError::VerificationFailed("key generation failed".into()))
    }

    /// The key pair of an expanded private key, as `private_key` returns it.
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, VerifierError> {
        PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, private_key)
            .map(Self)
            .map_err(|_| VerifierError::InvalidKeyLength(private_key.len()))
    }

    /// The raw public key.
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    /// The expanded private key.
    pub fn private_key(&self) -> Result<Vec<u8>, VerifierError> {
        self.0
            .private_key()
            .as_raw_bytes()
            .map(|raw| raw.as_ref().to_vec())
            .map_err(|_| VerifierError::VerificationFailed("private key export failed".into()))
    }

    /// Sign `message`, with the empty context.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        let mut signature = vec![0u8; signature_len()];
        let len = self
            .0
            .sign(message, &mut signature)
            .map_err(|_| VerifierError::VerificationFailed("signing failed".into()))?;
        signature.truncate(len);
        Ok(signature)
    }
}

pub struct MlDsa65SignatureVerifier;

impl SignatureVerifier for MlDsa65SignatureVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError> {
        if public_key.len() != public_key_len() {
            return Err(VerifierError::InvalidKeyLength(public_key.len()));
        }
        if signature.len() != signature_len() {
            return Err(VerifierError::VerificationFailed(format!(
                "signature is {} bytes, ML-DSA-65 takes {}",
                signature.len(),
                signature_len()
            )));
        }
        Ok(UnparsedPublicKey::new(&ML_DSA_65_VERIFICATION, public_key)
            .verify(message, signature)
            .is_ok())
    }
}

pub struct MlDsa65Signer;

impl Signer for MlDsa65Signer {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        MlDsa65KeyPair::from_private_key(private_key)?.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;

    #[test]
    fn sign_verify_roundtrip() {
        let key = MlDsa65KeyPair::generate().unwrap();
        let sig = MlDsa65Signer
            .sign(&key.private_key().unwrap(), b"message")
            .unwrap();
        assert_eq!(sig.len(), signature_len());
        assert!(MlDsa65SignatureVerifier
            .verify(key.public_key(), &sig, b"message")
            .unwrap());
    }

    #[test]
    fn tampered_message_fails() {
        let key = MlDsa65KeyPair::generate().unwrap();
        let sig = key.sign(b"original").unwrap();
        assert!(!MlDsa65SignatureVerifier
            .verify(key.public_key(), &sig, b"tampered")
            .unwrap());
    }

    #[test]
    fn a_private_key_gives_back_its_key_pair() {
        let key = MlDsa65KeyPair::generate().unwrap();
        let again = MlDsa65KeyPair::from_private_key(&key.private_key().unwrap()).unwrap();
        assert_eq!(again.public_key(), key.public_key());
    }

    #[test]
    fn wrong_key_or_signature_length_errors() {
        let key = MlDsa65KeyPair::generate().unwrap();
        let signature = key.sign(b"msg").unwrap();
        assert!(MlDsa65SignatureVerifier
            .verify(&[0u8; 1312], &signature, b"msg")
            .is_err());
        assert!(MlDsa65SignatureVerifier
            .verify(key.public_key(), &signature[..signature.len() - 1], b"msg")
            .is_err());
        assert!(MlDsa65Signer.sign(&[0u8; 2560], b"msg").is_err());
    }

    /// The same key as a DER `SubjectPublicKeyInfo` verifies in `aws-lc-rs`,
    /// but a record's key must be the raw encoding.
    #[test]
    fn a_der_public_key_is_refused() {
        let key = MlDsa65KeyPair::generate().unwrap();
        let signature = key.sign(b"msg").unwrap();
        let der = key.0.public_key().as_der().unwrap();
        assert!(
            UnparsedPublicKey::new(&ML_DSA_65_VERIFICATION, der.as_ref())
                .verify(b"msg", &signature)
                .is_ok()
        );
        assert!(MlDsa65SignatureVerifier
            .verify(der.as_ref(), &signature, b"msg")
            .is_err());
    }
}
