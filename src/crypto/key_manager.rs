/// Key manager for ML-DSA-65, Kyber, and Ed25519 key pairs.
///
/// Mirrors the Python `KeyManager` ABC and its concrete implementations:
/// `MlDsaKeyManager`, `KyberKeyManager`, `Ed25519KeyManager`.
///
/// `MlDsaKeyManager` handles ML-DSA-65 only, the algorithm of every record
/// (ADR 0003). `KyberKeyManager` stores its security level at construction
/// time.
///
/// File conventions (same as Python):
///   `<keys_dir>/<key_name>.public`  — raw public key bytes
///   `<keys_dir>/<key_name>.private` — raw private key bytes
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use thiserror::Error;

use crate::crypto::ed25519::{Ed25519SignatureVerifier, Ed25519Signer};
use crate::crypto::mldsa::{MlDsa65KeyPair, MlDsa65SignatureVerifier, MlDsa65Signer, ML_DSA_65};
use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("key not found: {0}")]
    NotFound(String),

    #[error("key already exists: {0}")]
    AlreadyExists(String),

    #[error("invalid security level: {0}")]
    InvalidSecurityLevel(u32),

    #[error("crypto error: {0}")]
    Crypto(#[from] VerifierError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn b64encode_key(key: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

pub fn b64decode_key(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// Abstract key manager — generate, persist, and retrieve key pairs.
///
/// Equivalent to the Python `KeyManager` ABC.
pub trait KeyManager {
    /// Generate a fresh (public_key, private_key) pair.
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError>;

    /// Write `public_key` to `<keys_dir>/<key_name>.public`.
    fn store_public_key(&self, key_name: &str, public_key: &[u8]) -> Result<(), KeyManagerError>;

    /// Write `private_key` to `<keys_dir>/<key_name>.private`.
    fn store_private_key(&self, key_name: &str, private_key: &[u8]) -> Result<(), KeyManagerError>;

    /// Read the public key stored as `<key_name>.public`.
    fn get_public_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError>;

    /// Read the private key stored as `<key_name>.private`.
    fn get_private_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError>;

    /// Return a JWK-style map for `public_key`.
    fn get_jose_format(&self, public_key: &[u8]) -> HashMap<String, String>;
}

fn write_key(path: &PathBuf, data: &[u8]) -> Result<(), KeyManagerError> {
    fs::write(path, data)?;
    Ok(())
}

fn read_key(path: &PathBuf, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
    fs::read(path).map_err(|_| KeyManagerError::NotFound(key_name.to_string()))
}

/// Key manager for ML-DSA-65 (FIPS 204), the signature of every record.
pub struct MlDsaKeyManager {
    pub keys_dir: PathBuf,
}

impl MlDsaKeyManager {
    /// The `keys_dir` directory is created if it does not exist.
    pub fn new(keys_dir: impl Into<PathBuf>) -> Self {
        let keys_dir = keys_dir.into();
        fs::create_dir_all(&keys_dir).ok();
        Self { keys_dir }
    }

    /// Sign `message` with the ML-DSA-65 `private_key`.
    pub fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(MlDsa65Signer.sign(private_key, message)?)
    }

    /// Verify `signature` over `message` against the ML-DSA-65 `public_key`.
    pub fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyManagerError> {
        Ok(MlDsa65SignatureVerifier.verify(public_key, signature, message)?)
    }
}

impl KeyManager for MlDsaKeyManager {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        let key = MlDsa65KeyPair::generate()?;
        Ok((key.public_key().to_vec(), key.private_key()?))
    }

    fn store_public_key(&self, key_name: &str, public_key: &[u8]) -> Result<(), KeyManagerError> {
        write_key(
            &self.keys_dir.join(format!("{}.public", key_name)),
            public_key,
        )
    }

    fn store_private_key(&self, key_name: &str, private_key: &[u8]) -> Result<(), KeyManagerError> {
        write_key(
            &self.keys_dir.join(format!("{}.private", key_name)),
            private_key,
        )
    }

    fn get_public_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
        read_key(
            &self.keys_dir.join(format!("{}.public", key_name)),
            key_name,
        )
    }

    fn get_private_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
        read_key(
            &self.keys_dir.join(format!("{}.private", key_name)),
            key_name,
        )
    }

    /// The public key as a JWK of RFC 9964:
    /// `{"kty": "AKP", "alg": "ML-DSA-65", "pub": <base64url>}`.
    fn get_jose_format(&self, public_key: &[u8]) -> HashMap<String, String> {
        HashMap::from([
            ("kty".into(), "AKP".into()),
            ("alg".into(), ML_DSA_65.into()),
            ("pub".into(), b64encode_key(public_key)),
        ])
    }
}

/// Key manager for CRYSTALS-Kyber (post-quantum KEM — key encapsulation).
///
/// Security levels: 512, 768, or 1024.
/// Kyber is a KEM, not a signature scheme; there are no `sign`/`verify` methods.
pub struct KyberKeyManager {
    pub keys_dir: PathBuf,
    pub security_level: u16,
}

impl KyberKeyManager {
    /// Create a manager for `security_level` ∈ {512, 768, 1024}.
    pub fn new(keys_dir: impl Into<PathBuf>, security_level: u16) -> Self {
        let keys_dir = keys_dir.into();
        fs::create_dir_all(&keys_dir).ok();
        Self {
            keys_dir,
            security_level,
        }
    }
}

impl KeyManager for KyberKeyManager {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        match self.security_level {
            512 => {
                let (pk, sk) = kyber512::keypair();
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            768 => {
                let (pk, sk) = kyber768::keypair();
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            1024 => {
                let (pk, sk) = kyber1024::keypair();
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            _ => Err(KeyManagerError::InvalidSecurityLevel(
                self.security_level as u32,
            )),
        }
    }

    fn store_public_key(&self, key_name: &str, public_key: &[u8]) -> Result<(), KeyManagerError> {
        write_key(
            &self.keys_dir.join(format!("{}.public", key_name)),
            public_key,
        )
    }

    fn store_private_key(&self, key_name: &str, private_key: &[u8]) -> Result<(), KeyManagerError> {
        write_key(
            &self.keys_dir.join(format!("{}.private", key_name)),
            private_key,
        )
    }

    fn get_public_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
        read_key(
            &self.keys_dir.join(format!("{}.public", key_name)),
            key_name,
        )
    }

    fn get_private_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
        read_key(
            &self.keys_dir.join(format!("{}.private", key_name)),
            key_name,
        )
    }

    /// JWK format: `{"kty": "KEM", "alg": "KYBER<level>", "x": <base64url>}`.
    fn get_jose_format(&self, public_key: &[u8]) -> HashMap<String, String> {
        HashMap::from([
            ("kty".into(), "KEM".into()),
            ("alg".into(), format!("KYBER{}", self.security_level)),
            ("x".into(), b64encode_key(public_key)),
        ])
    }
}

/// Key manager for Ed25519 (classical signature scheme).
pub struct Ed25519KeyManager {
    keys_dir: PathBuf,
}

impl Ed25519KeyManager {
    pub fn new(keys_dir: impl Into<PathBuf>) -> Self {
        let keys_dir = keys_dir.into();
        fs::create_dir_all(&keys_dir).ok();
        Self { keys_dir }
    }

    /// Sign `message` with the 32-byte Ed25519 `private_key` seed.
    pub fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(Ed25519Signer.sign(private_key, message)?)
    }

    /// Verify `signature` over `message` against the 32-byte `public_key`.
    pub fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyManagerError> {
        Ok(Ed25519SignatureVerifier.verify(public_key, signature, message)?)
    }
}

impl KeyManager for Ed25519KeyManager {
    /// Returns `(public_key [32 bytes], private_key_seed [32 bytes])`.
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let private_key = signing_key.to_bytes().to_vec();
        Ok((public_key, private_key))
    }

    fn store_public_key(&self, key_name: &str, public_key: &[u8]) -> Result<(), KeyManagerError> {
        write_key(
            &self.keys_dir.join(format!("{}.public", key_name)),
            public_key,
        )
    }

    fn store_private_key(&self, key_name: &str, private_key: &[u8]) -> Result<(), KeyManagerError> {
        write_key(
            &self.keys_dir.join(format!("{}.private", key_name)),
            private_key,
        )
    }

    fn get_public_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
        read_key(
            &self.keys_dir.join(format!("{}.public", key_name)),
            key_name,
        )
    }

    fn get_private_key(&self, key_name: &str) -> Result<Vec<u8>, KeyManagerError> {
        read_key(
            &self.keys_dir.join(format!("{}.private", key_name)),
            key_name,
        )
    }

    /// JWK format: `{"kty": "OKP", "crv": "Ed25519", "x": <base64url>}`.
    fn get_jose_format(&self, public_key: &[u8]) -> HashMap<String, String> {
        HashMap::from([
            ("kty".into(), "OKP".into()),
            ("crv".into(), "Ed25519".into()),
            ("x".into(), b64encode_key(public_key)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_dir() -> PathBuf {
        let mut d = env::temp_dir();
        d.push(format!("km_test_{}", rand_suffix()));
        d
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64
    }

    #[test]
    fn ml_dsa_generate_store_retrieve() {
        let km = MlDsaKeyManager::new(tmp_dir());
        let (pk, sk) = km.generate_keypair().unwrap();
        assert_eq!(pk.len(), crate::crypto::mldsa::public_key_len());
        assert_eq!(
            MlDsa65KeyPair::from_private_key(&sk).unwrap().public_key(),
            pk
        );
        km.store_public_key("alice", &pk).unwrap();
        km.store_private_key("alice", &sk).unwrap();
        assert_eq!(km.get_public_key("alice").unwrap(), pk);
        assert_eq!(km.get_private_key("alice").unwrap(), sk);
    }

    #[test]
    fn ml_dsa_sign_verify_roundtrip() {
        let km = MlDsaKeyManager::new(tmp_dir());
        let (pk, sk) = km.generate_keypair().unwrap();
        let msg = b"hello ml-dsa-65";
        let sig = km.sign(&sk, msg).unwrap();
        assert!(km.verify_signature(&pk, msg, &sig).unwrap());
        assert!(!km.verify_signature(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn ml_dsa_jose_format_is_rfc_9964() {
        let km = MlDsaKeyManager::new(tmp_dir());
        let (pk, _) = km.generate_keypair().unwrap();
        let jose = km.get_jose_format(&pk);
        assert_eq!(jose["kty"], "AKP");
        assert_eq!(jose["alg"], "ML-DSA-65");
        assert_eq!(b64decode_key(&jose["pub"]).unwrap(), pk);
    }

    #[test]
    fn ml_dsa_key_not_found_error() {
        let km = MlDsaKeyManager::new(tmp_dir());
        assert!(matches!(
            km.get_public_key("nonexistent"),
            Err(KeyManagerError::NotFound(_))
        ));
    }

    #[test]
    fn kyber512_generate_store_retrieve() {
        let km = KyberKeyManager::new(tmp_dir(), 512);
        let (pk, sk) = km.generate_keypair().unwrap();
        km.store_public_key("bob", &pk).unwrap();
        km.store_private_key("bob", &sk).unwrap();
        assert_eq!(km.get_public_key("bob").unwrap(), pk);
        assert_eq!(km.get_private_key("bob").unwrap(), sk);
    }

    #[test]
    fn kyber768_generate() {
        let km = KyberKeyManager::new(tmp_dir(), 768);
        let (pk, _) = km.generate_keypair().unwrap();
        assert!(!pk.is_empty());
    }

    #[test]
    fn kyber1024_generate() {
        let km = KyberKeyManager::new(tmp_dir(), 1024);
        let (pk, _) = km.generate_keypair().unwrap();
        assert!(!pk.is_empty());
    }

    #[test]
    fn kyber_invalid_level_errors() {
        let km = KyberKeyManager::new(tmp_dir(), 256);
        assert!(km.generate_keypair().is_err());
    }

    #[test]
    fn kyber_jose_format() {
        let km = KyberKeyManager::new(tmp_dir(), 512);
        let (pk, _) = km.generate_keypair().unwrap();
        let jose = km.get_jose_format(&pk);
        assert_eq!(jose["kty"], "KEM");
        assert_eq!(jose["alg"], "KYBER512");
        assert!(!jose["x"].is_empty());
    }

    #[test]
    fn ed25519_generate_store_retrieve() {
        let km = Ed25519KeyManager::new(tmp_dir());
        let (pk, sk) = km.generate_keypair().unwrap();
        km.store_public_key("carol", &pk).unwrap();
        km.store_private_key("carol", &sk).unwrap();
        assert_eq!(km.get_public_key("carol").unwrap(), pk);
        assert_eq!(km.get_private_key("carol").unwrap(), sk);
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let km = Ed25519KeyManager::new(tmp_dir());
        let (pk, sk) = km.generate_keypair().unwrap();
        let msg = b"hello ed25519 key manager";
        let sig = km.sign(&sk, msg).unwrap();
        assert!(km.verify_signature(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn ed25519_tampered_message_rejected() {
        let km = Ed25519KeyManager::new(tmp_dir());
        let (pk, sk) = km.generate_keypair().unwrap();
        let sig = km.sign(&sk, b"original").unwrap();
        assert!(!km.verify_signature(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn ed25519_jose_format() {
        let km = Ed25519KeyManager::new(tmp_dir());
        let (pk, _) = km.generate_keypair().unwrap();
        let jose = km.get_jose_format(&pk);
        assert_eq!(jose["kty"], "OKP");
        assert_eq!(jose["crv"], "Ed25519");
        assert!(!jose["x"].is_empty());
    }

    #[test]
    fn b64_roundtrip() {
        let data = b"test bytes \x00\xFF";
        let encoded = b64encode_key(data);
        let decoded = b64decode_key(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
