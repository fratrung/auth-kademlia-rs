/// Key managers: ML-DSA-65 and Ed25519 key pairs, and ephemeral ML-KEM-768
/// key pairs.
///
/// Mirrors the Python `KeyManager` ABC and its concrete implementations:
/// `MlDsaKeyManager`, `Ed25519KeyManager`.
///
/// `MlDsaKeyManager` handles ML-DSA-65 only, the algorithm of every record
/// (ADR 0003). `MlKemKeyManager` gives out one ML-KEM-768 key pair per
/// handshake and keeps it in memory only: it is no `KeyManager`, and has no
/// key file.
///
/// File conventions (same as Python):
///   `<keys_dir>/<key_name>.public`  — raw public key bytes
///   `<keys_dir>/<key_name>.private` — raw private key bytes
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use aws_lc_rs::kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret as KemSharedSecret, ML_KEM_768,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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

    #[error("no ephemeral key {0}: unknown, already used or expired")]
    UnknownEphemeralKey(u64),

    #[error("{0} ephemeral keys are already given out")]
    TooManyEphemeralKeys(usize),

    #[error("ML-KEM-768: {0}")]
    Kem(&'static str),

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

    /// The `(public_key, private_key)` pair of a 32-byte ML-DSA-65 seed
    /// (FIPS 204, Algorithm 6): the same seed gives the same pair, so the
    /// owner keeps only the seed of its next key (ADR 0005, open point 22).
    /// The private key is the expanded one `sign` takes.
    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        let key = MlDsa65KeyPair::from_seed(seed)?;
        Ok((key.public_key().to_vec(), key.private_key()?))
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

/// How long an ephemeral ML-KEM key pair given out stays usable (ADR 0003).
pub const EPHEMERAL_KEY_MAX_AGE: Duration = Duration::from_secs(30);

/// How many ephemeral ML-KEM key pairs may be given out at once, by default.
pub const MAX_EPHEMERAL_KEYS: usize = 64;

/// An ML-KEM-768 shared secret, 32 bytes, cleared when dropped.
pub struct SharedSecret(KemSharedSecret);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

/// ML-KEM-768 (FIPS 203) with ephemeral keys, for the handshake between
/// devices, outside the DHT (ADR 0003).
///
/// Each handshake gets its own key pair. `ephemeral_public_key` gives one out
/// under an id; `decapsulate` uses it once and destroys it, whatever the
/// ciphertext. A pair given out and never used expires after `max_age`, and
/// at most `max_outstanding` pairs are given out at once. The private keys stay
/// inside AWS-LC, which clears them when it frees them; none is exported or
/// written to a file. An expired pair is destroyed at the next call to the
/// manager, or when the manager is dropped.
///
/// The public key is not in the DID Document: the handshake must sign it with
/// the device's ML-DSA-65 key.
pub struct MlKemKeyManager {
    max_age: Duration,
    max_outstanding: usize,
    pairs: Arc<Mutex<Pairs>>,
}

#[derive(Default)]
struct Pairs {
    /// The next pair to give out, generated in advance.
    spare: Option<DecapsulationKey>,
    /// A thread is generating `spare`.
    generating: bool,
    /// The pairs given out and not used yet, by id, with when each was given out.
    given: HashMap<u64, (DecapsulationKey, Instant)>,
}

impl Pairs {
    fn remove_expired(&mut self, max_age: Duration) {
        self.given
            .retain(|_, (_, given_at)| given_at.elapsed() < max_age);
    }

    /// A random id, so that an answer meant for a pair given out before a
    /// restart does not reach a pair given out after it.
    fn new_id(&self) -> u64 {
        loop {
            let id = rand::random::<u64>();
            if !self.given.contains_key(&id) {
                return id;
            }
        }
    }
}

fn lock(pairs: &Mutex<Pairs>) -> MutexGuard<'_, Pairs> {
    pairs.lock().unwrap_or_else(PoisonError::into_inner)
}

fn generate_kem_key() -> Result<DecapsulationKey, KeyManagerError> {
    DecapsulationKey::generate(&ML_KEM_768)
        .map_err(|_| KeyManagerError::Kem("key generation failed"))
}

impl Default for MlKemKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MlKemKeyManager {
    /// A manager with `EPHEMERAL_KEY_MAX_AGE` and `MAX_EPHEMERAL_KEYS`.
    pub fn new() -> Self {
        Self::with_limits(EPHEMERAL_KEY_MAX_AGE, MAX_EPHEMERAL_KEYS)
    }

    /// A manager whose pairs expire after `max_age`, with at most
    /// `max_outstanding` given out at once.
    pub fn with_limits(max_age: Duration, max_outstanding: usize) -> Self {
        let manager = Self {
            max_age,
            max_outstanding,
            pairs: Arc::new(Mutex::new(Pairs::default())),
        };
        manager.generate_spare();
        manager
    }

    /// `(id, public key)` of a new key pair, for one handshake. The pair was
    /// generated in advance when possible, and the next one is generated in
    /// another thread, so the handshake does not wait for key generation.
    pub fn ephemeral_public_key(&self) -> Result<(u64, Vec<u8>), KeyManagerError> {
        let spare = {
            let mut pairs = lock(&self.pairs);
            pairs.remove_expired(self.max_age);
            if pairs.given.len() >= self.max_outstanding {
                return Err(KeyManagerError::TooManyEphemeralKeys(self.max_outstanding));
            }
            pairs.spare.take()
        };
        let key = match spare {
            Some(key) => key,
            None => generate_kem_key()?,
        };
        let public_key = key
            .encapsulation_key()
            .and_then(|public_key| public_key.key_bytes())
            .map(|bytes| bytes.as_ref().to_vec())
            .map_err(|_| KeyManagerError::Kem("public key export failed"))?;
        let id = {
            // Another call may have given out pairs while this one generated.
            let mut pairs = lock(&self.pairs);
            pairs.remove_expired(self.max_age);
            if pairs.given.len() >= self.max_outstanding {
                pairs.spare.get_or_insert(key);
                return Err(KeyManagerError::TooManyEphemeralKeys(self.max_outstanding));
            }
            let id = pairs.new_id();
            pairs.given.insert(id, (key, Instant::now()));
            id
        };
        self.generate_spare();
        Ok((id, public_key))
    }

    /// The shared secret of `ciphertext` under the pair `id`, which is then
    /// destroyed. A modified ciphertext gives another secret, not an error
    /// (implicit rejection, FIPS 203): the handshake finds out when it
    /// confirms the key. Either way the pair cannot be used again.
    pub fn decapsulate(&self, id: u64, ciphertext: &[u8]) -> Result<SharedSecret, KeyManagerError> {
        let key = {
            let mut pairs = lock(&self.pairs);
            pairs.remove_expired(self.max_age);
            pairs.given.remove(&id).map(|(key, _)| key)
        }
        .ok_or(KeyManagerError::UnknownEphemeralKey(id))?;
        key.decapsulate(Ciphertext::from(ciphertext))
            .map(SharedSecret)
            .map_err(|_| KeyManagerError::Kem("decapsulation failed, wrong ciphertext length"))
    }

    /// `(shared secret, ciphertext)` for `public_key`, the other side of the
    /// handshake. It keeps no state.
    pub fn encapsulate(public_key: &[u8]) -> Result<(SharedSecret, Vec<u8>), KeyManagerError> {
        let (ciphertext, secret) = EncapsulationKey::new(&ML_KEM_768, public_key)
            .map_err(|_| KeyManagerError::Kem("not an ML-KEM-768 public key"))?
            .encapsulate()
            .map_err(|_| KeyManagerError::Kem("encapsulation failed"))?;
        Ok((SharedSecret(secret), ciphertext.as_ref().to_vec()))
    }

    /// Generate the next pair to give out in another thread, unless there is
    /// one or a thread is already at it. If no thread can start, the next
    /// call generates its pair itself.
    fn generate_spare(&self) {
        {
            let mut pairs = lock(&self.pairs);
            if pairs.spare.is_some() || pairs.generating {
                return;
            }
            pairs.generating = true;
        }
        let shared = Arc::clone(&self.pairs);
        let started = thread::Builder::new()
            .name("ml-kem-spare".into())
            .spawn(move || {
                let key = generate_kem_key().ok();
                let mut pairs = lock(&shared);
                pairs.generating = false;
                if pairs.spare.is_none() {
                    pairs.spare = key;
                }
            });
        if started.is_err() {
            lock(&self.pairs).generating = false;
        }
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
    use std::time::Duration;

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
    fn ml_dsa_a_seed_gives_the_same_pair_and_it_signs() {
        let km = MlDsaKeyManager::new(tmp_dir());
        let seed = [3u8; MlDsa65KeyPair::SEED_LEN];
        let (pk, sk) = km.keypair_from_seed(&seed).unwrap();
        assert_eq!(
            km.keypair_from_seed(&seed).unwrap(),
            (pk.clone(), sk.clone())
        );
        assert_eq!(pk.len(), crate::crypto::mldsa::public_key_len());
        let sig = km.sign(&sk, b"next version").unwrap();
        assert!(km.verify_signature(&pk, b"next version", &sig).unwrap());

        let (other, _) = km
            .keypair_from_seed(&[4u8; MlDsa65KeyPair::SEED_LEN])
            .unwrap();
        assert_ne!(other, pk);
        for wrong in [
            0,
            MlDsa65KeyPair::SEED_LEN - 1,
            MlDsa65KeyPair::SEED_LEN + 1,
        ] {
            assert!(km.keypair_from_seed(&vec![3u8; wrong]).is_err(), "{wrong}");
        }
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
    fn ml_kem_two_calls_give_two_different_pairs() {
        let km = MlKemKeyManager::new();
        let (id1, pk1) = km.ephemeral_public_key().unwrap();
        let (id2, pk2) = km.ephemeral_public_key().unwrap();
        assert_ne!(id1, id2);
        assert_ne!(pk1, pk2);
        assert_eq!(pk1.len(), 1184);
    }

    #[test]
    fn ml_kem_encapsulate_and_decapsulate_agree() {
        let km = MlKemKeyManager::new();
        let (id, pk) = km.ephemeral_public_key().unwrap();
        let (secret, ciphertext) = MlKemKeyManager::encapsulate(&pk).unwrap();
        assert_eq!(ciphertext.len(), 1088);
        assert_eq!(secret.as_bytes().len(), 32);
        assert_eq!(
            km.decapsulate(id, &ciphertext).unwrap().as_bytes(),
            secret.as_bytes()
        );
    }

    #[test]
    fn ml_kem_a_second_decapsulate_with_the_same_id_fails() {
        let km = MlKemKeyManager::new();
        let (id, pk) = km.ephemeral_public_key().unwrap();
        let (_, ciphertext) = MlKemKeyManager::encapsulate(&pk).unwrap();
        km.decapsulate(id, &ciphertext).unwrap();
        assert!(matches!(
            km.decapsulate(id, &ciphertext),
            Err(KeyManagerError::UnknownEphemeralKey(unknown)) if unknown == id
        ));
    }

    /// ML-KEM answers a modified ciphertext with another secret (implicit
    /// rejection, FIPS 203), and the pair is used up all the same; a
    /// ciphertext of the wrong length is an error, and uses it up too.
    #[test]
    fn ml_kem_any_ciphertext_uses_up_the_pair() {
        let km = MlKemKeyManager::new();
        let (id, pk) = km.ephemeral_public_key().unwrap();
        let (secret, mut ciphertext) = MlKemKeyManager::encapsulate(&pk).unwrap();
        ciphertext[0] ^= 1;
        let rejected = km.decapsulate(id, &ciphertext).unwrap();
        assert_ne!(rejected.as_bytes(), secret.as_bytes());
        ciphertext[0] ^= 1;
        assert!(matches!(
            km.decapsulate(id, &ciphertext),
            Err(KeyManagerError::UnknownEphemeralKey(_))
        ));

        let (id, _) = km.ephemeral_public_key().unwrap();
        assert!(km.decapsulate(id, &ciphertext[..100]).is_err());
        assert!(matches!(
            km.decapsulate(id, &ciphertext),
            Err(KeyManagerError::UnknownEphemeralKey(_))
        ));
    }

    #[test]
    fn ml_kem_a_pair_expires() {
        let km = MlKemKeyManager::with_limits(Duration::from_millis(50), 1);
        let (id, pk) = km.ephemeral_public_key().unwrap();
        let (_, ciphertext) = MlKemKeyManager::encapsulate(&pk).unwrap();
        assert!(matches!(
            km.ephemeral_public_key(),
            Err(KeyManagerError::TooManyEphemeralKeys(1))
        ));
        std::thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            km.decapsulate(id, &ciphertext),
            Err(KeyManagerError::UnknownEphemeralKey(_))
        ));
        km.ephemeral_public_key().unwrap();
    }

    #[test]
    fn ml_kem_pairs_given_out_at_once_are_bounded() {
        let km = MlKemKeyManager::with_limits(Duration::from_secs(30), 2);
        let (id, pk) = km.ephemeral_public_key().unwrap();
        km.ephemeral_public_key().unwrap();
        assert!(matches!(
            km.ephemeral_public_key(),
            Err(KeyManagerError::TooManyEphemeralKeys(2))
        ));
        let (_, ciphertext) = MlKemKeyManager::encapsulate(&pk).unwrap();
        km.decapsulate(id, &ciphertext).unwrap();
        km.ephemeral_public_key().unwrap();
    }

    /// FIPS 203 (section 7.2) checks an encapsulation key: every coefficient
    /// below q = 3329.
    #[test]
    fn ml_kem_encapsulate_refuses_what_is_not_an_ml_kem_768_key() {
        let km = MlKemKeyManager::new();
        let (_, pk) = km.ephemeral_public_key().unwrap();
        assert!(MlKemKeyManager::encapsulate(&pk[..pk.len() - 1]).is_err());
        let mut out_of_range = pk.clone();
        out_of_range[0] = 0xFF;
        out_of_range[1] |= 0x0F;
        assert!(MlKemKeyManager::encapsulate(&out_of_range).is_err());
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
