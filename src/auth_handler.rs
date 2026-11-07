//! Verification of DID records.
//!
//! `SignatureVerifierHandler` is the rule, and it is pluggable:
//! `DIDSignatureVerifierHandler` checks records in the DID-document format
//! below. The functions after it are how a node runs the rule, shared by
//! `protocol` and `network`: the binding to the key first, then the signature
//! cache, then the signature on a blocking thread.
//!
//! ```text
//! | algorithm "ML-DSA-65" (12 bytes, null-padded) | signature | DID Document (JSON) |
//! ```
//!
//! A record must be signed with ML-DSA-65, and its DID Document must hold the
//! public key as an RFC 9964 JWK whose `alg` is the record's algorithm
//! (ADR 0003).
use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::factory::SignatureVerifierFactory;
use crate::crypto::mldsa::ML_DSA_65;
use crate::crypto::signature_verifier::{resolve_alg_and_length, VerifierError};
use crate::signature_cache::{SignatureCache, VerificationDomain};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

#[derive(Debug, Error)]
pub enum AuthHandlerError {
    #[error("crypto error: {0}")]
    Crypto(#[from] VerifierError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("invalid record format")]
    InvalidFormat,
    #[error("invalid did:iiot identifier")]
    InvalidDid,
    #[error("the key in the DID Document does not match the record: {0}")]
    KeyMismatch(String),
}

/// The only algorithm a record may be signed with (ADR 0003).
pub const RECORD_ALGORITHM: &str = ML_DSA_65;

/// Abstract handler for signature operations performed by the DHT.
///
/// Implementing this trait allows callers to plug in different verification
/// strategies (e.g. ML-DSA, Ed25519) without changing the protocol layer.
pub trait SignatureVerifierHandler: Send + Sync {
    /// Verify that the DID Document carried by the signed record identifies
    /// the requested DHT key.
    fn handle_key_binding_verification(
        &self,
        key: &[u8; ID_LEN],
        value: &[u8],
    ) -> Result<bool, AuthHandlerError>;

    /// Verify that `value` is correctly self-signed (store / get path).
    fn handle_signature_verification(&self, value: &[u8]) -> Result<bool, AuthHandlerError>;

    /// Verify a key-rotation update.
    ///
    /// `value` is the new record, `old_value` is the existing record,
    /// and `auth_signature` is a signature of `value` produced with the
    /// private key corresponding to `old_value`'s public key.
    fn handle_update_verification(
        &self,
        value: &[u8],
        old_value: &[u8],
        auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError>;

    /// Verify that `value` is signed by the issuer node's public key.
    fn handle_issuer_node_signature_verification(
        &self,
        value: &[u8],
    ) -> Result<bool, AuthHandlerError>;
}

/// Parse the algorithm string from the first 12 bytes of a record.
///
/// The 12-byte field is null-padded on the right; we strip trailing nulls.
fn get_alg_string(value: &[u8]) -> Result<String, AuthHandlerError> {
    if value.len() < 12 {
        return Err(AuthHandlerError::InvalidFormat);
    }
    let raw = &value[..12];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if raw[end..].iter().any(|&byte| byte != 0) {
        return Err(AuthHandlerError::InvalidFormat);
    }
    Ok(std::str::from_utf8(&raw[..end])?.to_string())
}

/// The algorithm of a record, which must be `RECORD_ALGORITHM`. Records
/// signed with any other algorithm, even one `crypto/` implements, are refused.
fn record_algorithm(value: &[u8]) -> Result<String, AuthHandlerError> {
    let alg = get_alg_string(value)?;
    if alg != RECORD_ALGORITHM {
        return Err(VerifierError::UnsupportedAlgorithm(alg).into());
    }
    Ok(alg)
}

/// Split a record into `(signature_bytes, data_bytes)`.
///
/// The record layout is:
/// ```text
/// [0..12]              → algorithm (null-padded)
/// [12..12+sig_length]  → signature
/// [12+sig_length..]    → data (DID Document JSON)
/// ```
fn extract_sig_and_data(
    value: &[u8],
    sig_length: usize,
) -> Result<(&[u8], &[u8]), AuthHandlerError> {
    let data_start = 12 + sig_length;
    if value.len() < data_start {
        return Err(AuthHandlerError::InvalidFormat);
    }
    Ok((&value[12..data_start], &value[data_start..]))
}

/// Decode a base64url string (with or without padding).
fn decode_b64url(key: &str) -> Result<Vec<u8>, AuthHandlerError> {
    // URL_SAFE_NO_PAD handles both padded and unpadded input.
    let stripped = key.trim_end_matches('=');
    Ok(URL_SAFE_NO_PAD.decode(stripped)?)
}

/// Extract the signing key from a DID Document: `verificationMethod[0]
/// .publicKeyJwk`, an RFC 9964 key (`kty` "AKP") whose `alg` is `alg`, the
/// algorithm of the record. Its `pub` is the raw public key, base64url.
fn public_key_from_did_doc(data: &[u8], alg: &str) -> Result<Vec<u8>, AuthHandlerError> {
    let doc: Value = serde_json::from_slice(data)?;
    let jwk = &doc["verificationMethod"][0]["publicKeyJwk"];
    if jwk["kty"].as_str() != Some("AKP") {
        return Err(AuthHandlerError::KeyMismatch(format!(
            "kty {} instead of AKP",
            jwk["kty"]
        )));
    }
    if jwk["alg"].as_str() != Some(alg) {
        return Err(AuthHandlerError::KeyMismatch(format!(
            "alg {} instead of {alg}",
            jwk["alg"]
        )));
    }
    let public = jwk["pub"].as_str().ok_or_else(|| {
        AuthHandlerError::MissingField("verificationMethod[0].publicKeyJwk.pub".into())
    })?;
    decode_b64url(public)
}

/// Verify that `value` contains `id = "did:iiot:<uuid>"` and that the digest
/// of the UUID is exactly the requested DHT key.
fn did_document_matches_key(value: &[u8], key: &[u8; ID_LEN]) -> Result<bool, AuthHandlerError> {
    let alg = record_algorithm(value)?;
    let (_, sig_len) = resolve_alg_and_length(&alg)?;
    let (_, data) = extract_sig_and_data(value, sig_len)?;
    let doc: Value = serde_json::from_slice(data)?;
    let did = doc["id"]
        .as_str()
        .ok_or_else(|| AuthHandlerError::MissingField("id".into()))?;
    let uuid = did
        .strip_prefix("did:iiot:")
        .ok_or(AuthHandlerError::InvalidDid)?;
    Uuid::parse_str(uuid).map_err(|_| AuthHandlerError::InvalidDid)?;
    Ok(digest(uuid) == *key)
}

/// Concrete handler that verifies ML-DSA-65-signed DID Document records.
pub struct DIDSignatureVerifierHandler {
    /// Path to the issuer node's raw public key file.
    issuer_pub_key_path: PathBuf,
}

impl DIDSignatureVerifierHandler {
    /// Create a new handler.
    ///
    /// `issuer_pub_key_path` points to a file containing the raw bytes of the
    /// issuer node's ML-DSA-65 public key. The file is read lazily on each
    /// issuer-verification call so that key rotation does not require a restart.
    pub fn new(issuer_pub_key_path: impl Into<PathBuf>) -> Self {
        Self {
            issuer_pub_key_path: issuer_pub_key_path.into(),
        }
    }

    fn load_issuer_pub_key(&self) -> Result<Vec<u8>, AuthHandlerError> {
        Ok(std::fs::read(&self.issuer_pub_key_path)?)
    }

    /// Verify that `value` is self-signed: the public key is extracted from
    /// the embedded DID Document and used to check the record's own signature.
    fn verify_self_signed(&self, value: &[u8]) -> Result<bool, AuthHandlerError> {
        let alg = record_algorithm(value)?;
        let (_, sig_len) = resolve_alg_and_length(&alg)?;
        let (signature, data) = extract_sig_and_data(value, sig_len)?;
        let pub_key = public_key_from_did_doc(data, &alg)?;
        let verifier = SignatureVerifierFactory::get_verifier(&alg)?;
        Ok(verifier.verify(&pub_key, signature, data)?)
    }

    /// Verify a key-rotation update:
    ///
    /// 1. Extract the public key from the *old* DID Document.
    /// 2. Verify that `auth_signature` over `new_value` is valid under that key.
    /// 3. Verify the self-signature embedded in `new_value`.
    fn verify_key_rotation(
        &self,
        new_value: &[u8],
        old_value: &[u8],
        auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        let old_alg = record_algorithm(old_value)?;
        let (_, old_sig_len) = resolve_alg_and_length(&old_alg)?;
        let (_, old_data) = extract_sig_and_data(old_value, old_sig_len)?;
        let old_pub_key = public_key_from_did_doc(old_data, &old_alg)?;

        let verifier = SignatureVerifierFactory::get_verifier(&old_alg)?;
        if !verifier.verify(&old_pub_key, auth_signature, new_value)? {
            return Ok(false);
        }

        self.verify_self_signed(new_value)
    }
}

impl SignatureVerifierHandler for DIDSignatureVerifierHandler {
    fn handle_key_binding_verification(
        &self,
        key: &[u8; ID_LEN],
        value: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        did_document_matches_key(value, key)
    }

    fn handle_signature_verification(&self, value: &[u8]) -> Result<bool, AuthHandlerError> {
        self.verify_self_signed(value)
    }

    fn handle_update_verification(
        &self,
        value: &[u8],
        old_value: &[u8],
        auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        self.verify_key_rotation(value, old_value, auth_signature)
    }

    fn handle_issuer_node_signature_verification(
        &self,
        value: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        let alg = record_algorithm(value)?;
        let (_, sig_len) = resolve_alg_and_length(&alg)?;
        let (signature, data) = extract_sig_and_data(value, sig_len)?;
        let issuer_pub_key = self.load_issuer_pub_key()?;
        let verifier = SignatureVerifierFactory::get_verifier(&alg)?;
        Ok(verifier.verify(&issuer_pub_key, signature, data)?)
    }
}

/// Whether `value` belongs to `key`: its DID Document names the DID whose UUID
/// hashes to `key`. A JSON parse, no signature. The Status List is exempt: its
/// key is fixed and its record is signed by the issuer.
pub(crate) fn is_bound_to_key(
    handler: &dyn SignatureVerifierHandler,
    key: &[u8; ID_LEN],
    value: &[u8],
) -> bool {
    *key == digest(STATUS_LIST_KEY)
        || handler
            .handle_key_binding_verification(key, value)
            .unwrap_or(false)
}

/// Whether `value` is a valid record for `key`, as a node checks it before
/// storing or returning it: bound to `key`, then signed with the key in its
/// own DID Document, or by the issuer for the Status List.
///
/// The binding comes first, so a record of another key never reaches the
/// cache. The result of the signature check is cached (`cache`, when enabled)
/// under the SHA-256 of the record, in separate domains for self-signed and
/// issuer-signed records. The signature runs on a blocking thread, so
/// ML-DSA does not stall the async workers.
pub(crate) async fn verify_record(
    handler: &Arc<dyn SignatureVerifierHandler>,
    cache: Option<&SignatureCache>,
    key: &[u8; ID_LEN],
    value: &[u8],
) -> bool {
    let is_status = *key == digest(STATUS_LIST_KEY);
    if !is_bound_to_key(handler.as_ref(), key, value) {
        return false;
    }
    let domain = if is_status {
        VerificationDomain::IssuerSigned
    } else {
        VerificationDomain::SelfSigned
    };
    let cache_key = cache.map(|_| SignatureCache::compute_key(domain, value));
    if let (Some(cache), Some(ck)) = (cache, &cache_key) {
        if let Some(cached) = cache.get_by_key(ck) {
            return cached;
        }
    }
    let handler = Arc::clone(handler);
    let v = value.to_vec();
    let result = tokio::task::spawn_blocking(move || {
        if is_status {
            handler
                .handle_issuer_node_signature_verification(&v)
                .unwrap_or(false)
        } else {
            handler.handle_signature_verification(&v).unwrap_or(false)
        }
    })
    .await
    .unwrap_or(false);
    if result && is_status {
        log::info!("Status-list signature verified");
    }
    if let (Some(cache), Some(ck)) = (cache, cache_key) {
        cache.insert_by_key(ck, result);
    }
    result
}

/// Whether `new` may replace `old` for `key` (a key rotation): both are bound
/// to `key`, `auth_signature` signs `new` with the key of `old`, and `new` is
/// self-signed. Not cached. Runs on a blocking thread.
pub(crate) async fn verify_rotation(
    handler: &Arc<dyn SignatureVerifierHandler>,
    key: &[u8; ID_LEN],
    new: &[u8],
    old: &[u8],
    auth_signature: &[u8],
) -> bool {
    let handler = Arc::clone(handler);
    let (key, new, old, auth_signature) =
        (*key, new.to_vec(), old.to_vec(), auth_signature.to_vec());
    tokio::task::spawn_blocking(move || {
        handler
            .handle_key_binding_verification(&key, &old)
            .unwrap_or(false)
            && handler
                .handle_key_binding_verification(&key, &new)
                .unwrap_or(false)
            && handler
                .handle_update_verification(&new, &old, &auth_signature)
                .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Whether `value` is signed by the issuer node (an update of the Status
/// List). Not cached. Runs on a blocking thread.
pub(crate) async fn verify_issuer_signed(
    handler: &Arc<dyn SignatureVerifierHandler>,
    value: &[u8],
) -> bool {
    let handler = Arc::clone(handler);
    let value = value.to_vec();
    tokio::task::spawn_blocking(move || {
        handler
            .handle_issuer_node_signature_verification(&value)
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::crypto::mldsa::MlDsa65KeyPair;
    use serde_json::json;

    use super::*;

    /// `(key, record)`: a DID Document holding one ML-DSA-65 key (RFC 9964),
    /// self-signed, under the DHT key of its DID.
    fn ml_dsa_65_record() -> ([u8; ID_LEN], Vec<u8>) {
        let key = MlDsa65KeyPair::generate().unwrap();
        let uuid = Uuid::new_v4().to_string();
        let did = format!("did:iiot:{uuid}");
        let doc = json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#k0"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "AKP",
                    "alg": "ML-DSA-65",
                    "pub": URL_SAFE_NO_PAD.encode(key.public_key()),
                },
            }],
        });
        let data = serde_json::to_vec(&doc).unwrap();
        let mut record = [0u8; 12].to_vec();
        record[..RECORD_ALGORITHM.len()].copy_from_slice(RECORD_ALGORITHM.as_bytes());
        record.extend_from_slice(&key.sign(&data).unwrap());
        record.extend_from_slice(&data);
        (digest(&uuid), record)
    }

    /// A complete ML-DSA-65 record passes the check a node runs before storing
    /// or returning it, with and without the signature cache; a tampered copy
    /// does not.
    #[tokio::test]
    async fn verify_record_accepts_an_ml_dsa_65_record() {
        let handler: Arc<dyn SignatureVerifierHandler> =
            Arc::new(DIDSignatureVerifierHandler::new("unused"));
        let cache = SignatureCache::new(16);
        let (key, record) = ml_dsa_65_record();
        assert!(verify_record(&handler, None, &key, &record).await);
        assert!(verify_record(&handler, Some(&cache), &key, &record).await);
        assert!(verify_record(&handler, Some(&cache), &key, &record).await);

        // A bit of the signature: the document still parses and binds.
        let mut tampered = record.clone();
        tampered[20] ^= 1;
        assert!(is_bound_to_key(handler.as_ref(), &key, &tampered));
        assert!(!verify_record(&handler, None, &key, &tampered).await);
        assert!(!verify_record(&handler, None, &[0; ID_LEN], &record).await);
    }

    #[test]
    fn algorithm_header_requires_null_only_right_padding() {
        let mut canonical = [0_u8; 12];
        canonical[..3].copy_from_slice(b"RSA");
        assert_eq!(get_alg_string(&canonical).unwrap(), "RSA");

        let mut embedded_data = canonical;
        embedded_data[4] = b'X';
        assert!(matches!(
            get_alg_string(&embedded_data),
            Err(AuthHandlerError::InvalidFormat)
        ));
    }
}
