/// Signature verification handlers for authenticated DHT operations.
///
/// `SignatureVerifierHandler` is the abstract interface consumed by the
/// protocol and server layers. `DIDSignatureVerifierHandler` is the concrete
/// implementation that understands the DID-document record format:
///
/// ```text
/// | algorithm (12 bytes, null-padded) | signature | DID Document (JSON) |
/// ```
use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::factory::SignatureVerifierFactory;
use crate::crypto::signature_verifier::{resolve_alg_and_length, VerifierError};
use crate::utils::{digest, ID_LEN};

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
}

/// Abstract handler for signature operations performed by the DHT.
///
/// Implementing this trait allows callers to plug in different verification
/// strategies (e.g. Dilithium, Ed25519) without changing the protocol layer.
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

/// Extract the primary public key from a DID Document.
///
/// Expects `verificationMethod[0].publicKeyJwk.x` to be a base64url string.
fn public_key_from_did_doc(data: &[u8]) -> Result<Vec<u8>, AuthHandlerError> {
    let doc: Value = serde_json::from_slice(data)?;
    let x = doc["verificationMethod"][0]["publicKeyJwk"]["x"]
        .as_str()
        .ok_or_else(|| {
            AuthHandlerError::MissingField("verificationMethod[0].publicKeyJwk.x".into())
        })?;
    decode_b64url(x)
}

/// Verify that `value` contains `id = "did:iiot:<uuid>"` and that the digest
/// of the UUID is exactly the requested DHT key.
fn did_document_matches_key(value: &[u8], key: &[u8; ID_LEN]) -> Result<bool, AuthHandlerError> {
    let alg = get_alg_string(value)?;
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

/// Concrete handler that verifies Dilithium-signed DID Document records.
pub struct DIDSignatureVerifierHandler {
    /// Path to the issuer node's raw public key file.
    issuer_pub_key_path: PathBuf,
}

impl DIDSignatureVerifierHandler {
    /// Create a new handler.
    ///
    /// `issuer_pub_key_path` points to a file containing the raw bytes of the
    /// issuer node's Dilithium public key. The file is read lazily on each
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
        let alg = get_alg_string(value)?;
        let (_, sig_len) = resolve_alg_and_length(&alg)?;
        let (signature, data) = extract_sig_and_data(value, sig_len)?;
        let pub_key = public_key_from_did_doc(data)?;
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
        let old_alg = get_alg_string(old_value)?;
        let (_, old_sig_len) = resolve_alg_and_length(&old_alg)?;
        let (_, old_data) = extract_sig_and_data(old_value, old_sig_len)?;
        let old_pub_key = public_key_from_did_doc(old_data)?;

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
        let alg = get_alg_string(value)?;
        let (_, sig_len) = resolve_alg_and_length(&alg)?;
        let (signature, data) = extract_sig_and_data(value, sig_len)?;
        let issuer_pub_key = self.load_issuer_pub_key()?;
        let verifier = SignatureVerifierFactory::get_verifier(&alg)?;
        Ok(verifier.verify(&issuer_pub_key, signature, data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
