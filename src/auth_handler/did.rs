//! The `did:iiot` identifier and the form of a DID Document (ADR 0005,
//! sections 1 and 2).
//!
//! The DID is `did:iiot:` followed by the base64url, without padding, of the
//! SHA-256 of version 0 in canonical form, its own DID written as the
//! placeholder `did:iiot:self` and without `id`. The DHT key is that hash,
//! the decoded suffix. Every document carries `seq`, `prev` (not version 0)
//! and `nextKeyHash`, the SHA-256 of the raw public key that signs the next
//! version.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use thiserror::Error;

use crate::crypto::signature_verifier::resolve_alg_and_length;
use crate::utils::{digest_bytes, ID_LEN};

use super::{decode_b64url, extract_sig_and_data, record_algorithm};

/// The method prefix of every DID.
pub const DID_PREFIX: &str = "did:iiot:";

/// What a draft of version 0 holds in place of its own DID (open point 2).
pub const PLACEHOLDER: &str = "did:iiot:self";

/// Characters of a suffix: 32 bytes in base64url without padding.
pub const SUFFIX_LEN: usize = 43;

/// The largest integer a document may hold, `seq` included: 2^53 − 1, which
/// RFC 8785 and `serde_json` both write as a plain decimal (open point 3).
pub const MAX_INTEGER: u64 = (1 << 53) - 1;

/// Why a record has not the form of a DID record: `InvalidRecord`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormError {
    #[error("not a record of the expected layout")]
    Layout,
    #[error("the document is not JSON: {0}")]
    NotJson(String),
    #[error("the document is not in canonical form: {0}")]
    NotCanonical(&'static str),
    #[error("the document holds the placeholder {PLACEHOLDER}")]
    Placeholder,
    #[error("invalid or missing {0}")]
    Field(&'static str),
    #[error("the DID does not belong to the key")]
    WrongKey,
}

/// What step 1 of the rules reads from a record (ADR 0005, section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordForm {
    pub seq: u64,
    /// `record_hash` of the version before; `None` for version 0.
    pub prev: Option<[u8; ID_LEN]>,
    /// SHA-256 of the raw public key that signs the next version.
    pub next_key_hash: [u8; ID_LEN],
    /// SHA-256 of this version's raw public key.
    pub key_hash: [u8; ID_LEN],
}

/// The canonical suffix of 32 bytes: base64url without padding, 43 characters.
pub fn encode_suffix(bytes: &[u8; ID_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The 32 bytes of a canonical suffix, or `None`: 43 characters of the
/// URL-safe alphabet, no padding, encoding back to the same text (open
/// point 1). The re-encoding refuses any other text of the same bytes.
pub fn decode_suffix(text: &str) -> Option<[u8; ID_LEN]> {
    if text.len() != SUFFIX_LEN {
        return None;
    }
    let bytes: [u8; ID_LEN] = URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()?;
    (encode_suffix(&bytes) == text).then_some(bytes)
}

/// The DHT key of a DID: its suffix, decoded.
pub fn key_of_did(did: &str) -> Option<[u8; ID_LEN]> {
    decode_suffix(did.strip_prefix(DID_PREFIX)?)
}

/// The DID whose key is `key`.
pub fn did_of_key(key: &[u8; ID_LEN]) -> String {
    format!("{DID_PREFIX}{}", encode_suffix(key))
}

/// Printable ASCII, from space to `~`: written alike by RFC 8785 and
/// `serde_json`, escaping only `"` and `\`.
fn printable(text: &str) -> bool {
    text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Whether every key and value of `value` has a canonical form.
fn check_canonical(value: &Value) -> Result<(), FormError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(text) if printable(text) => Ok(()),
        Value::String(_) => Err(FormError::NotCanonical(
            "a character outside printable ASCII",
        )),
        Value::Number(number) => {
            let safe = match (number.as_u64(), number.as_i64()) {
                (Some(unsigned), _) => unsigned <= MAX_INTEGER,
                (None, Some(signed)) => signed.unsigned_abs() <= MAX_INTEGER,
                (None, None) => false,
            };
            if safe {
                Ok(())
            } else {
                Err(FormError::NotCanonical(
                    "a number that is not an integer within 2^53 - 1",
                ))
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_canonical),
        Value::Object(map) => map.iter().try_for_each(|(key, item)| {
            if !printable(key) {
                return Err(FormError::NotCanonical("a key outside printable ASCII"));
            }
            check_canonical(item)
        }),
    }
}

/// Parse document bytes that must already be canonical: printable ASCII in
/// keys and strings, integers within ±`MAX_INTEGER` and no other numbers, and
/// the same bytes as `serde_json` writes the parsed document (open point 3).
/// The last check refuses whitespace, keys out of order, needless escapes and
/// duplicate keys.
pub fn parse_canonical(bytes: &[u8]) -> Result<Value, FormError> {
    let doc: Value =
        serde_json::from_slice(bytes).map_err(|error| FormError::NotJson(error.to_string()))?;
    if canonical_bytes(&doc)? != bytes {
        return Err(FormError::NotCanonical(
            "not the bytes of its canonical form",
        ));
    }
    Ok(doc)
}

/// The canonical bytes of a document, refusing what has no canonical form.
pub fn canonical_bytes(doc: &Value) -> Result<Vec<u8>, FormError> {
    if !doc.is_object() {
        return Err(FormError::NotCanonical("not an object"));
    }
    check_canonical(doc)?;
    serde_json::to_vec(doc).map_err(|error| FormError::NotJson(error.to_string()))
}

/// Whether `text` is `prefix`, or starts with it followed by `#`, `?` or `/`
/// (a DID URL of that DID); the rest of it if so.
fn after_did<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(prefix)?;
    (rest.is_empty() || rest.starts_with(['#', '?', '/'])).then_some(rest)
}

/// Whether any string value of `value` is the placeholder, or a DID URL of it.
fn holds_placeholder(value: &Value) -> bool {
    match value {
        Value::String(text) => after_did(text, PLACEHOLDER).is_some(),
        Value::Array(items) => items.iter().any(holds_placeholder),
        Value::Object(map) => map.values().any(holds_placeholder),
        _ => false,
    }
}

/// Replace `from` by `to` in every string value that is `from` or a DID URL
/// of it. Object keys are not changed.
fn replace_did(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(text) => {
            if let Some(rest) = after_did(text, from) {
                *text = format!("{to}{rest}");
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| replace_did(item, from, to)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| replace_did(item, from, to)),
        _ => {}
    }
}

/// The `id` of a document, a DID with a canonical suffix, and its key.
fn id_of(doc: &Value) -> Result<(&str, [u8; ID_LEN]), FormError> {
    let did = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(FormError::Field("id"))?;
    let key = key_of_did(did).ok_or(FormError::Field("id"))?;
    Ok((did, key))
}

/// The SHA-256 of the hashed form of `doc` (section 1): its `id` must be a
/// canonical DID, it may not hold the placeholder, and the DID is put back as
/// the placeholder with `id` removed.
pub fn hashed_form(doc: &Value) -> Result<[u8; ID_LEN], FormError> {
    let (did, _) = id_of(doc)?;
    if holds_placeholder(doc) {
        return Err(FormError::Placeholder);
    }
    let mut form = doc.clone();
    if let Some(map) = form.as_object_mut() {
        map.remove("id");
    }
    replace_did(&mut form, did, PLACEHOLDER);
    Ok(digest_bytes(&canonical_bytes(&form)?))
}

/// The DID of a draft of version 0 (no `id`, the placeholder in place of its
/// own DID), and the document with the DID in place and `id` added, as the
/// owner builds it before signing.
pub fn derive_did(draft: &Value) -> Result<(String, Value), FormError> {
    if draft.get("id").is_some() {
        return Err(FormError::Field("id"));
    }
    let key = digest_bytes(&canonical_bytes(draft)?);
    let did = did_of_key(&key);
    let mut doc = draft.clone();
    replace_did(&mut doc, PLACEHOLDER, &did);
    if let Some(map) = doc.as_object_mut() {
        map.insert("id".into(), Value::String(did.clone()));
    }
    // The node computes the hashed form back: it must give the same key.
    if hashed_form(&doc)? != key {
        return Err(FormError::WrongKey);
    }
    Ok((did, doc))
}

/// The signed document of a record, after its algorithm and signature.
pub(crate) fn document_of(record: &[u8]) -> Result<&[u8], FormError> {
    let alg = record_algorithm(record).map_err(|_| FormError::Layout)?;
    let (_, sig_len) = resolve_alg_and_length(&alg).map_err(|_| FormError::Layout)?;
    let (_, data) = extract_sig_and_data(record, sig_len).map_err(|_| FormError::Layout)?;
    Ok(data)
}

/// Step 1 of the rules for a record sent under `key`, without verifying any
/// signature (section 3): the layout and algorithm, the canonical form, the
/// placeholder, an `id` whose suffix is `key`, `seq`, `prev` and
/// `nextKeyHash`, and for version 0 the hashed form.
pub fn record_form(key: &[u8; ID_LEN], record: &[u8]) -> Result<RecordForm, FormError> {
    let doc = parse_canonical(document_of(record)?)?;
    if holds_placeholder(&doc) {
        return Err(FormError::Placeholder);
    }
    if id_of(&doc)?.1 != *key {
        return Err(FormError::WrongKey);
    }
    let seq = doc
        .get("seq")
        .and_then(Value::as_u64)
        .filter(|seq| *seq <= MAX_INTEGER)
        .ok_or(FormError::Field("seq"))?;
    let prev = match (seq, doc.get("prev")) {
        (0, None) => None,
        (0, Some(_)) => return Err(FormError::Field("prev")),
        (_, prev) => Some(
            prev.and_then(Value::as_str)
                .and_then(decode_suffix)
                .ok_or(FormError::Field("prev"))?,
        ),
    };
    let next_key_hash = doc
        .get("nextKeyHash")
        .and_then(Value::as_str)
        .and_then(decode_suffix)
        .ok_or(FormError::Field("nextKeyHash"))?;
    let public_key = doc["verificationMethod"][0]["publicKeyJwk"]["pub"]
        .as_str()
        .and_then(|text| decode_b64url(text).ok())
        .ok_or(FormError::Field("publicKeyJwk"))?;
    let key_hash = digest_bytes(&public_key);
    // A commitment to its own key would let the current key sign the next
    // version.
    if next_key_hash == key_hash {
        return Err(FormError::Field("nextKeyHash"));
    }
    if seq == 0 && hashed_form(&doc)? != *key {
        return Err(FormError::WrongKey);
    }
    Ok(RecordForm {
        seq,
        prev,
        next_key_hash,
        key_hash,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::super::test_chain::{
        b64, derive, document, key_of, new_key, record_of, sha256, sign, Chain,
    };
    use super::super::{
        is_bound_to_key, verify_record, DIDSignatureVerifierHandler, SignatureVerifierHandler,
    };
    use super::*;

    fn handler() -> Arc<dyn SignatureVerifierHandler> {
        Arc::new(DIDSignatureVerifierHandler::new("unused"))
    }

    fn binds(key: &[u8; ID_LEN], record: &[u8]) -> bool {
        is_bound_to_key(handler().as_ref(), key, record)
    }

    /// Version 0 of a new DID from `draft` (no `id`, the placeholder in place
    /// of the DID), signed by `signer`: its key and record.
    fn version0(
        draft: &Value,
        signer: &crate::crypto::mldsa::MlDsa65KeyPair,
    ) -> ([u8; ID_LEN], Vec<u8>) {
        let (did, doc) = derive(draft);
        (key_of(&did), sign(&doc, signer))
    }

    // ---- The suffix --------------------------------------------------------

    #[test]
    fn a_suffix_is_the_canonical_base64url_of_32_bytes() {
        let bytes: [u8; ID_LEN] = std::array::from_fn(|i| (i * 37 + 5) as u8);
        let suffix = encode_suffix(&bytes);
        assert_eq!(suffix.len(), SUFFIX_LEN);
        assert_eq!(suffix, b64(&bytes));
        assert_eq!(decode_suffix(&suffix), Some(bytes));

        let zeros = "A".repeat(SUFFIX_LEN);
        assert_eq!(decode_suffix(&zeros), Some([0; ID_LEN]));
        for bad in [
            format!("{zeros}="),             // padding
            "A".repeat(SUFFIX_LEN - 1),      // too short
            "A".repeat(SUFFIX_LEN + 1),      // too long
            format!("{}B", "A".repeat(42)),  // non-zero trailing bits: 32 zero bytes again
            format!("{}+A", "A".repeat(41)), // standard alphabet, not URL-safe
            format!("{}/A", "A".repeat(41)),
            format!("{}é", "A".repeat(41)),
            String::new(),
        ] {
            assert_eq!(decode_suffix(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_key_of_a_did_is_its_decoded_suffix() {
        let key: [u8; ID_LEN] = std::array::from_fn(|i| i as u8);
        let did = did_of_key(&key);
        assert_eq!(did, format!("did:iiot:{}", b64(&key)));
        assert_eq!(key_of_did(&did), Some(key));
        for bad in [
            "did:iiot:3f2b1c4e-8a6d-4e2b-9c1a-5d7e8f9a0b1c".to_string(),
            format!("did:web:{}", b64(&key)),
            format!("did:iiot:{}=", b64(&key)),
            b64(&key),
        ] {
            assert_eq!(key_of_did(&bad), None, "{bad}");
        }
    }

    // ---- The canonical form ------------------------------------------------

    /// The canonical form is `serde_json`'s output with sorted keys and no
    /// whitespace. It holds only while no dependency turns on `serde_json`'s
    /// `preserve_order`, which would keep keys in insertion order.
    #[test]
    fn serde_json_writes_sorted_keys_without_whitespace() {
        let doc = json!({ "b": 1, "a": { "d": [true, null], "c": "x" } });
        assert_eq!(
            serde_json::to_vec(&doc).unwrap(),
            br#"{"a":{"c":"x","d":[true,null]},"b":1}"#
        );
    }

    #[test]
    fn the_canonical_form_accepts_sorted_compact_ascii_with_safe_integers() {
        let good = br#"{"a":[1,-2,9007199254740991,-9007199254740991],"b":"x y~","c":{"d":null,"e":true}}"#;
        assert!(parse_canonical(good).is_ok());
        let doc: Value = serde_json::from_slice(good).unwrap();
        assert_eq!(canonical_bytes(&doc).unwrap(), good.to_vec());
    }

    #[test]
    fn the_canonical_form_refuses_everything_else() {
        for (bad, why) in [
            (r#"{"a":1, "b":2}"#, "whitespace"),
            (r#"{ "a":1}"#, "whitespace"),
            (r#"{"b":1,"a":2}"#, "keys out of order"),
            (r#"{"a":1,"a":2}"#, "duplicate key"),
            (r#"{"a":"x\/y"}"#, "needless escape"),
            (r#"{"a":"\u0041"}"#, "needless escape"),
            ("{\"a\":\"caf\u{e9}\"}", "non-ASCII"),
            (r#"{"a":"\u00e9"}"#, "escaped non-ASCII"),
            (r#"{"a":"\u0001"}"#, "control character"),
            (r#"{"a":"\t"}"#, "control character"),
            (r#"{"a":1.5}"#, "fraction"),
            (r#"{"a":1.0}"#, "fraction"),
            (r#"{"a":1e3}"#, "exponent"),
            (r#"{"a":9007199254740992}"#, "integer beyond 2^53 - 1"),
            (r#"{"a":-9007199254740992}"#, "integer beyond -(2^53 - 1)"),
            (r#"{"a":18446744073709551616}"#, "integer beyond u64"),
            (r#"[1]"#, "not an object"),
            (r#"{"a":1}x"#, "trailing bytes"),
        ] {
            assert!(parse_canonical(bad.as_bytes()).is_err(), "{why}: {bad}");
        }
        for doc in [
            json!({ "a": 1.5 }),
            json!({ "a": "caf\u{e9}" }),
            json!({ "a": 9007199254740992u64 }),
        ] {
            assert!(canonical_bytes(&doc).is_err(), "{doc}");
        }
    }

    // ---- The hashed form and the derivation ---------------------------------

    /// Rule 3 of the hashed form: a value equal to the DID, or starting with
    /// it followed by `#`, `?` or `/`, takes the placeholder; the DID inside a
    /// longer value does not, nor the DID followed by another character.
    #[test]
    fn the_hashed_form_puts_the_placeholder_back_in_place_of_the_did() {
        let did = format!("did:iiot:{}", b64(&[7; ID_LEN]));
        let doc = json!({
            "id": did,
            "a": did,
            "b": [format!("{did}#k0"), format!("{did}?q=1"), format!("{did}/path")],
            "c": { "d": format!("http://example.com/{did}"), "e": format!("{did}x") },
            did.clone(): "keys are not changed",
        });
        let expected = json!({
            "a": PLACEHOLDER,
            "b": [format!("{PLACEHOLDER}#k0"), format!("{PLACEHOLDER}?q=1"), format!("{PLACEHOLDER}/path")],
            "c": { "d": format!("http://example.com/{did}"), "e": format!("{did}x") },
            did.clone(): "keys are not changed",
        });
        assert_eq!(
            hashed_form(&doc),
            Ok(sha256(&serde_json::to_vec(&expected).unwrap()))
        );
    }

    /// The test vector computed by the Python application's rule, with only
    /// `json`, `hashlib` and `base64` of the standard library
    /// (`python3 -I did_vector.py`):
    ///
    /// ```python
    /// import base64, hashlib, json
    /// b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    /// P = "did:iiot:self"
    /// pk = bytes(i % 256 for i in range(1952))
    /// next_pk = bytes((255 - i) % 256 for i in range(1952))
    /// doc = {
    ///     "@context": ["https://www.w3.org/ns/did/v1"],
    ///     "verificationMethod": [{"id": P + "#k0", "type": "JsonWebKey2020", "controller": P,
    ///                             "publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-65", "pub": b64(pk)}}],
    ///     "authentication": [P + "#k0"],
    ///     "service": [{"id": P + "#device", "type": "DeviceAgent",
    ///                  "serviceEndpoint": "http://example.com/device"}],
    ///     "seq": 0,
    ///     "nextKeyHash": b64(hashlib.sha256(next_pk).digest()),
    /// }
    /// hashed = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    /// print("did:iiot:" + b64(hashlib.sha256(hashed).digest()))
    /// ```
    #[test]
    fn the_python_test_vector_gives_the_same_did() {
        const PYTHON_DID: &str = "did:iiot:_3PVRuTEqJRzcTzByFZy94ebjMt3-tO7Dwx-TKIW2FE";
        let public_key: Vec<u8> = (0..1952).map(|i| (i % 256) as u8).collect();
        let next_key: Vec<u8> = (0..1952).map(|i| ((255 - i % 256) % 256) as u8).collect();
        let draft = document(PLACEHOLDER, &public_key, 0, None, &next_key);
        assert_eq!(
            draft["nextKeyHash"],
            "LrFXN_kwajyR4Iegwo0fzTODtseh7diWnII8xoZU7G8"
        );
        // The tests' own derivation agrees with Python, and so does the node's.
        assert_eq!(derive(&draft).0, PYTHON_DID);
        let (did, doc) = derive_did(&draft).unwrap();
        assert_eq!(did, PYTHON_DID);
        assert_eq!(doc, derive(&draft).1);
        assert_eq!(key_of_did(&did), Some(key_of(PYTHON_DID)));
        assert_eq!(hashed_form(&doc), Ok(key_of(PYTHON_DID)));
    }

    // ---- The binding ---------------------------------------------------------

    #[tokio::test]
    async fn a_version_0_binds_and_verifies() {
        let chain = Chain::new();
        assert!(binds(&chain.key, chain.version(0)));
        assert!(verify_record(&handler(), None, &chain.key, chain.version(0)).await);
        assert_eq!(
            record_form(&chain.key, chain.version(0)),
            Ok(RecordForm {
                seq: 0,
                prev: None,
                next_key_hash: sha256(chain.keys[1].public_key()),
                key_hash: sha256(chain.keys[0].public_key()),
            })
        );
    }

    /// A later version binds by its suffix and its fields, not by its hash.
    #[tokio::test]
    async fn a_later_version_binds_by_its_suffix() {
        let mut chain = Chain::new();
        let v1 = chain.grow();
        assert!(binds(&chain.key, &v1));
        assert!(verify_record(&handler(), None, &chain.key, &v1).await);
        let form = record_form(&chain.key, &v1).unwrap();
        assert_eq!(form.seq, 1);
        assert_eq!(form.prev, Some(sha256(chain.version(0))));
    }

    #[test]
    fn changing_any_field_of_a_version_0_breaks_its_binding() {
        let chain = Chain::new();
        assert!(binds(&chain.key, chain.version(0)));
        let original = chain.doc(
            0,
            None,
            chain.keys[0].public_key(),
            chain.keys[1].public_key(),
        );

        let other_key = new_key();
        let mut changed = original.clone();
        changed["verificationMethod"][0]["publicKeyJwk"]["pub"] =
            json!(b64(other_key.public_key()));
        assert!(
            !binds(&chain.key, &sign(&changed, &other_key)),
            "another key"
        );

        let mut changed = original.clone();
        changed["service"][0]["serviceEndpoint"] = json!("http://example.com/other");
        assert!(
            !binds(&chain.key, &sign(&changed, &chain.keys[0])),
            "another service"
        );

        let mut changed = original.clone();
        changed["seq"] = json!(1);
        assert!(
            !binds(&chain.key, &sign(&changed, &chain.keys[0])),
            "another seq"
        );

        let mut changed = original;
        changed["nextKeyHash"] = json!(b64(&sha256(new_key().public_key())));
        assert!(
            !binds(&chain.key, &sign(&changed, &chain.keys[0])),
            "another next key"
        );
    }

    #[test]
    fn a_record_does_not_bind_to_another_key() {
        let (first, second) = (Chain::new(), Chain::new());
        assert!(binds(&first.key, first.version(0)));
        assert!(!binds(&second.key, first.version(0)));
        assert_eq!(
            record_form(&second.key, first.version(0)),
            Err(FormError::WrongKey)
        );
    }

    /// The suffix of `id` must be the canonical text of the key: another text
    /// that a lenient decoder reads as the same 32 bytes does not bind.
    #[test]
    fn an_id_with_a_non_canonical_suffix_does_not_bind() {
        let chain = Chain::new();
        assert!(binds(&chain.key, chain.version(0)));
        let suffix = b64(&chain.key);
        let last = suffix.chars().last().unwrap();
        // The last character carries 2 unused bits; flip the lowest one.
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let index = alphabet.find(last).unwrap();
        let lenient = format!("{}{}", &suffix[..42], &alphabet[index ^ 1..(index ^ 1) + 1]);
        for id in [
            format!("did:iiot:{suffix}="),
            format!("did:iiot:{}", &suffix[..42]),
            format!("did:iiot:{lenient}"),
        ] {
            let mut doc = chain.doc(
                0,
                None,
                chain.keys[0].public_key(),
                chain.keys[1].public_key(),
            );
            doc["id"] = json!(id);
            assert!(!binds(&chain.key, &sign(&doc, &chain.keys[0])), "{id}");
        }
    }

    /// The owner forgot to put the DID in one place, which still holds the
    /// placeholder. The hashed form would still give the key, since that
    /// place reads the same in the draft, so only rule 2 of the hashed form
    /// refuses the record.
    #[test]
    fn a_document_that_holds_the_placeholder_does_not_bind() {
        let (key, next) = (new_key(), new_key());
        for value in [
            PLACEHOLDER.to_string(),
            format!("{PLACEHOLDER}#k1"),
            format!("{PLACEHOLDER}?x"),
            format!("{PLACEHOLDER}/x"),
        ] {
            let mut draft = document(PLACEHOLDER, key.public_key(), 0, None, next.public_key());
            draft["alsoKnownAs"] = json!(value);
            let (did, mut doc) = derive(&draft);
            doc["alsoKnownAs"] = json!(value);
            assert!(!binds(&key_of(&did), &sign(&doc, &key)), "{value}");
        }
        // A string that only starts with the letters of the placeholder is fine.
        let mut draft = document(PLACEHOLDER, key.public_key(), 0, None, next.public_key());
        draft["alsoKnownAs"] = json!(format!("{PLACEHOLDER}ish"));
        let (dht_key, record) = version0(&draft, &key);
        assert!(binds(&dht_key, &record));
    }

    #[test]
    fn a_version_0_with_prev_does_not_bind() {
        let (key, next) = (new_key(), new_key());
        let good = document(PLACEHOLDER, key.public_key(), 0, None, next.public_key());
        let (dht_key, record) = version0(&good, &key);
        assert!(binds(&dht_key, &record));
        let draft = document(
            PLACEHOLDER,
            key.public_key(),
            0,
            Some(b"some record"),
            next.public_key(),
        );
        let (dht_key, record) = version0(&draft, &key);
        assert!(!binds(&dht_key, &record));
    }

    #[test]
    fn next_key_hash_must_be_present_canonical_and_not_the_own_key() {
        let (key, next) = (new_key(), new_key());
        let good = document(PLACEHOLDER, key.public_key(), 0, None, next.public_key());
        let (dht_key, record) = version0(&good, &key);
        assert!(binds(&dht_key, &record));
        let own = b64(&sha256(key.public_key()));
        for next_key_hash in [
            None,
            Some(json!(null)),
            Some(json!("")),
            Some(json!(format!("{own}="))),
            Some(json!(own[..42].to_string())),
            Some(json!(own)),
        ] {
            let mut draft = good.clone();
            match &next_key_hash {
                None => {
                    draft.as_object_mut().unwrap().remove("nextKeyHash");
                }
                Some(value) => draft["nextKeyHash"] = value.clone(),
            }
            let (dht_key, record) = version0(&draft, &key);
            assert!(!binds(&dht_key, &record), "{next_key_hash:?}");
        }
    }

    #[test]
    fn a_later_version_needs_a_canonical_prev() {
        let mut chain = Chain::new();
        let v1 = chain.grow();
        assert!(binds(&chain.key, &v1));
        let doc = chain.doc(
            1,
            Some(chain.version(0)),
            chain.keys[1].public_key(),
            chain.keys[2].public_key(),
        );
        for prev in [
            None,
            Some(json!(null)),
            Some(json!("")),
            Some(json!(b64(&[1; 31]))),
        ] {
            let mut changed = doc.clone();
            match &prev {
                None => {
                    changed.as_object_mut().unwrap().remove("prev");
                }
                Some(value) => changed["prev"] = value.clone(),
            }
            assert!(
                !binds(&chain.key, &sign(&changed, &chain.keys[1])),
                "{prev:?}"
            );
        }
    }

    /// `seq` is an integer from 0 to 2^53 − 1.
    #[test]
    fn seq_must_be_a_safe_non_negative_integer() {
        let mut chain = Chain::new();
        let v1 = chain.grow();
        assert!(binds(&chain.key, &v1));
        let doc = chain.doc(
            1,
            Some(chain.version(0)),
            chain.keys[1].public_key(),
            chain.keys[2].public_key(),
        );
        for seq in [json!(-1), json!("1"), json!(null), json!(MAX_INTEGER + 1)] {
            let mut changed = doc.clone();
            changed["seq"] = seq.clone();
            assert!(!binds(&chain.key, &sign(&changed, &chain.keys[1])), "{seq}");
        }
        let mut far = doc;
        far["seq"] = json!(MAX_INTEGER);
        assert!(binds(&chain.key, &sign(&far, &chain.keys[1])));
    }

    /// The node reads the bytes it is sent: whitespace in the document
    /// refuses it even when its DID was computed from the canonical form.
    #[test]
    fn a_document_sent_with_whitespace_does_not_bind() {
        let chain = Chain::new();
        assert!(binds(&chain.key, chain.version(0)));
        let doc = chain.doc(
            0,
            None,
            chain.keys[0].public_key(),
            chain.keys[1].public_key(),
        );
        let pretty = serde_json::to_vec_pretty(&doc).unwrap();
        assert!(!binds(&chain.key, &record_of(&pretty, &chain.keys[0])));
    }
}
