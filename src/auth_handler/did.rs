//! The `did:iiot` identifier, the canonical JSON of its documents, and the
//! placeholder a draft holds in place of its own DID.
//!
//! A DID is `did:iiot:` followed by 43 characters of base64url without
//! padding; the DHT key is the decoded suffix.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use thiserror::Error;

use crate::crypto::signature_verifier::resolve_alg_and_length;
use crate::utils::ID_LEN;

use super::{extract_sig_and_data, record_algorithm};

/// The method prefix of every DID.
pub const DID_PREFIX: &str = "did:iiot:";

/// What a draft holds in place of its own DID, which does not exist yet.
pub const PLACEHOLDER: &str = "did:iiot:self";

/// Characters of a suffix: 32 bytes in base64url without padding.
pub const SUFFIX_LEN: usize = 43;

/// The largest integer a document may hold: 2^53 − 1, which
/// RFC 8785 and `serde_json` both write as a plain decimal.
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
    /// The leaf of the document's key and code does not reach the root of
    /// its genesis.
    #[error("the key and code are not those of the position in the tree")]
    NotInTree,
}

/// The canonical suffix of 32 bytes: base64url without padding, 43 characters.
pub fn encode_suffix(bytes: &[u8; ID_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The 32 bytes of a canonical suffix, or `None`: 43 characters of the
/// URL-safe alphabet, no padding, encoding back to the same text. The
/// re-encoding refuses any other text of the same bytes.
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
/// the same bytes as `serde_json` writes the parsed document.
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
pub(crate) fn holds_placeholder(value: &Value) -> bool {
    match value {
        Value::String(text) => after_did(text, PLACEHOLDER).is_some(),
        Value::Array(items) => items.iter().any(holds_placeholder),
        Value::Object(map) => map.values().any(holds_placeholder),
        _ => false,
    }
}

/// Replace `from` by `to` in every string value that is `from` or a DID URL
/// of it. Object keys are not changed.
pub(crate) fn replace_did(value: &mut Value, from: &str, to: &str) {
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
pub(crate) fn id_of(doc: &Value) -> Result<(&str, [u8; ID_LEN]), FormError> {
    let did = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(FormError::Field("id"))?;
    let key = key_of_did(did).ok_or(FormError::Field("id"))?;
    Ok((did, key))
}

/// The signed document of a record, after its algorithm and signature.
pub(crate) fn document_of(record: &[u8]) -> Result<&[u8], FormError> {
    let alg = record_algorithm(record).map_err(|_| FormError::Layout)?;
    let (_, sig_len) = resolve_alg_and_length(&alg).map_err(|_| FormError::Layout)?;
    let (_, data) = extract_sig_and_data(record, sig_len).map_err(|_| FormError::Layout)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_tree::b64;
    use super::*;

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
}
