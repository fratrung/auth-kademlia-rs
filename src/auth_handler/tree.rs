//! Rotation keys committed in a Merkle tree (ADR 0006).
//!
//! The DID is the SHA-256 of a canonical genesis that commits the initial
//! body and the root of a 64-leaf tree. Leaf `i` commits the ML-DSA-65 key
//! and the activation code of position `i`. A record carries the genesis,
//! its code and its path in `treeProof`, so its key is checked against the
//! DID alone. [`tree_form`] is step 1 of the rules and verifies no
//! signature; [`Tree`], [`Genesis`] and [`document_at`] are the owner side.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

use crate::crypto::mldsa;
use crate::utils::{digest_bytes, ID_LEN};

use super::did::{
    canonical_bytes, decode_suffix, did_of_key, document_of, encode_suffix, holds_placeholder,
    id_of, parse_canonical, replace_did, FormError, PLACEHOLDER,
};
use super::RECORD_ALGORITHM;

/// A SHA-256 digest: a leaf, a node, a root or a key.
pub type Hash = [u8; ID_LEN];

/// Height of the first tree (point 8).
pub const HEIGHT: usize = 6;

/// Positions of the tree, 64: the documents use 0 to 62.
pub const POSITIONS: usize = 1 << HEIGHT;

/// The reserved position, refused even with a valid path (point 8).
pub const RESERVED: u64 = POSITIONS as u64 - 1;

/// Bytes of an activation code (Decision 2).
pub const CODE_LEN: usize = 32;

/// Bytes of a membership path: one 32-byte sibling per level, 192.
pub const PATH_LEN: usize = HEIGHT * ID_LEN;

/// The format version committed in the genesis (point 12).
pub const FORMAT_VERSION: u64 = 1;

/// The hash algorithm committed in the genesis.
pub const HASH_ALG: &str = "SHA-256";

/// The member of a signed document that holds the genesis, the code and
/// the path (point 12).
pub const PROOF: &str = "treeProof";

/// Domain separation of leaves and nodes: in Certificate Transparency "this
/// domain separation is required to give second preimage resistance"
/// (RFC 9162, section 2.1.1).
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// The bytes of base64url text without padding, if the text is the
/// canonical encoding of exactly `N` bytes: it encodes back to itself.
fn decode_exact<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes: [u8; N] = URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(bytes) == text).then_some(bytes)
}

/// The bytes of canonical base64url text without padding, of any length.
fn decode_canonical(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

/// A leaf: SHA-256(0x00 ‖ index as 4 bytes big-endian ‖ raw public key ‖
/// code) (Decision 2). The index ties the leaf to its position, written as
/// LMS writes its leaf number `q` (RFC 8554, section 5.4).
pub fn leaf_hash(index: u32, public_key: &[u8], code: &[u8; CODE_LEN]) -> Hash {
    let mut input = Vec::with_capacity(1 + 4 + public_key.len() + CODE_LEN);
    input.push(LEAF_PREFIX);
    input.extend_from_slice(&index.to_be_bytes());
    input.extend_from_slice(public_key);
    input.extend_from_slice(code);
    digest_bytes(&input)
}

/// An internal node: SHA-256(0x01 ‖ left ‖ right) (Decision 2).
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut input = [0u8; 1 + 2 * ID_LEN];
    input[0] = NODE_PREFIX;
    input[1..1 + ID_LEN].copy_from_slice(left);
    input[1 + ID_LEN..].copy_from_slice(right);
    digest_bytes(&input)
}

/// The root reached from `leaf` at `index` through `path`: the leaf's
/// sibling first, the sibling just below the root last, as LMS orders its
/// path (RFC 8554, section 5.4). Bit `i` of `index`, from the least
/// significant, is 1 when the node at level `i` is a right child (point 12).
pub fn root_from_path(leaf: Hash, index: u32, path: &[u8; PATH_LEN]) -> Hash {
    let mut node = leaf;
    for (level, chunk) in path.chunks_exact(ID_LEN).enumerate() {
        let mut sibling = [0u8; ID_LEN];
        sibling.copy_from_slice(chunk);
        node = if (index >> level) & 1 == 1 {
            node_hash(&sibling, &node)
        } else {
            node_hash(&node, &sibling)
        };
    }
    node
}

/// The whole tree, as the owner builds it at provisioning (point 8): every
/// level, from the 64 leaves up to the root.
#[derive(Debug, Clone)]
pub struct Tree {
    levels: Vec<Vec<Hash>>,
}

impl Tree {
    /// The tree of `leaves`, or `None` unless there are exactly `POSITIONS`.
    pub fn new(leaves: &[Hash]) -> Option<Self> {
        if leaves.len() != POSITIONS {
            return None;
        }
        let mut levels = vec![leaves.to_vec()];
        while let Some(below) = levels.last().filter(|level| level.len() > 1) {
            let above = below
                .chunks_exact(2)
                .map(|pair| node_hash(&pair[0], &pair[1]))
                .collect();
            levels.push(above);
        }
        Some(Self { levels })
    }

    /// The root, committed in the genesis.
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|top| top.first())
            .copied()
            .unwrap_or_default()
    }

    /// The membership path of position `index`, or `None` beyond the tree.
    pub fn path(&self, index: u32) -> Option<[u8; PATH_LEN]> {
        let mut path = [0u8; PATH_LEN];
        let mut at = usize::try_from(index).ok()?;
        for (level, nodes) in self.levels.iter().take(HEIGHT).enumerate() {
            let sibling = nodes.get(at ^ 1)?;
            path[level * ID_LEN..(level + 1) * ID_LEN].copy_from_slice(sibling);
            at /= 2;
        }
        Some(path)
    }
}

/// The genesis of a DID (Decision 1, point 12): the hash of the initial
/// body and the root, with the algorithms, the height and the format
/// version, which this node accepts with one value each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Genesis {
    /// SHA-256 of the hashed body of document 0 (point 7).
    pub initial_body_hash: Hash,
    /// The root of the tree.
    pub root: Hash,
}

impl Genesis {
    /// The genesis as a JSON object.
    pub fn to_json(&self) -> Value {
        json!({
            "hashAlg": HASH_ALG,
            "height": HEIGHT,
            "initialBodyHash": encode_suffix(&self.initial_body_hash),
            "root": encode_suffix(&self.root),
            "sigAlg": RECORD_ALGORITHM,
            "version": FORMAT_VERSION,
        })
    }

    /// The canonical bytes of the genesis: sorted keys, no whitespace, as
    /// `serde_json` writes `to_json` (ADR 0005, open point 3).
    pub fn canonical(&self) -> Vec<u8> {
        format!(
            r#"{{"hashAlg":"{HASH_ALG}","height":{HEIGHT},"initialBodyHash":"{}","root":"{}","sigAlg":"{RECORD_ALGORITHM}","version":{FORMAT_VERSION}}}"#,
            encode_suffix(&self.initial_body_hash),
            encode_suffix(&self.root),
        )
        .into_bytes()
    }

    /// The DHT key of the DID: the SHA-256 of the canonical genesis.
    pub fn key(&self) -> Hash {
        digest_bytes(&self.canonical())
    }

    /// The DID: `did:iiot:` and the base64url of `key`.
    pub fn did(&self) -> String {
        did_of_key(&self.key())
    }

    /// The genesis a document carries. It holds exactly the six members,
    /// with SHA-256, ML-DSA-65, height 6 and version 1; any other value is
    /// refused (point 12).
    pub fn from_json(value: &Value) -> Result<Self, FormError> {
        let invalid = FormError::Field("genesis");
        let map = value.as_object().ok_or(invalid.clone())?;
        let fixed = map.len() == 6
            && map.get("hashAlg") == Some(&json!(HASH_ALG))
            && map.get("sigAlg") == Some(&json!(RECORD_ALGORITHM))
            && map.get("height") == Some(&json!(HEIGHT))
            && map.get("version") == Some(&json!(FORMAT_VERSION));
        if !fixed {
            return Err(invalid);
        }
        let hash = |name: &str| {
            map.get(name)
                .and_then(Value::as_str)
                .and_then(decode_suffix)
                .ok_or(invalid.clone())
        };
        Ok(Self {
            initial_body_hash: hash("initialBodyHash")?,
            root: hash("root")?,
        })
    }
}

/// The SHA-256 of a draft body, as the owner computes `initialBodyHash`
/// before the DID exists (point 7, step 1): no `id`, no `treeProof`, the
/// placeholder in place of the DID.
pub fn draft_body_hash(draft: &Value) -> Result<Hash, FormError> {
    if draft.get("id").is_some() {
        return Err(FormError::Field("id"));
    }
    if draft.get(PROOF).is_some() {
        return Err(FormError::Field(PROOF));
    }
    Ok(digest_bytes(&canonical_bytes(draft)?))
}

/// The SHA-256 of the hashed body of a received document 0 (point 7, step
/// 3): its `id` must be a canonical DID, it may not hold the placeholder,
/// and `id` and `treeProof` are removed with the DID written back as the
/// placeholder (ADR 0005, section 1).
pub fn initial_body_hash(doc: &Value) -> Result<Hash, FormError> {
    let (did, _) = id_of(doc)?;
    if holds_placeholder(doc) {
        return Err(FormError::Placeholder);
    }
    let mut body = doc.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("id");
        map.remove(PROOF);
    }
    replace_did(&mut body, did, PLACEHOLDER);
    Ok(digest_bytes(&canonical_bytes(&body)?))
}

/// The document of a position from its draft body, as the custody backend
/// completes it before signing (point 7, step 2; point 12): the DID in
/// place of the placeholder, `id`, and `treeProof` with the genesis, the
/// code and the path.
pub fn document_at(
    draft: &Value,
    genesis: &Genesis,
    code: &[u8; CODE_LEN],
    path: &[u8; PATH_LEN],
) -> Result<Value, FormError> {
    draft_body_hash(draft)?;
    let did = genesis.did();
    let mut doc = draft.clone();
    replace_did(&mut doc, PLACEHOLDER, &did);
    let map = doc
        .as_object_mut()
        .ok_or(FormError::NotCanonical("not an object"))?;
    map.insert("id".into(), Value::String(did));
    map.insert(
        PROOF.into(),
        json!({
            "code": URL_SAFE_NO_PAD.encode(code),
            "genesis": genesis.to_json(),
            "path": URL_SAFE_NO_PAD.encode(path),
        }),
    );
    Ok(doc)
}

/// What step 1 reads from a record under ADR 0006.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeForm {
    /// The position: the index of the leaf (point 12).
    pub seq: u64,
    /// `record_hash` of the record the owner names as its previous
    /// publication; `None` at position 0. Only its form is checked
    /// (Decision 4).
    pub prev: Option<Hash>,
    /// SHA-256 of the raw public key of the position, as a credential names
    /// it (point 9).
    pub key_hash: Hash,
}

/// Step 1 for a record sent under `key`, without verifying any signature
/// (Decision 3, point 12): the layout and algorithm, the canonical form, no
/// placeholder, an `id` whose suffix is `key`, `seq` from 0 to 62, `prev`
/// absent at 0 and canonical after, a `treeProof` of exactly the genesis,
/// the code and the path, a genesis that hashes to `key`, the leaf of the
/// document's key and code at `seq` reaching the root through the path,
/// and at 0 the initial body hash.
pub fn tree_form(key: &Hash, record: &[u8]) -> Result<TreeForm, FormError> {
    let doc = parse_canonical(document_of(record)?)?;
    if holds_placeholder(&doc) {
        return Err(FormError::Placeholder);
    }
    if id_of(&doc)?.1 != *key {
        return Err(FormError::WrongKey);
    }
    // 63 is reserved and refused even when its path verifies (point 8).
    let seq = doc
        .get("seq")
        .and_then(Value::as_u64)
        .filter(|seq| *seq < RESERVED)
        .ok_or(FormError::Field("seq"))?;
    let index = u32::try_from(seq).map_err(|_| FormError::Field("seq"))?;
    let prev = match (seq, doc.get("prev")) {
        (0, None) => None,
        (0, Some(_)) => return Err(FormError::Field("prev")),
        (_, prev) => Some(
            prev.and_then(Value::as_str)
                .and_then(decode_suffix)
                .ok_or(FormError::Field("prev"))?,
        ),
    };
    let proof = doc
        .get(PROOF)
        .and_then(Value::as_object)
        .filter(|proof| proof.len() == 3)
        .ok_or(FormError::Field(PROOF))?;
    let genesis = Genesis::from_json(proof.get("genesis").ok_or(FormError::Field(PROOF))?)?;
    if genesis.key() != *key {
        return Err(FormError::WrongKey);
    }
    let code = proof
        .get("code")
        .and_then(Value::as_str)
        .and_then(decode_exact::<CODE_LEN>)
        .ok_or(FormError::Field("code"))?;
    let path = proof
        .get("path")
        .and_then(Value::as_str)
        .and_then(decode_exact::<PATH_LEN>)
        .ok_or(FormError::Field("path"))?;
    // The key is read strictly: the bytes of the leaf are those of one text.
    let public_key = doc["verificationMethod"][0]["publicKeyJwk"]["pub"]
        .as_str()
        .and_then(decode_canonical)
        .filter(|public_key| public_key.len() == mldsa::public_key_len())
        .ok_or(FormError::Field("publicKeyJwk"))?;
    let leaf = leaf_hash(index, &public_key, &code);
    if root_from_path(leaf, index, &path) != genesis.root {
        return Err(FormError::NotInTree);
    }
    if seq == 0 && initial_body_hash(&doc)? != genesis.initial_body_hash {
        return Err(FormError::WrongKey);
    }
    Ok(TreeForm {
        seq,
        prev,
        key_hash: digest_bytes(&public_key),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::super::test_chain::{b64, sha256, sign};
    use super::super::test_tree::{body, leaf, node, TreeOwner};
    use super::super::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
    use super::*;

    fn signature_verifies(record: &[u8]) -> bool {
        let handler: Arc<dyn SignatureVerifierHandler> =
            Arc::new(DIDSignatureVerifierHandler::new("unused"));
        handler
            .handle_signature_verification(record)
            .unwrap_or(false)
    }

    fn genesis_of(owner: &TreeOwner) -> Genesis {
        Genesis::from_json(&owner.genesis).expect("the owner's genesis")
    }

    // ---- The tree ------------------------------------------------------------

    #[test]
    fn leaves_and_nodes_hash_with_their_prefixes() {
        let public_key = [7u8; 1952];
        let code = [9u8; CODE_LEN];
        assert_eq!(
            leaf_hash(5, &public_key, &code),
            leaf(5, &public_key, &code)
        );
        assert_eq!(
            leaf_hash(5, &public_key, &code),
            sha256(&[&[0u8, 0, 0, 0, 5][..], &public_key, &code].concat())
        );
        let (left, right) = ([1u8; ID_LEN], [2u8; ID_LEN]);
        assert_eq!(node_hash(&left, &right), node(&left, &right));
        assert_eq!(
            node_hash(&left, &right),
            sha256(&[&[1u8][..], &left, &right].concat())
        );
        // A leaf cannot be read as a node of the same bytes.
        assert_ne!(node_hash(&left, &right), leaf_hash(0, &left, &right));
    }

    #[test]
    fn every_path_of_the_tree_reaches_its_root() {
        let owner = TreeOwner::new(1);
        let tree = Tree::new(&owner.levels[0]).expect("64 leaves");
        assert_eq!(tree.root(), owner.root());
        for index in 0..POSITIONS as u32 {
            let path = tree.path(index).expect("a position of the tree");
            assert_eq!(path.to_vec(), owner.path(index as usize), "{index}");
            let leaf = owner.levels[0][index as usize];
            assert_eq!(root_from_path(leaf, index, &path), owner.root(), "{index}");
        }
        // The first sibling is the leaf's: leaf 4 for position 5.
        let path = tree.path(5).expect("position 5");
        assert_eq!(&path[..ID_LEN], &owner.levels[0][4]);
        assert_eq!(tree.path(POSITIONS as u32), None);
        assert!(Tree::new(&owner.levels[0][..63]).is_none());
    }

    #[test]
    fn another_index_code_key_or_sibling_reaches_another_root() {
        let owner = TreeOwner::new(1);
        let path: [u8; PATH_LEN] = owner.path(5).try_into().expect("192 bytes");
        let public_key = owner.keys[5].public_key();
        let code = owner.codes[5];
        assert_eq!(
            root_from_path(leaf_hash(5, public_key, &code), 5, &path),
            owner.root()
        );
        let other_code = [code[0] ^ 1; CODE_LEN];
        for (leaf, index) in [
            (leaf_hash(4, public_key, &code), 5),
            (leaf_hash(5, public_key, &code), 4),
            (leaf_hash(5, public_key, &other_code), 5),
            (leaf_hash(5, owner.keys[6].public_key(), &code), 5),
        ] {
            assert_ne!(root_from_path(leaf, index, &path), owner.root());
        }
        let mut changed = path;
        changed[PATH_LEN - 1] ^= 1;
        assert_ne!(
            root_from_path(leaf_hash(5, public_key, &code), 5, &changed),
            owner.root()
        );
    }

    // ---- The genesis ---------------------------------------------------------

    #[test]
    fn the_genesis_hashes_its_canonical_bytes() {
        let owner = TreeOwner::new(1);
        let genesis = genesis_of(&owner);
        assert_eq!(genesis.root, owner.root());
        assert_eq!(genesis.to_json(), owner.genesis);
        assert_eq!(
            genesis.canonical(),
            canonical_bytes(&genesis.to_json()).unwrap()
        );
        assert_eq!(genesis.key(), owner.key);
        assert_eq!(genesis.did(), owner.did);
    }

    #[test]
    fn the_genesis_refuses_any_other_member_or_value() {
        let good = TreeOwner::new(1).genesis;
        assert!(Genesis::from_json(&good).is_ok());
        let changes: [(&str, Option<Value>); 9] = [
            ("hashAlg", Some(json!("SHA-512"))),
            ("sigAlg", Some(json!("Ed25519"))),
            ("height", Some(json!(5))),
            ("version", Some(json!(2))),
            (
                "root",
                Some(json!(format!("{}=", good["root"].as_str().unwrap()))),
            ),
            ("initialBodyHash", Some(json!(b64(&[1; 31])))),
            ("root", None),
            ("extra", Some(json!(1))),
            ("version", Some(json!("1"))),
        ];
        for (name, value) in changes {
            let mut changed = good.clone();
            let map = changed.as_object_mut().unwrap();
            match value {
                Some(value) => {
                    map.insert(name.into(), value);
                }
                None => {
                    map.remove(name);
                }
            }
            assert_eq!(
                Genesis::from_json(&changed),
                Err(FormError::Field("genesis")),
                "{name}"
            );
        }
    }

    /// The test vector of the Python application's rule, with only
    /// `hashlib`, `json` and `base64` of the standard library
    /// (`python3 -I tree_vector.py`):
    ///
    /// ```python
    /// import base64, hashlib, json
    /// b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    /// sha = lambda raw: hashlib.sha256(raw).digest()
    /// P = "did:iiot:self"
    /// pk = [bytes((i * 7 + j) % 256 for j in range(1952)) for i in range(64)]
    /// code = [bytes((i * 13 + j) % 256 for j in range(32)) for i in range(64)]
    /// level = [sha(b"\x00" + i.to_bytes(4, "big") + pk[i] + code[i]) for i in range(64)]
    /// while len(level) > 1:
    ///     level = [sha(b"\x01" + level[n] + level[n + 1]) for n in range(0, len(level), 2)]
    /// body = {
    ///     "@context": ["https://www.w3.org/ns/did/v1"],
    ///     "verificationMethod": [{"id": P + "#k0", "type": "JsonWebKey2020", "controller": P,
    ///                             "publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-65", "pub": b64(pk[0])}}],
    ///     "authentication": [P + "#k0"],
    ///     "service": [{"id": P + "#device", "type": "DeviceAgent",
    ///                  "serviceEndpoint": "http://example.com/device"}],
    ///     "seq": 0,
    /// }
    /// canon = lambda doc: json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    /// genesis = {"hashAlg": "SHA-256", "height": 6, "initialBodyHash": b64(sha(canon(body))),
    ///            "root": b64(level[0]), "sigAlg": "ML-DSA-65", "version": 1}
    /// print("did:iiot:" + b64(sha(canon(genesis))))
    /// ```
    #[test]
    fn the_python_test_vector_gives_the_same_did() {
        const PYTHON_ROOT: &str = "MM7CRUx-ZyLMhPaObQEik50Wa4VxDQSfT_Wl0krQAIg";
        const PYTHON_BODY_HASH: &str = "tF6OBNXuP3Ot4sBLSw2zVSYpOXppsZFNoEeNqJ5Jlbg";
        const PYTHON_DID: &str = "did:iiot:4BrPl1dyD0z_y03fs3XmwyKC0L25N33p1g-SZlsT4Tg";
        let public_key =
            |i: usize| -> Vec<u8> { (0..1952).map(|j| ((i * 7 + j) % 256) as u8).collect() };
        let code =
            |i: usize| -> [u8; CODE_LEN] { std::array::from_fn(|j| ((i * 13 + j) % 256) as u8) };
        let leaves: Vec<Hash> = (0..POSITIONS)
            .map(|i| leaf_hash(i as u32, &public_key(i), &code(i)))
            .collect();
        let tree = Tree::new(&leaves).expect("64 leaves");
        assert_eq!(encode_suffix(&tree.root()), PYTHON_ROOT);
        let draft = body(PLACEHOLDER, &public_key(0), 0, None);
        let initial_body_hash = draft_body_hash(&draft).unwrap();
        assert_eq!(encode_suffix(&initial_body_hash), PYTHON_BODY_HASH);
        let genesis = Genesis {
            initial_body_hash,
            root: tree.root(),
        };
        assert_eq!(genesis.did(), PYTHON_DID);
    }

    // ---- The form of a record --------------------------------------------------

    #[test]
    fn records_at_0_and_5_have_the_form_and_verify() {
        let owner = TreeOwner::new(1);
        let v0 = owner.record(0, None);
        assert_eq!(
            tree_form(&owner.key, &v0),
            Ok(TreeForm {
                seq: 0,
                prev: None,
                key_hash: sha256(owner.keys[0].public_key()),
            })
        );
        assert!(signature_verifies(&v0));
        // Position 5 names record 2 as the previous publication: 3 and 4
        // were never released, and nothing before 5 is needed.
        let v2 = owner.record(2, Some(&v0));
        let v5 = owner.record(5, Some(&v2));
        assert_eq!(
            tree_form(&owner.key, &v5),
            Ok(TreeForm {
                seq: 5,
                prev: Some(sha256(&v2)),
                key_hash: sha256(owner.keys[5].public_key()),
            })
        );
        assert!(signature_verifies(&v5));
    }

    /// Open point 1, acceptance: the real key and path of 5 with the wrong
    /// code are refused even though the signature verifies.
    #[test]
    fn a_wrong_code_is_refused_even_when_the_signature_verifies() {
        let owner = TreeOwner::new(1);
        let mut doc = owner.doc(5, Some(b"record 4"));
        doc[PROOF]["code"] = json!(b64(&[0x42; CODE_LEN]));
        let record = sign(&doc, &owner.keys[5]);
        assert!(signature_verifies(&record));
        assert_eq!(tree_form(&owner.key, &record), Err(FormError::NotInTree));
        // The code of another position, or the key of another position.
        let mut doc = owner.doc(5, Some(b"record 4"));
        doc[PROOF]["code"] = json!(b64(&owner.codes[6]));
        assert_eq!(
            tree_form(&owner.key, &sign(&doc, &owner.keys[5])),
            Err(FormError::NotInTree)
        );
        let doc = owner.complete(
            &body(PLACEHOLDER, owner.keys[6].public_key(), 5, Some(b"4")),
            5,
        );
        let record = sign(&doc, &owner.keys[6]);
        assert!(signature_verifies(&record));
        assert_eq!(tree_form(&owner.key, &record), Err(FormError::NotInTree));
    }

    /// Point 8: 63 is reserved and refused with a valid path; beyond the tree
    /// there is no position.
    #[test]
    fn the_reserved_position_and_beyond_are_refused() {
        let owner = TreeOwner::new(1);
        let v62 = owner.record(62, Some(b"record 61"));
        assert_eq!(tree_form(&owner.key, &v62).map(|form| form.seq), Ok(62));
        let v63 = owner.record(63, Some(b"record 62"));
        assert!(signature_verifies(&v63));
        assert_eq!(tree_form(&owner.key, &v63), Err(FormError::Field("seq")));
        for seq in [
            json!(64),
            json!(u32::MAX),
            json!(-1),
            json!("5"),
            json!(null),
        ] {
            let mut doc = owner.doc(5, Some(b"record 4"));
            doc["seq"] = seq.clone();
            assert_eq!(
                tree_form(&owner.key, &sign(&doc, &owner.keys[5])),
                Err(FormError::Field("seq")),
                "{seq}"
            );
        }
    }

    /// Point 7, acceptance: with the root fixed, another serial number in
    /// the initial body gives another DID, and a leaf-0 signature on the
    /// altered body under the original DID fails the digest check. A later
    /// position may change the field under the original DID.
    #[test]
    fn the_initial_body_is_bound_to_the_did() {
        let owner = TreeOwner::new(1);
        let mut draft = body(PLACEHOLDER, owner.keys[0].public_key(), 0, None);
        draft["serialNumber"] = json!("SN-1");
        let original = owner.with_initial_body(&draft);
        let v0 = original.record_from(&draft, 0);
        assert!(tree_form(&original.key, &v0).is_ok());

        let mut altered = draft.clone();
        altered["serialNumber"] = json!("SN-2");
        let other = owner.with_initial_body(&altered);
        assert_eq!(other.root(), original.root());
        assert_ne!(other.did, original.did);

        let forged = original.record_from(&altered, 0);
        assert!(signature_verifies(&forged));
        assert_eq!(tree_form(&original.key, &forged), Err(FormError::WrongKey));

        let mut later = body(PLACEHOLDER, owner.keys[1].public_key(), 1, Some(&v0));
        later["serialNumber"] = json!("SN-2");
        let v1 = original.record_from(&later, 1);
        assert!(tree_form(&original.key, &v1).is_ok());
    }

    #[test]
    fn a_record_of_another_did_is_refused() {
        let (first, second) = (TreeOwner::new(1), TreeOwner::new(2));
        let record = first.record(5, Some(b"record 4"));
        assert!(tree_form(&first.key, &record).is_ok());
        assert_eq!(tree_form(&second.key, &record), Err(FormError::WrongKey));
        // The DID of the second owner on the first owner's proof.
        let mut doc = first.doc(5, Some(b"record 4"));
        doc["id"] = json!(second.did);
        assert_eq!(
            tree_form(&second.key, &sign(&doc, &first.keys[5])),
            Err(FormError::WrongKey)
        );
    }

    #[test]
    fn the_proof_holds_exactly_a_canonical_code_genesis_and_path() {
        let owner = TreeOwner::new(1);
        let good = owner.doc(5, Some(b"record 4"));
        let code = good[PROOF]["code"].as_str().unwrap().to_string();
        let path = good[PROOF]["path"].as_str().unwrap().to_string();
        type Change = Box<dyn Fn(&mut Value)>;
        let cases: [(&str, Change, FormError); 9] = [
            (
                "no proof",
                Box::new(|doc| {
                    doc.as_object_mut().unwrap().remove(PROOF);
                }),
                FormError::Field(PROOF),
            ),
            (
                "an extra member",
                Box::new(|doc| doc[PROOF]["index"] = json!(5)),
                FormError::Field(PROOF),
            ),
            (
                "no genesis",
                Box::new(|doc| {
                    doc[PROOF].as_object_mut().unwrap().remove("genesis");
                    doc[PROOF]["other"] = json!(1);
                }),
                FormError::Field(PROOF),
            ),
            (
                "a short code",
                Box::new(|doc| doc[PROOF]["code"] = json!(b64(&[1; 31]))),
                FormError::Field("code"),
            ),
            (
                "a padded code",
                {
                    let code = code.clone();
                    Box::new(move |doc| doc[PROOF]["code"] = json!(format!("{code}=")))
                },
                FormError::Field("code"),
            ),
            (
                "a short path",
                Box::new(|doc| doc[PROOF]["path"] = json!(b64(&[1; PATH_LEN - 1]))),
                FormError::Field("path"),
            ),
            (
                "a long path",
                Box::new(|doc| doc[PROOF]["path"] = json!(b64(&[1; PATH_LEN + 1]))),
                FormError::Field("path"),
            ),
            (
                "a path in the standard alphabet",
                {
                    let path = path.replace('-', "+").replace('_', "/");
                    Box::new(move |doc| doc[PROOF]["path"] = json!(path))
                },
                FormError::Field("path"),
            ),
            (
                "another genesis",
                Box::new(|doc| doc[PROOF]["genesis"]["version"] = json!(2)),
                FormError::Field("genesis"),
            ),
        ];
        for (why, change, error) in cases {
            let mut doc = good.clone();
            change(&mut doc);
            let record = sign(&doc, &owner.keys[5]);
            // The standard alphabet may happen to match: skip that case then.
            if why == "a path in the standard alphabet" && doc == good {
                continue;
            }
            assert_eq!(tree_form(&owner.key, &record), Err(error), "{why}");
        }
    }

    #[test]
    fn prev_is_absent_at_0_and_canonical_after() {
        let owner = TreeOwner::new(1);
        let v0 = owner.record(0, None);
        let mut doc = owner.doc(0, None);
        doc["prev"] = json!(b64(&sha256(b"something")));
        assert_eq!(
            tree_form(&owner.key, &sign(&doc, &owner.keys[0])),
            Err(FormError::Field("prev"))
        );
        let good = owner.doc(5, Some(&v0));
        for prev in [
            None,
            Some(json!(null)),
            Some(json!("")),
            Some(json!(b64(&[1; 31]))),
        ] {
            let mut doc = good.clone();
            match &prev {
                None => {
                    doc.as_object_mut().unwrap().remove("prev");
                }
                Some(value) => doc["prev"] = value.clone(),
            }
            assert_eq!(
                tree_form(&owner.key, &sign(&doc, &owner.keys[5])),
                Err(FormError::Field("prev")),
                "{prev:?}"
            );
        }
    }

    #[test]
    fn a_record_that_holds_the_placeholder_or_a_lenient_key_is_refused() {
        let owner = TreeOwner::new(1);
        let mut doc = owner.doc(5, Some(b"record 4"));
        doc["alsoKnownAs"] = json!(format!("{PLACEHOLDER}#k1"));
        assert_eq!(
            tree_form(&owner.key, &sign(&doc, &owner.keys[5])),
            Err(FormError::Placeholder)
        );
        // The key with padding: a lenient decoder reads the same bytes.
        let mut doc = owner.doc(5, Some(b"record 4"));
        let public = b64(owner.keys[5].public_key());
        doc["verificationMethod"][0]["publicKeyJwk"]["pub"] = json!(format!("{public}=="));
        assert_eq!(
            tree_form(&owner.key, &sign(&doc, &owner.keys[5])),
            Err(FormError::Field("publicKeyJwk"))
        );
    }

    #[test]
    fn the_owner_side_builds_the_same_document_as_the_tests() {
        let owner = TreeOwner::new(1);
        let genesis = genesis_of(&owner);
        let draft = body(
            PLACEHOLDER,
            owner.keys[5].public_key(),
            5,
            Some(b"record 4"),
        );
        let path: [u8; PATH_LEN] = owner.path(5).try_into().expect("192 bytes");
        let doc = document_at(&draft, &genesis, &owner.codes[5], &path).unwrap();
        assert_eq!(doc, owner.complete(&draft, 5));
        let initial = body(PLACEHOLDER, owner.keys[0].public_key(), 0, None);
        assert_eq!(draft_body_hash(&initial), Ok(genesis.initial_body_hash));
        let doc0 = owner.doc(0, None);
        assert_eq!(initial_body_hash(&doc0), Ok(genesis.initial_body_hash));
        assert_eq!(
            draft_body_hash(&doc0),
            Err(FormError::Field("id")),
            "a completed document is not a draft"
        );
    }
}
