//! The custody's acceptance cases, on the file backend with a clock the
//! tests move: what is signed, when, and what survives a restart.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::auth_handler::did::{canonical_bytes, document_of, PLACEHOLDER};
use crate::auth_handler::owner::signed_record;
use crate::auth_handler::tree::{document_at, tree_form, Genesis, RESERVED};
use crate::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use crate::crypto::mldsa::MlDsa65KeyPair;
use crate::durable::test_dir::{set_read_only, TestDir};
use crate::utils::digest_bytes;

use super::*;

const DAY: u64 = 86_400_000;
const START: u64 = 20_000 * DAY;
const INTERVAL: u64 = 7 * DAY;

/// The start of slot `index`.
fn slot(index: u64) -> u64 {
    START + index * INTERVAL
}

fn template() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{PLACEHOLDER}#k0"),
            "type": "JsonWebKey2020",
            "controller": PLACEHOLDER,
            "publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-65"},
        }],
        "authentication": [format!("{PLACEHOLDER}#k0")],
        "service": [{
            "id": format!("{PLACEHOLDER}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "https://device.example/agent",
        }],
    })
}

fn other_template() -> Value {
    let mut template = template();
    template["service"][0]["serviceEndpoint"] = json!("https://elsewhere.example/agent");
    template
}

/// A custody provisioned at the start of slot 0, its directory and its
/// clock.
struct Owner {
    dir: TestDir,
    now: Arc<AtomicU64>,
    custody: FileCustody,
}

impl Owner {
    fn new() -> Self {
        let dir = TestDir::new();
        let now = Arc::new(AtomicU64::new(slot(0)));
        let calendar = Calendar::new(START, INTERVAL).unwrap();
        let custody = FileCustody::provision_with(
            dir.path().to_path_buf(),
            calendar,
            &template(),
            clock(&now),
        )
        .unwrap();
        Self { dir, now, custody }
    }

    fn at(&self, now: u64) -> &Self {
        self.now.store(now, Ordering::SeqCst);
        self
    }

    /// The custody as a restart finds it, on the same clock.
    fn restart(&mut self) {
        self.custody =
            FileCustody::open_with(self.dir.path().to_path_buf(), clock(&self.now)).unwrap();
    }

    /// Prepare and publish `position`, due now.
    fn publish(&self, position: u64) -> Vec<u8> {
        let record = self.custody.prepare(position, &template()).unwrap();
        self.custody.mark_published(&record).unwrap();
        record
    }

    fn seq(&self, record: &[u8]) -> u64 {
        tree_form(&self.custody.genesis().key(), record)
            .unwrap()
            .seq
    }

    fn authorization(&self, position: u64) -> Vec<u8> {
        format!("{}:{position}", self.custody.did()).into_bytes()
    }

    /// The code of `position` as a record carries it.
    fn code_text(&self, position: u64) -> String {
        URL_SAFE_NO_PAD.encode(self.custody.secrets_of(position).unwrap().1)
    }
}

fn clock(now: &Arc<AtomicU64>) -> crate::storage::Clock {
    let now = now.clone();
    Arc::new(move || now.load(Ordering::SeqCst))
}

fn document(record: &[u8]) -> Value {
    serde_json::from_slice(document_of(record).unwrap()).unwrap()
}

fn signature_verifies(record: &[u8]) -> bool {
    DIDSignatureVerifierHandler::new("unused")
        .handle_signature_verification(record)
        .unwrap_or(false)
}

/// Accepts `<did>:<position>`, as an issuer's signature would bind both,
/// and counts the authorizations it was shown.
#[derive(Default)]
struct Issuer {
    shown: AtomicUsize,
}

impl ActivationVerifier for Issuer {
    fn verify(&self, did: &str, position: u64, authorization: &[u8]) -> bool {
        self.shown.fetch_add(1, Ordering::SeqCst);
        authorization == format!("{did}:{position}").as_bytes()
    }
}

// ---- The acceptance cases --------------------------------------------------

#[test]
fn a_position_is_never_signed_before_its_slot_without_an_authorization() {
    let owner = Owner::new();
    owner.at(slot(3)).publish(3);
    for _ in 0..3 {
        assert!(matches!(
            owner.custody.prepare(5, &template()),
            Err(CustodyError::NotDue {
                requested: 5,
                due: Due::Position(3)
            })
        ));
    }
    assert_eq!(owner.custody.pending(), None);
    assert_eq!(owner.custody.due(), Due::Position(3));
}

#[test]
fn the_boundary_belongs_to_the_slot_it_opens() {
    let owner = Owner::new();
    owner.at(slot(3)).publish(3);
    owner.at(slot(4) - 1);
    assert_eq!(owner.custody.due(), Due::Position(3));
    assert!(owner.custody.prepare(4, &template()).is_err());
    owner.at(slot(4));
    assert_eq!(owner.custody.due(), Due::Position(4));
    let record = owner.custody.prepare(4, &template()).unwrap();
    assert_eq!(owner.seq(&record), 4);
}

#[test]
fn a_retry_in_the_same_slot_gives_the_same_bytes() {
    let mut owner = Owner::new();
    let first = owner.at(slot(3)).custody.prepare(3, &template()).unwrap();
    assert_eq!(owner.custody.prepare(3, &template()).unwrap(), first);
    owner.custody.mark_published(&first).unwrap();
    assert_eq!(owner.custody.prepare(3, &template()).unwrap(), first);
    owner.restart();
    assert_eq!(owner.custody.prepare(3, &template()).unwrap(), first);
    // A position is signed once: another document is refused.
    assert!(matches!(
        owner.custody.prepare(3, &other_template()),
        Err(CustodyError::AlreadySigned(3))
    ));
}

#[test]
fn a_restart_in_slot_5_after_publishing_2_prepares_5_after_2() {
    let mut owner = Owner::new();
    let zero = owner.custody.pending().unwrap();
    owner.custody.mark_published(&zero).unwrap();
    let two = owner.at(slot(2)).publish(2);
    owner.at(slot(5));
    owner.restart();

    assert_eq!(owner.custody.published(), Some(two.clone()));
    let five = owner.custody.prepare(5, &template()).unwrap();
    let form = tree_form(&owner.custody.genesis().key(), &five).unwrap();
    assert_eq!((form.seq, form.prev), (5, Some(digest_bytes(&two))));
    // 2 stays published until the application publishes 5.
    assert_eq!(owner.custody.published(), Some(two.clone()));
    assert_eq!(owner.custody.pending(), Some(five.clone()));
    // The only code released is 5's: 3 and 4 never leave.
    let released = [&zero, &two, &five].map(|record| document(record)["treeProof"]["code"].clone());
    assert!(!released.contains(&json!(owner.code_text(3))));
    assert!(!released.contains(&json!(owner.code_text(4))));
    assert_eq!(released[2], owner.code_text(5));
    // Once 5 is published, they are erased.
    owner.custody.mark_published(&five).unwrap();
    assert_eq!(owner.custody.secrets_of(3), None);
    assert_eq!(owner.custody.secrets_of(4), None);
}

#[test]
fn a_clock_set_back_reopens_no_position() {
    let mut owner = Owner::new();
    let five = owner.at(slot(5)).publish(5);
    owner.at(slot(3));
    for position in [3, 4] {
        assert!(matches!(
            owner.custody.prepare(position, &template()),
            Err(CustodyError::NotDue {
                due: Due::Position(5),
                ..
            })
        ));
    }
    owner.restart();
    assert_eq!(owner.custody.due(), Due::Position(5));
    assert_eq!(owner.custody.prepare(5, &template()).unwrap(), five);
}

#[test]
fn the_first_slot_beyond_the_last_position_exhausts_the_tree() {
    let owner = Owner::new();
    let last = owner.at(slot(62)).publish(62);
    assert_eq!(owner.seq(&last), 62);
    for now in [slot(63), slot(64), slot(10_000)] {
        owner.at(now);
        assert_eq!(owner.custody.due(), Due::Exhausted);
        for position in [0, 62, RESERVED] {
            assert!(owner.custody.prepare(position, &template()).is_err());
        }
        assert!(matches!(
            owner.custody.activate_early(
                RESERVED,
                &template(),
                &owner.authorization(RESERVED),
                &Issuer::default()
            ),
            Err(CustodyError::NotNext(RESERVED))
        ));
    }
    // The last record stays published, for republication.
    assert_eq!(owner.custody.published(), Some(last));
}

/// The real key and path of 5 with a wrong code: the signature verifies,
/// the leaf does not reach the root. With the right code, both hold.
#[test]
fn a_record_with_another_code_fails_the_tree_though_its_signature_verifies() {
    let owner = Owner::new();
    let custody = &owner.custody;
    let genesis: Genesis = custody.genesis();
    let (seed, code) = custody.secrets_of(5).unwrap();
    let key = MlDsa65KeyPair::from_seed(&seed).unwrap();
    let path = custody.path_of(5).unwrap();
    let previous = custody.pending().unwrap();
    let draft = draft_of(
        &template(),
        5,
        key.public_key(),
        Some(&digest_bytes(&previous)),
    )
    .unwrap();
    let record_with = |code: &[u8; 32]| {
        let document =
            canonical_bytes(&document_at(&draft, &genesis, code, &path).unwrap()).unwrap();
        signed_record(&key.sign(&document).unwrap(), &document)
    };

    let mut wrong = code;
    wrong[0] ^= 1;
    let forged = record_with(&wrong);
    assert!(signature_verifies(&forged));
    assert_eq!(
        tree_form(&genesis.key(), &forged),
        Err(crate::auth_handler::did::FormError::NotInTree)
    );

    let genuine = record_with(&code);
    assert!(signature_verifies(&genuine));
    assert_eq!(tree_form(&genesis.key(), &genuine).unwrap().seq, 5);
}

#[test]
fn an_authorized_early_activation_signs_the_next_position_and_keeps_it() {
    let mut owner = Owner::new();
    owner.at(slot(5)).publish(5);
    let issuer = Issuer::default();
    let six = owner
        .custody
        .activate_early(6, &template(), &owner.authorization(6), &issuer)
        .unwrap();
    assert_eq!(owner.seq(&six), 6);
    assert!(signature_verifies(&six));
    assert_eq!(document(&six)["treeProof"]["code"], owner.code_text(6));
    owner.restart();
    assert_eq!(owner.custody.due(), Due::Position(6));
    assert_eq!(owner.custody.pending(), Some(six));
}

/// The record leaves only once 6 is stored as the highest activated: when
/// that write fails, nothing is returned and nothing changes.
#[test]
fn an_early_activation_that_cannot_be_stored_releases_nothing() {
    let mut owner = Owner::new();
    let five = owner.at(slot(5)).publish(5);
    if !set_read_only(owner.dir.path(), true) {
        eprintln!("skipped: this process writes to a read-only directory");
        return;
    }
    let early =
        owner
            .custody
            .activate_early(6, &template(), &owner.authorization(6), &Issuer::default());
    set_read_only(owner.dir.path(), false);
    assert!(matches!(early, Err(CustodyError::Io(_))), "{early:?}");
    assert_eq!(owner.custody.pending(), None);
    owner.restart();
    assert_eq!(owner.custody.due(), Due::Position(5));
    assert_eq!(owner.custody.published(), Some(five));
}

#[test]
fn an_authorization_holds_once_for_its_did_and_position() {
    let owner = Owner::new();
    owner.at(slot(5)).publish(5);
    let issuer = Issuer::default();
    let other_did = b"did:iiot:another:6".to_vec();
    for wrong in [other_did, owner.authorization(7)] {
        assert!(matches!(
            owner
                .custody
                .activate_early(6, &template(), &wrong, &issuer),
            Err(CustodyError::Unauthorized(6))
        ));
    }
    assert_eq!(owner.custody.due(), Due::Position(5));
    let authorization = owner.authorization(6);
    owner
        .custody
        .activate_early(6, &template(), &authorization, &issuer)
        .unwrap();
    assert!(matches!(
        owner
            .custody
            .activate_early(6, &template(), &authorization, &issuer),
        Err(CustodyError::NotNext(6))
    ));
    assert_eq!(issuer.shown.load(Ordering::SeqCst), 3);
}

#[test]
fn the_slot_of_an_early_position_brings_no_new_record() {
    let owner = Owner::new();
    owner.at(slot(5)).publish(5);
    let six = owner
        .custody
        .activate_early(6, &template(), &owner.authorization(6), &Issuer::default())
        .unwrap();
    owner.custody.mark_published(&six).unwrap();
    owner.at(slot(6));
    assert_eq!(owner.custody.prepare(6, &template()).unwrap(), six);
    owner.at(slot(7) - 1);
    assert_eq!(owner.custody.due(), Due::Position(6));
    assert!(owner.custody.prepare(7, &template()).is_err());
    owner.at(slot(7));
    let seven = owner.custody.prepare(7, &template()).unwrap();
    let form = tree_form(&owner.custody.genesis().key(), &seven).unwrap();
    assert_eq!((form.seq, form.prev), (7, Some(digest_bytes(&six))));
}

#[test]
fn an_authorization_never_reaches_a_skipped_lower_or_reserved_position() {
    let owner = Owner::new();
    owner.at(slot(3)).publish(3);
    owner.custody.skip(4).unwrap();
    let issuer = Issuer::default();
    for position in [4, 3, 2, RESERVED] {
        assert!(matches!(
            owner.custody.activate_early(
                position,
                &template(),
                &owner.authorization(position),
                &issuer
            ),
            Err(CustodyError::NotNext(p)) if p == position
        ));
    }
    assert_eq!(issuer.shown.load(Ordering::SeqCst), 0);
    // The next one past the skipped position is 5.
    let five = owner
        .custody
        .activate_early(5, &template(), &owner.authorization(5), &issuer)
        .unwrap();
    assert_eq!(owner.seq(&five), 5);
}

// ---- The file backend --------------------------------------------------------

#[test]
fn provisioning_gives_a_record_of_position_0_that_verifies() {
    let owner = Owner::new();
    let zero = owner.custody.pending().unwrap();
    assert_eq!(owner.seq(&zero), 0);
    assert!(signature_verifies(&zero));
    assert_eq!(document(&zero)["id"], owner.custody.did());
    assert_eq!(owner.custody.published(), None);
    assert_eq!(owner.custody.due(), Due::Position(0));
}

#[test]
fn provisioning_never_replaces_a_custody() {
    let owner = Owner::new();
    let again = FileCustody::provision_with(
        owner.dir.path().to_path_buf(),
        owner.custody.calendar(),
        &template(),
        clock(&owner.now),
    );
    assert!(matches!(again, Err(CustodyError::Exists(_))));
    let reopened =
        FileCustody::open_with(owner.dir.path().to_path_buf(), clock(&owner.now)).unwrap();
    assert_eq!(reopened.did(), owner.custody.did());
    assert_eq!(reopened.calendar(), owner.custody.calendar());
    assert_eq!(reopened.pending(), owner.custody.pending());
}

#[test]
fn publishing_erases_the_secrets_below_the_published_position() {
    let owner = Owner::new();
    owner.at(slot(3)).publish(3);
    for position in 0..3 {
        assert_eq!(owner.custody.secrets_of(position), None);
    }
    assert!(owner.custody.secrets_of(3).is_some());
    assert!(owner.custody.secrets_of(62).is_some());
}

#[test]
fn only_the_record_prepared_can_be_marked_published() {
    let owner = Owner::new();
    let zero = owner.custody.pending().unwrap();
    owner.custody.mark_published(&zero).unwrap();
    owner.custody.mark_published(&zero).unwrap();
    let three = owner.at(slot(3)).custody.prepare(3, &template()).unwrap();
    assert!(owner.custody.mark_published(b"not a record").is_err());
    owner.custody.mark_published(&three).unwrap();
    assert_eq!(owner.custody.published(), Some(three));
    // An older record, neither prepared nor published now.
    assert!(matches!(
        owner.custody.mark_published(&zero),
        Err(CustodyError::NotPrepared)
    ));
}

#[test]
fn a_skipped_position_stays_skipped_across_a_restart() {
    let mut owner = Owner::new();
    owner.at(slot(3)).publish(3);
    for position in [0, 3, RESERVED, 64] {
        assert!(matches!(
            owner.custody.skip(position),
            Err(CustodyError::NotSkippable(p)) if p == position
        ));
    }
    owner.custody.skip(4).unwrap();
    owner.at(slot(4));
    owner.restart();
    assert_eq!(owner.custody.due(), Due::Skipped(4));
    assert!(owner.custody.prepare(4, &template()).is_err());
    owner.at(slot(5));
    assert_eq!(owner.seq(&owner.publish(5)), 5);
}

#[test]
fn a_template_must_leave_the_filled_fields_to_the_custody() {
    let owner = Owner::new();
    owner.at(slot(1));
    let mut with_seq = template();
    with_seq["seq"] = json!(1);
    let mut with_key = template();
    with_key["verificationMethod"][0]["publicKeyJwk"]["pub"] = json!("AAAA");
    for (template, field) in [(with_seq, "seq"), (with_key, "pub")] {
        assert!(matches!(
            owner.custody.prepare(1, &template),
            Err(CustodyError::Template(f)) if f == field
        ));
    }
    assert_eq!(owner.seq(&owner.custody.pending().unwrap()), 0);
    assert_eq!(owner.custody.due(), Due::Position(1));
}

#[cfg(unix)]
#[test]
fn only_the_owner_can_read_the_custody() {
    use std::os::unix::fs::PermissionsExt;
    let owner = Owner::new();
    let mode = |name: &str| {
        std::fs::metadata(owner.dir.path().join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(""), 0o700);
    for file in ["tree", "secrets", "state"] {
        assert_eq!(mode(file), 0o600, "{file}");
    }
}

/// The verifier runs without the custody's lock, so it may read the
/// custody itself.
#[test]
fn the_verifier_may_call_back_into_the_custody() {
    struct Asking<'a>(&'a FileCustody);
    impl ActivationVerifier for Asking<'_> {
        fn verify(&self, _: &str, position: u64, _: &[u8]) -> bool {
            self.0.due() == Due::Position(position - 1)
        }
    }
    let owner = Owner::new();
    owner.at(slot(2)).publish(2);
    let three = owner
        .custody
        .activate_early(3, &template(), b"", &Asking(&owner.custody))
        .unwrap();
    assert_eq!(owner.seq(&three), 3);
}
