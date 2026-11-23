//! The owner's custody of a DID's tree: the secrets of its positions, which
//! position may be signed and when, and the records signed so far.
//!
//! Positions fall due on a calendar fixed at provisioning: from a start `T`,
//! one every interval `D`, the position due at `now` is
//! `floor((now - T) / D)`. Position 0 is signed at provisioning, since the
//! genesis commits its body, and is due from then until `T + D`, also
//! before `T`. A position is signed once, when it is due and
//! above every position activated before, and it is written durably as the
//! highest activated position before its record leaves the backend: a
//! restart, a clock set back or a request never reopen a lower position.
//! Before its slot only the next position can be activated, with an
//! authorization that the application's verifier accepts; the position due
//! is then the greater of the calendar's and the highest activated, so the
//! one after it falls due at its normal boundary.
//!
//! The application writes one template of the document: every field except
//! `id`, `seq`, `prev`, `treeProof` and the `pub` of its key, with the
//! placeholder in place of the DID. The backend fills them in and signs, so
//! a code never passes through the application before its record does.
//!
//! Replicas need none of this: a record proves its key against the DID.

mod file;

#[cfg(test)]
mod acceptance_tests;

use std::io;
use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::auth_handler::did::{
    encode_suffix, id_of, parse_canonical, replace_did, FormError, PLACEHOLDER,
};
use crate::auth_handler::owner::OwnerError;
use crate::auth_handler::tree::{Hash, PROOF, RESERVED};

pub use file::FileCustody;

/// When positions fall due, in milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calendar {
    start: u64,
    interval: u64,
}

impl Calendar {
    /// Position 0 from `start`, then one position every `interval`; `None`
    /// for an empty interval.
    pub fn new(start: u64, interval: u64) -> Option<Self> {
        (interval > 0).then_some(Self { start, interval })
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// The slot holding `now`, `None` before the start. A boundary belongs
    /// to the slot it opens.
    pub fn index(&self, now: u64) -> Option<u64> {
        now.checked_sub(self.start)
            .map(|elapsed| elapsed / self.interval)
    }
}

/// What can be signed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// This position: a new record if it is above the highest activated,
    /// otherwise the record already signed for it.
    Position(u64),
    /// The position due was skipped for good: nothing new until the next
    /// one falls due or is activated early.
    Skipped(u64),
    /// The calendar is past the last position that signs: the DID can
    /// rotate no more.
    Exhausted,
}

impl std::fmt::Display for Due {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Due::Position(position) => write!(f, "position {position} is due"),
            Due::Skipped(position) => write!(f, "position {position} is due but skipped"),
            Due::Exhausted => write!(f, "the tree is exhausted"),
        }
    }
}

/// What a backend has activated: the highest position, and the positions
/// skipped for good. Every backend enforces the same rules on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    highest: u64,
    /// Bit `p` is set when position `p` is skipped.
    skipped: u64,
}

impl Activation {
    /// Position 0 activated and nothing skipped: the state after
    /// provisioning.
    pub fn first() -> Self {
        Self {
            highest: 0,
            skipped: 0,
        }
    }

    pub(crate) fn from_parts(highest: u64, skipped: u64) -> Option<Self> {
        let up_to_highest = (1u64 << (highest.min(RESERVED - 1) + 1)) - 1;
        (highest < RESERVED && skipped >> RESERVED == 0 && skipped & up_to_highest == 0)
            .then_some(Self { highest, skipped })
    }

    pub(crate) fn skipped_bits(&self) -> u64 {
        self.skipped
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }

    pub fn is_skipped(&self, position: u64) -> bool {
        position < RESERVED && (self.skipped >> position) & 1 == 1
    }

    /// The position the calendar or an early activation has reached,
    /// whichever is greater.
    fn reached(&self, calendar: &Calendar, now: u64) -> u64 {
        calendar
            .index(now)
            .map_or(self.highest, |index| index.max(self.highest))
    }

    /// What can be signed at `now`.
    pub fn due(&self, calendar: &Calendar, now: u64) -> Due {
        match self.reached(calendar, now) {
            at if at >= RESERVED => Due::Exhausted,
            at if self.is_skipped(at) => Due::Skipped(at),
            at => Due::Position(at),
        }
    }

    /// The one position an authorization can activate at `now`: the first
    /// above the position reached that is not skipped, never the reserved
    /// one.
    pub fn next_early(&self, calendar: &Calendar, now: u64) -> Option<u64> {
        (self.reached(calendar, now).saturating_add(1)..RESERVED)
            .find(|position| !self.is_skipped(*position))
    }

    /// `position` activated: it is above the highest, as `due` or
    /// `next_early` gave it.
    pub(crate) fn activate(self, position: u64) -> Self {
        Self {
            highest: position,
            ..self
        }
    }

    /// `position` skipped for good: one above the highest activated and
    /// below the reserved one.
    pub(crate) fn skip(self, position: u64) -> Option<Self> {
        // Lazily: the shift overflows beyond the tree.
        (position > self.highest && position < RESERVED).then(|| Self {
            skipped: self.skipped | 1 << position,
            ..self
        })
    }
}

/// Checks an authorization to activate a position before its slot. The
/// application supplies it: the authorization is signed above the DHT, by
/// the issuer that certifies the new key, and nodes never see it.
pub trait ActivationVerifier {
    /// Whether `authorization` lets `did` activate `position` now, once.
    fn verify(&self, did: &str, position: u64, authorization: &[u8]) -> bool;
}

/// The owner's custody of one DID's tree.
pub trait Custody {
    /// The DID: `did:iiot:` and the base64url of the SHA-256 of its genesis.
    fn did(&self) -> String;

    /// What can be signed now.
    fn due(&self) -> Due;

    /// The record of `position` from `template`, if `position` is due. Above
    /// the highest activated position it is a new record: the position is
    /// stored durably as the highest activated before the record is
    /// returned, and the record is kept as prepared. At the highest
    /// activated position it is the record already signed, the same bytes,
    /// if `template` is the one it was signed from; another template is
    /// `AlreadySigned`.
    fn prepare(&self, position: u64, template: &Value) -> Result<Vec<u8>, CustodyError>;

    /// The record of `position` before its slot, as `prepare` signs it, if
    /// `position` is the next one that can be activated and `verifier`
    /// accepts `authorization` for this DID and `position`. The verifier is
    /// consulted before anything is signed. Never a lower position, a
    /// skipped one or the reserved one, and never the same position twice.
    fn activate_early(
        &self,
        position: u64,
        template: &Value,
        authorization: &[u8],
        verifier: &dyn ActivationVerifier,
    ) -> Result<Vec<u8>, CustodyError>;

    /// Never sign `position`, nor release its code, across restarts: its key
    /// is known to have leaked. Only a position above the highest
    /// activated.
    fn skip(&self, position: u64) -> Result<(), CustodyError>;

    /// The record prepared and not yet published, if any.
    fn pending(&self) -> Option<Vec<u8>>;

    /// The record published last, which republication sends again.
    fn published(&self) -> Option<Vec<u8>>;

    /// `record`, the one prepared, is published: it replaces the published
    /// record, and the secrets of the positions below it are no longer
    /// needed.
    fn mark_published(&self, record: &[u8]) -> Result<(), CustodyError>;
}

#[derive(Debug, Error)]
pub enum CustodyError {
    #[error("position {requested} cannot be signed now: {due}")]
    NotDue { requested: u64, due: Due },
    #[error("position {0} is already signed from another template")]
    AlreadySigned(u64),
    #[error("position {0} is not the next position that can be activated early")]
    NotNext(u64),
    #[error("the authorization does not allow position {0}")]
    Unauthorized(u64),
    #[error("position {0} cannot be skipped: it is activated, reserved or beyond the tree")]
    NotSkippable(u64),
    #[error("the record is not the one prepared")]
    NotPrepared,
    #[error("the template must be an object without `{0}`: the custody fills it in")]
    Template(&'static str),
    #[error("{0} already holds a custody")]
    Exists(PathBuf),
    #[error("another instance holds the custody in {0}")]
    Busy(PathBuf),
    #[error("the custody files are damaged: {0}")]
    Damaged(&'static str),
    #[error(transparent)]
    Form(#[from] FormError),
    #[error(transparent)]
    Owner(#[from] OwnerError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The key of the document: `verificationMethod[0].publicKeyJwk`.
fn jwk_of(document: &mut Value) -> Option<&mut Map<String, Value>> {
    document
        .get_mut("verificationMethod")?
        .get_mut(0)?
        .get_mut("publicKeyJwk")?
        .as_object_mut()
}

/// The draft body of `position` from `template`: its position, the hash of
/// the record before it and its public key filled in.
pub(crate) fn draft_of(
    template: &Value,
    position: u64,
    public_key: &[u8],
    prev: Option<&Hash>,
) -> Result<Value, CustodyError> {
    let mut draft = template.clone();
    let map = draft
        .as_object_mut()
        .ok_or(CustodyError::Template("an object"))?;
    for filled in ["id", "seq", "prev", PROOF] {
        if map.contains_key(filled) {
            return Err(CustodyError::Template(filled));
        }
    }
    map.insert("seq".into(), position.into());
    if let Some(prev) = prev {
        map.insert("prev".into(), encode_suffix(prev).into());
    }
    let jwk = jwk_of(&mut draft).ok_or(CustodyError::Template("publicKeyJwk"))?;
    if jwk.contains_key("pub") {
        return Err(CustodyError::Template("pub"));
    }
    jwk.insert("pub".into(), URL_SAFE_NO_PAD.encode(public_key).into());
    Ok(draft)
}

/// The template a document was signed from: without what the backend
/// fills in, and with the placeholder in place of the DID.
pub(crate) fn template_of(document: &[u8]) -> Result<Value, CustodyError> {
    let mut template = parse_canonical(document)?;
    let did = id_of(&template)?.0.to_owned();
    if let Some(map) = template.as_object_mut() {
        for filled in ["id", "seq", "prev", PROOF] {
            map.remove(filled);
        }
    }
    if let Some(jwk) = jwk_of(&mut template) {
        jwk.remove("pub");
    }
    replace_did(&mut template, &did, PLACEHOLDER);
    Ok(template)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400_000;

    fn calendar() -> Calendar {
        Calendar::new(1_000 * DAY, 7 * DAY).unwrap()
    }

    /// The start of slot `index`.
    fn slot(index: u64) -> u64 {
        1_000 * DAY + index * 7 * DAY
    }

    #[test]
    fn a_calendar_needs_an_interval_and_starts_at_its_start() {
        assert_eq!(Calendar::new(5, 0), None);
        let calendar = calendar();
        assert_eq!(calendar.index(slot(0) - 1), None);
        assert_eq!(calendar.index(slot(0)), Some(0));
        assert_eq!(calendar.index(slot(4) - 1), Some(3));
        assert_eq!(calendar.index(slot(4)), Some(4));
    }

    #[test]
    fn the_position_due_is_the_calendars_or_the_highest_activated() {
        let calendar = calendar();
        let activation = Activation::first();
        assert_eq!(activation.due(&calendar, 0), Due::Position(0));
        assert_eq!(activation.due(&calendar, slot(3)), Due::Position(3));
        let activation = activation.activate(5);
        assert_eq!(activation.due(&calendar, slot(3)), Due::Position(5));
        assert_eq!(activation.due(&calendar, slot(6)), Due::Position(6));
        assert_eq!(activation.due(&calendar, slot(62)), Due::Position(62));
        assert_eq!(activation.due(&calendar, slot(63)), Due::Exhausted);
        assert_eq!(activation.due(&calendar, u64::MAX), Due::Exhausted);
    }

    #[test]
    fn a_skipped_position_is_never_due_and_never_next() {
        let calendar = calendar();
        let activation = Activation::first().activate(3);
        assert_eq!(activation.skip(3), None);
        assert_eq!(activation.skip(RESERVED), None);
        let activation = activation.skip(4).unwrap().skip(5).unwrap();
        assert_eq!(activation.due(&calendar, slot(4)), Due::Skipped(4));
        assert_eq!(activation.next_early(&calendar, slot(3)), Some(6));
        assert_eq!(activation.next_early(&calendar, slot(4)), Some(6));
        assert_eq!(activation.due(&calendar, slot(6)), Due::Position(6));
    }

    #[test]
    fn nothing_is_next_after_the_last_position_that_signs() {
        let calendar = calendar();
        let activation = Activation::first().activate(61);
        assert_eq!(activation.next_early(&calendar, slot(61)), Some(62));
        assert_eq!(activation.activate(62).next_early(&calendar, 0), None);
        assert_eq!(
            Activation::first()
                .skip(62)
                .unwrap()
                .next_early(&calendar, slot(61)),
            None
        );
    }

    #[test]
    fn activation_read_back_must_be_consistent() {
        assert!(Activation::from_parts(5, 1 << 7).is_some());
        assert_eq!(Activation::from_parts(RESERVED, 0), None);
        assert_eq!(Activation::from_parts(5, 1 << 3), None);
        assert_eq!(Activation::from_parts(5, 1 << RESERVED), None);
    }

    #[test]
    fn a_template_holds_nothing_the_custody_fills_in() {
        let template = serde_json::json!({
            "verificationMethod": [{"publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-65"}}],
        });
        let draft = draft_of(&template, 5, &[1, 2, 3], Some(&[7; 32])).unwrap();
        assert_eq!(draft["seq"], 5);
        assert_eq!(draft["prev"], encode_suffix(&[7; 32]));
        assert_eq!(
            draft["verificationMethod"][0]["publicKeyJwk"]["pub"],
            "AQID"
        );
        assert!(matches!(
            draft_of(&draft, 5, &[1], None),
            Err(CustodyError::Template("seq"))
        ));
        assert!(matches!(
            draft_of(&serde_json::json!({}), 5, &[1], None),
            Err(CustodyError::Template("publicKeyJwk"))
        ));
        assert!(matches!(
            draft_of(&serde_json::json!([]), 5, &[1], None),
            Err(CustodyError::Template("an object"))
        ));
    }
}
