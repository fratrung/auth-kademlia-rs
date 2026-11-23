//! The custody of a DID's tree in local files.
//!
//! A directory holds three files. `tree` is public: the calendar, the hash
//! of the initial body and the 64 leaves. `secrets` holds the seed and the
//! code of every position. `state` holds the highest activated position,
//! the skipped ones, and the records prepared and published. Each file is
//! replaced atomically and flushed to the device before a call returns, and
//! only the owner of the process can read them. Whoever can read `secrets`
//! holds every future key and code of the DID: keep and back it up as a
//! private key.
//!
//! A position's secrets are read only to sign it. Once a record is
//! published, the secrets of the positions below it are erased, since no
//! call signs below the highest activated position again.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aws_lc_rs::rand;
use serde_json::Value;

use crate::auth_handler::did::document_of;
use crate::auth_handler::owner::{sign_position, OwnerError, SEED_LEN};
use crate::auth_handler::tree::{
    draft_body_hash, leaf_hash, tree_form, Genesis, Hash, Tree, CODE_LEN, POSITIONS,
};
use crate::crypto::mldsa::MlDsa65KeyPair;
use crate::durable::write_durably;
use crate::storage::{system_clock, Clock};
use crate::utils::{digest_bytes, ID_LEN};

use super::{
    draft_of, template_of, Activation, ActivationVerifier, Calendar, Custody, CustodyError, Due,
};

const MAGIC: &[u8; 4] = b"AKCU";
const VERSION: u8 = 1;
const TREE: (&str, u8) = ("tree", 1);
const SECRETS: (&str, u8) = ("secrets", 2);
const STATE: (&str, u8) = ("state", 3);
const HEADER_LEN: usize = MAGIC.len() + 2;
const SECRET_LEN: usize = SEED_LEN + CODE_LEN;

/// The seed and the code of every position.
struct Secrets(Vec<[u8; SECRET_LEN]>);

impl Secrets {
    fn generate() -> Result<Self, CustodyError> {
        let mut secrets = vec![[0u8; SECRET_LEN]; POSITIONS];
        for secret in &mut secrets {
            rand::fill(secret).map_err(|_| OwnerError::Random)?;
        }
        Ok(Self(secrets))
    }

    /// The seed and code of `position`, unless erased.
    fn of(&self, position: u64) -> Result<([u8; SEED_LEN], [u8; CODE_LEN]), CustodyError> {
        let secret = usize::try_from(position)
            .ok()
            .and_then(|index| self.0.get(index))
            .filter(|secret| secret.iter().any(|byte| *byte != 0))
            .ok_or(CustodyError::Damaged(
                "the secrets of the position are erased",
            ))?;
        let (seed, code) = secret.split_at(SEED_LEN);
        Ok((
            seed.try_into()
                .map_err(|_| CustodyError::Damaged("secrets"))?,
            code.try_into()
                .map_err(|_| CustodyError::Damaged("secrets"))?,
        ))
    }

    /// Erase the secrets of the positions below `position`; whether any was
    /// left.
    fn erase_below(&mut self, position: u64) -> bool {
        let below = usize::try_from(position)
            .unwrap_or(POSITIONS)
            .min(POSITIONS);
        let mut erased = false;
        for secret in &mut self.0[..below] {
            if secret.iter().any(|byte| *byte != 0) {
                *secret = [0; SECRET_LEN];
                erased = true;
            }
        }
        erased
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = header(SECRETS.1);
        self.0
            .iter()
            .for_each(|secret| bytes.extend_from_slice(secret));
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let body = body_of(bytes, SECRETS.1)?;
        (body.len() == POSITIONS * SECRET_LEN).then(|| {
            Self(
                body.chunks_exact(SECRET_LEN)
                    .filter_map(|secret| secret.try_into().ok())
                    .collect(),
            )
        })
    }
}

/// What is activated, and the records signed and not yet replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    activation: Activation,
    pending: Option<Vec<u8>>,
    published: Option<Vec<u8>>,
}

impl State {
    /// `| highest | skipped | pending | published |`: two u64, then each
    /// record as a u32 length and its bytes, length 0 for none.
    fn encode(&self) -> Vec<u8> {
        let mut bytes = header(STATE.1);
        bytes.extend_from_slice(&self.activation.highest().to_be_bytes());
        bytes.extend_from_slice(&self.activation.skipped_bits().to_be_bytes());
        for record in [&self.pending, &self.published] {
            let record = record.as_deref().unwrap_or_default();
            let len = u32::try_from(record.len()).unwrap_or(u32::MAX);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(record);
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(body_of(bytes, STATE.1)?);
        let activation = Activation::from_parts(reader.u64()?, reader.u64()?)?;
        let mut record = || -> Option<Option<Vec<u8>>> {
            let len = usize::try_from(u32::from_be_bytes(reader.take(4)?.try_into().ok()?)).ok()?;
            if len == 0 {
                return Some(None);
            }
            Some(Some(reader.take(len)?.to_vec()))
        };
        let (pending, published) = (record()?, record()?);
        reader.0.is_empty().then_some(Self {
            activation,
            pending,
            published,
        })
    }

    /// The record signed at the highest activated position: the one
    /// prepared, or the one published.
    fn at_highest(&self, key: &Hash) -> Option<&Vec<u8>> {
        let highest = self.activation.highest();
        [&self.pending, &self.published]
            .into_iter()
            .flatten()
            .find(|record| tree_form(key, record).is_ok_and(|form| form.seq == highest))
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(taken)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
}

fn header(kind: u8) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(VERSION);
    bytes.push(kind);
    bytes
}

fn body_of(bytes: &[u8], kind: u8) -> Option<&[u8]> {
    let (head, body) = bytes.split_at_checked(HEADER_LEN)?;
    (head == header(kind).as_slice()).then_some(body)
}

/// `| start | interval | initial body hash | the 64 leaves |`
fn encode_tree(calendar: &Calendar, initial_body_hash: &Hash, leaves: &[Hash]) -> Vec<u8> {
    let mut bytes = header(TREE.1);
    bytes.extend_from_slice(&calendar.start().to_be_bytes());
    bytes.extend_from_slice(&calendar.interval().to_be_bytes());
    bytes.extend_from_slice(initial_body_hash);
    leaves.iter().for_each(|leaf| bytes.extend_from_slice(leaf));
    bytes
}

fn decode_tree(bytes: &[u8]) -> Option<(Calendar, Genesis, Tree)> {
    let mut reader = Reader(body_of(bytes, TREE.1)?);
    let calendar = Calendar::new(reader.u64()?, reader.u64()?)?;
    let initial_body_hash: Hash = reader.take(ID_LEN)?.try_into().ok()?;
    let leaves: Vec<Hash> = reader
        .0
        .chunks_exact(ID_LEN)
        .filter_map(|leaf| leaf.try_into().ok())
        .collect();
    if reader.0.len() != POSITIONS * ID_LEN {
        return None;
    }
    let tree = Tree::new(&leaves)?;
    let genesis = Genesis {
        initial_body_hash,
        root: tree.root(),
    };
    Some((calendar, genesis, tree))
}

/// The custody of one DID in a directory.
pub struct FileCustody {
    dir: PathBuf,
    calendar: Calendar,
    genesis: Genesis,
    tree: Tree,
    clock: Clock,
    state: Mutex<State>,
}

impl FileCustody {
    /// A new DID in `dir`, created if missing: fresh seeds and codes, the
    /// genesis of `template` at position 0, and the record of position 0,
    /// prepared. `Exists` if `dir` already holds a custody.
    pub fn provision(
        dir: impl Into<PathBuf>,
        calendar: Calendar,
        template: &Value,
    ) -> Result<Self, CustodyError> {
        Self::provision_with(dir.into(), calendar, template, Arc::new(system_clock))
    }

    /// The custody kept in `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CustodyError> {
        Self::open_with(dir.into(), Arc::new(system_clock))
    }

    pub(crate) fn provision_with(
        dir: PathBuf,
        calendar: Calendar,
        template: &Value,
        clock: Clock,
    ) -> Result<Self, CustodyError> {
        create_private_dir(&dir)?;
        if dir.join(STATE.0).exists() {
            return Err(CustodyError::Exists(dir));
        }
        let secrets = Secrets::generate()?;
        let mut keys = Vec::with_capacity(POSITIONS);
        let mut leaves = Vec::with_capacity(POSITIONS);
        for position in 0..POSITIONS as u32 {
            let (seed, code) = secrets.of(u64::from(position))?;
            let key = MlDsa65KeyPair::from_seed(&seed).map_err(OwnerError::from)?;
            leaves.push(leaf_hash(position, key.public_key(), &code));
            keys.push(key);
        }
        let tree = Tree::new(&leaves).ok_or(CustodyError::Damaged("tree"))?;
        let (_, code) = secrets.of(0)?;
        let draft = draft_of(template, 0, keys[0].public_key(), None)?;
        let genesis = Genesis {
            initial_body_hash: draft_body_hash(&draft)?,
            root: tree.root(),
        };
        let path = tree.path(0).ok_or(CustodyError::Damaged("tree"))?;
        let record = sign_position(&genesis, &draft, &keys[0], &code, &path)?;
        let state = State {
            activation: Activation::first(),
            pending: Some(record),
            published: None,
        };
        // The state last: until it exists, provisioning can start again.
        write_file(&dir, SECRETS.0, &secrets.encode())?;
        write_file(
            &dir,
            TREE.0,
            &encode_tree(&calendar, &genesis.initial_body_hash, &leaves),
        )?;
        write_file(&dir, STATE.0, &state.encode())?;
        Ok(Self {
            dir,
            calendar,
            genesis,
            tree,
            clock,
            state: Mutex::new(state),
        })
    }

    pub(crate) fn open_with(dir: PathBuf, clock: Clock) -> Result<Self, CustodyError> {
        let (calendar, genesis, tree) =
            decode_tree(&fs::read(dir.join(TREE.0))?).ok_or(CustodyError::Damaged("tree"))?;
        let state =
            State::decode(&fs::read(dir.join(STATE.0))?).ok_or(CustodyError::Damaged("state"))?;
        let custody = Self {
            dir,
            calendar,
            genesis,
            tree,
            clock,
            state: Mutex::new(state),
        };
        let key = custody.genesis.key();
        let state = custody.lock();
        let records_hold = state
            .pending
            .iter()
            .chain(&state.published)
            .all(|record| tree_form(&key, record).is_ok());
        if !records_hold || state.at_highest(&key).is_none() {
            return Err(CustodyError::Damaged("state"));
        }
        drop(state);
        Ok(custody)
    }

    pub fn calendar(&self) -> Calendar {
        self.calendar
    }

    pub fn genesis(&self) -> Genesis {
        self.genesis
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Memory changes only after the files: a panic leaves it whole.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read_secrets(&self) -> Result<Secrets, CustodyError> {
        Secrets::decode(&fs::read(self.dir.join(SECRETS.0))?)
            .ok_or(CustodyError::Damaged("secrets"))
    }

    /// The new record of `position`, above the highest activated, written
    /// as prepared with `position` as the highest activated before it is
    /// returned.
    fn sign_new(
        &self,
        state: &mut State,
        position: u64,
        template: &Value,
    ) -> Result<Vec<u8>, CustodyError> {
        let (seed, code) = self.read_secrets()?.of(position)?;
        let key = MlDsa65KeyPair::from_seed(&seed).map_err(OwnerError::from)?;
        // `prev` names the record published last; before any, the one
        // prepared at provisioning.
        let previous = state
            .published
            .as_ref()
            .or(state.pending.as_ref())
            .ok_or(CustodyError::Damaged("state"))?;
        let draft = draft_of(
            template,
            position,
            key.public_key(),
            Some(&digest_bytes(previous)),
        )?;
        let path = u32::try_from(position)
            .ok()
            .and_then(|index| self.tree.path(index))
            .ok_or(CustodyError::Damaged("tree"))?;
        let record = sign_position(&self.genesis, &draft, &key, &code, &path)?;
        self.commit(
            state,
            State {
                activation: state.activation.activate(position),
                pending: Some(record.clone()),
                published: state.published.clone(),
            },
        )?;
        Ok(record)
    }

    fn commit(&self, state: &mut State, next: State) -> Result<(), CustodyError> {
        write_file(&self.dir, STATE.0, &next.encode())?;
        *state = next;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path_of(
        &self,
        position: u32,
    ) -> Option<[u8; crate::auth_handler::tree::PATH_LEN]> {
        self.tree.path(position)
    }

    #[cfg(test)]
    pub(crate) fn secrets_of(&self, position: u64) -> Option<([u8; SEED_LEN], [u8; CODE_LEN])> {
        self.read_secrets().ok()?.of(position).ok()
    }
}

impl Custody for FileCustody {
    fn did(&self) -> String {
        self.genesis.did()
    }

    fn due(&self) -> Due {
        self.lock().activation.due(&self.calendar, (self.clock)())
    }

    fn prepare(&self, position: u64, template: &Value) -> Result<Vec<u8>, CustodyError> {
        let mut state = self.lock();
        let due = state.activation.due(&self.calendar, (self.clock)());
        if due != Due::Position(position) {
            return Err(CustodyError::NotDue {
                requested: position,
                due,
            });
        }
        if position > state.activation.highest() {
            return self.sign_new(&mut state, position, template);
        }
        draft_of(template, position, &[], None)?;
        let saved = state
            .at_highest(&self.genesis.key())
            .ok_or(CustodyError::Damaged("state"))?;
        if template_of(document_of(saved)?)? != *template {
            return Err(CustodyError::AlreadySigned(position));
        }
        Ok(saved.clone())
    }

    fn activate_early(
        &self,
        position: u64,
        template: &Value,
        authorization: &[u8],
        verifier: &dyn ActivationVerifier,
    ) -> Result<Vec<u8>, CustodyError> {
        let next = |state: &State| state.activation.next_early(&self.calendar, (self.clock)());
        if next(&self.lock()) != Some(position) {
            return Err(CustodyError::NotNext(position));
        }
        // Without the lock: the verifier may call back into the custody.
        if !verifier.verify(&self.did(), position, authorization) {
            return Err(CustodyError::Unauthorized(position));
        }
        let mut state = self.lock();
        if next(&state) != Some(position) {
            return Err(CustodyError::NotNext(position));
        }
        self.sign_new(&mut state, position, template)
    }

    fn skip(&self, position: u64) -> Result<(), CustodyError> {
        let mut state = self.lock();
        let activation = state
            .activation
            .skip(position)
            .ok_or(CustodyError::NotSkippable(position))?;
        let next = State {
            activation,
            ..state.clone()
        };
        self.commit(&mut state, next)
    }

    fn pending(&self) -> Option<Vec<u8>> {
        self.lock().pending.clone()
    }

    fn published(&self) -> Option<Vec<u8>> {
        self.lock().published.clone()
    }

    fn mark_published(&self, record: &[u8]) -> Result<(), CustodyError> {
        let mut state = self.lock();
        let position = tree_form(&self.genesis.key(), record)?.seq;
        if state.published.as_deref() != Some(record) {
            if state.pending.as_deref() != Some(record) {
                return Err(CustodyError::NotPrepared);
            }
            let next = State {
                activation: state.activation,
                pending: None,
                published: Some(record.to_vec()),
            };
            self.commit(&mut state, next)?;
        }
        // Also when called again: an erasure that failed is retried.
        let mut secrets = self.read_secrets()?;
        if secrets.erase_below(position) {
            write_file(&self.dir, SECRETS.0, &secrets.encode())?;
        }
        Ok(())
    }
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), CustodyError> {
    let temporary = dir.join(format!("{name}.tmp"));
    Ok(write_durably(
        dir,
        &temporary,
        &dir.join(name),
        bytes,
        true,
    )?)
}

fn create_private_dir(dir: &Path) -> Result<(), CustodyError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    Ok(builder.create(dir)?)
}
