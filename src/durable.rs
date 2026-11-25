//! The files of a persistent replica store, one per key.
//!
//! A file holds a record with its expiry or, once the record has expired,
//! the highest position accepted for the key and until when it is
//! remembered. It is replaced by writing a temporary file, flushing it to
//! the device, renaming it over the old one and flushing the directory. On
//! a journaling file system such as ext4 a power cut then leaves the old
//! file or the new one, never a mix of them.
//!
//! A record file is written when its record changes, never to renew it.
//! The expiries that renewals moved later are kept apart, all in one file,
//! `renewals`, each with the SHA-256 of the record it renews: a renewal
//! rewrites a few bytes per record instead of every record, and applies
//! only to the exact record it renewed, never to one written after it.
//!
//! Each file ends with the SHA-256 of the bytes before it. A file whose
//! bytes the device changed, such as a flipped bit on an SD card, is not
//! loaded, as a file that cannot be read: the store would otherwise serve,
//! and keep against valid copies, a record whose signature no longer
//! verifies, or remember a position that was never accepted. A damaged
//! file of renewals is ignored, and the records keep the expiries of their
//! own files. A writer that can change the files can also recompute the
//! hash: it is no defence against the host.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::utils::{digest_bytes, ID_LEN};

const MAGIC: &[u8; 4] = b"AKRS";
const VERSION: u8 = 2;
const RECORD: u8 = 1;
const MARKER: u8 = 2;
const RENEWALS: u8 = 3;
const HEADER_LEN: usize = MAGIC.len() + 2;
const CHECKSUM_LEN: usize = ID_LEN;
const EXTENSION: &str = "rec";
const TEMPORARY: &str = "tmp";
const RENEWALS_FILE: &str = "renewals";

/// What a file holds for its key. Times are milliseconds since the Unix
/// epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    /// A record, the expiry its file holds, and the later expiry a renewal
    /// of this exact record gave it, if any.
    Record {
        value: Vec<u8>,
        expires: u64,
        renewed: Option<u64>,
    },
    Marker {
        seq: u64,
        until: u64,
    },
}

/// The renewals of a file of renewals: by key, the SHA-256 of the record
/// each renews and its later expiry.
type Renewed = HashMap<Vec<u8>, ([u8; ID_LEN], u64)>;

/// The bytes of one renewal of a key of `ID_LEN` bytes in the file of
/// renewals: the length of the key, the key, the SHA-256 of the record and
/// the expiry.
const RENEWAL_LEN: usize = 2 + ID_LEN + ID_LEN + 8;

/// The file of renewals as it is built, one renewal at a time, for
/// `write_renewals`: the renewals go straight into the bytes of the file,
/// sized once, rather than into a list copied into them afterwards.
#[derive(Debug)]
pub(crate) struct Renewals {
    bytes: Vec<u8>,
    count: usize,
}

impl Renewals {
    /// Room for `entries` renewals of keys of `ID_LEN` bytes and the
    /// SHA-256 that ends the file, in one allocation.
    pub(crate) fn with_capacity(entries: usize) -> Self {
        let mut bytes = Vec::with_capacity(HEADER_LEN + entries * RENEWAL_LEN + CHECKSUM_LEN);
        bytes.extend_from_slice(&header(RENEWALS));
        Self { bytes, count: 0 }
    }

    /// A later expiry for the record of `key` whose SHA-256 is `record`.
    pub(crate) fn push(
        &mut self,
        key: &[u8],
        record: &[u8; ID_LEN],
        expires: u64,
    ) -> io::Result<()> {
        let len = u16::try_from(key.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "key too long"))?;
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(key);
        self.bytes.extend_from_slice(record);
        self.bytes.extend_from_slice(&expires.to_be_bytes());
        self.count += 1;
        Ok(())
    }

    /// How many renewals it holds.
    pub(crate) fn count(&self) -> usize {
        self.count
    }
}

/// The directory of a persistent store.
#[derive(Debug)]
pub(crate) struct DurableDir {
    dir: PathBuf,
}

impl DurableDir {
    /// The directory `dir`, created if missing.
    pub(crate) fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, key: &[u8], extension: &str) -> PathBuf {
        self.dir.join(format!("{}.{extension}", hex::encode(key)))
    }

    /// Make the file of `key` hold the record `value`, which expires at
    /// `expires`, durably, before returning.
    pub(crate) fn write_record(&self, key: &[u8], value: &[u8], expires: u64) -> io::Result<()> {
        let mut bytes = header(RECORD);
        bytes.extend_from_slice(&expires.to_be_bytes());
        bytes.extend_from_slice(value);
        self.replace(key, &bytes)
    }

    /// Make the file of `key` hold the marker of position `seq`, remembered
    /// until `until`, durably, before returning.
    pub(crate) fn write_marker(&self, key: &[u8], seq: u64, until: u64) -> io::Result<()> {
        let mut bytes = header(MARKER);
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&until.to_be_bytes());
        self.replace(key, &bytes)
    }

    fn replace(&self, key: &[u8], bytes: &[u8]) -> io::Result<()> {
        write_durably(
            &self.dir,
            &self.path(key, TEMPORARY),
            &self.path(key, EXTENSION),
            &seal(bytes),
            false,
        )
    }

    /// Make the file of renewals hold `renewals`, and only them, durably,
    /// before returning.
    pub(crate) fn write_renewals(&self, renewals: Renewals) -> io::Result<()> {
        let mut bytes = renewals.bytes;
        let checksum = digest_bytes(&bytes);
        bytes.extend_from_slice(&checksum);
        let target = self.dir.join(RENEWALS_FILE);
        let temporary = target.with_extension(TEMPORARY);
        write_durably(&self.dir, &temporary, &target, &bytes, false)
    }

    /// The renewals the file of renewals holds, by key; none if it is
    /// missing, or damaged, which is logged.
    fn renewals(&self) -> Renewed {
        let path = self.dir.join(RENEWALS_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return HashMap::new(),
            Err(error) => {
                log::warn!("storage: cannot read {}: {error}", path.display());
                return HashMap::new();
            }
        };
        decode_renewals(&bytes).unwrap_or_else(|| {
            log::warn!(
                "storage: {} is damaged, records keep the expiries of their files",
                path.display()
            );
            HashMap::new()
        })
    }

    /// Remove the file of `key`, if any.
    pub(crate) fn remove(&self, key: &[u8]) -> io::Result<()> {
        match fs::remove_file(self.path(key, EXTENSION)) {
            Ok(()) => sync_dir(&self.dir),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Every key and what its file holds, a record with the later expiry a
    /// renewal of its exact bytes gave it. A temporary file is what a crash
    /// left before its rename, and is removed; a file that cannot be read
    /// is logged and left where it is.
    pub(crate) fn load(&self) -> io::Result<Vec<(Vec<u8>, Stored)>> {
        let renewals = self.renewals();
        let mut entries = vec![];
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let extension = path.extension().and_then(|extension| extension.to_str());
            if extension == Some(TEMPORARY) {
                fs::remove_file(&path)?;
                continue;
            }
            if extension != Some(EXTENSION) {
                continue;
            }
            let key = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| hex::decode(stem).ok());
            match (key, fs::read(&path).ok().as_deref().and_then(decode)) {
                (Some(key), Some(Stored::Record { value, expires, .. })) => {
                    let renewed = renewals
                        .get(&key)
                        .filter(|(record, later)| {
                            *later > expires && *record == digest_bytes(&value)
                        })
                        .map(|(_, later)| *later);
                    let record = Stored::Record {
                        value,
                        expires,
                        renewed,
                    };
                    entries.push((key, record));
                }
                (Some(key), Some(marker)) => entries.push((key, marker)),
                _ => log::warn!("storage: cannot read {}, left as is", path.display()),
            }
        }
        Ok(entries)
    }
}

/// Make `target`, a file of `dir`, hold `bytes`: written to `temporary`,
/// flushed to the device, renamed over `target`, and the directory
/// flushed. With `owner_only` only the owner of the process can read or
/// write the file.
pub(crate) fn write_durably(
    dir: &Path,
    temporary: &Path,
    target: &Path,
    bytes: &[u8],
    owner_only: bool,
) -> io::Result<()> {
    // A temporary file left by a crash keeps its permissions when opened
    // again: start from a new one.
    match fs::remove_file(temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, target)?;
    sync_dir(dir)
}

/// A rename or a removal is durable once its directory is.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// `| "AKRS" | version | kind | ... | SHA-256 |`, integers big-endian: a
/// record is its expiry and its bytes, a marker its position and its
/// deadline, the file of renewals a list of `| key length (2) | key |
/// SHA-256 of the record | expiry |`, and the hash covers everything before
/// it.
fn header(kind: u8) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(VERSION);
    bytes.push(kind);
    bytes
}

/// `bytes` followed by their SHA-256.
fn seal(bytes: &[u8]) -> Vec<u8> {
    let mut sealed = bytes.to_vec();
    sealed.extend_from_slice(&digest_bytes(bytes));
    sealed
}

/// The kind and the body of a file whose hash and header hold.
fn unseal(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (sealed, checksum) = bytes.split_at_checked(bytes.len().checked_sub(CHECKSUM_LEN)?)?;
    if digest_bytes(sealed) != checksum {
        return None;
    }
    let (header, body) = sealed.split_at_checked(HEADER_LEN)?;
    if &header[..MAGIC.len()] != MAGIC || header[MAGIC.len()] != VERSION {
        return None;
    }
    Some((header[MAGIC.len() + 1], body))
}

fn number(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn decode(bytes: &[u8]) -> Option<Stored> {
    match unseal(bytes)? {
        (RECORD, body) => Some(Stored::Record {
            expires: number(body, 0)?,
            value: body.get(8..)?.to_vec(),
            renewed: None,
        }),
        (MARKER, body) if body.len() == 16 => Some(Stored::Marker {
            seq: number(body, 0)?,
            until: number(body, 8)?,
        }),
        _ => None,
    }
}

fn decode_renewals(bytes: &[u8]) -> Option<Renewed> {
    let (RENEWALS, mut body) = unseal(bytes)? else {
        return None;
    };
    let mut renewals = HashMap::new();
    while !body.is_empty() {
        let (len, rest) = body.split_first_chunk::<2>()?;
        let (key, rest) = rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))?;
        let (record, rest) = rest.split_first_chunk::<ID_LEN>()?;
        let expires = number(rest, 0)?;
        renewals.insert(key.to_vec(), (*record, expires));
        body = &rest[8..];
    }
    Some(renewals)
}

#[cfg(test)]
pub(crate) mod test_dir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// A fresh directory under the system's temporary directory, removed
    /// when dropped.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new() -> Self {
            let name = format!(
                "akrs-{}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
                rand::random::<u32>()
            );
            Self(std::env::temp_dir().join(name))
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            set_read_only(&self.0, false);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Make `dir` refuse new files, or accept them again. `false` when the
    /// process can write there anyway, as root can.
    pub(crate) fn set_read_only(dir: &Path, read_only: bool) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let mode = if read_only { 0o555 } else { 0o755 };
        if std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).is_err() {
            return false;
        }
        let probe = dir.join("probe");
        let writable = std::fs::write(&probe, b"").is_ok();
        let _ = std::fs::remove_file(&probe);
        read_only != writable
    }
}

#[cfg(test)]
mod tests {
    use super::test_dir::TestDir;
    use super::*;

    #[test]
    fn records_and_markers_read_back_as_written() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        store
            .write_record(&[1; 32], b"record", 1_700_000_000_000)
            .unwrap();
        store.write_marker(&[2; 32], 6, 42).unwrap();
        let record = Stored::Record {
            value: b"record".to_vec(),
            expires: 1_700_000_000_000,
            renewed: None,
        };
        let marker = Stored::Marker { seq: 6, until: 42 };
        let mut loaded = store.load().unwrap();
        loaded.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(loaded, vec![(vec![1; 32], record), (vec![2; 32], marker)]);
    }

    #[test]
    fn a_write_replaces_the_file_and_a_removal_deletes_it() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        store.write_marker(&[1; 32], 5, 1).unwrap();
        store.write_marker(&[1; 32], 6, 2).unwrap();
        let six = Stored::Marker { seq: 6, until: 2 };
        assert_eq!(store.load().unwrap(), vec![(vec![1; 32], six)]);
        store.remove(&[1; 32]).unwrap();
        store.remove(&[1; 32]).unwrap();
        assert!(store.load().unwrap().is_empty());
    }

    /// A crash before the rename leaves the temporary file and the old one:
    /// the old one is read, the temporary one removed.
    #[test]
    fn a_temporary_file_left_by_a_crash_is_removed_and_the_old_file_kept() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        store.write_marker(&[1; 32], 5, 1).unwrap();
        let five = Stored::Marker { seq: 5, until: 1 };
        let half_written = dir.path().join(format!("{}.tmp", hex::encode([1u8; 32])));
        std::fs::write(&half_written, b"AKRS\x01").unwrap();
        assert_eq!(store.load().unwrap(), vec![(vec![1; 32], five)]);
        assert!(!half_written.exists());
    }

    /// A byte changed on the device, in a record or in a marker: the file is
    /// not loaded, and is left as it is.
    #[test]
    fn a_file_whose_bytes_changed_is_skipped_and_kept() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        store.write_record(&[1; 32], b"record", 7).unwrap();
        store.write_marker(&[2; 32], 6, 42).unwrap();
        for (key, at) in [([1u8; 32], HEADER_LEN + 8 + 2), ([2u8; 32], HEADER_LEN + 7)] {
            let path = dir.path().join(format!("{}.rec", hex::encode(key)));
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[at] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
        }
        assert!(store.load().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    /// A renewal moves the expiry of the exact record it renewed, and only
    /// later: not that of another record under the same key. A damaged file
    /// of renewals moves nothing.
    #[test]
    fn a_renewal_applies_only_to_the_record_it_renewed() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        for (key, value) in [(1u8, &b"six"[..]), (2, b"seven"), (3, b"eight")] {
            store.write_record(&[key; 32], value, 100).unwrap();
        }
        let mut renewals = Renewals::with_capacity(3);
        for (key, record, expires) in [(1u8, &b"six"[..], 200), (2, b"six", 200), (3, b"eight", 50)]
        {
            renewals
                .push(&[key; 32], &digest_bytes(record), expires)
                .unwrap();
        }
        store.write_renewals(renewals).unwrap();
        let renewed = || -> Vec<Option<u64>> {
            let mut loaded = store.load().unwrap();
            loaded.sort_by(|a, b| a.0.cmp(&b.0));
            loaded
                .into_iter()
                .map(|(_, stored)| match stored {
                    Stored::Record { renewed, .. } => renewed,
                    Stored::Marker { .. } => None,
                })
                .collect()
        };
        assert_eq!(renewed(), vec![Some(200), None, None]);

        let path = dir.path().join(RENEWALS_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN + 2] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(renewed(), vec![None, None, None]);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_skipped() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        for bytes in [
            &b"AKRS"[..],
            b"XXXX\x01\x02",
            b"AKRS\x09\x02",
            b"AKRS\x01\x02short",
        ] {
            std::fs::write(
                dir.path().join(format!("{}.rec", hex::encode([3u8; 32]))),
                bytes,
            )
            .unwrap();
            assert!(store.load().unwrap().is_empty(), "{bytes:?}");
        }
    }
}
