//! The files of a persistent replica store, one per key.
//!
//! A file holds a record with its expiry or, once the record has expired,
//! the highest position accepted for the key and until when it is
//! remembered. It is replaced by writing a temporary file, flushing it to
//! the device, renaming it over the old one and flushing the directory. On
//! a journaling file system such as ext4 a power cut then leaves the old
//! file or the new one, never a mix of them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"AKRS";
const VERSION: u8 = 1;
const RECORD: u8 = 1;
const MARKER: u8 = 2;
const HEADER_LEN: usize = MAGIC.len() + 2;
const EXTENSION: &str = "rec";
const TEMPORARY: &str = "tmp";

/// What a file holds for its key. Times are milliseconds since the Unix
/// epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    Record { value: Vec<u8>, expires: u64 },
    Marker { seq: u64, until: u64 },
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
        let temporary = self.path(key, TEMPORARY);
        write_durably(
            &self.dir,
            &temporary,
            &self.path(key, EXTENSION),
            bytes,
            false,
        )
    }

    /// Remove the file of `key`, if any.
    pub(crate) fn remove(&self, key: &[u8]) -> io::Result<()> {
        match fs::remove_file(self.path(key, EXTENSION)) {
            Ok(()) => sync_dir(&self.dir),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Every key and what its file holds. A temporary file is what a crash
    /// left before its rename, and is removed; a file that cannot be read
    /// is logged and left where it is.
    pub(crate) fn load(&self) -> io::Result<Vec<(Vec<u8>, Stored)>> {
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
                (Some(key), Some(stored)) => entries.push((key, stored)),
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

/// `| "AKRS" | version | kind | ... |`, integers big-endian: a record is its
/// expiry and its bytes, a marker its position and its deadline.
fn header(kind: u8) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(VERSION);
    bytes.push(kind);
    bytes
}

fn decode(bytes: &[u8]) -> Option<Stored> {
    let (header, body) = bytes.split_at_checked(HEADER_LEN)?;
    if &header[..MAGIC.len()] != MAGIC || header[MAGIC.len()] != VERSION {
        return None;
    }
    let number = |at: usize| -> Option<u64> {
        Some(u64::from_be_bytes(body.get(at..at + 8)?.try_into().ok()?))
    };
    match header[MAGIC.len() + 1] {
        RECORD => Some(Stored::Record {
            expires: number(0)?,
            value: body.get(8..)?.to_vec(),
        }),
        MARKER if body.len() == 16 => Some(Stored::Marker {
            seq: number(0)?,
            until: number(8)?,
        }),
        _ => None,
    }
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

    #[test]
    fn a_file_that_cannot_be_read_is_skipped() {
        let dir = TestDir::new();
        let store = DurableDir::open(dir.path().to_path_buf()).unwrap();
        for bytes in [
            &b"AKRS"[..],
            b"XXXX\x01\x02",
            b"AKRS\x02\x02",
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
