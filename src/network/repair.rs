//! Repair of a DID record this node served that failed the caller's check:
//! a bounded lookup for the record the caller expects, written by the rules
//! of a replica. An ordinary GET stores nothing; only a repair writes,
//! because the caller has checked what it asked for against a credential.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::auth_handler::did::key_of_did;
use crate::auth_handler::rules::{decide_locally, Held, Local};
use crate::auth_handler::tree::{tree_form, Hash};
use crate::crawling::{SpiderProtocol, ValueSearch, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::KademliaProtocol;
use crate::storage::{IStorage, ReplaceStatus, StorageWriteStatus};

use super::Server;

/// How long a repair looks for the expected record.
const REPAIR_TIMEOUT: Duration = Duration::from_secs(5);

/// The record a caller expects, as its credential names it.
#[derive(Clone, Copy)]
struct Expected {
    seq: u64,
    key_hash: Hash,
}

impl Expected {
    /// Whether `record` is the expected one for `key`, by its form alone.
    fn matches(&self, key: &Hash, record: &[u8]) -> bool {
        tree_form(key, record)
            .is_ok_and(|form| form.seq == self.seq && form.key_hash == self.key_hash)
    }
}

impl Server {
    /// Look in the network for the record of `did` at position `seq` whose
    /// raw public key hashes to `key_hash`, as the caller's credential names
    /// them, once `failed`, a record of `did` this node served, has failed
    /// the caller's check. `seq` must be above the position of `failed`.
    ///
    /// The lookup goes past copies of `failed`, lower positions, records
    /// that do not verify and records that differ from the expected one,
    /// until `REPAIR_TIMEOUT`. A verified record above `seq` met on the way
    /// supersedes the expected one, which is then refused. The record found
    /// is written as a replica writes a STORE: it replaces a lower position,
    /// and never a higher one nor another record at its own.
    ///
    /// Returns the expected record, now stored here, or `None` when none
    /// qualified or this node holds a higher position.
    pub async fn repair(
        &self,
        did: &str,
        failed: &[u8],
        seq: u64,
        key_hash: &Hash,
    ) -> Option<Vec<u8>> {
        let key = key_of_did(did)?;
        let Ok(baseline) = tree_form(&key, failed) else {
            log::error!("repair({}): the failed record is not one of this DID", did);
            return None;
        };
        if seq <= baseline.seq {
            log::error!(
                "repair({}): position {} is not above the failed {}",
                did,
                seq,
                baseline.seq
            );
            return None;
        }
        let expected = Expected {
            seq,
            key_hash: *key_hash,
        };
        let (held, marker) = self.storage.record_or_marker(&key);
        let highest = match held {
            Some(held) if expected.matches(&key, &held) => return Some(held),
            Some(held) => tree_form(&key, &held).ok().map(|form| form.seq),
            None => marker,
        };
        if highest.is_some_and(|highest| highest > seq) {
            log::warn!(
                "repair({}): this node holds or remembers a higher position",
                did
            );
            return None;
        }
        let found = self.look_for(did, key, expected).await?;
        self.install(did, key, expected, found)
    }

    /// The first record of the lookup that is the expected one and verifies,
    /// unless a verified higher record came before it.
    async fn look_for(&self, did: &str, key: Hash, expected: Expected) -> Option<Vec<u8>> {
        let proto = self.protocol.as_ref()?;
        let target = Node::from_id(key);
        let nearest = proto.router.read().await.find_neighbors(&target, None);
        if nearest.is_empty() {
            log::warn!("repair({}): no known neighbours", did);
            return None;
        }
        let mut crawl =
            ValueSpiderCrawl::new(Arc::clone(proto), target, nearest, self.ksize, self.alpha);
        let highest = AtomicU64::new(expected.seq);
        let find_value =
            |protocol: Arc<KademliaProtocol>, peer, target| protocol.call_find_value(peer, target);
        let accept = |_peer: Node, value: Vec<u8>| {
            let highest = &highest;
            async move {
                let form = tree_form(&key, &value).ok()?;
                let candidate = form.seq == expected.seq && form.key_hash == expected.key_hash;
                if !candidate && form.seq <= expected.seq {
                    return None;
                }
                if !self.verify_value(did, &value).await {
                    return None;
                }
                if !candidate {
                    highest.fetch_max(form.seq, Ordering::Relaxed);
                    return None;
                }
                (highest.load(Ordering::Relaxed) == expected.seq).then_some(value)
            }
        };
        let deadline = tokio::time::Instant::now() + REPAIR_TIMEOUT;
        match crawl.search(Some(deadline), find_value, accept).await {
            ValueSearch::Found(record) => Some(record),
            ValueSearch::NotFound | ValueSearch::Incomplete => {
                log::warn!(
                    "repair({}): no verified record at position {} with the expected key",
                    did,
                    expected.seq
                );
                None
            }
        }
    }

    /// Write `found`, the expected record, verified, by the rules of a
    /// replica. A concurrent writer may have stored it, or a record that
    /// supersedes it, meanwhile.
    fn install(&self, did: &str, key: Hash, expected: Expected, found: Vec<u8>) -> Option<Vec<u8>> {
        for _ in 0..2 {
            let (held, marker) = self.storage.record_or_marker(&key);
            if let Some(held) = held.as_ref().filter(|held| expected.matches(&key, held)) {
                return Some(held.clone());
            }
            match decide_locally(&key, Held::of(held.as_deref(), marker), &found) {
                Local::AskNetwork(_) => {
                    match self.storage.insert_if_absent(key.to_vec(), found.clone()) {
                        StorageWriteStatus::Stored | StorageWriteStatus::AlreadyStored => {
                            return Some(found)
                        }
                        StorageWriteStatus::Conflict => continue,
                        StorageWriteStatus::CapacityExceeded | StorageWriteStatus::WriteFailed => {
                            return None
                        }
                    }
                }
                Local::VerifyAndReplace => {
                    let Some(held) = held else {
                        continue;
                    };
                    match self.storage.replace_if(&key, &held, found.clone()) {
                        ReplaceStatus::Replaced => return Some(found),
                        ReplaceStatus::Changed => continue,
                        ReplaceStatus::CapacityExceeded | ReplaceStatus::WriteFailed => {
                            return None
                        }
                    }
                }
                _ => {
                    log::warn!(
                        "repair({}): this node holds or remembers a higher position",
                        did
                    );
                    return None;
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::auth_handler::test_tree::{sha256, TreeOwner};
    use crate::auth_handler::DIDSignatureVerifierHandler;

    use super::*;

    fn server() -> Server {
        Server::new(
            Arc::new(DIDSignatureVerifierHandler::new("unused")),
            20,
            3,
            None,
            None,
            false,
        )
    }

    fn expected(owner: &TreeOwner, seq: usize) -> Expected {
        Expected {
            seq: seq as u64,
            key_hash: sha256(owner.keys[seq].public_key()),
        }
    }

    #[test]
    fn the_expected_record_replaces_a_lower_one_or_fills_an_empty_store() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        for held in [None, Some(v5.clone())] {
            let server = server();
            if let Some(held) = held {
                server.storage.set(owner.key.to_vec(), held);
            }
            assert_eq!(
                server.install(&owner.did, owner.key, expected(&owner, 6), v6.clone()),
                Some(v6.clone())
            );
            assert_eq!(server.storage.get(&owner.key), Some(v6.clone()));
        }
    }

    /// A writer stored 7, or another record at 6, while the repair of 5
    /// looked for 6.
    #[test]
    fn what_a_concurrent_writer_stored_decides() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let v7 = owner.record(7, Some(&v6));
        let server = server();
        server.storage.set(owner.key.to_vec(), v7.clone());
        assert_eq!(
            server.install(&owner.did, owner.key, expected(&owner, 6), v6.clone()),
            None
        );
        assert_eq!(server.storage.get(&owner.key), Some(v7));

        let signed_again = owner.record(6, Some(&v5));
        server.storage.set(owner.key.to_vec(), signed_again.clone());
        assert_eq!(
            server.install(&owner.did, owner.key, expected(&owner, 6), v6),
            Some(signed_again.clone()),
            "the expected position and key, signed by the owner"
        );
        assert_eq!(server.storage.get(&owner.key), Some(signed_again));
    }

    #[tokio::test]
    async fn a_repair_needs_a_failed_record_of_the_did_below_the_expected_position() {
        let (owner, other) = (TreeOwner::new(1), TreeOwner::new(2));
        let v5 = owner.record(5, Some(b"4"));
        let server = server();
        let key_hash = sha256(owner.keys[6].public_key());
        let theirs = other.record(5, Some(b"4"));
        assert_eq!(server.repair(&owner.did, &theirs, 6, &key_hash).await, None);
        assert_eq!(
            server
                .repair(&owner.did, &v5, 5, &sha256(owner.keys[5].public_key()))
                .await,
            None
        );
        assert_eq!(
            server.repair("did:iiot:nope", &v5, 6, &key_hash).await,
            None
        );
    }

    #[tokio::test]
    async fn a_held_match_is_returned_and_a_held_higher_position_refuses() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let v7 = owner.record(7, Some(&v6));
        let key_hash = sha256(owner.keys[6].public_key());
        let server = server();
        server.storage.set(owner.key.to_vec(), v6.clone());
        assert_eq!(server.repair(&owner.did, &v5, 6, &key_hash).await, Some(v6));
        server.storage.set(owner.key.to_vec(), v7.clone());
        assert_eq!(server.repair(&owner.did, &v5, 6, &key_hash).await, None);
        assert_eq!(server.storage.get(&owner.key), Some(v7));
    }

    /// This node remembers 7 after it expired: a repair for 6 finds nothing.
    #[tokio::test]
    async fn a_repair_below_a_remembered_position_finds_nothing() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use crate::storage::{ForgetfulStorage, DEFAULT_MAX_STORAGE_BYTES};

        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let v7 = owner.record(7, Some(&v6));
        let time = Arc::new(AtomicU64::new(0));
        let now = Arc::clone(&time);
        let storage = ForgetfulStorage::in_memory(
            100,
            DEFAULT_MAX_STORAGE_BYTES,
            Arc::new(move || now.load(Ordering::Relaxed)),
        );
        storage.set(owner.key.to_vec(), v7);
        time.store(100_000, Ordering::Relaxed);
        let server = Server::new(
            Arc::new(DIDSignatureVerifierHandler::new("unused")),
            20,
            3,
            None,
            Some(Arc::new(storage)),
            false,
        );
        let key_hash = sha256(owner.keys[6].public_key());
        assert_eq!(server.repair(&owner.did, &v5, 6, &key_hash).await, None);
        assert_eq!(
            server.install(&owner.did, owner.key, expected(&owner, 6), v6),
            None
        );
    }
}
