//! How a replica takes a DID record: the order of its checks, the network
//! check of a replica that holds nothing, with mock neighbours, and the
//! replacement of a record. The rules themselves are tested in
//! `auth_handler/rules.rs`; here, that a replica gathers what they need, asks
//! only when they say so, and writes only what they accept.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use crate::auth_handler::test_tree::{body, sha256, sign, TreeOwner, PLACEHOLDER};
use crate::node::Node;
use crate::protocol::messages::{record_hash, rpc_message_name, RpcMessage, StoreStatus, WireNode};
use crate::protocol::test_support::*;
use crate::storage::{ForgetfulStorage, IStorage, DEFAULT_MAX_STORAGE_BYTES};
use crate::utils::ID_LEN;

use super::KademliaProtocol;

const SENDER: [u8; ID_LEN] = [2; ID_LEN];

fn sender_addr() -> (String, u16) {
    ("127.0.0.1".to_string(), 9050)
}

/// A replica with the real DID rules, reading its datagrams.
async fn replica() -> (Arc<KademliaProtocol>, Arc<CountingDidHandler>) {
    replica_with(Arc::new(ForgetfulStorage::new(-1))).await
}

async fn replica_with(
    storage: Arc<ForgetfulStorage>,
) -> (Arc<KademliaProtocol>, Arc<CountingDidHandler>) {
    let handler = Arc::new(CountingDidHandler::new());
    let protocol = test_protocol_with_storage(handler.clone(), false, storage).await;
    serve(&protocol);
    (protocol, handler)
}

/// What a mock neighbour holds and answers.
#[derive(Clone)]
enum Neighbour {
    /// Holds `record` at position `seq`: answers `FindHash` with its hash,
    /// and `FindValue` with the record.
    Holder(u64, Vec<u8>),
    /// Answers `FindHash` with `(seq, hash)`, and has no record to give.
    Claims(u64, [u8; ID_LEN]),
    /// Answers `FindHash` with `(seq, hash)`, and `FindValue` with `record`.
    ClaimsServing(u64, [u8; ID_LEN], Vec<u8>),
    /// Answers `FindHash` with `(seq, hash)`, and never `FindValue`.
    ClaimsThenSilent(u64, [u8; ID_LEN]),
    /// One node under many ids: the first `FindHash` gets `count` made-up
    /// nodes closer to the key, all at this node's address, and every later
    /// one a claim of position `seq` under a made-up hash.
    Sybil { count: u8, seq: u64 },
    /// Holds nothing: answers with no closer nodes.
    Empty,
    /// Never answers.
    Silent,
}

/// The requests one mock neighbour received, by message name.
type Seen = Arc<Mutex<Vec<&'static str>>>;

/// Mock neighbours known to `protocol`, from the closest to `key`.
async fn neighbours(
    protocol: &Arc<KademliaProtocol>,
    key: [u8; ID_LEN],
    kinds: Vec<Neighbour>,
) -> Vec<Seen> {
    let mut all = vec![];
    for (index, kind) in kinds.into_iter().enumerate() {
        let mut id = key;
        id[ID_LEN - 2] ^= index as u8 + 1;
        let (socket, contact) = raw_peer(id).await;
        protocol.router.write().await.add_contact(contact.clone());
        let seen: Seen = Arc::new(Mutex::new(vec![]));
        all.push(Arc::clone(&seen));
        let introduced = AtomicBool::new(false);
        tokio::spawn(async move {
            while let Some((frame, from)) = try_read_frame(&socket, Duration::from_secs(5)).await {
                if !frame.is_request {
                    continue;
                }
                seen.lock().unwrap().push(rpc_message_name(&frame.message));
                let find_hash = matches!(frame.message, RpcMessage::FindHash { .. });
                let find_value = matches!(frame.message, RpcMessage::FindValue { .. });
                let answer = match &kind {
                    Neighbour::Silent => None,
                    Neighbour::Holder(seq, record) if find_hash => Some(RpcMessage::FindHashHit {
                        seq: *seq,
                        hash: record_hash(record),
                    }),
                    Neighbour::Holder(_, record) | Neighbour::ClaimsServing(_, _, record)
                        if find_value =>
                    {
                        Some(RpcMessage::FindValueHit {
                            value: record.clone(),
                        })
                    }
                    Neighbour::Claims(seq, hash)
                    | Neighbour::ClaimsServing(seq, hash, _)
                    | Neighbour::ClaimsThenSilent(seq, hash)
                        if find_hash =>
                    {
                        Some(RpcMessage::FindHashHit {
                            seq: *seq,
                            hash: *hash,
                        })
                    }
                    Neighbour::ClaimsThenSilent(..) => None,
                    Neighbour::Sybil { count, .. }
                        if find_hash && !introduced.swap(true, Ordering::Relaxed) =>
                    {
                        let made_up = (1..=*count)
                            .map(|n| {
                                let mut id = key;
                                id[ID_LEN - 1] ^= n;
                                WireNode::from(&Node::new(id, contact.ip.clone(), contact.port))
                            })
                            .collect();
                        Some(RpcMessage::FindValueNodes { nodes: made_up })
                    }
                    Neighbour::Sybil { seq, .. } if find_hash => Some(RpcMessage::FindHashHit {
                        seq: *seq,
                        hash: rand::random(),
                    }),
                    _ if find_hash || find_value => {
                        Some(RpcMessage::FindValueNodes { nodes: vec![] })
                    }
                    _ => None,
                };
                if let Some(answer) = answer {
                    send_raw(&socket, from, frame.msg_id, false, answer).await;
                }
            }
        });
    }
    all
}

fn asked(seen: &[Seen]) -> Vec<&'static str> {
    seen.iter()
        .flat_map(|s| s.lock().unwrap().clone())
        .collect()
}

async fn store(
    protocol: &Arc<KademliaProtocol>,
    key: [u8; ID_LEN],
    record: &[u8],
) -> Option<StoreStatus> {
    protocol
        .rpc_store(SENDER, sender_addr(), key, record.to_vec())
        .await
}

async fn knows(protocol: &Arc<KademliaProtocol>, id: [u8; ID_LEN]) -> bool {
    protocol.router.read().await.get_contact(&id).is_some()
}

/// Position `seq` of `owner` with another service endpoint: a second valid
/// document at that position.
fn other_document(owner: &TreeOwner, seq: usize, prev: &[u8]) -> Vec<u8> {
    let mut doc = owner.doc(seq, Some(prev));
    doc["service"][0]["serviceEndpoint"] = json!("http://example.com/other");
    sign(&doc, &owner.keys[seq])
}

// ---- The order of checks ------------------------------------------------------

/// A record that fails the form is `InvalidRecord` before any signature is
/// verified or any node asked, and its sender does not enter the routing
/// table; a genuine one is checked against the network and stored.
#[tokio::test]
async fn a_record_that_fails_the_form_is_invalid_before_anything_else() {
    let (protocol, handler) = replica().await;
    let (owner, other) = (TreeOwner::new(1), TreeOwner::new(2));
    let seen = neighbours(&protocol, other.key, vec![Neighbour::Empty]).await;
    assert_eq!(
        store(&protocol, owner.key, &owner.record(0, None)).await,
        Some(StoreStatus::Stored)
    );
    let verified = handler.verified();
    let requests = asked(&seen).len();

    let stranger = [3; ID_LEN];
    assert_eq!(
        protocol
            .rpc_store(stranger, sender_addr(), other.key, owner.record(0, None))
            .await,
        Some(StoreStatus::InvalidRecord)
    );
    assert_eq!(handler.verified(), verified, "no signature verified");
    assert_eq!(asked(&seen).len(), requests, "nobody asked");
    assert!(!knows(&protocol, stranger).await);
    assert_eq!(protocol.storage.get(&other.key), None);
}

/// A record signed by a key that is not its position's is invalid however
/// many nodes claim to hold it: no lookup runs at all.
#[tokio::test]
async fn a_forged_record_is_invalid_whatever_the_network_says() {
    let (protocol, handler) = replica().await;
    let owner = TreeOwner::new(1);
    let forger = TreeOwner::new(9);
    let forged = owner.record_from(
        &body(PLACEHOLDER, forger.keys[5].public_key(), 5, Some(b"4")),
        5,
    );
    let claims = vec![Neighbour::Claims(5, sha256(&forged)); 5];
    let seen = neighbours(&protocol, owner.key, claims).await;
    assert_eq!(
        store(&protocol, owner.key, &forged).await,
        Some(StoreStatus::InvalidRecord)
    );
    assert!(asked(&seen).is_empty());
    assert_eq!(handler.verified(), 0);
    assert_eq!(protocol.storage.get(&owner.key), None);
}

/// The same bytes refresh the expiry, verify nothing and ask nobody.
#[tokio::test]
async fn the_same_bytes_refresh_the_stored_record() {
    let (protocol, handler) = replica().await;
    let owner = TreeOwner::new(1);
    let v5 = owner.record(5, Some(b"4"));
    protocol
        .storage
        .insert_if_absent(owner.key.to_vec(), v5.clone());
    let seen = neighbours(&protocol, owner.key, vec![Neighbour::Empty]).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(protocol.storage.iter_older_than(1).len(), 1);

    assert_eq!(
        store(&protocol, owner.key, &v5).await,
        Some(StoreStatus::AlreadyStored)
    );
    assert!(protocol.storage.iter_older_than(1).is_empty());
    assert!(knows(&protocol, SENDER).await);
    assert_eq!(handler.verified(), 0);
    assert!(asked(&seen).is_empty());
}

// ---- A replica that holds a record -----------------------------------------------

/// A holder decides alone: a higher position replaces its record, without
/// the positions in between, and a lower one is stale. Nobody is asked, not
/// even a node that would claim a higher position.
#[tokio::test]
async fn a_holder_decides_alone_by_position() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let (v3, v5) = (owner.record(3, Some(b"2")), owner.record(5, Some(b"2")));
    protocol
        .storage
        .insert_if_absent(owner.key.to_vec(), v3.clone());
    let seen = neighbours(
        &protocol,
        owner.key,
        vec![Neighbour::Claims(9, [9; ID_LEN])],
    )
    .await;
    assert_eq!(
        store(&protocol, owner.key, &v5).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(
        store(&protocol, owner.key, &v3).await,
        Some(StoreStatus::Stale)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(v5));
    assert!(asked(&seen).is_empty());
}

/// A holder of 5A keeps it against a valid 5B, whichever arrives first,
/// answers `Conflict`, and takes the same valid 6 in both runs. The same
/// document signed again is a conflict too, and the original bytes are
/// already stored.
#[tokio::test]
async fn another_record_at_the_stored_position_leaves_the_stored_one() {
    let owner = TreeOwner::new(1);
    let five_a = owner.record(5, Some(b"4"));
    let five_b = other_document(&owner, 5, b"4");
    let six = owner.record(6, Some(&five_a));
    for (first, second) in [(&five_a, &five_b), (&five_b, &five_a)] {
        let (protocol, _) = replica().await;
        protocol
            .storage
            .insert_if_absent(owner.key.to_vec(), first.clone());
        assert_eq!(
            store(&protocol, owner.key, second).await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(protocol.storage.get(&owner.key).as_ref(), Some(first));
        assert_eq!(
            store(&protocol, owner.key, &owner.record(5, Some(b"4"))).await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(
            store(&protocol, owner.key, first).await,
            Some(StoreStatus::AlreadyStored)
        );
        assert_eq!(
            store(&protocol, owner.key, &six).await,
            Some(StoreStatus::Stored)
        );
        assert_eq!(protocol.storage.get(&owner.key).as_ref(), Some(&six));
    }
}

/// A second signature that does not verify is no conflict: `InvalidRecord`.
#[tokio::test]
async fn an_invalid_second_record_at_the_stored_position_is_invalid() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let v5 = owner.record(5, Some(b"4"));
    protocol
        .storage
        .insert_if_absent(owner.key.to_vec(), v5.clone());
    let mut again = owner.record(5, Some(b"4"));
    again[20] ^= 1;
    assert_eq!(
        store(&protocol, owner.key, &again).await,
        Some(StoreStatus::InvalidRecord)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(v5));
}

#[tokio::test]
async fn find_hash_answers_with_the_position_held() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let v5 = owner.record(5, Some(b"4"));
    protocol
        .storage
        .insert_if_absent(owner.key.to_vec(), v5.clone());
    let answer = protocol
        .dispatch_request(
            RpcMessage::FindHash {
                sender_id: SENDER,
                key: owner.key,
            },
            "127.0.0.1:9051".parse().unwrap(),
        )
        .await;
    assert!(matches!(
        answer,
        Some(RpcMessage::FindHashHit { seq: 5, hash }) if hash == record_hash(&v5)
    ));
}

/// Two valid documents at position 6, sent at once to a holder of 5: one is
/// stored, the other is a conflict.
#[tokio::test]
async fn two_records_at_once_at_one_position_leave_exactly_one() {
    let owner = TreeOwner::new(1);
    let (protocol, _) = replica().await;
    let v5 = owner.record(5, Some(b"4"));
    protocol
        .storage
        .insert_if_absent(owner.key.to_vec(), v5.clone());
    let sixes = [owner.record(6, Some(&v5)), other_document(&owner, 6, &v5)];
    let (first, second) = tokio::join!(
        store(&protocol, owner.key, &sixes[0]),
        store(&protocol, owner.key, &sixes[1]),
    );
    let mut statuses = [first, second];
    statuses.sort_by_key(|status| format!("{status:?}"));
    assert_eq!(
        statuses,
        [Some(StoreStatus::Conflict), Some(StoreStatus::Stored)]
    );
    let winner = if first == Some(StoreStatus::Stored) {
        &sixes[0]
    } else {
        &sixes[1]
    };
    assert_eq!(protocol.storage.get(&owner.key).as_ref(), Some(winner));
}

/// A record checked against the network while a lower position is stored
/// meanwhile is decided again against it, and replaces it.
#[tokio::test]
async fn a_record_checked_while_another_arrives_is_decided_again() {
    let owner = TreeOwner::new(1);
    let (protocol, _) = replica().await;
    let (peer, contact) = raw_peer({
        let mut id = owner.key;
        id[ID_LEN - 1] ^= 1;
        id
    })
    .await;
    protocol.router.write().await.add_contact(contact);
    let (v3, v5) = (owner.record(3, Some(b"2")), owner.record(5, Some(b"4")));
    let replica = Arc::clone(&protocol);
    let (key, sent) = (owner.key, v5.clone());
    let stored = tokio::spawn(async move { store(&replica, key, &sent).await });

    let (question, from) = read_frame_of_kind(&peer, true).await;
    assert!(matches!(question.message, RpcMessage::FindHash { .. }));
    protocol
        .storage
        .insert_if_absent(owner.key.to_vec(), v3.clone());
    send_raw(
        &peer,
        from,
        question.msg_id,
        false,
        RpcMessage::FindHashHit {
            seq: 3,
            hash: record_hash(&v3),
        },
    )
    .await;
    assert_eq!(stored.await.unwrap(), Some(StoreStatus::Stored));
    assert_eq!(protocol.storage.get(&owner.key), Some(v5));
}

// ---- A replica that holds nothing ---------------------------------------------------------

/// One peer that shows a valid 6 refuses the incoming 5 as stale, however
/// many hold 3, and the replica keeps 6.
#[tokio::test]
async fn one_shown_higher_position_refuses_and_is_stored() {
    let (protocol, handler) = replica().await;
    let owner = TreeOwner::new(1);
    let v3 = owner.record(3, Some(b"2"));
    let v5 = owner.record(5, Some(&v3));
    let v6 = owner.record(6, Some(&v5));
    let mut kinds = vec![Neighbour::Holder(3, v3.clone()); 4];
    kinds.push(Neighbour::Holder(6, v6.clone()));
    neighbours(&protocol, owner.key, kinds).await;
    assert_eq!(
        store(&protocol, owner.key, &v5).await,
        Some(StoreStatus::Stale)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(v6));
    assert_eq!(handler.verified(), 1, "only the shown 6 is verified");
}

/// A claim of 6 proves nothing: not shown, not shown in time, shown with
/// invalid bytes, or with a valid 6 of another DID. The verified 5 is
/// stored.
#[tokio::test]
async fn a_claim_that_is_not_shown_refuses_nothing() {
    let (protocol, _) = replica().await;
    let (owner, other) = (TreeOwner::new(1), TreeOwner::new(2));
    let v5 = owner.record(5, Some(b"4"));
    let theirs = other.record(6, Some(b"5"));
    let mut invalid = owner.record(6, Some(&v5));
    invalid[20] ^= 1;
    let seen = neighbours(
        &protocol,
        owner.key,
        vec![
            Neighbour::Claims(6, [1; ID_LEN]),
            Neighbour::ClaimsThenSilent(6, [2; ID_LEN]),
            Neighbour::ClaimsServing(6, sha256(&invalid), invalid),
            Neighbour::ClaimsServing(6, sha256(&theirs), theirs),
            Neighbour::Holder(3, owner.record(3, Some(b"2"))),
        ],
    )
    .await;
    assert_eq!(
        store(&protocol, owner.key, &v5).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(v5));
    // Each claimant is asked for its record (a silent one again, by the
    // resends); the holder of 3 is not.
    let fetched: Vec<bool> = seen
        .iter()
        .map(|s| s.lock().unwrap().contains(&"FindValue"))
        .collect();
    assert_eq!(fetched, [true, true, true, true, false]);
    #[cfg(feature = "counters")]
    assert_eq!(protocol.counters().checks.unshown_claims, 4);
}

/// Every peer holding a lower position, or nothing, lets the record in.
#[tokio::test]
async fn peers_holding_lower_positions_let_the_record_in() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let v3 = owner.record(3, Some(b"2"));
    let v5 = owner.record(5, Some(&v3));
    let seen = neighbours(
        &protocol,
        owner.key,
        vec![
            Neighbour::Holder(3, v3.clone()),
            Neighbour::Holder(3, v3),
            Neighbour::Empty,
        ],
    )
    .await;
    assert_eq!(
        store(&protocol, owner.key, &v5).await,
        Some(StoreStatus::Stored)
    );
    assert!(!asked(&seen).contains(&"FindValue"));
}

/// No peer answers by the deadline: the verified record is stored all the
/// same, and one with a bad signature is not.
#[tokio::test]
async fn a_verified_record_is_stored_when_no_peer_answers() {
    let owner = TreeOwner::new(1);
    let v5 = owner.record(5, Some(b"4"));
    let (protocol, _) = replica().await;
    neighbours(&protocol, owner.key, vec![Neighbour::Silent; 3]).await;
    assert_eq!(
        store(&protocol, owner.key, &v5).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(v5.clone()));

    let (protocol, _) = replica().await;
    neighbours(&protocol, owner.key, vec![Neighbour::Silent; 3]).await;
    let mut bad = v5;
    bad[20] ^= 1;
    assert_eq!(
        store(&protocol, owner.key, &bad).await,
        Some(StoreStatus::InvalidRecord)
    );
    assert_eq!(protocol.storage.get(&owner.key), None);
}

/// 13 of 19 peers report another valid record at position 5: the replica
/// stores the 5 it was sent, without fetching theirs.
#[tokio::test]
async fn reports_of_another_record_at_the_same_position_change_nothing() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let five_a = owner.record(5, Some(b"4"));
    let five_b = other_document(&owner, 5, b"4");
    let mut kinds = vec![Neighbour::Holder(5, five_b); 13];
    kinds.extend(vec![Neighbour::Empty; 6]);
    let seen = neighbours(&protocol, owner.key, kinds).await;
    assert_eq!(
        store(&protocol, owner.key, &five_a).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(five_a));
    assert!(!asked(&seen).contains(&"FindValue"));
}

/// One node answering under 19 made-up ids at its address, each claiming a
/// later position: the replica fetches at most `k - 1` claims, none is
/// shown, and the verified record is stored. The made-up ids cast no vote.
#[tokio::test]
async fn made_up_ids_at_one_address_cannot_block_a_record() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let v0 = owner.record(0, None);
    neighbours(
        &protocol,
        owner.key,
        vec![Neighbour::Sybil { count: 19, seq: 62 }],
    )
    .await;
    assert_eq!(
        store(&protocol, owner.key, &v0).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(protocol.storage.get(&owner.key), Some(v0));
}

/// The same attack with the claims pointing at a forged record: the forged
/// record is invalid before any lookup, so the made-up ids are never asked.
#[tokio::test]
async fn made_up_ids_cannot_get_a_forged_record_stored() {
    let (protocol, _) = replica().await;
    let owner = TreeOwner::new(1);
    let forger = TreeOwner::new(9);
    let forged = owner.record_from(
        &body(PLACEHOLDER, forger.keys[1].public_key(), 1, Some(b"0")),
        1,
    );
    let seen = neighbours(
        &protocol,
        owner.key,
        vec![Neighbour::Sybil { count: 19, seq: 1 }],
    )
    .await;
    assert_eq!(
        store(&protocol, owner.key, &forged).await,
        Some(StoreStatus::InvalidRecord)
    );
    assert!(asked(&seen).is_empty());
    assert_eq!(protocol.storage.get(&owner.key), None);
}

/// A replica whose 6 expired remembers its position: a replay of 5 is stale
/// without asking anyone, 6 and 7 go through the check and are stored. Once
/// the marker's own deadline has passed, 5 is a record like any other.
#[tokio::test]
async fn a_remembered_position_refuses_a_lower_one_without_asking() {
    const TTL_MS: u64 = 100_000;
    let owner = TreeOwner::new(1);
    let v5 = owner.record(5, Some(b"4"));
    let v6 = owner.record(6, Some(&v5));
    let v7 = owner.record(7, Some(&v6));
    let cases = [
        (TTL_MS, &v5, StoreStatus::Stale),
        (TTL_MS, &v6, StoreStatus::Stored),
        (TTL_MS, &v7, StoreStatus::Stored),
        (2 * TTL_MS, &v5, StoreStatus::Stored),
    ];
    for (elapsed, incoming, answer) in cases {
        let time = Arc::new(AtomicU64::new(0));
        let now = Arc::clone(&time);
        let storage = ForgetfulStorage::in_memory(
            100,
            DEFAULT_MAX_STORAGE_BYTES,
            Arc::new(move || now.load(Ordering::Relaxed)),
        );
        storage.set(owner.key.to_vec(), v6.clone());
        time.store(elapsed, Ordering::Relaxed);
        let (protocol, _) = replica_with(Arc::new(storage)).await;
        let seen = neighbours(&protocol, owner.key, vec![Neighbour::Empty; 3]).await;
        assert_eq!(store(&protocol, owner.key, incoming).await, Some(answer));
        if answer == StoreStatus::Stale {
            assert!(asked(&seen).is_empty());
            assert_eq!(protocol.storage.get(&owner.key), None);
        } else {
            assert_eq!(protocol.storage.get(&owner.key), Some(incoming.clone()));
        }
    }
}
