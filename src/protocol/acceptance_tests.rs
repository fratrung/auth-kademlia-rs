//! How a replica takes a DID record from the network (ADR 0005, section 3):
//! the order of its checks, the network checks of a replica that holds
//! nothing, with mock neighbours, UPDATE, and the replacement of a record.
//! The rules themselves are tested in `auth_handler/rules.rs`; here, that a
//! replica gathers what they need, asks only when they say so, and writes
//! only what they accept.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::auth_handler::test_chain::{new_key, sign, Chain};
use crate::protocol::messages::{
    record_hash, rpc_message_name, RpcMessage, StoreStatus, UpdateStatus,
};
use crate::protocol::test_support::*;
use crate::storage::{ForgetfulStorage, IStorage};
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
    /// Holds `record` as version `seq`: answers `FindHash` with its hash, and
    /// `FindValue` with the record.
    Holder(u64, Vec<u8>),
    /// Answers `FindHash` with `(seq, hash)`, and has no record to give.
    Claims(u64, [u8; ID_LEN]),
    /// Answers `FindHash` with `(seq, hash)`, and `FindValue` with `record`.
    ClaimsServing(u64, [u8; ID_LEN], Vec<u8>),
    /// Answers `FindHash` with `(seq, hash)`, and never `FindValue`.
    ClaimsThenSilent(u64, [u8; ID_LEN]),
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
        id[ID_LEN - 1] ^= index as u8 + 1;
        let (socket, contact) = raw_peer(id).await;
        protocol.router.write().await.add_contact(contact);
        let seen: Seen = Arc::new(Mutex::new(vec![]));
        all.push(Arc::clone(&seen));
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

async fn update(
    protocol: &Arc<KademliaProtocol>,
    key: [u8; ID_LEN],
    record: &[u8],
) -> UpdateStatus {
    protocol
        .rpc_update(SENDER, sender_addr(), key, record.to_vec())
        .await
        .expect("an UPDATE answered")
}

async fn knows(protocol: &Arc<KademliaProtocol>, id: [u8; ID_LEN]) -> bool {
    protocol.router.read().await.get_contact(&id).is_some()
}

/// Version `seq` of `chain` with a longer document, signed by the key the
/// version before commits to.
fn larger_version(chain: &Chain, seq: usize) -> Vec<u8> {
    let mut doc = chain.doc(
        seq as u64,
        Some(chain.version(seq - 1)),
        chain.keys[seq].public_key(),
        chain.keys[seq + 1].public_key(),
    );
    doc["service"][0]["serviceEndpoint"] = json!(format!("http://example.com/{}", "x".repeat(200)));
    sign(&doc, &chain.keys[seq])
}

/// Another version `seq` of `chain` at the same place, signed by `signer`.
fn fork(
    chain: &Chain,
    seq: usize,
    prev: &[u8],
    signer: &crate::crypto::mldsa::MlDsa65KeyPair,
) -> Vec<u8> {
    sign(
        &chain.doc(
            seq as u64,
            Some(prev),
            signer.public_key(),
            new_key().public_key(),
        ),
        signer,
    )
}

// ---- The order of checks ------------------------------------------------------

/// A record that fails the form is `InvalidRecord` before any signature is
/// verified or any node asked, and its sender does not enter the routing
/// table; a genuine one is checked against the network and stored.
#[tokio::test]
async fn a_record_that_fails_the_form_is_invalid_before_anything_else() {
    let (protocol, handler) = replica().await;
    let (chain, other) = (Chain::new(), Chain::new());
    let seen = neighbours(&protocol, other.key, vec![Neighbour::Empty]).await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(0)).await,
        Some(StoreStatus::Stored)
    );
    let verified = handler.verified();
    let requests = asked(&seen).len();

    let stranger = [3; ID_LEN];
    let record = chain.version(0).to_vec();
    assert_eq!(
        protocol
            .rpc_store(stranger, sender_addr(), other.key, record.clone())
            .await,
        Some(StoreStatus::InvalidRecord)
    );
    assert_eq!(
        protocol
            .rpc_update(stranger, sender_addr(), other.key, record)
            .await,
        Some(UpdateStatus::InvalidRecord)
    );
    assert_eq!(handler.verified(), verified, "no signature verified");
    assert_eq!(asked(&seen).len(), requests, "nobody asked");
    assert!(!knows(&protocol, stranger).await);
    assert_eq!(protocol.storage.get(&other.key), None);
}

/// Version 0 follows no version: an UPDATE of it is `InvalidRecord`, even
/// with the bytes the replica holds.
#[tokio::test]
async fn an_update_of_version_0_is_invalid() {
    let (protocol, _) = replica().await;
    let chain = Chain::new();
    assert_eq!(
        update(&protocol, chain.key, chain.version(0)).await,
        UpdateStatus::InvalidRecord
    );
    protocol
        .storage
        .set(chain.key.to_vec(), chain.version(0).to_vec());
    assert_eq!(
        update(&protocol, chain.key, chain.version(0)).await,
        UpdateStatus::InvalidRecord
    );
}

/// The same bytes: a STORE refreshes the expiry of the stored record, so that
/// republication keeps it alive, and adds the sender to the routing table;
/// an UPDATE does neither. Nothing is verified.
#[tokio::test]
async fn the_same_bytes_refresh_by_store_and_not_by_update() {
    let (protocol, handler) = replica().await;
    let chain = Chain::with_versions(1);
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(1).to_vec());
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let updater = [4; ID_LEN];
    assert_eq!(
        protocol
            .rpc_update(updater, sender_addr(), chain.key, chain.version(1).to_vec())
            .await,
        Some(UpdateStatus::AlreadyStored)
    );
    assert_eq!(
        protocol.storage.iter_older_than(1).len(),
        1,
        "an UPDATE does not refresh"
    );
    assert!(!knows(&protocol, updater).await);

    assert_eq!(
        store(&protocol, chain.key, chain.version(1)).await,
        Some(StoreStatus::AlreadyStored)
    );
    assert!(
        protocol.storage.iter_older_than(1).is_empty(),
        "a STORE refreshes"
    );
    assert!(knows(&protocol, SENDER).await);
    assert_eq!(handler.verified(), 0);
}

/// A successor that does not fit in the budget is `CapacityExceeded`, and the
/// stored version stays.
#[tokio::test]
async fn a_successor_beyond_the_budget_leaves_the_stored_version() {
    let chain = Chain::with_versions(1);
    let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
        -1,
        ID_LEN + chain.version(1).len() + 10,
    ));
    let (protocol, _) = replica_with(storage).await;
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(1).to_vec());
    let mut chain = chain;
    chain.keys.push(new_key());
    let v2 = larger_version(&chain, 2);
    assert_eq!(
        update(&protocol, chain.key, &v2).await,
        UpdateStatus::CapacityExceeded
    );
    assert_eq!(
        store(&protocol, chain.key, &v2).await,
        Some(StoreStatus::CapacityExceeded)
    );
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(1).to_vec())
    );
}

// ---- Version 0 at a replica that holds nothing ---------------------------------------

/// With `n` = 2 nodes asked, the quorum is 2: both claiming a later version
/// refuse version 0, one alone does not.
#[tokio::test]
async fn version_0_is_refused_when_the_quorum_claims_a_later_version() {
    let chain = Chain::with_versions(2);
    let (protocol, handler) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![
            Neighbour::Holder(1, chain.version(1).to_vec()),
            Neighbour::Holder(2, chain.version(2).to_vec()),
        ],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(0)).await,
        Some(StoreStatus::NewerClaimed)
    );
    assert_eq!(protocol.storage.get(&chain.key), None);
    assert_eq!(handler.verified(), 0);

    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![
            Neighbour::Holder(2, chain.version(2).to_vec()),
            Neighbour::Empty,
        ],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(0)).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(0).to_vec())
    );
}

/// One node holding another version 0, the same document signed again (or
/// signed by whoever stole the first key), refuses it.
#[tokio::test]
async fn version_0_is_refused_when_a_node_holds_another_version_0() {
    let chain = Chain::new();
    let again = sign(
        &chain.doc(
            0,
            None,
            chain.keys[0].public_key(),
            chain.keys[1].public_key(),
        ),
        &chain.keys[0],
    );
    let (protocol, handler) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::Holder(0, again), Neighbour::Empty],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(0)).await,
        Some(StoreStatus::Conflict)
    );
    assert_eq!(protocol.storage.get(&chain.key), None);
    assert_eq!(handler.verified(), 0);
}

/// Never accept on silence: a node that does not answer, or nobody to ask,
/// gives no answer to the sender.
#[tokio::test]
async fn version_0_gets_no_answer_on_silence_or_with_nobody_to_ask() {
    let chain = Chain::new();
    let (protocol, _) = replica().await;
    assert_eq!(store(&protocol, chain.key, chain.version(0)).await, None);
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::Empty, Neighbour::Silent],
    )
    .await;
    assert_eq!(store(&protocol, chain.key, chain.version(0)).await, None);
    assert_eq!(protocol.storage.get(&chain.key), None);
}

// ---- A replica that holds a version ------------------------------------------------------

/// A replica holding the same version 0 signed differently keeps its copy and
/// asks nobody.
#[tokio::test]
async fn version_0_signed_again_is_a_conflict_at_its_holder() {
    let chain = Chain::new();
    let again = sign(
        &chain.doc(
            0,
            None,
            chain.keys[0].public_key(),
            chain.keys[1].public_key(),
        ),
        &chain.keys[0],
    );
    let (protocol, _) = replica().await;
    let seen = neighbours(&protocol, chain.key, vec![Neighbour::Empty]).await;
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(0).to_vec());
    assert_eq!(
        store(&protocol, chain.key, &again).await,
        Some(StoreStatus::Conflict)
    );
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(0).to_vec())
    );
    assert!(asked(&seen).is_empty());
}

/// A replica holding version N−1 decides alone: a fork is a conflict, without
/// asking; the genuine successor replaces its copy, by UPDATE or by STORE,
/// with one signature verified each and no authorization but the chain.
#[tokio::test]
async fn a_holder_of_the_version_before_decides_alone() {
    let chain = Chain::with_versions(3);
    let (protocol, handler) = replica().await;
    let seen = neighbours(&protocol, chain.key, vec![Neighbour::Empty]).await;
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(1).to_vec());

    let wrong_prev = fork(&chain, 2, b"another record", &chain.keys[2]);
    assert_eq!(
        store(&protocol, chain.key, &wrong_prev).await,
        Some(StoreStatus::Conflict)
    );
    assert_eq!(
        update(&protocol, chain.key, &wrong_prev).await,
        UpdateStatus::Conflict
    );
    assert_eq!(
        handler.verified(),
        0,
        "a fork is refused without verifying it"
    );

    assert_eq!(
        update(&protocol, chain.key, chain.version(2)).await,
        UpdateStatus::Updated
    );
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(2).to_vec())
    );
    assert_eq!(
        store(&protocol, chain.key, chain.version(3)).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(3).to_vec())
    );
    assert_eq!(handler.verified(), 2);
    assert!(asked(&seen).is_empty(), "a holder asks nobody");
}

/// At the place of the stored version: proven duplicity costs one signature
/// verification, another key none, and the stored version stays; an older
/// version is stale.
#[tokio::test]
async fn another_record_at_the_stored_place_leaves_the_stored_version() {
    let chain = Chain::with_versions(2);
    let (protocol, handler) = replica().await;
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(2).to_vec());

    let mut doc = chain.doc(
        2,
        Some(chain.version(1)),
        chain.keys[2].public_key(),
        new_key().public_key(),
    );
    doc["service"][0]["serviceEndpoint"] = json!("http://attacker.example");
    let duplicity = sign(&doc, &chain.keys[2]);
    assert_eq!(
        store(&protocol, chain.key, &duplicity).await,
        Some(StoreStatus::Conflict)
    );
    assert_eq!(handler.verified(), 1);

    let attacker = new_key();
    let other_key = fork(&chain, 2, chain.version(1), &attacker);
    assert_eq!(
        store(&protocol, chain.key, &other_key).await,
        Some(StoreStatus::Conflict)
    );
    assert_eq!(handler.verified(), 1);

    assert_eq!(
        store(&protocol, chain.key, chain.version(1)).await,
        Some(StoreStatus::Stale)
    );
    assert_eq!(
        update(&protocol, chain.key, chain.version(1)).await,
        UpdateStatus::Stale
    );
    assert_eq!(handler.verified(), 1);
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(2).to_vec())
    );
}

/// The UPDATE table, row by row. An UPDATE never asks the network.
#[tokio::test]
async fn an_update_answers_why_it_is_refused() {
    let chain = Chain::with_versions(4);
    let (protocol, _) = replica().await;
    let seen = neighbours(&protocol, chain.key, vec![Neighbour::Empty]).await;
    let key = chain.key;
    let set = |seq: usize| {
        protocol
            .storage
            .set(key.to_vec(), chain.version(seq).to_vec())
    };

    assert_eq!(
        update(&protocol, key, chain.version(3)).await,
        UpdateStatus::MissingPrevious { seq: None }
    );
    set(1);
    assert_eq!(
        update(&protocol, key, chain.version(3)).await,
        UpdateStatus::MissingPrevious { seq: Some(1) }
    );
    set(4);
    assert_eq!(
        update(&protocol, key, chain.version(3)).await,
        UpdateStatus::Stale
    );
    set(3);
    assert_eq!(
        update(
            &protocol,
            key,
            &fork(&chain, 3, chain.version(2), &new_key())
        )
        .await,
        UpdateStatus::Conflict
    );
    assert_eq!(
        update(&protocol, key, chain.version(3)).await,
        UpdateStatus::AlreadyStored
    );
    set(2);
    assert_eq!(
        update(&protocol, key, &fork(&chain, 3, b"x", &chain.keys[3])).await,
        UpdateStatus::Conflict
    );
    assert_eq!(
        update(&protocol, key, Chain::new().version(0)).await,
        UpdateStatus::InvalidRecord
    );
    let mut bad_signature = chain.version(3).to_vec();
    bad_signature[20] ^= 1;
    assert_eq!(
        update(&protocol, key, &bad_signature).await,
        UpdateStatus::InvalidRecord
    );
    assert_eq!(protocol.storage.get(&key), Some(chain.version(2).to_vec()));
    assert_eq!(
        update(&protocol, key, chain.version(3)).await,
        UpdateStatus::Updated
    );
    assert_eq!(protocol.storage.get(&key), Some(chain.version(3).to_vec()));
    assert!(asked(&seen).is_empty(), "an UPDATE asks nobody");
}

/// A holder answers `FindHash` with the version it holds and its hash.
#[tokio::test]
async fn find_hash_answers_with_the_version_held() {
    let chain = Chain::with_versions(2);
    let (protocol, _) = replica().await;
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(2).to_vec());
    let answer = protocol
        .dispatch_request(
            RpcMessage::FindHash {
                sender_id: SENDER,
                key: chain.key,
            },
            "127.0.0.1:9051".parse().unwrap(),
        )
        .await;
    assert!(
        matches!(answer, Some(RpcMessage::FindHashHit { seq: 2, hash }) if hash == record_hash(chain.version(2))),
        "{answer:?}"
    );
}

// ---- Replacing atomically -----------------------------------------------------------------

/// Two valid versions 3, both signed by the key version 2 commits to, sent at
/// once to a replica holding version 2: one is stored, the other is a
/// conflict (proven duplicity).
#[tokio::test]
async fn two_successors_at_once_leave_exactly_one() {
    let chain = Chain::with_versions(2);
    let (protocol, _) = replica().await;
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(2).to_vec());
    let successors: Vec<Vec<u8>> = ["a", "b"]
        .iter()
        .map(|tag| {
            let mut doc = chain.doc(
                3,
                Some(chain.version(2)),
                chain.keys[3].public_key(),
                new_key().public_key(),
            );
            doc["service"][0]["serviceEndpoint"] = json!(format!("http://example.com/{tag}"));
            sign(&doc, &chain.keys[3])
        })
        .collect();
    let (first, second) = tokio::join!(
        update(&protocol, chain.key, &successors[0]),
        update(&protocol, chain.key, &successors[1]),
    );
    let mut statuses = [first, second];
    statuses.sort_by_key(|status| format!("{status:?}"));
    assert_eq!(statuses, [UpdateStatus::Conflict, UpdateStatus::Updated]);
    let winner = if first == UpdateStatus::Updated {
        &successors[0]
    } else {
        &successors[1]
    };
    assert_eq!(protocol.storage.get(&chain.key).as_ref(), Some(winner));
}

/// A version 1 checked against the network while version 0 is stored
/// meanwhile is checked again, as a successor of version 0, and stored.
#[tokio::test]
async fn a_version_checked_while_its_predecessor_arrives_is_checked_again() {
    let chain = Chain::with_versions(1);
    let (protocol, _) = replica().await;
    let (peer, contact) = raw_peer({
        let mut id = chain.key;
        id[ID_LEN - 1] ^= 1;
        id
    })
    .await;
    protocol.router.write().await.add_contact(contact);
    let replica = Arc::clone(&protocol);
    let v1 = chain.version(1).to_vec();
    let key = chain.key;
    let stored = tokio::spawn(async move { store(&replica, key, &v1).await });

    let (question, from) = read_frame_of_kind(&peer, true).await;
    assert!(matches!(question.message, RpcMessage::FindHash { .. }));
    protocol
        .storage
        .insert_if_absent(chain.key.to_vec(), chain.version(0).to_vec());
    send_raw(
        &peer,
        from,
        question.msg_id,
        false,
        RpcMessage::FindHashHit {
            seq: 0,
            hash: record_hash(chain.version(0)),
        },
    )
    .await;
    if let Some((fetch, from)) = try_read_frame(&peer, Duration::from_secs(1)).await {
        send_raw(
            &peer,
            from,
            fetch.msg_id,
            false,
            RpcMessage::FindValueHit {
                value: chain.version(0).to_vec(),
            },
        )
        .await;
    }
    assert_eq!(stored.await.unwrap(), Some(StoreStatus::Stored));
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(1).to_vec())
    );
}

// ---- A version N ≥ 1 at a replica that holds nothing -----------------------------------------

/// Every refusing answer refuses, also when another node is silent: a node
/// claims a newer version, holds another version N, holds a version N−1 the
/// record does not follow, or holds an older one.
#[tokio::test]
async fn a_refusing_answer_refuses_a_version_n() {
    let chain = Chain::with_versions(3);
    let v2 = chain.version(2);
    let attacker = new_key();
    for (neighbour, expected) in [
        (Neighbour::Claims(3, [9; ID_LEN]), StoreStatus::NewerClaimed),
        (
            Neighbour::Holder(2, fork(&chain, 2, chain.version(1), &attacker)),
            StoreStatus::Conflict,
        ),
        (Neighbour::Claims(1, [9; ID_LEN]), StoreStatus::Conflict),
        (
            Neighbour::Holder(0, chain.version(0).to_vec()),
            StoreStatus::Conflict,
        ),
    ] {
        let (protocol, handler) = replica().await;
        neighbours(
            &protocol,
            chain.key,
            vec![neighbour, Neighbour::Holder(2, v2.to_vec())],
        )
        .await;
        assert_eq!(store(&protocol, chain.key, v2).await, Some(expected));
        assert_eq!(protocol.storage.get(&chain.key), None);
        assert_eq!(handler.verified(), 0);
    }
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::Claims(3, [9; ID_LEN]), Neighbour::Silent],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, v2).await,
        Some(StoreStatus::NewerClaimed)
    );
}

/// Version 1: one node holding version 0, fetched and checked, is enough.
#[tokio::test]
async fn version_1_needs_one_holder_of_version_0() {
    let chain = Chain::with_versions(1);
    let (protocol, handler) = replica().await;
    let seen = neighbours(
        &protocol,
        chain.key,
        vec![
            Neighbour::Holder(0, chain.version(0).to_vec()),
            Neighbour::Empty,
        ],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(1)).await,
        Some(StoreStatus::Stored)
    );
    assert_eq!(
        protocol.storage.get(&chain.key),
        Some(chain.version(1).to_vec())
    );
    assert_eq!(
        handler.verified(),
        2,
        "version 0's signature and version 1's"
    );
    assert!(asked(&seen).contains(&"FindValue"));
}

/// Version N ≥ 2: votes for it and for version N−1 together reach the
/// quorum; one short gives no answer.
#[tokio::test]
async fn version_n_needs_the_quorum() {
    let chain = Chain::with_versions(2);
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![
            Neighbour::Holder(2, chain.version(2).to_vec()),
            Neighbour::Holder(1, chain.version(1).to_vec()),
            Neighbour::Holder(1, chain.version(1).to_vec()),
        ],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(2)).await,
        Some(StoreStatus::Stored)
    );

    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![
            Neighbour::Holder(2, chain.version(2).to_vec()),
            Neighbour::Holder(1, chain.version(1).to_vec()),
            Neighbour::Empty,
        ],
    )
    .await;
    assert_eq!(store(&protocol, chain.key, chain.version(2)).await, None);
    assert_eq!(protocol.storage.get(&chain.key), None);
}

/// The fetch asks the next voter when one gives no record, or one that does
/// not hash to `prev`; past the deadline it gives no answer.
#[tokio::test]
async fn the_fetch_asks_the_next_voter() {
    let chain = Chain::with_versions(1);
    let v0 = chain.version(0);
    let again = sign(
        &chain.doc(
            0,
            None,
            chain.keys[0].public_key(),
            chain.keys[1].public_key(),
        ),
        &chain.keys[0],
    );
    for first in [
        Neighbour::Claims(0, record_hash(v0)),
        Neighbour::ClaimsServing(0, record_hash(v0), again.clone()),
    ] {
        let (protocol, _) = replica().await;
        neighbours(
            &protocol,
            chain.key,
            vec![first, Neighbour::Holder(0, v0.to_vec())],
        )
        .await;
        assert_eq!(
            store(&protocol, chain.key, chain.version(1)).await,
            Some(StoreStatus::Stored)
        );
    }
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::ClaimsThenSilent(0, record_hash(v0))],
    )
    .await;
    let started = Instant::now();
    assert_eq!(store(&protocol, chain.key, chain.version(1)).await, None);
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
}

/// The key security case at a replica that holds nothing: right after
/// version 0, a version 1 whose `prev` is the real version 0, signed by a key
/// version 0 does not commit to (an attacker's, or version 0's own).
#[tokio::test]
async fn a_forged_version_1_is_refused_by_the_fetched_version_0() {
    let chain = Chain::new();
    for signer in [new_key(), chain.keys[0].clone()] {
        let forged = fork(&chain, 1, chain.version(0), &signer);
        let (protocol, _) = replica().await;
        neighbours(
            &protocol,
            chain.key,
            vec![Neighbour::Holder(0, chain.version(0).to_vec())],
        )
        .await;
        assert_eq!(
            store(&protocol, chain.key, &forged).await,
            Some(StoreStatus::Conflict)
        );
        assert_eq!(protocol.storage.get(&chain.key), None);
    }
}

/// A version N whose own signature does not verify is `InvalidRecord`.
#[tokio::test]
async fn a_version_n_with_a_bad_signature_is_invalid() {
    let chain = Chain::with_versions(1);
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::Holder(0, chain.version(0).to_vec())],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, chain.version(1)).await,
        Some(StoreStatus::Stored)
    );

    let mut bad = chain.version(1).to_vec();
    bad[20] ^= 1;
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::Holder(0, chain.version(0).to_vec())],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, &bad).await,
        Some(StoreStatus::InvalidRecord)
    );
}

/// One node serving a made-up version 0 that commits to its own key, after
/// which its version 1 follows: the made-up version does not bind to the key.
#[tokio::test]
async fn a_made_up_version_0_gets_nothing_accepted() {
    let chain = Chain::new();
    let (attacker, next) = (new_key(), new_key());
    let mut doc = chain.doc(0, None, attacker.public_key(), next.public_key());
    doc["service"][0]["serviceEndpoint"] = json!("http://attacker.example");
    let made_up = sign(&doc, &attacker);
    let forged = fork(&chain, 1, &made_up, &next);
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![Neighbour::ClaimsServing(0, record_hash(&made_up), made_up)],
    )
    .await;
    assert_eq!(
        store(&protocol, chain.key, &forged).await,
        Some(StoreStatus::Conflict)
    );
    assert_eq!(protocol.storage.get(&chain.key), None);
}

/// Version N ≥ 2: one node serving a made-up version N−1 that commits to the
/// attacker's key is one vote, below the quorum.
#[tokio::test]
async fn a_made_up_version_n_minus_1_is_one_vote() {
    let chain = Chain::with_versions(1);
    let (attacker, next) = (new_key(), new_key());
    let made_up = sign(
        &chain.doc(
            1,
            Some(chain.version(0)),
            attacker.public_key(),
            next.public_key(),
        ),
        &attacker,
    );
    let forged = fork(&chain, 2, &made_up, &next);
    let (protocol, _) = replica().await;
    neighbours(
        &protocol,
        chain.key,
        vec![
            Neighbour::ClaimsServing(1, record_hash(&made_up), made_up),
            Neighbour::Empty,
        ],
    )
    .await;
    assert_eq!(store(&protocol, chain.key, &forged).await, None);
    assert_eq!(protocol.storage.get(&chain.key), None);
}
