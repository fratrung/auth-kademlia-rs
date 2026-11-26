//! What a node that has just started asks its neighbours: which records it
//! should hold (`ListKeys`), so that it fetches those it lacks or holds at a
//! lower position. Nodes that meet a node send it its records
//! (`welcome.rs`), but a neighbour that never noticed it was gone sends
//! nothing, and a node restarted from its data directory misses what was
//! rotated or first published while it was down: both would wait for a
//! republication, once a day.
//!
//! A neighbour answers with lists of keys, each with the position and
//! SHA-256 of its record, one datagram per page; the node fetches each
//! record from a neighbour that listed it, checks that it is what was
//! listed, verifies its signature, and writes it by the rules of a replica.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use primitive_types::U256;
use tokio::sync::Semaphore;

use crate::auth_handler::rules::{decide_locally, Held, Local};
use crate::auth_handler::tree::tree_form;
use crate::crawling::{RPCFindResponse, SpiderProtocol};
use crate::node::Node;
use crate::protocol::messages::{record_hash, KeyEntry, RpcMessage, RECORD_HASH_LEN};
use crate::routing::RoutingTable;
use crate::storage::{IStorage, ReplaceStatus, StorageWriteStatus};
use crate::utils::{digest, ID_LEN, STATUS_LIST_KEY};

use super::welcome::WELCOME_SCAN_CHUNK;
use super::KademliaProtocol;

/// Entries in one page: the most that fit in one datagram with the frame
/// around them (`FRAG_CHUNK_SIZE`), so that a page is never fragmented. A
/// lost page is asked again alone, and a page takes no place among the
/// messages in reassembly, which the fetches use.
pub(super) const PAGE_ENTRIES: usize = 19;

/// How long a synchronization lasts at most, from its first list request.
/// With neighbours that answer, the records of DIDs take well under a
/// second; the bound is for a neighbour that lists keys it never shows,
/// each of which costs a fetch until `RPC_TIMEOUT`. What was written by then
/// stays, and the rest comes with a republication.
const SYNC_DEADLINE: Duration = Duration::from_secs(30);

/// Pages asked of one neighbour at most, about 1,200 keys: the records of
/// DIDs take one or two. A neighbour that lists made-up keys page after page
/// fills no more memory than this before the deadline; keys beyond them come
/// with a republication.
const MAX_PAGES: usize = 64;

/// Records fetched at once.
const FETCHES: usize = 4;

/// Records fetched at once from one neighbour: a peer has at most
/// `MAX_REASSEMBLY_ENTRIES_PER_PEER` (8) messages in reassembly here.
const FETCHES_PER_NEIGHBOUR: usize = 2;

/// Neighbours asked at least, whatever `k`. With a small `k` the other
/// holders of a key are few and all close to this node: in a simulation
/// with `k` = 3, the 3 closest held no copy of 4% to 6% of the keys a node
/// should hold, the 10 closest of none.
const MIN_ASKED: usize = 10;

/// Records a neighbour may answer it does not hold, of those it listed,
/// before it is asked for no more: a neighbour that lists keys it does not
/// hold would otherwise cost a fetch for each of them.
const NOT_HELD_LIMIT: usize = 2;

impl KademliaProtocol {
    /// Answer `ListKeys`: the next page of the keys of the records this node
    /// holds of which the sender is one of the `k` closest nodes it knows,
    /// the test the welcome replication makes. One page at a time, whoever
    /// asks: a request that arrives while one is built gets no answer, which
    /// bounds the scans of the storage however many addresses ask, and the
    /// sender asks again or goes on with its other neighbours.
    pub(super) async fn rpc_list_keys(
        self: &Arc<Self>,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        after: Option<[u8; ID_LEN]>,
    ) -> Option<RpcMessage> {
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.schedule_welcome_if_new(source.clone()).await;
        let Some(_building) = Building::start(&self.building_page) else {
            log::debug!("No page for {source}: another one is being built");
            return None;
        };
        let (entries, more) = self.page_for(&source, after).await;
        #[cfg(feature = "testbed")]
        if self.lie() == super::Lie::MadeUpKeys {
            return Some(RpcMessage::KeyList {
                entries: made_up_page(after, &entries),
                more: true,
            });
        }
        Some(RpcMessage::KeyList { entries, more })
    }

    /// The keys after `after` that `requester` should hold, in key order, at
    /// most one page, and whether more follow.
    async fn page_for(
        &self,
        requester: &Node,
        after: Option<[u8; ID_LEN]>,
    ) -> (Vec<KeyEntry>, bool) {
        let mut keys: Vec<[u8; ID_LEN]> = self
            .storage
            .live_keys()
            .iter()
            .filter_map(|key| <[u8; ID_LEN]>::try_from(key.as_slice()).ok())
            .filter(|key| after.is_none_or(|after| *key > after))
            .collect();
        keys.sort_unstable();
        let mut entries = Vec::with_capacity(PAGE_ENTRIES);
        let mut keys = keys.into_iter().peekable();
        while keys.peek().is_some() {
            // One read lock per chunk, as the welcome scan: a node making
            // contact meanwhile enters the table without waiting for the
            // whole scan.
            let router = self.router.read().await;
            for key in keys.by_ref().take(WELCOME_SCAN_CHUNK) {
                if !should_hold(&router, requester, &key, self.ksize) {
                    continue;
                }
                if entries.len() == PAGE_ENTRIES {
                    return (entries, true);
                }
                if let Some(entry) = self.entry_of(key) {
                    entries.push(entry);
                }
            }
        }
        (entries, false)
    }

    /// The entry of the record held for `key`, if it is live and one this
    /// node serves (`rpc_find_value`).
    fn entry_of(&self, key: [u8; ID_LEN]) -> Option<KeyEntry> {
        let value = self.storage.get(&key)?;
        if !self.key_binding_is_valid(&key, &value) {
            return None;
        }
        Some(KeyEntry {
            key,
            seq: tree_form(&key, &value).map_or(0, |form| form.seq),
            hash: record_hash(&value),
        })
    }

    /// Whether this node has started its synchronization since it began
    /// listening.
    pub(crate) fn has_synchronized(&self) -> bool {
        self.synchronized.load(Ordering::Acquire)
    }

    /// Start, once per `listen`, the synchronization with the neighbours
    /// `to_ask` chooses. Nothing when none of them can be asked: a later
    /// lookup starts it.
    pub(crate) async fn start_synchronization(self: &Arc<Self>, answered: &[Node]) {
        if self.has_synchronized() {
            return;
        }
        let neighbours = self.to_ask(answered).await;
        if neighbours.is_empty() || self.synchronized.swap(true, Ordering::AcqRel) {
            return;
        }
        let protocol = Arc::clone(self);
        self.spawn_task(async move {
            log::info!("Synchronizing with {} neighbours", neighbours.len());
            let progress = Progress::default();
            let finished =
                tokio::time::timeout(SYNC_DEADLINE, protocol.synchronize(&neighbours, &progress))
                    .await
                    .is_ok();
            let (listed, taken) = (
                progress.listed.load(Ordering::Relaxed),
                progress.taken.load(Ordering::Relaxed),
            );
            if finished {
                log::info!("Synchronized: {listed} keys listed, {taken} records taken");
            } else {
                log::warn!(
                    "Synchronization stopped at its deadline: {listed} keys listed, {taken} records taken; the others come with a republication"
                );
            }
        });
    }

    /// The neighbours a synchronization asks:
    /// `max(alpha, ceil(k / 2), MIN_ASKED)`, chosen by `spread` among the
    /// `max(k, that number)` closest to this node of `answered`, the nodes
    /// that answered a lookup of its own id, and of its contacts that are not
    /// failing. With `k` = 20, 10 of the 20 closest; with `k` below 10, the
    /// 10 closest, more than a lookup returns.
    async fn to_ask(&self, answered: &[Node]) -> Vec<Node> {
        let count = self.alpha.max(self.ksize.div_ceil(2)).max(MIN_ASKED);
        let among = self.ksize.max(count);
        // Those that answered first: of one id known twice, the address it
        // answered from is kept.
        let mut known = answered.to_vec();
        known.extend(
            self.router
                .read()
                .await
                .healthy_closest(&self.source_node, among),
        );
        spread(&self.source_node, &known, among, count)
    }

    /// Ask `neighbours` for the keys this node should hold, and take the
    /// records it lacks or holds at a lower position, the keys listed by more
    /// neighbours first. Stops when the storage budget is reached or a write
    /// cannot be made durable.
    async fn synchronize(self: &Arc<Self>, neighbours: &[Node], progress: &Progress) {
        let lists =
            futures::future::join_all(neighbours.iter().map(|neighbour| self.list_of(neighbour)))
                .await;
        let wanted = merge(&lists);
        progress.listed.store(wanted.len(), Ordering::Relaxed);
        let sources: Vec<Source> = neighbours.iter().map(Source::new).collect();
        let stopped = AtomicBool::new(false);
        stream::iter(&wanted)
            .for_each_concurrent(FETCHES, |wanted| {
                let (sources, stopped) = (&sources, &stopped);
                async move {
                    if stopped.load(Ordering::Relaxed) {
                        return;
                    }
                    match self.take(wanted, sources).await {
                        Taken::Written => {
                            progress.taken.fetch_add(1, Ordering::Relaxed);
                        }
                        Taken::Full => {
                            log::warn!("Synchronization stopped: the storage budget is reached");
                            stopped.store(true, Ordering::Relaxed);
                        }
                        Taken::Failed => {
                            log::error!("Synchronization stopped: a record could not be written");
                            stopped.store(true, Ordering::Relaxed);
                        }
                        Taken::Kept | Taken::NotShown => {}
                    }
                }
            })
            .await;
    }

    /// The keys `neighbour` lists for this node, page after page, up to
    /// `MAX_PAGES`. A page longer than `PAGE_ENTRIES`, or whose keys do not
    /// follow the last one received in order, ends the list.
    async fn list_of(&self, neighbour: &Node) -> Vec<KeyEntry> {
        let mut listed: Vec<KeyEntry> = Vec::new();
        for _ in 0..MAX_PAGES {
            let after = listed.last().map(|entry| entry.key);
            let Some((page, more)) = self.call_list_keys(neighbour, after).await else {
                break;
            };
            if page.len() > PAGE_ENTRIES || !follows(after, &page) {
                log::warn!("{neighbour} sent a page out of order or too long");
                break;
            }
            let last = page.is_empty() || !more;
            listed.extend(page);
            if last {
                break;
            }
        }
        listed
    }

    /// Fetch and write a record of `wanted`: the highest position listed
    /// that this node would take, from a neighbour that listed it. Past a
    /// neighbour that does not show it, or shows something else, the next
    /// one that listed it, then a lower position. A neighbour that has said
    /// `NOT_HELD_LIMIT` times it does not hold a record it listed is passed
    /// over.
    async fn take(self: &Arc<Self>, wanted: &Wanted, sources: &[Source<'_>]) -> Taken {
        let key = wanted.key;
        for claim in &wanted.claims {
            if !self.would_take(&key, claim.seq) {
                continue;
            }
            for &index in &claim.listers {
                let source = &sources[index];
                let fetched = {
                    let Ok(_permit) = source.permits.acquire().await else {
                        continue;
                    };
                    if !source.still_asked() {
                        continue;
                    }
                    let fetched = self.fetch(source.node, key).await;
                    // Counted before the permit is released, so that the
                    // next fetch from it sees the count.
                    if matches!(fetched, Fetched::NotHeld)
                        && source.not_held.fetch_add(1, Ordering::Relaxed) + 1 == NOT_HELD_LIMIT
                    {
                        log::warn!(
                            "{} listed records it does not hold: no more are asked of it",
                            source.node
                        );
                    }
                    fetched
                };
                let record = match fetched {
                    Fetched::Record(record) => record,
                    Fetched::NotHeld => {
                        log::debug!(
                            "{} does not hold the record of {} it listed",
                            source.node,
                            hex::encode(key)
                        );
                        continue;
                    }
                    Fetched::Silent => {
                        log::debug!(
                            "{} did not answer for the record of {} it listed",
                            source.node,
                            hex::encode(key)
                        );
                        continue;
                    }
                };
                if !shows_entry(&key, claim, &record) || !self.verify_for_key(&key, &record).await {
                    log::warn!(
                        "{} showed for {} a record other than the one it listed, or invalid",
                        source.node,
                        hex::encode(key)
                    );
                    continue;
                }
                return self.write_pulled(&key, record);
            }
        }
        Taken::NotShown
    }

    /// Whether this node would take a record of `key` at `seq`, by what it
    /// holds: nothing, a lower position, or a remembered position not above
    /// it. The Status List only when it holds none: first writer wins.
    fn would_take(&self, key: &[u8; ID_LEN], seq: u64) -> bool {
        if *key == digest(STATUS_LIST_KEY) {
            return self.storage.get(key).is_none();
        }
        match self.storage.record_or_marker(key) {
            // Only verified records are stored, so one without this form
            // predates it: any valid record replaces it.
            (Some(held), _) => tree_form(key, &held).map_or(true, |form| seq > form.seq),
            (None, Some(remembered)) => seq >= remembered,
            (None, None) => true,
        }
    }

    async fn fetch(self: &Arc<Self>, peer: &Node, key: [u8; ID_LEN]) -> Fetched {
        let answer = RPCFindResponse::new(
            Arc::clone(self)
                .call_find_value(peer.clone(), Node::from_id(key))
                .await,
        );
        match answer.get_value() {
            Some(record) => Fetched::Record(record),
            None if answer.happened() => Fetched::NotHeld,
            None => Fetched::Silent,
        }
    }

    /// Write `record`, verified, by the rules of a replica, as a repair does:
    /// over nothing, a remembered position or a lower one, never over a
    /// higher position or another record at its own. A concurrent writer may
    /// store a record meanwhile: the write is decided once more.
    fn write_pulled(&self, key: &[u8; ID_LEN], record: Vec<u8>) -> Taken {
        if *key == digest(STATUS_LIST_KEY) {
            return Taken::of(self.storage.insert_if_absent(key.to_vec(), record));
        }
        for _ in 0..2 {
            let (held, marker) = self.storage.record_or_marker(key);
            match decide_locally(key, Held::of(held.as_deref(), marker), &record) {
                Local::AskNetwork(_) => {
                    match self.storage.insert_if_absent(key.to_vec(), record.clone()) {
                        StorageWriteStatus::Conflict => continue,
                        status => return Taken::of(status),
                    }
                }
                Local::VerifyAndReplace => {
                    let Some(held) = held else {
                        continue;
                    };
                    match self.storage.replace_if(key, &held, record.clone()) {
                        ReplaceStatus::Replaced => return Taken::Written,
                        ReplaceStatus::Changed => continue,
                        ReplaceStatus::CapacityExceeded => return Taken::Full,
                        ReplaceStatus::WriteFailed => return Taken::Failed,
                    }
                }
                Local::AlreadyStored
                | Local::Stale { .. }
                | Local::VerifyConflict(_)
                | Local::Invalid(_) => return Taken::Kept,
            }
        }
        Taken::Kept
    }
}

/// Holds the flag of the page being built; dropped, it releases it.
struct Building<'a>(&'a AtomicBool);

impl<'a> Building<'a> {
    fn start(flag: &'a AtomicBool) -> Option<Self> {
        (!flag.swap(true, Ordering::AcqRel)).then_some(Self(flag))
    }
}

impl Drop for Building<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Testbed only: the page a node that lies in `ListKeys` sends after
/// `after`: the keys of `honest`, the page it would send, at a position far
/// ahead under made-up hashes, then made-up keys after them up to a full
/// page, in key order. Made-up keys follow each other closely, so that pages
/// never run out.
#[cfg(feature = "testbed")]
fn made_up_page(after: Option<[u8; ID_LEN]>, honest: &[KeyEntry]) -> Vec<KeyEntry> {
    use crate::auth_handler::did::MAX_INTEGER;
    let lie = |key| KeyEntry {
        key,
        seq: MAX_INTEGER,
        hash: rand::random(),
    };
    let mut entries: Vec<KeyEntry> = honest.iter().map(|entry| lie(entry.key)).collect();
    let mut last = match (honest.last(), after) {
        (Some(entry), _) => U256::from_big_endian(&entry.key),
        (None, Some(after)) => U256::from_big_endian(&after),
        (None, None) => U256::from_big_endian(&rand::random::<[u8; ID_LEN]>()) >> 1,
    };
    while entries.len() < PAGE_ENTRIES {
        let step = (U256::one() << 200) + U256::from(rand::random::<u64>());
        let Some(next) = last.checked_add(step) else {
            break;
        };
        last = next;
        let mut key = [0; ID_LEN];
        next.to_big_endian(&mut key);
        entries.push(lie(key));
    }
    entries
}

/// Whether `node` should hold `key` by the contacts of `router`: one of the
/// `k` closest to it, `node` left out of them.
fn should_hold(router: &RoutingTable, node: &Node, key: &[u8; ID_LEN], k: usize) -> bool {
    let target = Node::from_id(*key);
    let neighbours = router.find_neighbors(&target, Some(node));
    neighbours.len() < k
        || neighbours
            .last()
            .is_none_or(|last| node.distance_to(&target) < last.distance_to(&target))
}

/// Whether the keys of `page` come after `after` in strictly increasing
/// order.
fn follows(after: Option<[u8; ID_LEN]>, page: &[KeyEntry]) -> bool {
    let mut last = after;
    page.iter().all(|entry| {
        let in_order = last.is_none_or(|last| entry.key > last);
        last = Some(entry.key);
        in_order
    })
}

/// `count` of `known`, among the `among` closest to `own`, spread across the
/// tree of ids: the closest first, then each time the one farthest, by XOR,
/// from the nearest of those already chosen, passing over a node at an IP
/// address already chosen. Nodes far from each other are close to different
/// keys, so they list more of the keys this node should hold than as many
/// nodes next to each other do; made-up ids close to this node share one
/// branch, from which few are taken, and one address gets one place however
/// many ids answer from it.
pub(super) fn spread(own: &Node, known: &[Node], among: usize, count: usize) -> Vec<Node> {
    let mut candidates: Vec<&Node> = known
        .iter()
        .filter(|node| node.id != own.id && node.address().is_some())
        .collect();
    // Stable: of one id known twice, the first is kept.
    candidates.sort_by_key(|node| node.distance_to(own));
    candidates.dedup_by_key(|node| node.id);
    candidates.truncate(among);

    let mut chosen: Vec<&Node> = Vec::with_capacity(count);
    let mut addresses: HashSet<&str> = HashSet::new();
    while chosen.len() < count {
        let mut best: Option<(usize, U256)> = None;
        for (index, candidate) in candidates.iter().enumerate() {
            let Some(ip) = candidate.ip.as_deref() else {
                continue;
            };
            if addresses.contains(ip) {
                continue;
            }
            let apart = chosen
                .iter()
                .map(|node| node.distance_to(candidate))
                .min()
                .unwrap_or(U256::MAX);
            // Strictly farther: among equals, the one closer to this node.
            if best.is_none_or(|(_, farthest)| apart > farthest) {
                best = Some((index, apart));
            }
        }
        let Some((index, _)) = best else {
            break;
        };
        let node = candidates.remove(index);
        if let Some(ip) = node.ip.as_deref() {
            addresses.insert(ip);
        }
        chosen.push(node);
    }
    chosen.into_iter().cloned().collect()
}

/// A record listed for one key: its position and hash, and the neighbours
/// that listed it, by index.
#[derive(Debug, PartialEq, Eq)]
struct Claim {
    seq: u64,
    hash: [u8; RECORD_HASH_LEN],
    listers: Vec<usize>,
}

/// A key listed by some neighbours: what they listed, the highest position
/// first, and how many listed it.
#[derive(Debug, PartialEq, Eq)]
struct Wanted {
    key: [u8; ID_LEN],
    listers: usize,
    claims: Vec<Claim>,
}

/// The keys of `lists`, the list of each neighbour, those listed by more
/// neighbours first. A key this node should hold is listed by most of the
/// neighbours it asks; a key made up by one is listed by that one alone, so
/// its fetches come last, where the deadline cuts them.
fn merge(lists: &[Vec<KeyEntry>]) -> Vec<Wanted> {
    let mut keys: BTreeMap<[u8; ID_LEN], Vec<Claim>> = BTreeMap::new();
    for (neighbour, list) in lists.iter().enumerate() {
        for entry in list {
            let claims = keys.entry(entry.key).or_default();
            match claims
                .iter_mut()
                .find(|claim| claim.seq == entry.seq && claim.hash == entry.hash)
            {
                Some(claim) => claim.listers.push(neighbour),
                None => claims.push(Claim {
                    seq: entry.seq,
                    hash: entry.hash,
                    listers: vec![neighbour],
                }),
            }
        }
    }
    let mut wanted: Vec<Wanted> = keys
        .into_iter()
        .map(|(key, mut claims)| {
            claims.sort_by(|a, b| {
                b.seq
                    .cmp(&a.seq)
                    .then(b.listers.len().cmp(&a.listers.len()))
            });
            Wanted {
                key,
                listers: claims.iter().map(|claim| claim.listers.len()).sum(),
                claims,
            }
        })
        .collect();
    // Stable: in key order among keys listed by as many neighbours.
    wanted.sort_by_key(|wanted| std::cmp::Reverse(wanted.listers));
    wanted
}

/// Whether `record`, fetched for `claim`, is the record listed: it hashes to
/// the entry, and a DID record has the form of a record of `key` at the
/// position listed. The caller then verifies its signature.
fn shows_entry(key: &[u8; ID_LEN], claim: &Claim, record: &[u8]) -> bool {
    record_hash(record) == claim.hash
        && (*key == digest(STATUS_LIST_KEY)
            || tree_form(key, record).is_ok_and(|form| form.seq == claim.seq))
}

/// A neighbour records are fetched from: the fetches it may have in flight,
/// and how many records it listed and then said it does not hold.
struct Source<'a> {
    node: &'a Node,
    permits: Semaphore,
    not_held: AtomicUsize,
}

impl<'a> Source<'a> {
    fn new(node: &'a Node) -> Self {
        Self {
            node,
            permits: Semaphore::new(FETCHES_PER_NEIGHBOUR),
            not_held: AtomicUsize::new(0),
        }
    }

    /// Whether it is still asked for records: it has said fewer than
    /// `NOT_HELD_LIMIT` times that it does not hold one it listed. A record
    /// other than the one listed does not count, since it may have taken a
    /// higher position after its list.
    fn still_asked(&self) -> bool {
        self.not_held.load(Ordering::Relaxed) < NOT_HELD_LIMIT
    }
}

/// The answer to the fetch of a record listed.
enum Fetched {
    Record(Vec<u8>),
    /// It answered with nodes: it holds no record of the key.
    NotHeld,
    /// No answer.
    Silent,
}

/// How the synchronization of one key ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Taken {
    Written,
    /// Nothing written: this node holds it already, or holds now a higher
    /// position or another record at its own.
    Kept,
    /// No neighbour showed a record it would take.
    NotShown,
    /// The storage budget is reached.
    Full,
    /// The record could not be made durable.
    Failed,
}

impl Taken {
    fn of(status: StorageWriteStatus) -> Self {
        match status {
            StorageWriteStatus::Stored => Self::Written,
            StorageWriteStatus::AlreadyStored | StorageWriteStatus::Conflict => Self::Kept,
            StorageWriteStatus::CapacityExceeded => Self::Full,
            StorageWriteStatus::WriteFailed => Self::Failed,
        }
    }
}

/// What a synchronization did so far, read once it ends or its deadline
/// passes.
#[derive(Default)]
struct Progress {
    listed: AtomicUsize,
    taken: AtomicUsize,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use tokio::net::UdpSocket;

    use crate::auth_handler::test_tree::{body, TreeOwner, PLACEHOLDER};
    use crate::fragmentation::FRAG_CHUNK_SIZE;
    use crate::protocol::messages::Frame;
    use crate::protocol::test_support::*;
    use crate::storage::ForgetfulStorage;

    use super::*;

    /// A node with id `id` holding `records` in `storage`, serving.
    async fn node_with_storage(
        id: [u8; ID_LEN],
        records: &[([u8; ID_LEN], Vec<u8>)],
        storage: ForgetfulStorage,
    ) -> Arc<KademliaProtocol> {
        for (key, record) in records {
            storage.set(key.to_vec(), record.clone());
        }
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let protocol = Arc::new(KademliaProtocol::new(
            contact_at(id, port),
            socket,
            Arc::new(storage),
            20,
            3,
            Arc::new(CountingDidHandler::new()),
            None,
        ));
        serve(&protocol);
        protocol
    }

    async fn node(id: [u8; ID_LEN], records: &[([u8; ID_LEN], Vec<u8>)]) -> Arc<KademliaProtocol> {
        node_with_storage(id, records, ForgetfulStorage::new(-1)).await
    }

    /// `node` asks `neighbours` for its records and takes them, with no
    /// deadline; how many it took.
    async fn synchronize(node: &Arc<KademliaProtocol>, neighbours: &[Node]) -> usize {
        let progress = Progress::default();
        node.synchronize(neighbours, &progress).await;
        progress.taken.load(Ordering::Relaxed)
    }

    fn entry(key: [u8; ID_LEN], seq: u64, record: &[u8]) -> KeyEntry {
        KeyEntry {
            key,
            seq,
            hash: record_hash(record),
        }
    }

    /// A neighbour that lists `entries`, in key order, in one page, and
    /// answers a `FindValue` with the record `shown` holds for its key, or
    /// with no record, counting the fetches.
    fn scripted_neighbour(
        socket: UdpSocket,
        mut entries: Vec<KeyEntry>,
        shown: HashMap<[u8; ID_LEN], Vec<u8>>,
        fetches: Arc<AtomicUsize>,
    ) {
        entries.sort_by_key(|entry| entry.key);
        tokio::spawn(async move {
            while let Some((frame, from)) = try_read_message(&socket, Duration::from_secs(10)).await
            {
                let answer = match frame.message {
                    RpcMessage::ListKeys { after: None, .. } => RpcMessage::KeyList {
                        entries: entries.clone(),
                        more: false,
                    },
                    RpcMessage::ListKeys { .. } => RpcMessage::KeyList {
                        entries: vec![],
                        more: false,
                    },
                    RpcMessage::FindValue { key, .. } => {
                        fetches.fetch_add(1, Ordering::Relaxed);
                        match shown.get(&key) {
                            Some(record) => RpcMessage::FindValueHit {
                                value: record.clone(),
                            },
                            None => RpcMessage::FindValueNodes { nodes: vec![] },
                        }
                    }
                    _ => continue,
                };
                send_raw(&socket, from, frame.msg_id, false, answer).await;
            }
        });
    }

    #[test]
    fn a_full_page_fits_in_one_datagram_and_one_more_entry_does_not() {
        let encoded = |entries: usize| {
            let frame = Frame {
                msg_id: u32::MAX,
                is_request: false,
                message: RpcMessage::KeyList {
                    entries: vec![
                        KeyEntry {
                            key: [0xff; ID_LEN],
                            seq: u64::MAX,
                            hash: [0xff; RECORD_HASH_LEN],
                        };
                        entries
                    ],
                    more: true,
                },
            };
            bincode::serialize(&frame).unwrap().len()
        };
        assert!(encoded(PAGE_ENTRIES) <= FRAG_CHUNK_SIZE);
        assert!(encoded(PAGE_ENTRIES + 1) > FRAG_CHUNK_SIZE);
    }

    /// The requester is listed a key it is closer to than the other
    /// contacts, not one that `k` contacts are closer to.
    #[tokio::test]
    async fn a_neighbour_lists_only_the_keys_the_requester_should_hold() {
        let requester = [0x80; ID_LEN];
        let mut near = requester;
        near[ID_LEN - 1] ^= 1;
        let far = [0x40; ID_LEN];
        let storage = Arc::new(ForgetfulStorage::new(-1));
        storage.set(near.to_vec(), b"near".to_vec());
        storage.set(far.to_vec(), b"far".to_vec());
        let protocol =
            test_protocol_with_storage(Arc::new(TestHandler::new(true, true)), false, storage)
                .await;
        {
            let mut router = protocol.router.write().await;
            for tag in 1..=20u8 {
                let mut id = far;
                id[ID_LEN - 1] ^= tag;
                router.add_contact(contact_at(id, 9000 + u16::from(tag)));
            }
        }

        let answer = protocol
            .rpc_list_keys(requester, ("127.0.0.1".into(), 9100), None)
            .await;
        let Some(RpcMessage::KeyList { entries, more }) = answer else {
            panic!("no page: {answer:?}");
        };
        assert_eq!(entries, vec![entry(near, 0, b"near")]);
        assert!(!more);
    }

    /// 45 keys come in three pages, in key order, each after the last key of
    /// the one before.
    #[tokio::test]
    async fn pages_follow_each_other_in_key_order() {
        let storage = Arc::new(ForgetfulStorage::new(-1));
        let mut keys: Vec<[u8; ID_LEN]> = (0..45u8)
            .map(|tag| {
                let mut key = [0x55; ID_LEN];
                key[0] = tag.wrapping_mul(97);
                key
            })
            .collect();
        for key in &keys {
            storage.set(key.to_vec(), key.to_vec());
        }
        keys.sort_unstable();
        let protocol =
            test_protocol_with_storage(Arc::new(TestHandler::new(true, true)), false, storage)
                .await;

        let mut listed = vec![];
        let mut after = None;
        let mut pages = vec![];
        loop {
            let answer = protocol
                .rpc_list_keys([0x80; ID_LEN], ("127.0.0.1".into(), 9100), after)
                .await;
            let Some(RpcMessage::KeyList { entries, more }) = answer else {
                panic!("no page: {answer:?}");
            };
            pages.push(entries.len());
            after = entries.last().map(|entry| entry.key);
            listed.extend(entries.iter().map(|entry| entry.key));
            if !more {
                break;
            }
        }
        assert_eq!(
            pages,
            vec![PAGE_ENTRIES, PAGE_ENTRIES, 45 - 2 * PAGE_ENTRIES]
        );
        assert_eq!(listed, keys);
    }

    #[tokio::test]
    async fn a_request_while_a_page_is_built_gets_no_answer() {
        let protocol = test_protocol(Arc::new(TestHandler::new(true, true)), false).await;
        let ask = || protocol.rpc_list_keys([0x80; ID_LEN], ("127.0.0.1".into(), 9100), None);
        let building = Building::start(&protocol.building_page).unwrap();
        assert!(ask().await.is_none());
        drop(building);
        assert!(matches!(ask().await, Some(RpcMessage::KeyList { .. })));
    }

    fn at(id_last: u8, top: u8, ip: &str) -> Node {
        let mut id = [0; ID_LEN];
        id[0] = top;
        id[ID_LEN - 1] = id_last;
        Node::new(id, Some(ip.to_string()), Some(9000))
    }

    /// Of a, b next to this node and c, d far from it and from each other,
    /// three spread nodes are a, c, d where the three closest are a, b, d.
    #[test]
    fn the_closest_comes_first_then_the_farthest_from_those_chosen() {
        let own = Node::from_id([0; ID_LEN]);
        let a = at(1, 0, "10.0.0.1");
        let b = at(2, 0, "10.0.0.2");
        let c = at(0, 0x80, "10.0.0.3");
        let d = at(0, 0x40, "10.0.0.4");
        let answered = [d.clone(), c.clone(), b, a.clone()];
        let ids = |nodes: Vec<Node>| nodes.iter().map(|node| node.id).collect::<Vec<_>>();
        assert_eq!(ids(spread(&own, &answered, 20, 3)), ids(vec![a, c, d]));
    }

    #[test]
    fn one_address_gets_one_place() {
        let own = Node::from_id([0; ID_LEN]);
        let a = at(1, 0, "10.0.0.1");
        let same_address = at(0, 0x80, "10.0.0.1");
        let c = at(0, 0x40, "10.0.0.3");
        let chosen = spread(&own, &[a.clone(), same_address, c.clone()], 20, 3);
        assert_eq!(
            chosen.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![a.id, c.id]
        );
    }

    /// Fewer nodes answered than it would ask: all of them, but neither
    /// itself, a node without an address, nor one beyond the `k` closest.
    #[test]
    fn fewer_nodes_than_asked_are_all_asked_among_the_k_closest() {
        let own = Node::new([0; ID_LEN], Some("10.0.0.9".into()), Some(9000));
        let a = at(1, 0, "10.0.0.1");
        let b = at(2, 0, "10.0.0.2");
        let beyond_k = at(0, 0x80, "10.0.0.3");
        let no_address = Node::from_id([7; ID_LEN]);
        let answered = [own.clone(), beyond_k, no_address, b.clone(), a.clone()];
        let mut chosen: Vec<_> = spread(&own, &answered, 2, 10)
            .iter()
            .map(|node| node.id)
            .collect();
        chosen.sort_unstable();
        assert_eq!(chosen, vec![a.id, b.id]);
    }

    /// A node with `k` that knows `known` contacts: one per distance from
    /// it, the closest last, each at its own address and in its own bucket.
    async fn knowing(k: usize, known: usize) -> (KademliaProtocol, Vec<Node>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let protocol = KademliaProtocol::new(
            contact_at([0; ID_LEN], port),
            socket,
            Arc::new(ForgetfulStorage::new(-1)),
            k,
            3,
            Arc::new(CountingDidHandler::new()),
            None,
        );
        let contacts: Vec<Node> = (0..known)
            .map(|bit| {
                let mut id = [0; ID_LEN];
                id[bit / 8] = 0x80 >> (bit % 8);
                let ip = format!("10.0.{}.{}", bit / 200, bit % 200 + 1);
                Node::new(id, Some(ip), Some(9000))
            })
            .collect();
        for contact in &contacts {
            protocol.router.write().await.add_contact(contact.clone());
        }
        (protocol, contacts)
    }

    fn sorted_ids(nodes: &[Node]) -> Vec<[u8; ID_LEN]> {
        let mut ids: Vec<_> = nodes.iter().map(|node| node.id).collect();
        ids.sort_unstable();
        ids
    }

    /// With `k` = 3 the lookup returns the 3 closest; the node asks the 10
    /// closest it knows.
    #[tokio::test]
    async fn with_a_small_k_the_ten_closest_it_knows_are_asked() {
        let (protocol, contacts) = knowing(3, 12).await;
        let answered = &contacts[9..];
        let asked = protocol.to_ask(answered).await;
        assert_eq!(sorted_ids(&asked), sorted_ids(&contacts[2..]));
    }

    /// With `k` = 20 the node asks 10, all among the 20 closest.
    #[tokio::test]
    async fn with_k_20_ten_of_the_twenty_closest_are_asked() {
        let (protocol, contacts) = knowing(20, 25).await;
        let asked = protocol.to_ask(&contacts[5..]).await;
        assert_eq!(asked.len(), 10);
        let closest = sorted_ids(&contacts[5..]);
        assert!(asked.iter().all(|node| closest.contains(&node.id)));
    }

    #[test]
    fn keys_listed_by_more_neighbours_come_first_the_highest_position_first() {
        let (k1, k2, k3) = ([1; ID_LEN], [2; ID_LEN], [3; ID_LEN]);
        let lists = vec![
            vec![entry(k1, 0, b"1"), entry(k2, 5, b"5"), entry(k3, 0, b"3")],
            vec![entry(k2, 6, b"6"), entry(k3, 0, b"3")],
            vec![entry(k2, 5, b"5")],
        ];
        let wanted = merge(&lists);
        let order: Vec<_> = wanted.iter().map(|w| (w.key, w.listers)).collect();
        assert_eq!(order, vec![(k2, 3), (k3, 2), (k1, 1)]);
        let claims: Vec<_> = wanted[0]
            .claims
            .iter()
            .map(|claim| (claim.seq, claim.listers.clone()))
            .collect();
        assert_eq!(claims, vec![(6, vec![1]), (5, vec![0, 2])]);
    }

    #[test]
    fn a_page_follows_only_in_strictly_increasing_order_after_the_cursor() {
        let page = |keys: &[u8]| -> Vec<KeyEntry> {
            keys.iter()
                .map(|&key| entry([key; ID_LEN], 0, b""))
                .collect()
        };
        assert!(follows(None, &page(&[1, 2, 3])));
        assert!(follows(Some([0; ID_LEN]), &page(&[1, 2])));
        assert!(!follows(Some([2; ID_LEN]), &page(&[2, 3])));
        assert!(!follows(None, &page(&[1, 3, 2])));
        assert!(!follows(None, &page(&[1, 1])));
        assert!(follows(Some([9; ID_LEN]), &page(&[])));
    }

    #[tokio::test]
    async fn an_empty_node_takes_the_records_its_neighbours_list() {
        let (one, two) = (TreeOwner::new(1), TreeOwner::new(2));
        let (one_0, two_0) = (one.record(0, None), two.record(0, None));
        let a = node(
            [0x20; ID_LEN],
            &[(one.key, one_0.clone()), (two.key, two_0.clone())],
        )
        .await;
        let b = node([0x30; ID_LEN], &[(one.key, one_0.clone())]).await;
        let empty = node([0x10; ID_LEN], &[]).await;

        let neighbours = [a.source_node.clone(), b.source_node.clone()];
        assert_eq!(synchronize(&empty, &neighbours).await, 2);
        assert_eq!(empty.storage.get(&one.key), Some(one_0));
        assert_eq!(empty.storage.get(&two.key), Some(two_0));
    }

    #[tokio::test]
    async fn the_highest_position_listed_is_written() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let a = node([0x20; ID_LEN], &[(owner.key, v5)]).await;
        let b = node([0x30; ID_LEN], &[(owner.key, v6.clone())]).await;
        let empty = node([0x10; ID_LEN], &[]).await;

        let neighbours = [a.source_node.clone(), b.source_node.clone()];
        assert_eq!(synchronize(&empty, &neighbours).await, 1);
        assert_eq!(empty.storage.get(&owner.key), Some(v6));
    }

    #[tokio::test]
    async fn a_restarted_node_takes_the_rotation_it_missed() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let a = node([0x20; ID_LEN], &[(owner.key, v6.clone())]).await;
        let behind = node([0x10; ID_LEN], &[(owner.key, v5)]).await;

        assert_eq!(
            synchronize(&behind, std::slice::from_ref(&a.source_node)).await,
            1
        );
        assert_eq!(behind.storage.get(&owner.key), Some(v6));
    }

    /// One neighbour lists 7 and does not show it, another shows 6: 6 is
    /// written.
    #[tokio::test]
    async fn a_position_listed_and_not_shown_refuses_nothing() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let v6 = owner.record(6, Some(&v5));
        let (socket, liar) = raw_peer([0x40; ID_LEN]).await;
        let fetches = Arc::new(AtomicUsize::new(0));
        scripted_neighbour(
            socket,
            vec![entry(owner.key, 7, b"never shown")],
            HashMap::new(),
            Arc::clone(&fetches),
        );
        let honest = node([0x20; ID_LEN], &[(owner.key, v6.clone())]).await;
        let empty = node([0x10; ID_LEN], &[]).await;

        let neighbours = [liar, honest.source_node.clone()];
        assert_eq!(synchronize(&empty, &neighbours).await, 1);
        assert_eq!(empty.storage.get(&owner.key), Some(v6));
        assert_eq!(fetches.load(Ordering::Relaxed), 1);
    }

    /// A neighbour lists ten keys and says it holds none: after two such
    /// answers it is asked for no more, and the record another lists is
    /// written. A fetch already in flight may still end.
    #[tokio::test]
    async fn a_neighbour_that_twice_does_not_hold_what_it_listed_is_asked_no_more() {
        let owner = TreeOwner::new(1);
        let v0 = owner.record(0, None);
        let (socket, liar) = raw_peer([0x40; ID_LEN]).await;
        let fetches = Arc::new(AtomicUsize::new(0));
        let made_up = (1..=10u8)
            .map(|tag| entry([tag; ID_LEN], 0, b"made up"))
            .collect();
        scripted_neighbour(socket, made_up, HashMap::new(), Arc::clone(&fetches));
        let honest = node([0x20; ID_LEN], &[(owner.key, v0.clone())]).await;
        let empty = node([0x10; ID_LEN], &[]).await;

        let neighbours = [liar, honest.source_node.clone()];
        assert_eq!(synchronize(&empty, &neighbours).await, 1);
        assert_eq!(empty.storage.get(&owner.key), Some(v0));
        let fetched = fetches.load(Ordering::Relaxed);
        assert!(
            (NOT_HELD_LIMIT..NOT_HELD_LIMIT + FETCHES_PER_NEIGHBOUR).contains(&fetched),
            "{fetched} fetches"
        );
    }

    /// A neighbour that shows records other than those it listed is still
    /// asked for each key it listed: its list may predate a rotation.
    #[tokio::test]
    async fn a_neighbour_showing_records_other_than_listed_is_still_asked() {
        let owners = [TreeOwner::new(1), TreeOwner::new(2), TreeOwner::new(3)];
        let (socket, neighbour) = raw_peer([0x40; ID_LEN]).await;
        let fetches = Arc::new(AtomicUsize::new(0));
        scripted_neighbour(
            socket,
            owners
                .iter()
                .map(|owner| entry(owner.key, 0, b"another record"))
                .collect(),
            owners
                .iter()
                .map(|owner| (owner.key, owner.record(0, None)))
                .collect(),
            Arc::clone(&fetches),
        );
        let empty = node([0x10; ID_LEN], &[]).await;

        assert_eq!(synchronize(&empty, &[neighbour]).await, 0);
        assert_eq!(fetches.load(Ordering::Relaxed), owners.len());
        assert!(empty.storage.is_empty());
    }

    /// A record whose key is not the tree's at its position, or whose
    /// signature does not verify, listed under its own hash and shown:
    /// nothing is written.
    #[tokio::test]
    async fn a_forged_record_listed_and_shown_is_not_written() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let wrong_key = owner.record_from(
            &body(PLACEHOLDER, owner.keys[5].public_key(), 6, Some(&v5)),
            6,
        );
        let unsigned = {
            let mut record = owner.record(6, Some(&v5));
            record[20] ^= 1;
            record
        };
        for forged in [wrong_key, unsigned] {
            let (socket, liar) = raw_peer([0x40; ID_LEN]).await;
            scripted_neighbour(
                socket,
                vec![entry(owner.key, 6, &forged)],
                HashMap::from([(owner.key, forged)]),
                Arc::new(AtomicUsize::new(0)),
            );
            let empty = node([0x10; ID_LEN], &[]).await;
            assert_eq!(synchronize(&empty, &[liar]).await, 0);
            assert_eq!(empty.storage.get(&owner.key), None);
        }
    }

    /// The position held, under its own hash or another one, and a lower
    /// position: nothing is fetched.
    #[tokio::test]
    async fn a_node_fetches_nothing_it_would_not_take() {
        let owners = [TreeOwner::new(1), TreeOwner::new(2), TreeOwner::new(3)];
        let held: Vec<_> = owners
            .iter()
            .map(|owner| (owner.key, owner.record(5, Some(b"4"))))
            .collect();
        let (socket, neighbour) = raw_peer([0x40; ID_LEN]).await;
        let fetches = Arc::new(AtomicUsize::new(0));
        scripted_neighbour(
            socket,
            vec![
                entry(owners[0].key, 5, &held[0].1),
                entry(owners[1].key, 5, b"another record at 5"),
                entry(owners[2].key, 4, b"a record at 4"),
            ],
            HashMap::new(),
            Arc::clone(&fetches),
        );
        let restarted = node([0x10; ID_LEN], &held).await;

        assert_eq!(synchronize(&restarted, &[neighbour]).await, 0);
        assert_eq!(fetches.load(Ordering::Relaxed), 0);
        for (key, record) in &held {
            assert_eq!(restarted.storage.get(key).as_ref(), Some(record));
        }
    }

    /// The budget holds one record: the synchronization stops at the first
    /// one refused, and nothing held is evicted.
    #[tokio::test]
    async fn the_storage_budget_stops_the_synchronization() {
        let owners = [TreeOwner::new(1), TreeOwner::new(2), TreeOwner::new(3)];
        let records: Vec<_> = owners
            .iter()
            .map(|owner| (owner.key, owner.record(0, None)))
            .collect();
        let a = node([0x20; ID_LEN], &records[1..]).await;
        let budget = ID_LEN + records[0].1.len() + 64;
        let full = node_with_storage(
            [0x10; ID_LEN],
            &records[..1],
            ForgetfulStorage::with_max_storage_bytes(-1, budget),
        )
        .await;

        assert_eq!(
            synchronize(&full, std::slice::from_ref(&a.source_node)).await,
            0
        );
        assert_eq!(full.storage.get(&records[0].0), Some(records[0].1.clone()));
        assert_eq!(full.storage.get(&records[1].0), None);
        assert_eq!(full.storage.get(&records[2].0), None);
    }

    #[tokio::test]
    async fn nothing_is_written_when_no_neighbour_answers() {
        let (_silent, contact) = raw_peer([0x40; ID_LEN]).await;
        let empty = node([0x10; ID_LEN], &[]).await;
        assert_eq!(synchronize(&empty, &[contact]).await, 0);
        assert!(empty.storage.is_empty());
    }

    /// 20 records come in two pages.
    #[tokio::test]
    async fn a_list_longer_than_one_page_is_taken_whole() {
        let records: Vec<_> = (1..=20u8)
            .map(|tag| {
                let owner = TreeOwner::new(tag);
                (owner.key, owner.record(0, None))
            })
            .collect();
        let a = node([0x20; ID_LEN], &records).await;
        let empty = node([0x10; ID_LEN], &[]).await;

        assert_eq!(
            synchronize(&empty, std::slice::from_ref(&a.source_node)).await,
            20
        );
        for (key, record) in &records {
            assert_eq!(empty.storage.get(key).as_ref(), Some(record));
        }
    }

    /// A neighbour that answers every `ListKeys` with a page of `page_len`
    /// made-up keys after the cursor, saying more follow, counting the pages
    /// it sent.
    fn endless_neighbour(socket: UdpSocket, page_len: usize, pages: Arc<AtomicUsize>) {
        tokio::spawn(async move {
            while let Some((frame, from)) = try_read_message(&socket, Duration::from_secs(10)).await
            {
                let RpcMessage::ListKeys { after, .. } = frame.message else {
                    continue;
                };
                let first = after.map_or(1, |key| {
                    u64::from_be_bytes(key[ID_LEN - 8..].try_into().unwrap()) + 1
                });
                let entries = (first..first + page_len as u64)
                    .map(|n| {
                        let mut key = [0; ID_LEN];
                        key[ID_LEN - 8..].copy_from_slice(&n.to_be_bytes());
                        entry(key, 0, b"made up")
                    })
                    .collect();
                pages.fetch_add(1, Ordering::Relaxed);
                let answer = RpcMessage::KeyList {
                    entries,
                    more: true,
                };
                send_raw(&socket, from, frame.msg_id, false, answer).await;
            }
        });
    }

    /// A neighbour that always says more keys follow is asked `MAX_PAGES`
    /// pages, and no more: what it lists stays bounded however fast it
    /// answers.
    #[tokio::test]
    async fn a_neighbour_is_asked_at_most_max_pages() {
        let (socket, liar) = raw_peer([0x40; ID_LEN]).await;
        let pages = Arc::new(AtomicUsize::new(0));
        endless_neighbour(socket, PAGE_ENTRIES, Arc::clone(&pages));
        let node = node([0x10; ID_LEN], &[]).await;

        let listed = node.list_of(&liar).await;
        assert_eq!(listed.len(), MAX_PAGES * PAGE_ENTRIES);
        assert_eq!(pages.load(Ordering::Relaxed), MAX_PAGES);
    }

    /// A page longer than one datagram holds, sent in fragments, ends the
    /// list with nothing taken from it.
    #[tokio::test]
    async fn a_page_longer_than_a_datagram_ends_the_list() {
        let (socket, liar) = raw_peer([0x40; ID_LEN]).await;
        let pages = Arc::new(AtomicUsize::new(0));
        endless_neighbour(socket, PAGE_ENTRIES + 1, Arc::clone(&pages));
        let node = node([0x10; ID_LEN], &[]).await;

        assert!(node.list_of(&liar).await.is_empty());
        assert_eq!(pages.load(Ordering::Relaxed), 1);
    }

    /// A node that lies in `ListKeys` lists the key it holds at a position
    /// far ahead under another hash, then made-up keys up to a full page, in
    /// order, saying more follow; the next page holds made-up keys only.
    #[cfg(feature = "testbed")]
    #[tokio::test]
    async fn a_lying_node_lists_its_keys_far_ahead_and_made_up_keys_after_them() {
        use crate::auth_handler::did::MAX_INTEGER;
        let key = [0x55; ID_LEN];
        let storage = Arc::new(ForgetfulStorage::new(-1));
        storage.set(key.to_vec(), b"record".to_vec());
        let protocol =
            test_protocol_with_storage(Arc::new(TestHandler::new(true, true)), false, storage)
                .await;
        protocol.set_lying(super::super::Lie::MadeUpKeys);
        let page =
            |after| protocol.rpc_list_keys([0x80; ID_LEN], ("127.0.0.1".into(), 9100), after);

        let Some(RpcMessage::KeyList { entries, more }) = page(None).await else {
            panic!("no page");
        };
        assert!(more);
        assert_eq!(entries.len(), PAGE_ENTRIES);
        assert!(follows(None, &entries));
        assert_eq!(entries[0].key, key);
        assert_ne!(entries[0].hash, record_hash(b"record"));
        assert!(entries.iter().all(|entry| entry.seq == MAX_INTEGER));

        let last = entries.last().map(|entry| entry.key);
        let Some(RpcMessage::KeyList { entries, more }) = page(last).await else {
            panic!("no page");
        };
        assert!(more);
        assert_eq!(entries.len(), PAGE_ENTRIES);
        assert!(follows(last, &entries));
        assert!(entries.iter().all(|entry| entry.key != key));
    }

    /// Past a neighbour that lists its key far ahead and made-up keys page
    /// after page, a node that starts takes the record an honest neighbour
    /// lists, and stores nothing made up.
    #[cfg(feature = "testbed")]
    #[tokio::test]
    async fn a_node_takes_its_records_past_a_neighbour_lying_in_list_keys() {
        let owner = TreeOwner::new(1);
        let v5 = owner.record(5, Some(b"4"));
        let liar = node([0x40; ID_LEN], &[(owner.key, v5.clone())]).await;
        liar.set_lying(super::super::Lie::MadeUpKeys);
        let honest = node([0x20; ID_LEN], &[(owner.key, v5.clone())]).await;
        let empty = node([0x10; ID_LEN], &[]).await;

        let neighbours = [liar.source_node.clone(), honest.source_node.clone()];
        assert_eq!(synchronize(&empty, &neighbours).await, 1);
        assert_eq!(empty.storage.get(&owner.key), Some(v5));
        assert_eq!(empty.storage.live_keys().len(), 1);
    }

    /// The Status List is taken when none is held, and only then: first
    /// writer wins.
    #[tokio::test]
    async fn the_status_list_is_taken_only_when_none_is_held() {
        let key = digest(STATUS_LIST_KEY);
        let handler = Arc::new(TestHandler::new(true, true));
        let a = test_protocol_with_storage(handler.clone(), false, {
            let storage = Arc::new(ForgetfulStorage::new(-1));
            storage.set(key.to_vec(), b"the list".to_vec());
            storage
        })
        .await;
        serve(&a);
        let contact = contact_at([1; ID_LEN], a.socket.local_addr().unwrap().port());

        let empty = {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let port = socket.local_addr().unwrap().port();
            Arc::new(KademliaProtocol::new(
                contact_at([0x10; ID_LEN], port),
                socket,
                Arc::new(ForgetfulStorage::new(-1)),
                20,
                3,
                handler.clone(),
                None,
            ))
        };
        serve(&empty);
        assert_eq!(synchronize(&empty, std::slice::from_ref(&contact)).await, 1);
        assert_eq!(empty.storage.get(&key), Some(b"the list".to_vec()));

        empty.storage.set(key.to_vec(), b"an earlier list".to_vec());
        assert_eq!(synchronize(&empty, &[contact]).await, 0);
        assert_eq!(empty.storage.get(&key), Some(b"an earlier list".to_vec()));
    }
}
