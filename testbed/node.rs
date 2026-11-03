//! Testbed node: one DHT node per container, driven through a control socket
//! that listens only inside the container. See `testbed/README.md`.
//!
//! `testbed_node`             run the node, configured from the environment
//! `testbed_node ctl <cmd>`   send one command to the node of this container
//!
//! Environment:
//! NODE_NAME   name shown in the logs (default `node`)
//! NODE_IP     this node's address, removed from SEEDS
//! NODE_PORT   UDP port of the DHT (default 4000)
//! DHT_K       Kademlia k (default 20)
//! DHT_ALPHA   Kademlia alpha (default 3)
//! SEEDS       comma-separated `ip:port` list of bootstrap nodes
//! CTL_PORT    TCP port of the control socket, on 127.0.0.1 (default 7000)
//! SIG_CACHE   1 enables the signature cache (default 0)
//! RUST_LOG    log filter (default `warn,testbed_node=info`)
//!
//! Commands: `info`, `publish`, `update`, `discard`, `get <did|uuid>`,
//! `stats`, `storage`, `routing`. Each answers with one JSON line.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::{Server, SetOutcome};
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::digest;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

const ALGORITHM: &str = "Dilithium-2";
const SIGNATURE_LEN: usize = 2420;
const STATS_EVERY: Duration = Duration::from_secs(30);

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// DID records
// ---------------------------------------------------------------------------

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| (key.clone(), sorted(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn did_document(
    did: &str,
    signing: &dilithium2::PublicKey,
    agreement: &kyber512::PublicKey,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#k0"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2",
                                  "x": URL_SAFE_NO_PAD.encode(signing.as_bytes()) }
            },
            {
                "id": format!("{did}#k1"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512",
                                  "x": URL_SAFE_NO_PAD.encode(agreement.as_bytes()) }
            }
        ],
        "authentication": [format!("{did}#k0")],
        "keyAgreement": [format!("{did}#k1")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    })
}

/// `[algorithm: 12 B][Dilithium-2 signature][DID Document JSON]`
fn signed_record(document: &Value, secret_key: &dilithium2::SecretKey) -> Vec<u8> {
    let body = serde_json::to_vec(&sorted(document)).expect("a DID Document serializes");
    let mut record = vec![0u8; 12];
    record[..ALGORITHM.len()].copy_from_slice(ALGORITHM.as_bytes());
    record.extend_from_slice(dilithium2::detached_sign(&body, secret_key).as_bytes());
    record.extend_from_slice(&body);
    record
}

fn short_hash(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes)[..6])
}

/// The DID of a record and short hashes of its two public keys, so versions
/// can be told apart in the output.
fn describe(record: &[u8]) -> Value {
    let document: Option<Value> = record
        .get(12 + SIGNATURE_LEN..)
        .and_then(|body| serde_json::from_slice(body).ok());
    let Some(document) = document else {
        return json!({ "bytes": record.len(), "error": "not a DID record" });
    };
    let key = |index: usize| {
        document["verificationMethod"][index]["publicKeyJwk"]["x"]
            .as_str()
            .and_then(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .map(|bytes| short_hash(&bytes))
    };
    json!({
        "did": document["id"],
        "signing_key": key(0),
        "agreement_key": key(1),
        "bytes": record.len(),
    })
}

fn signing_key_of(record: &[u8]) -> String {
    describe(record)["signing_key"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

/// One version of this node's DID Document. The Kyber secret key is not
/// kept: the testbed does not run key agreement.
struct Version {
    secret_key: dilithium2::SecretKey,
    record: Vec<u8>,
}

impl Version {
    fn generate(did: &str) -> Self {
        let (signing, secret_key) = dilithium2::keypair();
        let (agreement, _) = kyber512::keypair();
        let record = signed_record(&did_document(did, &signing, &agreement), &secret_key);
        Self { secret_key, record }
    }
}

/// A rotation that has not been confirmed yet. It is kept so that a retry
/// sends exactly the same record and authorization.
struct Rotation {
    next: Version,
    auth_signature: Vec<u8>,
}

struct Identity {
    uuid: String,
    did: String,
    current: Version,
    pending: Option<Rotation>,
}

// ---------------------------------------------------------------------------
// Node and commands
// ---------------------------------------------------------------------------

struct Node {
    name: String,
    address: String,
    server: RwLock<Server>,
    identity: Mutex<Option<Identity>>,
}

fn elapsed_ms(started: Instant) -> f64 {
    (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0
}

async fn handle(node: &Node, line: &str) -> Value {
    let mut words = line.split_whitespace();
    match words.next().unwrap_or("") {
        "info" => info(node).await,
        "publish" => publish(node).await,
        "update" => update(node).await,
        "discard" => discard(node).await,
        "get" => match words.next() {
            Some(target) => get(node, target).await,
            None => json!({ "error": "usage: get <did|uuid>" }),
        },
        "stats" => stats(node).await,
        "storage" => storage(node).await,
        "routing" => routing(node).await,
        other => json!({
            "error": format!("unknown command '{other}'"),
            "commands": ["info", "publish", "update", "discard", "get <did|uuid>",
                         "stats", "storage", "routing"],
        }),
    }
}

async fn info(node: &Node) -> Value {
    let identity = node.identity.lock().await;
    let server = node.server.read().await;
    json!({
        "name": node.name,
        "address": node.address,
        "node_id": hex::encode(server.node.id),
        "did": identity.as_ref().map(|id| id.did.clone()),
        "signing_key": identity.as_ref().map(|id| signing_key_of(&id.current.record)),
        "pending_rotation_to": identity.as_ref().and_then(|id| {
            id.pending.as_ref().map(|rotation| signing_key_of(&rotation.next.record))
        }),
    })
}

/// Publish this node's DID Document, creating the DID on first use. Publishing
/// again sends the same record, so it is a retry.
async fn publish(node: &Node) -> Value {
    let mut identity = node.identity.lock().await;
    let created = identity.is_none();
    let id = identity.get_or_insert_with(|| {
        let uuid = Uuid::new_v4().to_string();
        let did = format!("did:iiot:{uuid}");
        Identity {
            current: Version::generate(&did),
            uuid,
            did,
            pending: None,
        }
    });
    let server = node.server.read().await;
    let started = Instant::now();
    let outcome = server
        .set_detailed(&id.uuid, id.current.record.clone())
        .await;
    let ms = elapsed_ms(started);
    let (status, report) = match &outcome {
        SetOutcome::Complete(report) => ("complete".to_string(), report),
        SetOutcome::Degraded(report) => ("degraded".to_string(), report),
        SetOutcome::Rejected { reason, report } => (format!("rejected: {reason:?}"), report),
    };
    log::info!(
        "publish {} key {}: {} - stored {}, already present {}, unavailable {}, \
         conflicts {}, full {} ({} ms)",
        id.did,
        signing_key_of(&id.current.record),
        status,
        report.stored_replicas,
        report.already_present,
        report.unavailable_nodes,
        report.conflict_rejections,
        report.capacity_rejections,
        ms
    );
    json!({
        "did": id.did,
        "created": created,
        "outcome": status,
        "expected_replicas": report.expected_replicas,
        "stored": report.stored_replicas,
        "already_present": report.already_present,
        "unavailable": report.unavailable_nodes,
        "conflicts": report.conflict_rejections,
        "capacity_rejections": report.capacity_rejections,
        "invalid": report.invalid_rejections,
        "ms": ms,
        "record": describe(&id.current.record),
        "pending_rotation": id.pending.is_some(),
    })
}

/// Rotate the keys: new Dilithium and Kyber keys, the new record signed by
/// the new key and authorized by the old one. A rotation that was not
/// confirmed is retried as it is, until it is confirmed or discarded.
async fn update(node: &Node) -> Value {
    let mut identity = node.identity.lock().await;
    let Some(id) = identity.as_mut() else {
        return json!({ "error": "this node has no DID yet: run publish first" });
    };
    let retry = id.pending.is_some();
    let rotation = id.pending.get_or_insert_with(|| {
        let next = Version::generate(&id.did);
        let auth_signature = dilithium2::detached_sign(&next.record, &id.current.secret_key)
            .as_bytes()
            .to_vec();
        Rotation {
            next,
            auth_signature,
        }
    });
    let record = rotation.next.record.clone();
    let auth_signature = rotation.auth_signature.clone();
    let from = signing_key_of(&id.current.record);
    let to = signing_key_of(&record);

    let server = node.server.read().await;
    let started = Instant::now();
    let result = server.update(&id.uuid, record, Some(auth_signature)).await;
    let ms = elapsed_ms(started);
    let outcome = match result {
        Some(true) => "confirmed",
        Some(false) => "not confirmed",
        None => "refused",
    };
    if result == Some(true) {
        if let Some(rotation) = id.pending.take() {
            id.current = rotation.next;
        }
    }
    log::info!(
        "update {} key {} -> {}{}: {} ({} ms)",
        id.did,
        from,
        to,
        if retry { " (retry)" } else { "" },
        outcome,
        ms
    );
    json!({
        "did": id.did,
        "from_key": from,
        "to_key": to,
        "retry": retry,
        "outcome": outcome,
        "ms": ms,
        "pending_rotation": id.pending.is_some(),
        "hint": if id.pending.is_some() {
            "run update again to retry the same rotation, or discard to drop it"
        } else {
            ""
        },
    })
}

async fn discard(node: &Node) -> Value {
    let mut identity = node.identity.lock().await;
    let dropped = identity
        .as_mut()
        .and_then(|id| id.pending.take())
        .map(|rotation| signing_key_of(&rotation.next.record));
    if let Some(key) = &dropped {
        log::info!("discarded the pending rotation to key {key}");
    }
    json!({ "discarded_rotation_to": dropped })
}

async fn get(node: &Node, target: &str) -> Value {
    let uuid = target.strip_prefix("did:iiot:").unwrap_or(target);
    let server = node.server.read().await;
    let local_copy = server.storage.get(&digest(uuid)).is_some();
    let started = Instant::now();
    let found = server.get(uuid).await;
    let ms = elapsed_ms(started);
    log::info!(
        "get did:iiot:{}: {} ({} ms, {})",
        uuid,
        match &found {
            Some(record) => format!("found key {}", signing_key_of(record)),
            None => "not found".to_string(),
        },
        ms,
        if local_copy {
            "local copy"
        } else {
            "remote lookup"
        }
    );
    json!({
        "did": format!("did:iiot:{uuid}"),
        "found": found.is_some(),
        "local_copy": local_copy,
        "ms": ms,
        "record": found.map(|record| describe(&record)),
    })
}

async fn stats(node: &Node) -> Value {
    let stats = node.server.read().await.stats().await;
    json!({
        "name": node.name,
        "node_id": hex::encode(stats.node_id),
        "contacts": stats.routing_nodes,
        "live_contacts": stats.live_routing_nodes,
        "records": stats.storage_records,
        "storage_bytes": stats.storage_bytes,
    })
}

async fn storage(node: &Node) -> Value {
    let server = node.server.read().await;
    let records: Vec<Value> = server
        .storage
        .iter_all()
        .into_iter()
        .map(|(key, value)| json!({ "key": hex::encode(&key[..key.len().min(6)]), "record": describe(&value) }))
        .collect();
    json!({ "name": node.name, "records": records })
}

async fn routing(node: &Node) -> Value {
    let server = node.server.read().await;
    let closest: Vec<String> = server
        .bootstrappable_neighbors()
        .await
        .into_iter()
        .map(|(ip, port)| format!("{ip}:{port}"))
        .collect();
    json!({ "name": node.name, "closest_contacts": closest })
}

// ---------------------------------------------------------------------------
// Control socket
// ---------------------------------------------------------------------------

async fn answer(node: Arc<Node>, stream: TcpStream) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let reply = handle(&node, line.trim()).await;
    write.write_all(format!("{reply}\n").as_bytes()).await
}

async fn serve_control(node: Arc<Node>, port: u16) {
    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => listener,
        Err(error) => {
            log::error!("control socket on port {port}: {error}");
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let node = Arc::clone(&node);
                tokio::spawn(async move {
                    if let Err(error) = answer(node, stream).await {
                        log::warn!("control connection: {error}");
                    }
                });
            }
            Err(error) => log::warn!("control socket: {error}"),
        }
    }
}

async fn ctl(port: u16, line: String) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(format!("{line}\n").as_bytes()).await?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).await?;
    print!("{reply}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

fn parse_seeds(list: &str, own: &(String, u16)) -> Vec<(String, u16)> {
    list.split(',')
        .filter_map(|entry| {
            let (ip, port) = entry.trim().rsplit_once(':')?;
            Some((ip.to_string(), port.parse().ok()?))
        })
        .filter(|seed| seed != own)
        .collect()
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

async fn log_stats_regularly(node: Arc<Node>) {
    loop {
        tokio::time::sleep(STATS_EVERY).await;
        let stats = node.server.read().await.stats().await;
        log::info!(
            "contacts {} live of {}, records {}",
            stats.live_routing_nodes,
            stats.routing_nodes,
            stats.storage_records
        );
    }
}

async fn run(ctl_port: u16) {
    let name = std::env::var("NODE_NAME").unwrap_or_else(|_| "node".to_string());
    let ip = std::env::var("NODE_IP").unwrap_or_default();
    let port = env_or("NODE_PORT", 4000u16);
    let k = env_or("DHT_K", 20usize);
    let alpha = env_or("DHT_ALPHA", 3usize);
    let seeds = parse_seeds(
        &std::env::var("SEEDS").unwrap_or_default(),
        &(ip.clone(), port),
    );

    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));
    let mut server = Server::new(handler, k, alpha, None, None, env_or("SIG_CACHE", 0u8) == 1);
    if let Err(error) = server.listen(port, "0.0.0.0").await {
        log::error!("cannot listen on UDP port {port}: {error}");
        std::process::exit(1);
    }
    log::info!(
        "{name} listening on {ip}:{port}, k={k}, alpha={alpha}, id {}, {} seeds",
        hex::encode(&server.node.id[..4]),
        seeds.len()
    );
    let discovered = server.bootstrap(seeds).await;
    if discovered.is_empty() {
        log::info!("no seed answered yet: the node keeps retrying them");
    } else {
        log::info!("bootstrap done: {} contacts found", discovered.len());
    }

    let node = Arc::new(Node {
        name,
        address: format!("{ip}:{port}"),
        server: RwLock::new(server),
        identity: Mutex::new(None),
    });
    let control = tokio::spawn(serve_control(Arc::clone(&node), ctl_port));
    let reporter = tokio::spawn(log_stats_regularly(Arc::clone(&node)));

    shutdown_signal().await;
    control.abort();
    reporter.abort();
    log::info!("stopping: notifying neighbours");
    node.server.write().await.stop().await;
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ctl_port = env_or("CTL_PORT", 7000u16);

    if args.first().map(String::as_str) == Some("ctl") {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        if let Err(error) = runtime.block_on(ctl(ctl_port, args[1..].join(" "))) {
            eprintln!("ctl: {error}");
            std::process::exit(1);
        }
        return;
    }

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn,testbed_node=info"),
    )
    .init();
    // Cap the blocking pool, used for Dilithium verification, to the cores.
    let parallelism = std::thread::available_parallelism()
        .map(|cores| cores.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run(ctl_port));
}
