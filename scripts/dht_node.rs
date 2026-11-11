/// DHT node binary — used as the entry point for every Docker container.
///
/// Environment variables
/// ─────────────────────
/// NODE_PORT       UDP port to listen on (default: 5678)
/// IS_SEED         if set, skip bootstrap and act as permanent seed
/// BOOTSTRAP_ADDR  <ip>:<port> of the seed to bootstrap from
/// ROLE            "publisher" (default) | "retriever"
///                   publisher  → generate its keys, publish version 0 of a new
///                                DID, write the DID to /shared/did when that
///                                directory exists, then keep running
///                   retriever  → read the DID from /shared/did (or RETRIEVE_KEY),
///                                fetch its record from the DHT and print it
/// RETRIEVE_KEY    DID to look up instead of the one in /shared/did (optional)
/// MAX_STORAGE_BYTES  per-node key/value budget (default: 536870912 = 512 MiB)
/// RUST_LOG        log filter, e.g. "info", "debug", "auth_kademlia_rs=trace"
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::did::{canonical_bytes, derive_did, PLACEHOLDER};
use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::{ForgetfulStorage, DEFAULT_MAX_STORAGE_BYTES, DEFAULT_TTL};

use auth_kademlia_rs::crypto::mldsa::{self as mldsa, MlDsa65KeyPair};
use auth_kademlia_rs::utils::digest_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

/// Where the publisher writes the DID it published, and the retriever reads
/// it: a volume the two containers share (ADR 0005).
const DID_FILE: &str = "/shared/did";

/// How long the retriever waits for the DID file.
const DID_FILE_WAIT: Duration = Duration::from_secs(120);

fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// Wire format: [algorithm: 12 B][ML-DSA-65 signature][DID Document JSON]
fn build_signed_record(doc: &Value, secret_key: &MlDsa65KeyPair, algorithm: &str) -> Vec<u8> {
    let doc_bytes = canonical_bytes(doc).expect("a DID Document in canonical form");

    let mut alg_field = [0u8; 12];
    let copy_len = algorithm.len().min(12);
    alg_field[..copy_len].copy_from_slice(&algorithm.as_bytes()[..copy_len]);

    let sig = secret_key.sign(&doc_bytes).expect("ML-DSA-65 signing");
    let sig_bytes = sig.as_slice();

    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

/// The draft of version 0 of a new DID (ADR 0005): its own DID written as
/// the placeholder, no `id`, and the hash of the next public key.
fn version_zero_draft(signing_pk: &[u8], next_pk: &[u8]) -> Value {
    let did = PLACEHOLDER;
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65",
                                  "pub": base64url_encode(signing_pk) }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "service": [{
            "id":              format!("{}#device", did),
            "type":            "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }],
        "seq": 0,
        "nextKeyHash": base64url_encode(&digest_bytes(next_pk)),
    })
}

/// Write `did` to the DID file through a temporary file and a rename, so the
/// retriever never reads half of it. Without the shared directory (a
/// publisher with no volume, or a run outside Docker) it writes nothing.
fn write_did_file(did: &str) {
    let path = Path::new(DID_FILE);
    let Some(dir) = path.parent().filter(|dir| dir.is_dir()) else {
        log::info!("Publisher: no {} volume, DID not written", DID_FILE);
        return;
    };
    let partial = dir.join("did.partial");
    match std::fs::write(&partial, did).and_then(|()| std::fs::rename(&partial, path)) {
        Ok(()) => log::info!("Publisher: DID written to {}", DID_FILE),
        Err(error) => log::error!("Publisher: cannot write {}: {}", DID_FILE, error),
    }
}

/// The DID to look up: `RETRIEVE_KEY`, or the DID file once the publisher
/// has written it.
async fn did_to_retrieve() -> Option<String> {
    if let Ok(did) = std::env::var("RETRIEVE_KEY") {
        return Some(did);
    }
    log::info!("Retriever: waiting for the publisher's DID in {}", DID_FILE);
    let deadline = Instant::now() + DID_FILE_WAIT;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(DID_FILE) {
            return Some(text.trim().to_string());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    log::error!(
        "Retriever: no DID in {} after {} s",
        DID_FILE,
        DID_FILE_WAIT.as_secs()
    );
    None
}

/// Decode a signed record and return the pretty-printed DID Document JSON.
fn decode_record(record: &[u8]) -> Option<String> {
    // layout: [12 B alg] | [ML-DSA-65 signature] | [DID Document JSON]
    let sig_len = mldsa::signature_len();
    if record.len() < 12 + sig_len {
        return None;
    }
    let alg_raw = &record[..12];
    let alg = std::str::from_utf8(alg_raw)
        .unwrap_or("?")
        .trim_end_matches('\0');
    let json_bytes = &record[12 + sig_len..];
    let doc: Value = serde_json::from_slice(json_bytes).ok()?;
    log::debug!("Record algorithm field: {:?}", alg);
    serde_json::to_string_pretty(&doc).ok()
}

async fn start_server(port: u16, max_storage_bytes: usize) -> Server {
    let issuer_path = PathBuf::from("issuer.bin");
    if !issuer_path.exists() {
        log::warn!(
            "issuer.bin not found — STATUS_LIST_KEY verification will fail. \
             Normal DID record operations are unaffected."
        );
    }
    let handler = Arc::new(DIDSignatureVerifierHandler::new(issuer_path));
    let storage = Arc::new(ForgetfulStorage::with_max_storage_bytes(
        DEFAULT_TTL,
        max_storage_bytes,
    ));
    let mut server = Server::new(handler, 20, 3, None, Some(storage), true);
    server
        .listen(port, "0.0.0.0")
        .await
        .expect("Failed to bind UDP socket");
    log::info!("Node listening on 0.0.0.0:{}", port);
    server
}

/// Bootstrap with retries. Returns true when at least one peer is discovered.
async fn bootstrap_with_retries(server: &Server, ip: &str, port: u16) -> bool {
    let max_retries = 8;
    for attempt in 1..=max_retries {
        log::info!(
            "Bootstrap attempt {}/{} → {}:{}",
            attempt,
            max_retries,
            ip,
            port
        );
        let discovered = server.bootstrap(vec![(ip.to_string(), port)]).await;
        if !discovered.is_empty() {
            log::info!(
                "Bootstrap successful — discovered {} peer(s)",
                discovered.len()
            );
            return true;
        }
        log::warn!(
            "Bootstrap attempt {} returned no peers, retrying in 3 s…",
            attempt
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
    log::error!("Bootstrap failed after {} attempts", max_retries);
    false
}

async fn run_publisher(server: &Server) {
    // The current key signs version 0; the next one only commits to the
    // version after it, which this demo does not publish.
    let dsk = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
    let next = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
    log::debug!("Publisher: keypairs generated");

    let draft = version_zero_draft(dsk.public_key(), next.public_key());
    let (did, doc) = derive_did(&draft).expect("version 0 gives its DID");
    let dht_key = did.clone();
    log::info!("Publisher: DID  = {}", did);

    let record = build_signed_record(&doc, &dsk, "ML-DSA-65");

    log::info!(
        "Publisher: signed record size = {} B ({} fragments over UDP)",
        record.len(),
        record.len().div_ceil(1400),
    );

    let max_attempts = 10;
    for attempt in 1..=max_attempts {
        log::info!("Publisher: set attempt {}/{}", attempt, max_attempts);
        match server.set(&dht_key, record.clone()).await {
            Some(true) => {
                log::info!(
                    "Publisher: DID Document published successfully (key={})",
                    dht_key
                );
                write_did_file(&did);

                // Immediate local round-trip to confirm.
                match server.get(&dht_key).await {
                    Some(retrieved) => {
                        log::info!("Publisher: local get OK ({} B)", retrieved.len());
                        if let Some(pretty) = decode_record(&retrieved) {
                            log::debug!("Publisher: DID Document content:\n{}", pretty);
                        }
                    }
                    None => log::warn!("Publisher: local get returned None right after publish"),
                }
                return;
            }
            Some(false) => {
                log::warn!("Publisher: set returned false on attempt {}", attempt);
            }
            None => {
                log::warn!(
                    "Publisher: set returned None on attempt {} \
                     (key may already exist or signature rejected)",
                    attempt
                );
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
    log::error!(
        "Publisher: all {} attempts failed — node keeps running",
        max_attempts
    );
}

async fn run_retriever(server: &Server) {
    let Some(key) = did_to_retrieve().await else {
        return;
    };
    log::info!("Retriever: will look up key={}", key);

    let max_attempts = 10;
    for attempt in 1..=max_attempts {
        log::info!(
            "Retriever: get attempt {}/{} for key={}",
            attempt,
            max_attempts,
            key
        );
        match server.get(&key).await {
            Some(record) => {
                log::info!("Retriever: record found! ({} B, key={})", record.len(), key);
                match decode_record(&record) {
                    Some(pretty) => {
                        log::info!("Retriever: DID Document:\n{}", pretty);
                    }
                    None => log::warn!("Retriever: could not decode record structure"),
                }
                return;
            }
            None => {
                log::warn!(
                    "Retriever: key={} not found on attempt {}/{}",
                    key,
                    attempt,
                    max_attempts
                );
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
    log::error!(
        "Retriever: key={} not found after {} attempts",
        key,
        max_attempts
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port: u16 = std::env::var("NODE_PORT")
        .unwrap_or_else(|_| "5678".to_string())
        .parse()?;

    let role = std::env::var("ROLE").unwrap_or_else(|_| "publisher".to_string());
    let max_storage_bytes: usize = std::env::var("MAX_STORAGE_BYTES")
        .unwrap_or_else(|_| DEFAULT_MAX_STORAGE_BYTES.to_string())
        .parse()?;

    log::info!(
        "=== DHT node starting | port={} role={} max_storage_bytes={} ===",
        port,
        role,
        max_storage_bytes
    );

    let mut server = start_server(port, max_storage_bytes).await;

    if std::env::var("IS_SEED").is_ok() {
        log::info!("Running as SEED node — no bootstrap required");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    } else if let Ok(addr) = std::env::var("BOOTSTRAP_ADDR") {
        let parts: Vec<&str> = addr.splitn(2, ':').collect();
        if parts.len() != 2 {
            log::error!("BOOTSTRAP_ADDR must be <ip>:<port>, got: {}", addr);
            return Err("bad BOOTSTRAP_ADDR".into());
        }
        let bip = parts[0];
        let bport: u16 = parts[1].parse().map_err(|_| "bad port in BOOTSTRAP_ADDR")?;

        log::info!("Peer node — bootstrapping to {}:{}", bip, bport);
        // Brief wait so the seed container finishes binding.
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let ok = bootstrap_with_retries(&server, bip, bport).await;
        if !ok {
            log::warn!("Bootstrap did not discover any peers; continuing anyway");
        }
    } else {
        log::warn!("Neither IS_SEED nor BOOTSTRAP_ADDR is set — running as isolated node");
    }

    match role.as_str() {
        "retriever" => run_retriever(&server).await,
        _ => run_publisher(&server).await,
    }

    log::info!("Node active — waiting for Ctrl-C");
    tokio::signal::ctrl_c().await?;

    log::info!("Shutdown signal received — cleaning up…");
    server.stop().await;
    log::info!("Node stopped gracefully");
    Ok(())
}
