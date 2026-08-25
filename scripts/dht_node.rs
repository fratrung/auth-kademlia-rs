/// DHT node binary — used as the entry point for every Docker container.
///
/// Environment variables
/// ─────────────────────
/// NODE_PORT       UDP port to listen on (default: 5678)
/// IS_SEED         if set, skip bootstrap and act as permanent seed
/// BOOTSTRAP_ADDR  <ip>:<port> of the seed to bootstrap from
/// ROLE            "publisher" (default) | "retriever"
///                   publisher  → generate + publish a DID Document then keep running
///                   retriever  → wait, then fetch a key from the DHT and print it
/// FIXED_DID_UUID  if set, use this string as the DID UUID so the key is deterministic
///                 (pass the same value to the retriever via RETRIEVE_KEY)
/// RETRIEVE_KEY    DHT key to look up (required when ROLE=retriever)
/// MAX_STORAGE_BYTES  per-node key/value budget (default: 536870912 = 512 MiB)
/// RUST_LOG        log filter, e.g. "info", "debug", "auth_kademlia_rs=trace"
use std::path::PathBuf;
use std::sync::Arc;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::{ForgetfulStorage, DEFAULT_MAX_STORAGE_BYTES, DEFAULT_TTL};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use uuid::Uuid;

fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

fn sort_json_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

fn encode_did_document(doc: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_json_keys(doc)).expect("DID Document serialization failed")
}

/// Wire format: [algorithm: 12 B][Dilithium-2 signature][DID Document JSON]
fn build_signed_record(
    doc: &Value,
    secret_key: &dilithium2::SecretKey,
    algorithm: &str,
) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    let mut alg_field = [0u8; 12];
    let copy_len = algorithm.len().min(12);
    alg_field[..copy_len].copy_from_slice(&algorithm.as_bytes()[..copy_len]);

    let sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let sig_bytes = sig.as_bytes();

    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

fn build_did_document(
    did: &str,
    dilithium_pk: &dilithium2::PublicKey,
    kyber_pk: &kyber512::PublicKey,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2",
                                  "x": base64url_encode(dilithium_pk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512",
                                  "x": base64url_encode(kyber_pk.as_bytes()) }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "keyAgreement":   [ format!("{}#k1", did) ],
        "service": [{
            "id":              format!("{}#device", did),
            "type":            "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    })
}

/// Decode a signed record and return the pretty-printed DID Document JSON.
fn decode_record(record: &[u8]) -> Option<String> {
    // layout: [12 B alg] | [2420 B Dilithium-2 sig] | [DID Document JSON]
    const SIG_LEN: usize = 2420;
    if record.len() < 12 + SIG_LEN {
        return None;
    }
    let alg_raw = &record[..12];
    let alg = std::str::from_utf8(alg_raw)
        .unwrap_or("?")
        .trim_end_matches('\0');
    let json_bytes = &record[12 + SIG_LEN..];
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
    let uuid = std::env::var("FIXED_DID_UUID").unwrap_or_else(|_| Uuid::new_v4().to_string());
    let did = format!("did:iiot:{}", uuid);
    let dht_key = uuid.clone();

    log::info!("Publisher: DID  = {}", did);
    log::info!("Publisher: key  = {}", dht_key);

    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    log::debug!("Publisher: keypairs generated");

    let doc = build_did_document(&did, &dpk, &kpk);
    let record = build_signed_record(&doc, &dsk, "Dilithium-2");

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
    let key = match std::env::var("RETRIEVE_KEY") {
        Ok(k) => k,
        Err(_) => {
            log::error!("Retriever: RETRIEVE_KEY env var is not set — nothing to retrieve");
            return;
        }
    };

    log::info!("Retriever: will look up key={}", key);
    log::info!("Retriever: waiting 5 s for publisher to propagate…");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

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
