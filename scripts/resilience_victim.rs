/// Resilience test — Node A (victim / seed).
///
/// Seeds `SEED_COUNT` valid DID records directly into local storage, waits for
/// Node B to bootstrap, then stays alive accepting RPCs for `LIFETIME_SECS`.
///
/// Environment variables:
///   NODE_PORT      — UDP port (default: 5678)
///   SEED_COUNT     — records to pre-seed (default: 5)
///   LIFETIME_SECS  — auto-shutdown after N seconds (default: 180)
///   RUST_LOG       — log level (default: warn)
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::digest;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use uuid::Uuid;

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Sorts object keys recursively so the JSON is canonical before signing.
fn sort_json(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(sort_json).collect()),
        other => other.clone(),
    }
}

/// Builds a valid self-signed Dilithium-2 DID record (wire format: alg ‖ sig ‖ doc).
fn make_record() -> (String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();

    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did), "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2",
                                  "x": b64url(dpk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did), "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512",
                                  "x": b64url(kpk.as_bytes()) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "keyAgreement":   [format!("{}#k1", did)],
        "service": [{
            "id": format!("{}#device", did),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    });

    let doc_bytes = serde_json::to_vec(&sort_json(&doc)).unwrap();
    let sig = dilithium2::detached_sign(&doc_bytes, &dsk);

    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");

    let mut record = Vec::with_capacity(12 + sig.as_bytes().len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig.as_bytes());
    record.extend_from_slice(&doc_bytes);
    (key, record)
}

fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

async fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let port: u16 = std::env::var("NODE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5678);
    let seed_count: usize = std::env::var("SEED_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let lifetime_secs: u64 = std::env::var("LIFETIME_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(180);

    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Resilience Victim       ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Port      : {port}");
    println!("  Seeds     : {seed_count}");
    println!("  Lifetime  : {lifetime_secs}s");
    println!();

    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));
    let mut server = Server::new(handler, 20, 3, None, None, false);
    server
        .listen(port, "0.0.0.0")
        .await
        .expect("failed to bind UDP socket");
    println!("[victim] Listening on 0.0.0.0:{port}");

    println!("[victim] Waiting for attacker to bootstrap...");
    loop {
        if !server.bootstrappable_neighbors().await.is_empty() {
            println!("[victim] Attacker connected — seeding records.");
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Dilithium keypair generation is CPU-intensive; offloaded to avoid blocking the runtime.
    let records: Vec<(String, Vec<u8>)> =
        tokio::task::spawn_blocking(move || (0..seed_count).map(|_| make_record()).collect())
            .await
            .unwrap();

    for (key, record) in &records {
        server.storage.set(digest(key).to_vec(), record.clone());
    }
    println!("[victim] Seeded {seed_count} records. Ready.\n");

    // Emit a storage snapshot every 30 s so Docker logs show the node is alive under load.
    let storage_ref = Arc::clone(&server.storage);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            println!("[victim] storage={} records", storage_ref.iter_all().len());
        }
    });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler failed");
        tokio::select! {
            _ = sigterm.recv()                                          => {}
            _ = tokio::signal::ctrl_c()                                => {}
            _ = tokio::time::sleep(Duration::from_secs(lifetime_secs)) => {
                println!("[victim] Lifetime elapsed — shutting down.");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c()                                => {}
            _ = tokio::time::sleep(Duration::from_secs(lifetime_secs)) => {
                println!("[victim] Lifetime elapsed — shutting down.");
            }
        }
    }

    let final_count = server.storage.iter_all().len();
    println!("[victim] Final storage: {final_count} records (seeded {seed_count}).");
    server.stop().await;
    println!("[victim] Stopped.");
}
