use std::path::PathBuf;
/// Example: publish and retrieve a signed DID Document via auth_kademlia.
///
/// Rust equivalent of the Python AuthKademlia example:
///
///   1. Start a DHT node with signature verification
///   2. Generate an ML-DSA-65 key pair
///   3. Build a did:iiot DID Document
///   4. Sign it and pack it into the record format:
///      | algorithm (12 bytes, null-padded) | signature | DID Document (JSON) |
///   5. Store the signed record in the DHT under the DID's UUID fragment
///   6. Retrieve and verify it
///
/// To run:
///   cargo run --example publish_did -- --bootstrap 127.0.0.1:5678
///
/// If this is the first node in the network, omit --bootstrap.
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

// ML-DSA-65 keys and signatures, from aws-lc-rs (ADR 0003).
use auth_kademlia_rs::crypto::mldsa::{self as mldsa, MlDsa65KeyPair};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use tokio::time::sleep;
use uuid::Uuid;

/// Encode a raw public key as base64url (no padding).
fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// Serialize a DID Document to canonical JSON bytes (sorted keys, no spaces).
fn encode_did_document(doc: &Value) -> Vec<u8> {
    // serde_json does not guarantee key order on serialization of arbitrary
    // Value objects, so we convert to a BTreeMap-backed Value first.
    let canonical = sort_json_keys(doc);
    serde_json::to_vec(&canonical).expect("DID Document serialization failed")
}

/// Recursively sort all object keys so serialization is deterministic.
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

/// Build the signed record:
///
/// ```text
/// | algorithm (12 bytes, null-padded) | ML-DSA-65 signature | DID Document (JSON) |
/// ```
fn build_signed_record(doc: &Value, secret_key: &MlDsa65KeyPair, algorithm: &str) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    // Pack algorithm into exactly 12 bytes (UTF-8, null-padded on the right).
    let mut alg_field = [0u8; 12];
    let alg_bytes = algorithm.as_bytes();
    let copy_len = alg_bytes.len().min(12);
    alg_field[..copy_len].copy_from_slice(&alg_bytes[..copy_len]);

    // Sign using the detached API — returns only the signature bytes.
    let detached_sig = secret_key.sign(&doc_bytes).expect("ML-DSA-65 signing");
    let signature = detached_sig.as_slice();

    // Concatenate: alg_field || signature || doc_bytes
    let mut record = Vec::with_capacity(12 + signature.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(signature);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Generate a `did:iiot` URI using a random UUID v4.
fn generate_did_iiot() -> String {
    format!("did:iiot:{}", Uuid::new_v4())
}

/// Build a minimal `did:iiot` DID Document with its ML-DSA-65 key (RFC 9964)
/// and no key agreement key (ADR 0003).
fn build_did_document(did: &str, signing_pk: &[u8]) -> Value {
    let signing_x = base64url_encode(signing_pk);

    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "AKP", "alg": "ML-DSA-65",
                    "pub": signing_x
                }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "service": [
            {
                "id": format!("{}#device", did),
                "type": "DeviceAgent",
                "serviceEndpoint": "http://example.com/device"
            }
        ]
    })
}

// Helper function to initialize and start a Kademlia node
async fn start_node(port: u16) -> Server {
    // Initialize the signature handler with the issuer's public key
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));

    // Create a new Server: ksize=20, alpha=3
    let mut server = Server::new(handler, 20, 3, None, None, true);

    // Start listening on the specified port
    server.listen(port, "127.0.0.1").await.unwrap();
    println!(">>> Node started on port {}", port);
    server
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
    // Start two local nodes
    let node_1 = start_node(5678).await;
    let node_2 = start_node(5679).await;

    // Node 2 performs bootstrap toward Node 1 to join the network
    println!(">>> Node 2: Performing bootstrap towards Node 1 (5678)...");
    let discovered = node_2
        .bootstrap(vec![("127.0.0.1".to_string(), 5678)])
        .await;

    println!(
        ">>> Node 2 discovered {} nodes during bootstrap",
        discovered.len()
    );

    // Fallback logic if initial bootstrap fails
    if discovered.is_empty() {
        println!(">>> WARNING: Bootstrap failed, forcing manual retry...");
        node_2
            .bootstrap(vec![("127.0.0.1".to_string(), 5678)])
            .await;
    }

    // Allow some time for the DHT routing tables to update
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    node_2
        .bootstrap(vec![("127.0.0.1".to_string(), 5678)])
        .await;

    sleep(Duration::from_secs(1)).await;

    // Generate the ML-DSA-65 signing key pair (ADR 0003)
    let signing_sk = MlDsa65KeyPair::generate().expect("ML-DSA-65 key generation");
    let signing_pk = signing_sk.public_key().to_vec();

    // Create a unique Decentralized Identifier (DID)
    let did = generate_did_iiot();
    let did_doc = build_did_document(&did, &signing_pk);

    // Extract the hash-part of the DID to use as the DHT key
    let dht_key = did.split(':').next_back().unwrap().to_string();

    // Sign the DID Document with ML-DSA-65
    let signed_record = build_signed_record(&did_doc, &signing_sk, "ML-DSA-65");

    // Retry loop to publish the record (waiting for network stabilization)
    let mut is_ready = false;
    for i in 0..10 {
        let success = node_2.set(&dht_key.clone(), signed_record.clone()).await;

        if success == Some(true) {
            println!(
                ">>> Network stabilized and record published on attempt {}!",
                i + 1
            );
            is_ready = true;
            break;
        }
        println!(">>> Attempt {}: Waiting for neighbors in the DHT...", i + 1);
        sleep(Duration::from_millis(500)).await;
    }

    if !is_ready {
        println!(">>> ERROR: Failed to publish the record to the DHT.");
        return Ok(());
    }

    // Node 1 attempts to retrieve the record published by Node 2
    println!(">>> Node 1: Retrieving record '{}'...", dht_key);
    match node_1.get(&dht_key).await {
        Some(record) => {
            println!(">>> Node 1: Record found! ({} bytes)", record.len());

            // Parse the binary record: [Algorithm Name (12 bytes)] [Signature] [DID Document JSON]
            let alg_cow = String::from_utf8_lossy(&record[0..12]);
            let alg = alg_cow.trim_matches(char::from(0)); // Remove null padding
            let doc_start = 12 + mldsa::signature_len();
            let doc_bytes = &record[doc_start..];

            if let Ok(doc) = serde_json::from_slice::<Value>(doc_bytes) {
                println!(">>> Analysis:");
                println!("    - Algorithm: {}", alg);
                println!("    - DID Document ID: {}", doc["id"]);
                println!(
                    "    - Full JSON: {}",
                    serde_json::to_string_pretty(&doc).unwrap()
                );
            }
        }
        None => println!(">>> Node 1: Record not found!"),
    }

    Ok(())
}
