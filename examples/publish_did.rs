use std::path::PathBuf;
/// Example: publish, rotate and retrieve a signed DID Document via
/// auth_kademlia.
///
///   1. Start two DHT nodes with signature verification
///   2. Generate a tree of 64 ML-DSA-65 keys and activation codes, one per
///      position
///   3. Build the draft of position 0: its own DID written as the placeholder
///      `did:iiot:self`, `seq` 0, and the key of position 0
///   4. The DID is the hash of a genesis that commits the draft and the root
///      of the tree; the owner completes and signs the document of position 0
///   5. Publish it under its DID, then publish position 1, the first rotation
///   6. Retrieve the current record from the other node
///
/// To run:
///   cargo run --example publish_did
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::did::PLACEHOLDER;
use auth_kademlia_rs::auth_handler::owner::OwnerTree;
use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::crypto::mldsa;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::utils::digest_bytes;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use tokio::time::sleep;

/// Encode raw bytes as base64url (no padding).
fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The draft of position `seq` of a `did:iiot` DID Document: its ML-DSA-65
/// key (RFC 9964), no key agreement key, its own DID written as the
/// placeholder, no `id`, and after position 0 the hash of the record it
/// follows.
fn draft(signing_pk: &[u8], seq: u64, prev: Option<&[u8]>) -> Value {
    let did = PLACEHOLDER;
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "AKP", "alg": "ML-DSA-65",
                    "pub": base64url_encode(signing_pk)
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
        ],
        "seq": seq,
    });
    if let Some(prev) = prev {
        doc["prev"] = json!(base64url_encode(&digest_bytes(prev)));
    }
    doc
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

    // The tree of rotation keys: the device keeps its secrets behind its
    // custody backend; this example keeps them in memory.
    let owner = OwnerTree::generate().expect("a rotation-key tree");
    let initial = draft(owner.public_key(0).expect("position 0"), 0, None);
    let genesis = owner.genesis(&initial).expect("a draft body");
    let did = genesis.did();
    println!(">>> DID: {}", did);

    // Records are published and read under the DID
    let dht_key = did.clone();
    let signed_record = owner.record(&genesis, &initial, 0).expect("position 0");

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

    // The first rotation: position 1, signed by its own key. Replicas take
    // it directly; no other authorization is needed.
    let rotation = owner
        .record(
            &genesis,
            &draft(
                owner.public_key(1).expect("position 1"),
                1,
                Some(&signed_record),
            ),
            1,
        )
        .expect("position 1");
    println!(
        ">>> Node 2: rotation to position 1 published: {:?}",
        node_2.set(&dht_key, rotation).await
    );

    // Node 1 retrieves the current record
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
                println!("    - Position: {}", doc["seq"]);
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
