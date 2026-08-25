use std::path::PathBuf;
use std::sync::Arc;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

// ─── Encoding / JSON ──────────────────────────────────────────────────────────
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

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
/// | algorithm (12 bytes, null-padded) | Dilithium signature | DID Document (JSON) |
/// ```
fn build_signed_record(
    doc: &Value,
    secret_key: &dilithium2::SecretKey,
    algorithm: &str,
) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    // Pack algorithm into exactly 12 bytes (UTF-8, null-padded on the right).
    let mut alg_field = [0u8; 12];
    let alg_bytes = algorithm.as_bytes();
    let copy_len = alg_bytes.len().min(12);
    alg_field[..copy_len].copy_from_slice(&alg_bytes[..copy_len]);

    let detached_sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let signature = detached_sig.as_bytes();

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

/// Build a minimal `did:iiot` DID Document with one Dilithium and one Kyber key.
fn build_did_document(
    did: &str,
    dilithium_pk: &dilithium2::PublicKey,
    kyber_pk: &kyber512::PublicKey,
) -> Value {
    let dilithium_x = base64url_encode(dilithium_pk.as_bytes());
    let kyber_x = base64url_encode(kyber_pk.as_bytes());

    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Dilithium2",
                    "x": dilithium_x
                }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Kyber512",
                    "x": kyber_x
                }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "keyAgreement":   [ format!("{}#k1", did) ],
        "service": [
            {
                "id": format!("{}#device", did),
                "type": "DeviceAgent",
                "serviceEndpoint": "http://example.com/device"
            }
        ]
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_dht_publish_and_retrieve_detailed() {
        let parallelism = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        tokio::runtime::Builder::new_multi_thread()
            .max_blocking_threads(parallelism)
            .enable_all()
            .build()
            .unwrap()
            .block_on(test_body());
    }

    async fn test_body() {
        println!("\n--- Inizio Test DHT: Publish & Retrieve ---");

        // 1. Inizializza 3 nodi
        let mut nodes = Vec::new();
        let ports = [5678, 5679, 5680];
        for port in &ports {
            let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
                "issuer_pub_key.bin",
            )));
            let mut server = Server::new(handler, 20, 3, None, None, true);
            server.listen(*port, "127.0.0.1").await.unwrap();
            nodes.push(server);
        }

        // 2. Bootstrap
        nodes[1]
            .bootstrap(vec![("127.0.0.1".to_string(), 5678)])
            .await;
        nodes[2]
            .bootstrap(vec![("127.0.0.1".to_string(), 5678)])
            .await;
        sleep(Duration::from_secs(1)).await;
        println!("Stato rete: 3 nodi pronti.");

        let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
        let (kyber_pk, _) = kyber512::keypair();
        let did = generate_did_iiot();
        let did_doc = build_did_document(&did, &dilithium_pk, &kyber_pk);
        let dht_key = did.split(':').next_back().unwrap().to_string();

        let signed_record = build_signed_record(&did_doc, &dilithium_sk, "Dilithium-2");
        println!(
            "Nodo 2: Record pronto per il set(). Dimensione totale: {} bytes",
            signed_record.len()
        );

        let store_result = nodes[1].set(&dht_key, signed_record.clone()).await;
        assert!(
            store_result.unwrap_or(false),
            "Il salvataggio dovrebbe avere successo"
        );
        println!(
            "Nodo 2: Record salvato con successo sotto la chiave: {}",
            dht_key
        );

        println!("Nodo 3: Recupero record dalla chiave: {}", dht_key);
        let retrieved = nodes[2]
            .get(&dht_key)
            .await
            .expect("Il record dovrebbe essere presente");

        println!(
            "Nodo 3: Record ricevuto! Lunghezza totale: {} bytes",
            retrieved.len()
        );

        let binding = String::from_utf8_lossy(&retrieved[0..12]);
        let alg = binding.trim_matches(char::from(0));
        let sig = &retrieved[12..12 + dilithium2::signature_bytes()];
        let doc_bytes = &retrieved[12 + dilithium2::signature_bytes()..];

        println!("  -> Algoritmo estratto: {}", alg);
        println!("  -> Firma estratta: {} bytes", sig.len());

        let decoded_doc: Value = serde_json::from_slice(doc_bytes).expect("Errore parsing JSON");
        println!(
            "  -> Documento DID recuperato: {}",
            serde_json::to_string_pretty(&decoded_doc).unwrap()
        );

        assert_eq!(
            decoded_doc["id"], did,
            "L'ID nel DID Document recuperato non corrisponde!"
        );
        println!("--- Test completato con successo! ---\n");
    }
}
