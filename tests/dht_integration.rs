use std::path::PathBuf;
use std::sync::Arc;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

use auth_kademlia_rs::crypto::mldsa;
use serde_json::Value;

mod common;

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

        let (did, signed_record) = common::new_did_record();
        let dht_key = did.clone();
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
        let sig = &retrieved[12..12 + mldsa::signature_len()];
        let doc_bytes = &retrieved[12 + mldsa::signature_len()..];

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
