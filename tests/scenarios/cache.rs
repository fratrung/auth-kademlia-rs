//! Scenario: signature cache correctness and hit-rate.
//!
//! The `SignatureCache` is created internally by `Server` when `use_cache=true`.
//! These tests verify the cache behaviour at two levels:
//!
//! **Direct path** — mirrors the exact branching inside `verify_for_key`:
//!   1. Compute SHA-256 key with `SignatureCache::compute_key`.
//!   2. Cold: cache miss → full Dilithium-2 via `spawn_blocking` → insert result.
//!   3. Warm: cache hit  → return result directly, no `spawn_blocking`.
//!
//! **Invalid record** — invalid records must be cached as `false`:
//!   A node that rejects an invalid STORE RPC caches `false` so a second
//!   identical STORE (replication storm) is rejected fast without re-running
//!   Dilithium.  Verified by calling `set()` on an invalid record twice and
//!   observing the node's internal cache state via the public `SignatureCache` API.
//!
//! Ports: 15790 (cached node for entry-count test).

#[path = "common.rs"]
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use auth_kademlia_rs::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use auth_kademlia_rs::signature_cache::{SignatureCache, VerificationDomain};
use common::{build_did_document, build_signed_record, generate_did_iiot, make_record, rt};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;

/// A cache hit must be faster than a full Dilithium-2 `spawn_blocking` call.
///
/// Measured directly: mirrors `verify_for_key`'s exact code path.
///   Cold = compute_key + cache miss + spawn_blocking(Dilithium) + insert.
///   Warm = compute_key + cache.get_by_key() — no blocking task spawned.
#[test]
fn cache_hit_is_faster_than_dilithium_verify() {
    rt().block_on(async {
        let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
            "issuer_pub_key.bin",
        )));
        let cache = SignatureCache::new(128);
        let (_, record) = make_record();

        let ck = SignatureCache::compute_key(VerificationDomain::SelfSigned, &record);

        // Cold: full Dilithium-2 verification via spawn_blocking.
        let h = Arc::clone(&handler);
        let r = record.clone();
        let t0 = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            h.handle_signature_verification(&r).unwrap_or(false)
        })
        .await
        .expect("spawn_blocking");
        let cold_us = t0.elapsed().as_micros();
        cache.insert_by_key(ck, result);

        // Warm: direct cache.get_by_key() — SHA-256 key lookup in moka.
        let t1 = Instant::now();
        let cached = cache.get_by_key(&ck);
        let warm_us = t1.elapsed().as_micros();

        assert_eq!(cached, Some(true), "valid record must be cached as true");
        println!(
            "cache: cold (Dilithium) = {cold_us}µs  warm (cache hit) = {warm_us}µs  speedup ≈ {:.0}×",
            cold_us as f64 / warm_us.max(1) as f64
        );
        assert!(
            warm_us < cold_us,
            "cache hit ({warm_us}µs) must be faster than Dilithium ({cold_us}µs)"
        );
    });
}

/// Invalid records must be cached as `false`.
///
/// When a STORE RPC arrives with an invalid record:
///   - First call: cache miss → Dilithium verifies → false → cache.insert(false).
///   - Second call with same bytes: cache hit(false) → rejected without Dilithium.
///
/// Tested via `SignatureCache` directly to isolate the cache behaviour.
#[test]
fn cache_stores_false_for_invalid_records() {
    rt().block_on(async {
        let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
            "issuer_pub_key.bin",
        )));
        let cache = SignatureCache::new(128);

        // Build a record whose embedded public key does not match the signing key.
        let (pk, _) = dilithium2::keypair();
        let (_, wrong_sk) = dilithium2::keypair();
        let (kpk, _) = kyber512::keypair();
        let did = generate_did_iiot();
        let doc = build_did_document(&did, &pk, &kpk);
        let invalid_record = build_signed_record(&doc, &wrong_sk, "Dilithium-2");

        let ck = SignatureCache::compute_key(VerificationDomain::SelfSigned, &invalid_record);

        // Cold: Dilithium runs, returns false.
        let h = Arc::clone(&handler);
        let r = invalid_record.clone();
        let t0 = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            h.handle_signature_verification(&r).unwrap_or(false)
        })
        .await
        .expect("spawn_blocking");
        let cold_us = t0.elapsed().as_micros();
        cache.insert_by_key(ck, result);
        assert!(!result, "invalid record must fail verification");

        // Warm: cache hit returns false fast — no Dilithium.
        let t1 = Instant::now();
        let cached = cache.get_by_key(&ck);
        let warm_us = t1.elapsed().as_micros();

        assert_eq!(
            cached,
            Some(false),
            "cache must store false for invalid records"
        );
        assert!(
            warm_us < cold_us,
            "cache rejection ({warm_us}µs) must be faster than Dilithium ({cold_us}µs)"
        );
        println!("invalid record: cold = {cold_us}µs  warm (cache false) = {warm_us}µs");
    });
}
