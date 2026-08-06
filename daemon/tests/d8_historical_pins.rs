//! D8 — historical pins: responses verify against a pinned root that may be an
//! arbitrary PAST tree state (an unbonding provider's exit snapshot, a custody
//! commit taken mid-growth). The daemon must reconstruct peaks and paths at any
//! historical leafCount from the flat chunk file alone.

mod common;

use blobsitter_daemon::proofs::{build_proof_set, ProofError};
use blobsitter_reference::{root, testvec, verify, Mmr};
use common::*;

/// Ingest a growing store, then answer at every declaration-boundary snapshot (the
/// only leaf counts the contract can ever pin) — and at arbitrary interior counts
/// for good measure — with proofs the contract's verifier accepts.
#[tokio::test]
async fn d8_reconstruct_any_past_pin_from_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let sizes = [3u64, 5, 4096, 90, 4097, 11];
    let mut declarations = Vec::new();
    let mut boundaries = Vec::new();
    let mut n0 = 0u64;
    for (nonce, &m) in sizes.iter().enumerate() {
        declarations.push(declaration(nonce as u64, n0, m));
        n0 += m;
        boundaries.push(n0);
    }
    let mut r = rig_serving(dir.path(), &declarations);
    for (event, _) in &declarations {
        r.ingestor.ingest(event).await.unwrap();
    }
    let reader = r.ingestor.store().reader().unwrap();

    // xorshift for index picks — deterministic, dependency-free.
    let mut state = 0xD1CEB00Cu64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let interior = [1u64, 2, 4000, 7000]; // non-boundary counts: harmless generality
    for &n in boundaries.iter().chain(&interior) {
        // The pin as the contract would have stored it at that instant.
        let pinned_root = {
            let mut mmr = Mmr::new();
            for i in 0..n {
                mmr.append_leaf(&testvec::chunk(i));
            }
            mmr.root()
        };

        // Random indices, plus every edge the test plan names: index 0, the last
        // leaf, and a duplicate.
        let mut indices = vec![0u64, n - 1, n - 1];
        for _ in 0..5 {
            indices.push(next() % n);
        }

        let set = build_proof_set(&reader, &indices, n, &pinned_root).unwrap();
        assert_eq!(root(set.n, &set.peaks), pinned_root, "re-bag at n={n}");
        for (&i, proven) in indices.iter().zip(&set.proven) {
            assert_eq!(proven.chunk, testvec::chunk(i));
            assert!(
                verify(&proven.chunk, i, &proven.path, n, &set.peaks),
                "contract-side verify failed at n={n}, i={i}"
            );
        }
    }
}

/// Failure modes are errors to alarm on, never submittable calldata: a pin beyond
/// the frontier (store behind L1), an out-of-range index, and a root the store
/// cannot reproduce.
#[tokio::test]
async fn d8_unreproducible_pins_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let declarations = vec![declaration(0, 0, 40)];
    let mut r = rig_serving(dir.path(), &declarations);
    r.ingestor.ingest(&declarations[0].0).await.unwrap();
    let reader = r.ingestor.store().reader().unwrap();
    let good_root = r.ingestor.store().mmr().root();

    match build_proof_set(&reader, &[0], 50, &good_root) {
        Err(ProofError::BeyondFrontier { n: 50, frontier: 40 }) => {}
        other => panic!("expected BeyondFrontier, got {other:?}"),
    }
    match build_proof_set(&reader, &[40], 40, &good_root) {
        Err(ProofError::IndexOutOfRange { index: 40, n: 40 }) => {}
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
    match build_proof_set(&reader, &[0], 40, &[0xAB; 32]) {
        Err(ProofError::PinMismatch { n: 40, .. }) => {}
        other => panic!("expected PinMismatch, got {other:?}"),
    }
}
