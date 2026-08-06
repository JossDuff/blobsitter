//! D5 — crash consistency: whatever instant the daemon dies at, restart recovers to a
//! consistent state and re-ingest is idempotent; no partial blob is ever visible as
//! committed store content.
//!
//! The commit protocol has exactly one ordering (append chunks → fsync → atomically
//! replace frontier), so every crash lands in one of a small set of on-disk states.
//! These tests fabricate each state directly — plus a fuzz across arbitrary torn
//! tails — and prove recovery from all of them. Real process-kill fuzzing is Layer 3.

mod common;

use blobsitter_daemon::store::{Store, StoreError};
use blobsitter_reference::testvec;
use common::*;

/// Ingest `k` declarations into `dir` and return the expected final chunk count.
async fn ingest_some(dir: &std::path::Path, k: usize) -> u64 {
    let mut declarations = Vec::new();
    let mut n0 = 0;
    for nonce in 0..k as u64 {
        let m = 3 + 2 * nonce;
        declarations.push(declaration(nonce, n0, m));
        n0 += m;
    }
    let mut r = rig_serving(dir, &declarations);
    for (event, _) in &declarations {
        r.ingestor.ingest(event).await.unwrap();
    }
    n0
}

fn reopen_and_check(dir: &std::path::Path, expected_chunks: u64) {
    let store = Store::open(dir).unwrap();
    assert_eq!(store.frontier().leaf_count, expected_chunks);
    assert_eq!(
        std::fs::read(dir.join("chunks.dat")).unwrap().len() as u64,
        expected_chunks * 31,
        "recovery trims the file to exactly the committed frontier"
    );
    for i in 0..expected_chunks {
        assert_eq!(store.chunk(i).unwrap(), testvec::chunk(i));
    }
    let mmr = store.mmr();
    assert_eq!(mmr.leaf_count(), expected_chunks);
}

/// Crash between the chunk append and the frontier commit: the un-committed tail is
/// discarded on open, and re-ingesting the same declaration lands byte-identically.
#[tokio::test]
async fn d5_crash_after_append_before_commit() {
    let dir = tempfile::tempdir().unwrap();
    let n = ingest_some(dir.path(), 2).await;

    // Fabricate the torn state: the next declaration's bytes fully appended, frontier
    // never advanced.
    let next = declaration(2, n, 7);
    let chunks: Vec<_> = (n..n + 7).map(testvec::chunk).collect();
    let mut tail = Vec::new();
    for c in &chunks {
        tail.extend_from_slice(c);
    }
    let path = dir.path().join("chunks.dat");
    let mut file = std::fs::read(&path).unwrap();
    file.extend_from_slice(&tail);
    std::fs::write(&path, &file).unwrap();

    reopen_and_check(dir.path(), n);

    // Re-ingest is idempotent: same declaration, same offsets, same final state.
    let mut r = rig_serving(dir.path(), &[next.clone()]);
    assert!(r.ingestor.ingest(&next.0).await.unwrap());
    reopen_and_check(dir.path(), n + 7);
}

/// Fuzz arbitrary torn tails, including a torn write inside a single chunk: any
/// number of extra bytes past the committed frontier vanishes on open.
#[tokio::test]
async fn d5_torn_tail_fuzz() {
    for extra in [1usize, 30, 31, 32, 100, 31 * 7, 31 * 7 + 13] {
        let dir = tempfile::tempdir().unwrap();
        let n = ingest_some(dir.path(), 2).await;
        let path = dir.path().join("chunks.dat");
        let mut file = std::fs::read(&path).unwrap();
        file.extend(std::iter::repeat_n(0xAB, extra));
        std::fs::write(&path, &file).unwrap();

        reopen_and_check(dir.path(), n);
    }
}

/// A leftover frontier tmp file (crash inside the atomic replace, before rename) is
/// inert: the committed frontier still governs.
#[tokio::test]
async fn d5_leftover_frontier_tmp_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let n = ingest_some(dir.path(), 2).await;
    std::fs::write(dir.path().join("frontier.json.tmp"), b"{ torn garbage").unwrap();
    reopen_and_check(dir.path(), n);
}

/// Committed data MISSING (file shorter than the frontier) is damage, not a crash
/// artifact — the store must refuse to run rather than serve a silent hole.
#[tokio::test]
async fn d5_missing_committed_data_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let n = ingest_some(dir.path(), 2).await;
    let path = dir.path().join("chunks.dat");
    let file = std::fs::read(&path).unwrap();
    std::fs::write(&path, &file[..file.len() - 31]).unwrap();

    match Store::open(dir.path()) {
        Err(StoreError::MissingCommittedData { found, committed }) => {
            assert_eq!(found, n - 1);
            assert_eq!(committed, n);
        }
        other => panic!("expected MissingCommittedData, got {:?}", other.err()),
    }
}
