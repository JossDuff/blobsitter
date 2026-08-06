//! D2 — verify before write: every fetched blob is verified against its on-chain
//! versioned hash before a single byte enters the store; corrupt or mislabeled blobs
//! are rejected and refetched from the next source; unverified bytes have no path to
//! store state.

mod common;

use blobsitter_daemon::alarm::Severity;
use blobsitter_daemon::ingest::IngestError;
use blobsitter_daemon::source::BlobSource;
use blobsitter_daemon::verify;
use common::*;

fn store_bytes(dir: &std::path::Path) -> Vec<u8> {
    std::fs::read(dir.join("chunks.dat")).unwrap_or_default()
}

/// A corrupt primary must not poison anything: the blob fails hash identity, the
/// fallback serves the real bytes, ingest succeeds.
#[tokio::test]
async fn d2_corrupt_blob_rejected_and_refetched() {
    let dir = tempfile::tempdir().unwrap();
    let (event, blobs) = declaration(0, 0, 10);
    let vh = event.blob_versioned_hashes[0];

    let bad = MockSource::serving("corrupt-primary", [(vh, corrupted(&blobs[0]))]);
    let bad_calls = bad.call_counter();
    let good = MockSource::serving("good-fallback", [(vh, blobs[0].clone())]);
    let mut rig = rig(dir.path(), vec![Box::new(bad), Box::new(good)]);

    assert!(rig.ingestor.ingest(&event).await.unwrap());
    assert_eq!(bad_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(rig.ingestor.store().frontier().leaf_count, 10);
    // The fallback was a Warning-grade event; nothing critical happened.
    assert!(rig.alarm.criticals().is_empty());
    assert!(!rig.alarm.entries().is_empty(), "degraded acquisition must be visible");
}

/// A source that mislabels a valid-but-wrong blob is caught identically to one that
/// corrupts bytes: identity comes from the recomputed hash, never the label.
#[tokio::test]
async fn d2_mislabeled_blob_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (event, _) = declaration(0, 0, 10);
    let (_, other_blobs) = declaration(0, 500, 10);

    let liar = MockSource::serving("liar", [(event.blob_versioned_hashes[0], other_blobs[0].clone())]);
    let mut rig = rig(dir.path(), vec![Box::new(liar)]);

    match rig.ingestor.ingest(&event).await {
        Err(IngestError::BlobsUnavailable { nonce: 0, .. }) => {}
        other => panic!("expected BlobsUnavailable, got {other:?}"),
    }
    assert_eq!(store_bytes(dir.path()).len(), 0, "no unverified byte may reach the store");
    assert_eq!(rig.ingestor.store().frontier().leaf_count, 0);
    assert!(!rig.alarm.criticals().is_empty(), "exhaustion is a critical alarm");
}

/// Even with every source corrupt, the store files stay byte-identical — failure
/// leaves no residue whatsoever.
#[tokio::test]
async fn d2_failed_ingest_leaves_no_residue() {
    let dir = tempfile::tempdir().unwrap();
    let d0 = declaration(0, 0, 4);
    let mut first = rig_serving(dir.path(), &[d0.clone()]);
    first.ingestor.ingest(&d0.0).await.unwrap();
    let committed = store_bytes(dir.path());
    let frontier_before = std::fs::read(dir.path().join("frontier.json")).unwrap();
    drop(first);

    let (event, blobs) = declaration(1, 4, 6);
    let sources: Vec<Box<dyn BlobSource>> = vec![Box::new(MockSource::serving(
        "corrupt",
        event.blob_versioned_hashes.iter().copied().zip(blobs.iter().map(corrupted)),
    ))];
    let mut second = rig(dir.path(), sources);
    assert!(second.ingestor.ingest(&event).await.is_err());

    assert_eq!(store_bytes(dir.path()), committed, "chunk file untouched by failed ingest");
    assert_eq!(
        std::fs::read(dir.path().join("frontier.json")).unwrap(),
        frontier_before,
        "frontier untouched by failed ingest"
    );
}

/// A blob that verifies by hash but violates canonical chunk encoding contradicts the
/// on-chain equivalence proof — the loudest halt there is, never a skip.
#[tokio::test]
async fn d2_non_canonical_blob_is_a_protocol_contradiction() {
    let dir = tempfile::tempdir().unwrap();
    let (mut event, blobs) = declaration(0, 0, 10);
    let mut evil = blobs[0].clone();
    evil[0] = 0x01; // nonzero high byte of element 0: hash-consistent only with itself
    event.blob_versioned_hashes[0] = verify::versioned_hash(&evil).unwrap();

    let sources: Vec<Box<dyn BlobSource>> =
        vec![Box::new(MockSource::serving("s", [(event.blob_versioned_hashes[0], evil)]))];
    let mut rig = rig(dir.path(), sources);

    match rig.ingestor.ingest(&event).await {
        Err(IngestError::ProtocolContradiction { nonce: 0, .. }) => {}
        other => panic!("expected ProtocolContradiction, got {other:?}"),
    }
    assert_eq!(store_bytes(dir.path()).len(), 0);
    assert!(rig
        .alarm
        .entries()
        .iter()
        .any(|(s, m)| *s == Severity::Critical && m.contains("HALT")));
}

/// Direct checks of the verification primitives (identity + canonical unpacking).
#[tokio::test]
async fn d2_versioned_hash_and_unpacking() {
    let (event, blobs) = declaration(0, 0, 4097);

    for (vh, blob) in event.blob_versioned_hashes.iter().zip(&blobs) {
        let computed = verify::versioned_hash(blob).unwrap();
        assert_eq!(computed, *vh);
        assert_eq!(computed[0], 0x01, "version byte");
        assert_ne!(verify::versioned_hash(&corrupted(blob)).unwrap(), *vh);
    }

    // Unpacking rejects wrong blob counts and nonzero padding.
    assert!(verify::chunks_from_blobs(&blobs, 4097).is_ok());
    assert!(verify::chunks_from_blobs(&blobs[..1], 4097).is_err(), "missing blob");
    assert!(verify::chunks_from_blobs(&blobs, 4096).is_err(), "extra blob");
    // A zero PADDING element claimed as data is invisible here (an all-zero chunk is
    // legitimate data) — that lie is caught downstream by the subtree-root comparison.
    let claimed_extra = verify::chunks_from_blobs(&blobs, 4098).unwrap();
    assert_eq!(claimed_extra.len(), 4098);
    let mut dirty = blobs.clone();
    dirty[1][32 * 2 + 5] = 0xFF; // element 2 of blob 1 is padding for m=4097
    assert!(verify::chunks_from_blobs(&dirty, 4097).is_err(), "nonzero padding");
}
