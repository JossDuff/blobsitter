//! D3 — no holes, no skips: `Declared` events are processed exactly once, in nonce
//! order; an unobtainable blob halts ingest at that declaration (loud), never skips.

mod common;

use blobsitter_daemon::ingest::IngestError;
use blobsitter_daemon::source::BlobSource;
use common::*;

/// Redelivered old events (restart rescans) are ignored; state never moves twice.
#[tokio::test]
async fn d3_exactly_once_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let declarations =
        vec![declaration(0, 0, 3), declaration(1, 3, 5), declaration(2, 8, 2)];
    let mut rig = rig_serving(dir.path(), &declarations);

    for (event, _) in &declarations {
        assert!(rig.ingestor.ingest(event).await.unwrap(), "first delivery commits");
    }
    let frontier = rig.ingestor.store().frontier().clone();

    for (event, _) in &declarations {
        assert!(!rig.ingestor.ingest(event).await.unwrap(), "redelivery is a no-op");
    }
    assert_eq!(*rig.ingestor.store().frontier(), frontier);
    assert!(rig.alarm.criticals().is_empty());
}

/// A nonce arriving ahead of the owed one is a gap: halt and alarm, never skip —
/// a hole in the stream would break every later inclusion proof.
#[tokio::test]
async fn d3_gap_halts_and_alarms() {
    let dir = tempfile::tempdir().unwrap();
    let declarations = vec![declaration(0, 0, 3), declaration(2, 8, 2)];
    let mut rig = rig_serving(dir.path(), &declarations);

    rig.ingestor.ingest(&declarations[0].0).await.unwrap();
    match rig.ingestor.ingest(&declarations[1].0).await {
        Err(IngestError::NonceGap { expected: 1, got: 2 }) => {}
        other => panic!("expected NonceGap, got {other:?}"),
    }
    assert_eq!(rig.ingestor.store().frontier().nonce, 1, "frontier stays at the gap");
    assert!(rig.alarm.criticals().iter().any(|m| m.contains("refusing to skip")));
}

/// An unobtainable blob blocks the stream; once a source can serve it, retrying the
/// SAME declaration succeeds and the stream continues — recovery without residue.
#[tokio::test]
async fn d3_unobtainable_blob_halts_then_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let (event, blobs) = declaration(0, 0, 6);

    let mut starved = rig(dir.path(), vec![Box::new(MockSource::empty("empty"))]);
    match starved.ingestor.ingest(&event).await {
        Err(IngestError::BlobsUnavailable { nonce: 0, .. }) => {}
        other => panic!("expected BlobsUnavailable, got {other:?}"),
    }
    assert!(starved
        .alarm
        .criticals()
        .iter()
        .any(|m| m.contains("unavailable from every")));
    drop(starved);

    // The daemon restarts (or the source recovers); the same event must now commit.
    let entries = event.blob_versioned_hashes.iter().copied().zip(blobs.iter().cloned());
    let sources: Vec<Box<dyn BlobSource>> =
        vec![Box::new(MockSource::serving("recovered", entries))];
    let mut recovered = rig(dir.path(), sources);
    assert!(recovered.ingestor.ingest(&event).await.unwrap());
    assert_eq!(recovered.ingestor.store().frontier().leaf_count, 6);
}
