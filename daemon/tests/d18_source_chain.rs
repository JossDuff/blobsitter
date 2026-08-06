//! D18 — source redundancy: acquisition walks an ordered fallback chain; primary
//! failure degrades gracefully, full exhaustion is the D3 halt-and-alarm, and a
//! provider bootstrapping after the retention window can fill the whole store from an
//! archive-only source set.

mod common;

use blobsitter_daemon::ingest::IngestError;
use blobsitter_daemon::source::BlobSource;
use common::*;

/// Primary endpoint down (hard error): the fallback serves, ingest succeeds, and the
/// degradation is visible as warnings — not silence, not a critical.
#[tokio::test]
async fn d18_primary_failure_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let (event, blobs) = declaration(0, 0, 12);
    let entries = event.blob_versioned_hashes.iter().copied().zip(blobs.iter().cloned());

    let dead = MockSource::failing("dead-primary");
    let dead_calls = dead.call_counter();
    let sources: Vec<Box<dyn BlobSource>> =
        vec![Box::new(dead), Box::new(MockSource::serving("fallback", entries))];
    let mut r = rig(dir.path(), sources);

    assert!(r.ingestor.ingest(&event).await.unwrap());
    assert_eq!(dead_calls.load(std::sync::atomic::Ordering::SeqCst), 1, "primary was tried");
    assert!(r.alarm.criticals().is_empty());
    let warnings: Vec<_> = r.alarm.entries();
    assert!(warnings.iter().any(|(_, m)| m.contains("dead-primary")), "failure named");
    assert!(warnings.iter().any(|(_, m)| m.contains("fallback")), "fallback named");
}

/// Every source exhausted: the D3 halt — loudest alarm, stream blocked, no residue.
#[tokio::test]
async fn d18_chain_exhaustion_halts_and_alarms() {
    let dir = tempfile::tempdir().unwrap();
    let (event, _) = declaration(0, 0, 12);
    let sources: Vec<Box<dyn BlobSource>> = vec![
        Box::new(MockSource::failing("dead-primary")),
        Box::new(MockSource::empty("empty-fallback")),
        Box::new(MockSource::empty("empty-archive")),
    ];
    let mut r = rig(dir.path(), sources);

    match r.ingestor.ingest(&event).await {
        Err(IngestError::BlobsUnavailable { nonce: 0, source }) => {
            assert_eq!(source.wanted, 1);
            assert_eq!(source.missing, 1);
        }
        other => panic!("expected BlobsUnavailable, got {other:?}"),
    }
    assert!(r
        .alarm
        .criticals()
        .iter()
        .any(|m| m.contains("unavailable from every configured source")));
    assert_eq!(r.ingestor.store().frontier().leaf_count, 0);
}

/// One declaration's blobs split across two sources: the chain fills the remainder
/// from later sources instead of demanding any single one be complete.
#[tokio::test]
async fn d18_partial_fill_across_sources() {
    let dir = tempfile::tempdir().unwrap();
    let (event, blobs) = declaration(0, 0, 4097); // two blobs
    let vhs = &event.blob_versioned_hashes;

    let sources: Vec<Box<dyn BlobSource>> = vec![
        Box::new(MockSource::serving("has-first", [(vhs[0], blobs[0].clone())])),
        Box::new(MockSource::serving("has-second", [(vhs[1], blobs[1].clone())])),
    ];
    let mut r = rig(dir.path(), sources);
    assert!(r.ingestor.ingest(&event).await.unwrap());
    assert_eq!(r.ingestor.store().frontier().leaf_count, 4097);
}

/// A 200 with an empty (or short) blob list is a miss, not an answer: the beacon
/// adapter must keep walking its endpoint list — a pruned or under-custodying node
/// answers politely with nothing, and the fallback that has the data must be asked.
/// Driven over real HTTP against two beacon-shaped stubs so the production adapter
/// is what's under test.
#[tokio::test(flavor = "multi_thread")]
async fn d18_beacon_empty_200_falls_through_to_next_endpoint() {
    use blobsitter_daemon::source::beacon::BeaconSource;
    use blobsitter_daemon::source::BlobContext;
    use blobsitter_daemon::verify;
    use blobsitter_testkit::beacon_stub::BeaconStub;

    let (event, blobs) = declaration(0, 0, 12);
    let vh = event.blob_versioned_hashes[0];
    let slot = event.block_timestamp; // stub slots are timestamps (genesis 0, spt 1)

    let pruned = BeaconStub::spawn().await;
    pruned.register(slot, vec![]); // knows the slot, serves nothing: 200 + []
    let healthy = BeaconStub::spawn().await;
    healthy.register(slot, vec![(vh, blobs[0].to_vec())]);

    let source = BeaconSource::new(vec![pruned.url.clone(), healthy.url.clone()], 0, 1);
    let ctx = BlobContext { block_number: event.block_number, block_timestamp: slot };
    let got = source.fetch(&ctx, &[vh]).await.expect("second endpoint serves");
    assert_eq!(got.len(), 1);
    assert_eq!(verify::versioned_hash(&got[0]).unwrap(), vh);
}

/// A beacon config pointing at the wrong chain (genesis after the block timestamp)
/// must fail with an error that blames the config, not the blob sources.
#[tokio::test]
async fn d18_beacon_genesis_mismatch_is_a_config_error() {
    use blobsitter_daemon::source::beacon::BeaconSource;
    use blobsitter_daemon::source::BlobContext;

    let source = BeaconSource::new(vec!["http://127.0.0.1:1".into()], 2_000_000_000, 12);
    let ctx = BlobContext { block_number: 1, block_timestamp: 1_700_000_000 };
    let err = source.fetch(&ctx, &[[0u8; 32]]).await.unwrap_err();
    assert!(err.to_string().contains("different chain"), "got: {err}");
}

/// Bootstrap after the retention window: no near-head source has anything; a single
/// archive-style source (per-hash lookup, ignores block context) fills the entire
/// transcript from an empty store.
#[tokio::test]
async fn d18_archive_only_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let mut declarations = Vec::new();
    let mut n0 = 0;
    for nonce in 0..4u64 {
        let m = 5 + 100 * nonce;
        declarations.push(declaration(nonce, n0, m));
        n0 += m;
    }
    let archive_entries = declarations.iter().flat_map(|(e, blobs)| {
        e.blob_versioned_hashes.iter().copied().zip(blobs.iter().cloned())
    });
    let sources: Vec<Box<dyn BlobSource>> = vec![
        Box::new(MockSource::empty("beacon-past-retention")),
        Box::new(MockSource::serving("archive", archive_entries)),
    ];
    let mut r = rig(dir.path(), sources);

    for (event, _) in &declarations {
        assert!(r.ingestor.ingest(event).await.unwrap());
    }
    assert_eq!(r.ingestor.store().frontier().leaf_count, n0);
    assert!(r.alarm.criticals().is_empty());
}
