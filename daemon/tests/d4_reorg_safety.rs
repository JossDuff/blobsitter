//! D4 — reorg safety. The structural half: the follower delivers FINALIZED events
//! only, so ingest and the store never observe a declaration that can still be
//! reorged away (verified end-to-end in the Layer-2 anvil suite, where a declaration
//! is ingested only after anvil finalizes its block). What Layer 1 can pin down is
//! the store side: committed state is immune to conflicting redelivery — even a
//! buggy or malicious event stream cannot rewrite what finality already committed.

mod common;

use common::*;

#[tokio::test]
async fn d4_committed_state_immune_to_conflicting_redelivery() {
    let dir = tempfile::tempdir().unwrap();
    let real = declaration(0, 0, 4);
    let mut rig = rig_serving(dir.path(), &[real.clone()]);
    rig.ingestor.ingest(&real.0).await.unwrap();
    let frontier = rig.ingestor.store().frontier().clone();

    // A conflicting variant of nonce 0 — different size, different content — as a
    // hostile stream might replay it. Committed nonces are settled: no-op, no residue.
    let (conflicting, _) = declaration(0, 0, 9);
    assert!(!rig.ingestor.ingest(&conflicting).await.unwrap());
    assert_eq!(*rig.ingestor.store().frontier(), frontier);
    assert_eq!(
        std::fs::read(dir.path().join("chunks.dat")).unwrap().len(),
        4 * 31,
        "no bytes from the conflicting variant"
    );
}
