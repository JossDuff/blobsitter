//! D19 — follower liveness: a run of consecutive failed ticks is not log noise, it
//! means the daemon is not following the chain — and the loudest alarm must fire
//! (and keep firing) until the condition clears.

mod common;

use std::sync::Arc;
use std::time::Duration;

use blobsitter_daemon::alarm::CapturingAlarm;
use blobsitter_daemon::follower::{Follower, FollowerConfig};
use blobsitter_daemon::ingest::Ingestor;
use blobsitter_daemon::source::SourceChain;
use blobsitter_daemon::store::Store;
use common::MockSource;

#[tokio::test]
async fn d19_consecutive_tick_failures_escalate_to_critical() {
    let dir = tempfile::tempdir().unwrap();
    let alarm = Arc::new(CapturingAlarm::new());
    let store = Store::open(dir.path()).unwrap();
    let ingestor = Ingestor::new(
        store,
        SourceChain::new(vec![Box::new(MockSource::empty("unused"))]),
        alarm.clone(),
    );
    // A dead RPC: nothing listens on port 1, so every tick fails fast.
    let provider = alloy::providers::ProviderBuilder::new()
        .connect_http("http://127.0.0.1:1".parse().unwrap());
    let mut follower = Follower::new(
        provider,
        ingestor,
        alarm.clone(),
        FollowerConfig {
            instance: alloy::primitives::Address::ZERO,
            deployment_block: 0,
            poll_interval: Duration::from_millis(1),
            log_page: 100,
            data_dir: dir.path().into(),
        },
    )
    .unwrap();

    for i in 1..=9 {
        follower.poll_once().await;
        assert!(alarm.criticals().is_empty(), "no page yet after {i} failures");
    }
    follower.poll_once().await;
    let criticals = alarm.criticals();
    assert_eq!(criticals.len(), 1, "the 10th consecutive failure pages");
    assert!(criticals[0].contains("NOT following the chain"), "got: {}", criticals[0]);

    // The condition persists: the page repeats at the next threshold multiple
    // instead of firing once and going quiet.
    for _ in 0..10 {
        follower.poll_once().await;
    }
    assert_eq!(alarm.criticals().len(), 2);
}
