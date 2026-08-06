//! Layer 2 — the whole daemon BINARY doing enforcement: config with a `[provider]`
//! section, operator key via the environment, and no test scaffolding inside the
//! process. Covers D10's restart-with-open-obligation end to end: the challenge is
//! opened while the daemon is DOWN, and the restarted process must find it in the
//! finalized scan, answer it from its store, and keep its custody duties running —
//! all through the real contract.

mod common;

use std::time::Duration;

use blobsitter_testkit::anvil::{preconditions_met, Harness};
use blobsitter_testkit::beacon_stub::BeaconStub;
use blobsitter_testkit::declare::declare_pattern;
use common::l2::{daemon_log, spawn_daemon, wait_for_nonce};

fn skip_or_fail() -> bool {
    if preconditions_met() {
        return false;
    }
    if std::env::var_os("BLOBSITTER_REQUIRE_L2").is_some() {
        panic!("BLOBSITTER_REQUIRE_L2 is set but anvil/forge artifacts are unavailable");
    }
    eprintln!("skipping: anvil or forge artifacts unavailable");
    true
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_d10_binary_restarts_into_an_open_challenge() {
    if skip_or_fail() {
        return;
    }
    let harness = Harness::spawn_with(|p| {
        p.responseWindow = 300;
        p.custodyPeriod = 600;
        p.lapseGrace = 120;
        p.custodyK = 16;
        p.maxSample = 8;
    })
    .await
    .unwrap();
    let stub = BeaconStub::spawn().await;
    let dir = tempfile::tempdir().unwrap();

    // The operator is a pre-funded anvil dev key; the daemon gets it via env only.
    let operator_key = harness.dev_key(5);
    let key_hex = format!("0x{}", hex::encode(operator_key.to_bytes()));
    let withdrawal = harness.dev_key(6).address();
    let provider_id = harness.stake(operator_key.address(), withdrawal).await.unwrap();

    declare_pattern(&harness, &stub, 60).await.unwrap();
    harness.mine(3).await.unwrap();

    // First life: ingest the dataset, then die without ceremony.
    let daemon = spawn_daemon(dir.path(), &harness, &stub, Some((provider_id, &key_hex)));
    let f = wait_for_nonce(dir.path(), 1).await;
    assert_eq!(f.leaf_count, 60);
    drop(daemon); // SIGKILL

    // The challenge arrives while nobody is home, and finalizes.
    let id = harness.open_challenge(provider_id, vec![0, 30, 59, 59]).await.unwrap();
    harness.mine(3).await.unwrap();

    // Second life: the scan must surface the obligation and the responder answer it.
    let _daemon = spawn_daemon(dir.path(), &harness, &stub, Some((provider_id, &key_hex)));
    let contract = harness.instance_contract();
    let mut resolved = false;
    for _ in 0..120 {
        // The daemon's own txs mine instantly, but finality needs headroom: keep
        // blocks flowing like a real chain would.
        harness.mine(1).await.unwrap();
        if contract.getChallenge(id).call().await.unwrap().resolved {
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        resolved,
        "restarted daemon never answered the challenge; log:\n{}",
        daemon_log(dir.path())
    );

    // And its custody loop is alive too: period 0 gets proven (escape hatch — the
    // binary has no prover) without any test-side help.
    let mut proven = false;
    for _ in 0..120 {
        harness.mine(1).await.unwrap();
        let p = contract.getProvider(provider_id).call().await.unwrap();
        if p.lastProvenPlusOne >= 1 {
            assert!(p.lastDegraded, "escape hatch marks the period degraded");
            proven = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        proven,
        "custody loop never proved period 0; log:\n{}",
        daemon_log(dir.path())
    );
}
