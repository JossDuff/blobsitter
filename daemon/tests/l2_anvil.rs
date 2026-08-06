//! Layer 2 — the anvil integration rig: REAL contracts, REAL type-3 blob
//! transactions, the daemon running as a REAL separate process, blobs served through
//! the daemon's production beacon adapter (pointed at the harness's beacon-shaped
//! stub), and the mock SP1 verifier at the pinned address. M1 scenarios: declare →
//! ingest → verify root, finality gating (D4), and restart catch-up.
//!
//! Self-skips when anvil or the forge artifacts are missing (mirroring the fork-test
//! pattern); CI installs foundry and runs `forge build` so it never skips there.

mod common;

use std::path::Path;
use std::time::Duration;

use blobsitter_daemon::store::{Frontier, Store};
use blobsitter_reference::{testvec, Mmr};
use blobsitter_testkit::anvil::{preconditions_met, Harness};
use blobsitter_testkit::beacon_stub::BeaconStub;
use blobsitter_testkit::declare::declare_pattern;

struct Daemon {
    child: std::process::Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(dir: &Path, harness: &Harness, stub: &BeaconStub) -> Daemon {
    let data_dir = dir.join("data");
    let config = format!(
        r#"
instance = "{instance}"
execution_rpc = "{rpc}"
data_dir = "{data}"
deployment_block = {deploy}
poll_interval_secs = 1

[beacon]
endpoints = ["{stub}"]
genesis_time = 0
seconds_per_slot = 1
"#,
        instance = harness.instance,
        rpc = harness.endpoint,
        data = data_dir.display(),
        deploy = harness.instance_deploy_block,
        stub = stub.url,
    );
    let config_path = dir.join("blobsitterd.toml");
    std::fs::write(&config_path, config).unwrap();

    let log = std::fs::File::create(dir.join("daemon.log")).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_blobsitterd"))
        .arg(&config_path)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("daemon binary spawns");
    Daemon { child }
}

fn frontier(dir: &Path) -> Option<Frontier> {
    let raw = std::fs::read(dir.join("data/frontier.json")).ok()?;
    serde_json::from_slice(&raw).ok()
}

async fn wait_for_nonce(dir: &Path, nonce: u64) -> Frontier {
    for _ in 0..120 {
        if let Some(f) = frontier(dir) {
            if f.nonce >= nonce {
                return f;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let log = std::fs::read_to_string(dir.join("daemon.log")).unwrap_or_default();
    panic!("daemon never reached nonce {nonce}; log:\n{log}");
}

/// The core M1 scenario: declarations land as real blob txs, the daemon (own
/// process, production beacon adapter) ingests them once finalized, and the local
/// store is bit-for-bit the dataset the contract committed to.
#[tokio::test(flavor = "multi_thread")]
async fn l2_declare_ingest_verify_root_and_restart() {
    if !preconditions_met() {
        eprintln!("skipping: anvil or forge artifacts unavailable");
        return;
    }
    let harness = Harness::spawn().await.unwrap();
    let stub = BeaconStub::spawn().await;
    let dir = tempfile::tempdir().unwrap();

    // Mixed shapes: small, two-blob with partial tail, mid-size single blob.
    let mut total = 0u64;
    for m in [5u64, 4097, 100] {
        let outcome = declare_pattern(&harness, &stub, m).await.unwrap();
        assert_eq!(outcome.prior_leaf_count, total);
        total += m;
    }
    harness.mine(3).await.unwrap(); // finalize everything declared so far

    let daemon = spawn_daemon(dir.path(), &harness, &stub);
    let f = wait_for_nonce(dir.path(), 3).await;
    assert_eq!(f.leaf_count, total);

    // Local state == chain state, checked both by root and by raw bytes.
    let contract = harness.instance_contract();
    let chain_root = contract.root().call().await.unwrap();
    assert_eq!(Mmr::from_state(f.leaf_count, &f.peaks).unwrap().root(), chain_root.0);
    let raw = std::fs::read(dir.path().join("data/chunks.dat")).unwrap();
    assert_eq!(raw.len() as u64, total * 31);
    for i in 0..total {
        assert_eq!(&raw[(i as usize) * 31..(i as usize + 1) * 31], testvec::chunk(i).as_slice());
    }

    // Kill (SIGKILL — no graceful shutdown), declare more while the daemon is down,
    // restart, and require catch-up: crash consistency and cursor recovery together.
    drop(daemon);
    let m = 33u64;
    declare_pattern(&harness, &stub, m).await.unwrap();
    harness.mine(3).await.unwrap();

    let _daemon = spawn_daemon(dir.path(), &harness, &stub);
    let f = wait_for_nonce(dir.path(), 4).await;
    assert_eq!(f.leaf_count, total + m);
    let store = {
        // The daemon process holds the store; only inspect files after it's gone.
        drop(_daemon);
        Store::open(&dir.path().join("data")).unwrap()
    };
    assert_eq!(store.mmr().root(), contract.root().call().await.unwrap().0);
}

/// D4 at the integration level: a declaration in an UNFINALIZED block is invisible
/// to the store; it is ingested only once anvil's finalized tag passes its block.
#[tokio::test(flavor = "multi_thread")]
async fn l2_d4_ingest_follows_finality() {
    if !preconditions_met() {
        eprintln!("skipping: anvil or forge artifacts unavailable");
        return;
    }
    let harness = Harness::spawn().await.unwrap();
    let stub = BeaconStub::spawn().await;
    let dir = tempfile::tempdir().unwrap();

    harness.mine(3).await.unwrap(); // let the daemon's first scan cover deployment
    let _daemon = spawn_daemon(dir.path(), &harness, &stub);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Declared but NOT finalized (anvil: finalized = latest − 2).
    declare_pattern(&harness, &stub, 7).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = frontier(dir.path()).map(|f| f.nonce).unwrap_or(0);
    assert_eq!(before, 0, "unfinalized declaration must not be ingested");

    harness.mine(3).await.unwrap();
    let f = wait_for_nonce(dir.path(), 1).await;
    assert_eq!(f.leaf_count, 7);
}
