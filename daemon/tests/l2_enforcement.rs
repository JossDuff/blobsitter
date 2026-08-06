//! Layer 2 — enforcement against the REAL contract on anvil: the D7 response
//! differential (daemon-built calldata accepted by `respond`), deadline discipline
//! under a stalled mempool (D9), the full custody loop through both proof paths
//! (D11–D13), the lapse race (cure lands first), and unbonding behavior (D8/D17).
//!
//! In-process drivers (Responder / CustodyDriver / TxSender with a real operator
//! wallet) run against the deployed artifact with compressed windows; the
//! spawned-binary end-to-end lives in `l2_daemon_enforcement.rs`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;

use blobsitter_daemon::abi::Blobsitter;
use blobsitter_daemon::alarm::CapturingAlarm;
use blobsitter_daemon::custody::{CustodyDriver, CustodyParams, ProviderView};
use blobsitter_daemon::proofs::build_proof_set;
use blobsitter_daemon::prover::{NoProver, StubProver};
use blobsitter_daemon::responder::{Ledger, OpenChallenge, Responder};
use blobsitter_daemon::store::Reader;
use blobsitter_daemon::tx::TxSender;
use blobsitter_testkit::anvil::Harness;
use common::l2::skip_or_fail;
use common::*;

/// Everything an in-process enforcement test needs: a compressed-window instance, a
/// staked provider with a funded operator wallet, and a store mirroring the chain.
struct Rig2 {
    harness: Harness,
    dir: tempfile::TempDir,
    ingest: Rig,
    blob_feed: SharedBlobs,
    provider_id: u64,
    operator: Address,
    sender: Arc<TxSender>,
    alarm: Arc<CapturingAlarm>,
    contract: Blobsitter::BlobsitterInstance<DynProvider>,
    chunks_declared: u64,
}

impl Rig2 {
    /// Declare `m` pattern chunks on chain AND ingest them into the local store
    /// (the identical content, so roots agree by construction).
    async fn declare_and_ingest(&mut self, m: u64) {
        let stub = blobsitter_testkit::beacon_stub::BeaconStub::spawn().await;
        let outcome =
            blobsitter_testkit::declare::declare_pattern(&self.harness, &stub, m).await.unwrap();
        assert_eq!(outcome.prior_leaf_count, self.chunks_declared);
        let (event, blobs) = declaration(outcome.nonce, outcome.prior_leaf_count, m);
        {
            let mut feed = self.blob_feed.lock().unwrap();
            for (vh, blob) in event.blob_versioned_hashes.iter().zip(&blobs) {
                feed.insert(*vh, blob.clone());
            }
        }
        assert!(self.ingest.ingestor.ingest(&event).await.unwrap());
        self.chunks_declared += m;
    }

    fn reader(&self) -> Reader {
        self.ingest.ingestor.store().reader().unwrap()
    }

    async fn chain_now(&self) -> u64 {
        self.harness.block_timestamp(self.harness.provider.get_block_number().await.unwrap()).await.unwrap()
    }

    async fn provider_view(&self) -> ProviderView {
        let p = self.contract.getProvider(self.provider_id).call().await.unwrap();
        ProviderView::from(&p)
    }

    fn custody_params(&self, escape_threshold: u64) -> CustodyParams {
        CustodyParams {
            instance: self.harness.instance,
            provider_id: self.provider_id,
            custody_period: 300,
            lapse_grace: 60,
            custody_k: 16,
            max_sample: 8,
            escape_threshold,
            proving_timeout: Duration::from_secs(30),
        }
    }

    /// Tick a custody driver until `done` holds or the timeout hits.
    async fn drive_custody_until(
        &self,
        driver: &mut CustodyDriver,
        done: impl Fn(&Blobsitter::Provider) -> bool,
        what: &str,
    ) {
        for _ in 0..100 {
            let now = self.chain_now().await;
            let view = self.provider_view().await;
            driver.drive(now, &view, self.reader()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let p = self.contract.getProvider(self.provider_id).call().await.unwrap();
            if done(&p) {
                return;
            }
        }
        panic!("custody never reached: {what}; alarms: {:?}", self.alarm.entries());
    }
}

async fn rig2() -> Rig2 {
    let harness = Harness::spawn_with(|p| {
        p.responseWindow = 120;
        p.unbondingDelay = 60;
        p.custodyPeriod = 300;
        p.lapseGrace = 60;
        p.custodyK = 16;
        p.maxSample = 8;
    })
    .await
    .unwrap();

    let operator_key = PrivateKeySigner::random();
    let operator = operator_key.address();
    harness
        .fund(operator, U256::from(10u64) * U256::from(10u64).pow(U256::from(18)))
        .await
        .unwrap();
    let withdrawal = PrivateKeySigner::random().address();
    let provider_id = harness.stake(operator, withdrawal).await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (source, blob_feed) = MockSource::shared("l2-feed");
    let ingest = rig(dir.path().join("data").as_path(), vec![Box::new(source)]);
    let alarm = ingest.alarm.clone();

    let op_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(operator_key))
        .connect_http(harness.endpoint.parse().unwrap())
        .erased();
    let sender =
        Arc::new(TxSender::new(op_provider.clone(), operator, alarm.clone(), Duration::from_secs(3)));
    let contract = Blobsitter::new(harness.instance, op_provider);

    Rig2 {
        harness,
        dir,
        ingest,
        blob_feed,
        provider_id,
        operator,
        sender,
        alarm,
        contract,
        chunks_declared: 0,
    }
}

/// Answer one challenge with daemon-built calldata straight against the contract.
async fn respond(rig2: &Rig2, id: u64, indices: &[u64]) {
    let c = rig2.contract.getChallenge(id).call().await.unwrap();
    assert!(!c.resolved, "challenge {id} already resolved");
    let set =
        build_proof_set(&rig2.reader(), indices, c.pinnedLeafCount, &c.pinnedRoot.0).unwrap();
    let tx = TransactionRequest::default().with_to(rig2.harness.instance).with_input(
        Bytes::from(
            Blobsitter::respondCall {
                challengeId: id,
                indices: indices.to_vec(),
                n: set.n,
                pinnedPeaks: set.peaks.iter().map(|p| B256::from(*p)).collect(),
                proofs: set.proven.iter().map(|pc| pc.to_abi()).collect(),
            }
            .abi_encode(),
        ),
    );
    rig2.sender
        .send_until(tx, &format!("respond({id})"), Some(c.openedAt + 120))
        .await
        .unwrap_or_else(|e| panic!("respond({id}) rejected by the real contract: {e}"));
    assert!(rig2.contract.getChallenge(id).call().await.unwrap().resolved);
}

/// D7 — the response differential: random and adversarial index sets, including
/// duplicates, index 0, the last leaf, single-leaf trees, maxSample-sized sets, and
/// pins captured at PAST states (answered after the tree has grown).
#[tokio::test(flavor = "multi_thread")]
async fn l2_d7_response_differential() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;

    // Single-leaf tree: the smallest answerable state.
    r.declare_and_ingest(1).await;
    let single = r.harness.open_challenge(r.provider_id, vec![0]).await.unwrap();

    // Grow past a blob boundary, then open a spread of challenges pinned NOW.
    r.declare_and_ingest(4_500).await;
    let n = 4_501u64;
    let mut next = xorshift(0xC0FFEE);
    let mut cases: Vec<Vec<u64>> = vec![
        vec![0],
        vec![n - 1],
        vec![7, 7, 7],
        (0..8).map(|_| next() % n).collect(),
    ];
    // One more with the edges packed into a full maxSample set.
    let mut edge = vec![0, n - 1, n - 1, 4_095, 4_096];
    while edge.len() < 8 {
        edge.push(next() % n);
    }
    cases.push(edge);

    let mut ids = Vec::new();
    for indices in &cases {
        ids.push((r.harness.open_challenge(r.provider_id, indices.clone()).await.unwrap(), indices.clone()));
    }

    // Grow AGAIN so every pending pin is a historical state (D8 at Layer 2).
    r.declare_and_ingest(600).await;

    respond(&r, single, &[0]).await;
    for (id, indices) in ids {
        respond(&r, id, &indices).await;
    }
    // The bonds landed on the operator's hot wallet (compensating response gas).
    let balance = r.harness.provider.get_balance(r.operator).await.unwrap();
    assert!(balance > U256::from(10u64) * U256::from(10u64).pow(U256::from(18)) * U256::from(9) / U256::from(10));
}

/// D9 — deadline discipline: with the mempool stalled (automine off) the responder's
/// sender keeps replacing with higher fees and confirms once blocks flow again, well
/// inside the window.
#[tokio::test(flavor = "multi_thread")]
async fn l2_d9_escalation_through_a_stalled_mempool() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;
    r.declare_and_ingest(50).await;
    let id = r.harness.open_challenge(r.provider_id, vec![3, 30]).await.unwrap();
    let c = r.contract.getChallenge(id).call().await.unwrap();

    // Responder machinery end to end: ledger intake + drive + background job.
    let ledger = Ledger::open(r.dir.path()).unwrap();
    let mut responder = Responder::new(
        r.provider_id,
        r.harness.instance,
        120,
        ledger,
        r.sender.clone(),
        r.alarm.clone(),
    );
    responder
        .on_opened(OpenChallenge {
            challenge_id: id,
            indices: vec![3, 30],
            pinned_root: c.pinnedRoot.0,
            pinned_leaf_count: c.pinnedLeafCount,
            deadline: c.openedAt + 120,
            responded_tx: None,
        })
        .unwrap();

    r.harness.set_automine(false).await.unwrap();
    responder.drive(r.chain_now().await, &r.reader());

    // Let at least one confirm-timeout lapse so a replacement goes out.
    tokio::time::sleep(Duration::from_secs(4)).await;
    r.harness.set_automine(true).await.unwrap();
    r.harness.mine(1).await.unwrap();

    for _ in 0..50 {
        if r.contract.getChallenge(id).call().await.unwrap().resolved {
            break;
        }
        responder.drive(r.chain_now().await, &r.reader());
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        r.contract.getChallenge(id).call().await.unwrap().resolved,
        "response must confirm once the chain unblocks; alarms: {:?}",
        r.alarm.entries()
    );
    assert!(
        r.alarm.entries().iter().any(|(_, m)| m.contains("fee-escalation")),
        "the stall must have triggered at least one replacement"
    );
}

/// D11+D13 — the full escape-hatch loop on the real contract: the EMPTY snapshot
/// first (zero reveals), then a data-bearing period with real chunk reveals.
#[tokio::test(flavor = "multi_thread")]
async fn l2_custody_escape_hatch_loop() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;
    let params = r.custody_params(5);
    let mut driver =
        CustodyDriver::new(params, r.sender.clone(), Arc::new(NoProver), r.alarm.clone());

    // Period 0, empty dataset: begin → escape with ZERO reveals.
    r.drive_custody_until(
        &mut driver,
        |p| p.lastProvenPlusOne == 1 && p.lastDegraded,
        "empty snapshot proven via escape",
    )
    .await;

    // Data arrives; the next period's escape reveals real chunks.
    r.declare_and_ingest(500).await;
    r.harness.warp(300).await.unwrap();
    r.drive_custody_until(
        &mut driver,
        |p| p.lastProvenPlusOne == 2 && p.lastDegraded,
        "data-bearing snapshot proven via escape",
    )
    .await;
}

/// D11+D15 — the succinct path: a working prover (stub returning the mock verifier's
/// sentinel) proves the period without degradation.
#[tokio::test(flavor = "multi_thread")]
async fn l2_custody_succinct_path() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;
    r.declare_and_ingest(300).await;
    let prover = StubProver {
        proof: Ok(r.harness.valid_proof.to_vec()),
        delay: Duration::from_millis(100),
    };
    let mut driver = CustodyDriver::new(
        r.custody_params(5),
        r.sender.clone(),
        Arc::new(prover),
        r.alarm.clone(),
    );
    r.drive_custody_until(
        &mut driver,
        |p| p.lastProvenPlusOne == 1 && !p.lastDegraded,
        "period proven succinctly",
    )
    .await;
}

/// D13 — a failing prover falls back to the escape hatch within the same period.
#[tokio::test(flavor = "multi_thread")]
async fn l2_custody_prover_failure_falls_back() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;
    r.declare_and_ingest(200).await;
    let prover = StubProver {
        proof: Err("simulated prover outage".into()),
        delay: Duration::from_millis(50),
    };
    let mut driver = CustodyDriver::new(
        r.custody_params(5),
        r.sender.clone(),
        Arc::new(prover),
        r.alarm.clone(),
    );
    r.drive_custody_until(
        &mut driver,
        |p| p.lastProvenPlusOne == 1 && p.lastDegraded,
        "prover failure cured via escape hatch",
    )
    .await;
    assert!(r
        .alarm
        .entries()
        .iter()
        .any(|(_, m)| m.contains("falling back to the escape hatch")));
}

/// The lapse race: a provider deep in LAPSE_ELIGIBLE cures during the grace window,
/// and the pending lapse() reverts.
#[tokio::test(flavor = "multi_thread")]
async fn l2_lapse_race_cure_lands_first() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;
    r.declare_and_ingest(100).await;

    // Sleep through two full periods: LAPSE_ELIGIBLE (grace running).
    r.harness.warp(2 * 300).await.unwrap();
    let status = r.contract.custodyStatus(r.provider_id).call().await.unwrap();
    assert_eq!(status, Blobsitter::CustodyStatus::LAPSE_ELIGIBLE);

    // The cure: the driver notices, alarms Critical, and proves the CURRENT period.
    let mut driver = CustodyDriver::new(
        r.custody_params(5),
        r.sender.clone(),
        Arc::new(NoProver),
        r.alarm.clone(),
    );
    r.drive_custody_until(&mut driver, |p| p.lastProvenPlusOne != 0, "grace-window cure").await;
    assert!(r.alarm.criticals().iter().any(|m| m.contains("LAPSE_ELIGIBLE")));

    // The wolf shows up late: lapse() must now revert and the provider stays ACTIVE.
    assert!(r.contract.lapse(r.provider_id).call().await.is_err(), "cure beat the lapse");
    let p = r.contract.getProvider(r.provider_id).call().await.unwrap();
    assert_eq!(p.status, Blobsitter::ProviderStatus::ACTIVE);
}

/// D8+D17 — unbonding: custody obligations end, the store is still answerable, and a
/// challenge opened AFTER initiation pins the exit snapshot even though the chain has
/// grown past it.
#[tokio::test(flavor = "multi_thread")]
async fn l2_d17_unbonding_answers_at_the_exit_pin() {
    if skip_or_fail() {
        return;
    }
    let mut r = rig2().await;
    r.declare_and_ingest(80).await;
    let exit_leaf_count = 80u64;

    // Operator initiates unbonding (hot key; never the withdrawal key).
    let tx = TransactionRequest::default().with_to(r.harness.instance).with_input(Bytes::from(
        Blobsitter::initiateUnbondingCall { providerId: r.provider_id }.abi_encode(),
    ));
    r.sender.send_until(tx, "initiateUnbonding", None).await.unwrap();
    let p = r.contract.getProvider(r.provider_id).call().await.unwrap();
    assert_eq!(p.status, Blobsitter::ProviderStatus::UNBONDING);
    assert_eq!(p.exitLeafCount, exit_leaf_count);

    // Custody: obligations are over — the planner goes idle and beginProof reverts.
    let view = r.provider_view().await;
    assert!(!view.active);
    assert_eq!(
        blobsitter_daemon::custody::plan(
            r.chain_now().await,
            &view,
            &r.custody_params(5),
            Default::default(),
            true,
            false,
        ),
        blobsitter_daemon::custody::Plan::Idle
    );

    // The dataset keeps growing without us; the exit pin does not.
    r.declare_and_ingest(40).await;

    // A challenge in the unbonding window pins the EXIT snapshot; answering needs
    // the historical peak reconstruction (D8) — and must succeed.
    let id = r.harness.open_challenge(r.provider_id, vec![0, 79, 79]).await.unwrap();
    let c = r.contract.getChallenge(id).call().await.unwrap();
    assert_eq!(c.pinnedLeafCount, exit_leaf_count, "pin is the exit snapshot");
    respond(&r, id, &[0, 79, 79]).await;
}
