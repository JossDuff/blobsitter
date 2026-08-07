//! D11–D15 — the custody loop's decision logic, walked with a simulated clock
//! through every custody-status transition and cure. The planner is pure, so these tests cover
//! period discipline (D11), snapshot proving (D12), the escape-hatch routing (D13),
//! status tracking (D14), and the prover abstraction's failure behavior (D15)
//! without a chain; the same logic runs against the real contract in the L2 suite.

mod common;

use std::time::Duration;

use blobsitter_daemon::custody::{
    build_witness, derive_status, plan, Commit, CustodyParams, DerivedStatus, InFlight,
    Plan, ProviderView,
};
use blobsitter_daemon::prover::{CustodyProver, NoProver, ProverError, StubProver};
use blobsitter_reference::{custody_index, root, testvec, verify, Mmr};
use common::*;

fn params() -> CustodyParams {
    CustodyParams {
        instance: alloy::primitives::Address::ZERO,
        provider_id: 1,
        custody_period: 1_000,
        lapse_grace: 200,
        custody_k: 16,
        max_sample: 4,
        escape_threshold: 100,
        proving_timeout: Duration::from_secs(60),
    }
}

fn view(anchor: u64, q_plus_one: u64, commit: Option<Commit>) -> ProviderView {
    ProviderView { active: true, anchor, last_proven_plus_one: q_plus_one, commit }
}

fn commit_at(period: u64, leaf_count: u64) -> Commit {
    Commit { period, seed: [7u8; 32], root: [8u8; 32], leaf_count }
}

/// D11 — exactly one beginProof per period, submissions only in the commit's own
/// period, proven periods never re-rolled.
#[test]
fn d11_period_discipline() {
    let p = params();
    let idle = InFlight::default();

    // Fresh period, nothing proven: open the window.
    assert_eq!(
        plan(1_500, &view(0, 0, None), &p, idle, true, false),
        Plan::Begin { deadline: 2_000 },
        "unproven current period begins"
    );
    // A begin already in flight is never duplicated.
    assert_eq!(
        plan(1_500, &view(0, 0, None), &p, InFlight { begin: true, ..idle }, true, false),
        Plan::Idle
    );
    // Current-period commit with ample time: prove succinctly.
    assert_eq!(
        plan(1_500, &view(0, 0, Some(commit_at(1, 50))), &p, idle, true, false),
        Plan::Prove { commit: commit_at(1, 50), deadline: 2_000 }
    );
    // A commit from an EARLIER period is worthless: never submitted against, the
    // current period simply begins anew.
    assert_eq!(
        plan(2_500, &view(0, 0, Some(commit_at(1, 50))), &p, idle, true, false),
        Plan::Begin { deadline: 3_000 },
        "stale commit is overwritten by a fresh begin"
    );
    // Already proven this period (q == p): nothing to do — the first commit was
    // binding and a re-roll is forbidden.
    assert_eq!(
        plan(1_500, &view(0, 2, None), &p, idle, true, false),
        Plan::Idle,
        "proven period must not re-begin"
    );
    // Proving in flight: wait.
    assert_eq!(
        plan(
            1_500,
            &view(0, 0, Some(commit_at(1, 50))),
            &p,
            InFlight { proving: true, ..idle },
            true,
            false
        ),
        Plan::Idle
    );
    // A submission lingering across the period boundary blocks the next begin —
    // two episodes must never race on the operator account.
    assert_eq!(
        plan(2_500, &view(0, 0, None), &p, InFlight { submitting: true, ..idle }, true, false),
        Plan::Idle,
        "begin waits for the lingering submission"
    );
}

/// D12 — the witness is cut at the COMMITTED leaf count even while the store has
/// grown past it, and every sample sits at the contract-derived index.
#[tokio::test]
async fn d12_snapshot_witness_cut_at_commit() {
    let dir = tempfile::tempdir().unwrap();
    let declarations = vec![declaration(0, 0, 40), declaration(1, 40, 60)];
    let mut r = rig_serving(dir.path(), &declarations);
    for (event, _) in &declarations {
        r.ingestor.ingest(event).await.unwrap();
    }
    assert_eq!(r.ingestor.store().frontier().leaf_count, 100, "store grew past the snapshot");

    // The commit snapshot: taken when the tree had only 40 leaves.
    let snapshot_root = {
        let mut mmr = Mmr::new();
        for i in 0..40 {
            mmr.append_leaf(&testvec::chunk(i));
        }
        mmr.root()
    };
    let p = params();
    let commit = Commit { period: 3, seed: [9u8; 32], root: snapshot_root, leaf_count: 40 };
    let reader = r.ingestor.store().reader().unwrap();
    let witness = build_witness(&p, &commit, &reader).unwrap();

    assert_eq!(witness.leaf_count, 40);
    assert_eq!(witness.k, 16);
    assert_eq!(root(40, &witness.peaks), snapshot_root);
    let instance20 = p.instance.into_array();
    for (j, sample) in witness.samples.iter().enumerate() {
        let idx = custody_index(&instance20, &commit.seed, p.provider_id, j as u64, 40);
        assert!(idx < 40, "sampling stays inside the snapshot");
        assert_eq!(sample.chunk, testvec::chunk(idx));
        assert!(verify(&sample.chunk, idx, &sample.path, 40, &witness.peaks));
    }
}

/// D13 — every route to the escape hatch: no prover, a failed prover, a shrinking
/// window (even mid-proving), and the empty snapshot.
#[test]
fn d13_escape_fallback_routing() {
    let p = params();
    let idle = InFlight::default();
    let c = commit_at(1, 50);
    let escape = Plan::Escape { commit: c, deadline: 2_000 };

    assert_eq!(plan(1_500, &view(0, 0, Some(c)), &p, idle, false, false), escape, "no prover");
    assert_eq!(
        plan(1_500, &view(0, 0, Some(c)), &p, idle, true, true),
        escape,
        "prover failed this period"
    );
    assert_eq!(
        plan(1_950, &view(0, 0, Some(c)), &p, idle, true, false),
        escape,
        "remaining time below the escape threshold"
    );
    assert_eq!(
        plan(1_950, &view(0, 0, Some(c)), &p, InFlight { proving: true, ..idle }, true, false),
        escape,
        "a running prover does not block the deadline fallback"
    );
    let empty = commit_at(1, 0);
    assert_eq!(
        plan(1_500, &view(0, 0, Some(empty)), &p, idle, true, false),
        Plan::Escape { commit: empty, deadline: 2_000 },
        "the empty snapshot is escape-only (zero reveals)"
    );
    // But an escape already submitting is never duplicated.
    assert_eq!(
        plan(1_500, &view(0, 0, Some(c)), &p, InFlight { submitting: true, ..idle }, false, false),
        Plan::Idle
    );
}

/// D14 — the derived status walks CURRENT → STALE → LAPSE_ELIGIBLE → LAPSABLE with
/// the clock, and any accepted proof snaps it back to CURRENT.
#[test]
fn d14_status_walk() {
    let p = params();
    // q = -1 (nothing proven), anchor 0, period 1000, grace 200.
    let status = |now, q_plus_one| derive_status(now, 0, q_plus_one, &p);

    assert_eq!(status(500, 0), DerivedStatus::Current, "first period still running");
    assert_eq!(status(1_500, 0), DerivedStatus::Stale, "one completed period missed");
    // Two completed misses: T = 2000; grace runs [2000, 2200).
    assert_eq!(status(2_000, 0), DerivedStatus::LapseEligible);
    assert_eq!(status(2_199, 0), DerivedStatus::LapseEligible);
    assert_eq!(status(2_200, 0), DerivedStatus::Lapsable);
    assert_eq!(status(5_000, 0), DerivedStatus::Lapsable, "lapsable never un-lapses by waiting");

    // A proof accepted at chain time 5_000 sets q = p(5_000) = 5 → CURRENT.
    assert_eq!(status(5_000, 6), DerivedStatus::Current, "cure restores CURRENT");
    // And the walk restarts relative to the new q.
    assert_eq!(status(7_500, 6), DerivedStatus::Stale);
    assert_eq!(status(8_100, 6), DerivedStatus::LapseEligible);
    assert_eq!(status(8_200, 6), DerivedStatus::Lapsable);

    // A lagging RPC can serve `now` older than a fresh anchor: that reads as
    // CURRENT (saturating), never a wrapped LAPSABLE or a panic.
    assert_eq!(derive_status(100, 5_000, 0, &p), DerivedStatus::Current);
    assert_eq!(
        plan(100, &view(5_000, 0, None), &p, InFlight::default(), true, false),
        Plan::Begin { deadline: 6_000 },
        "pre-anchor time plans within period 0"
    );

    // Unbonding cancels the walk entirely (planner side): no plan while inactive.
    let mut v = view(0, 0, Some(commit_at(2, 10)));
    v.active = false;
    assert_eq!(plan(2_500, &v, &p, InFlight::default(), true, false), Plan::Idle);
}

/// D15 — backend failure is an error value, never a panic; the escape-only backend
/// reports itself unavailable so the planner routes around it without a witness.
#[tokio::test]
async fn d15_prover_abstraction() {
    assert!(!NoProver.available());
    let witness_free = plan(
        1_500,
        &view(0, 0, Some(commit_at(1, 50))),
        &params(),
        InFlight::default(),
        NoProver.available(),
        false,
    );
    assert!(matches!(witness_free, Plan::Escape { .. }));

    let failing = StubProver {
        proof: Err("simulated backend outage".into()),
        delay: Duration::from_millis(1),
    };
    let witness = build_stub_witness();
    match failing.prove(witness.clone()).await {
        Err(ProverError::Failed(msg)) => assert!(msg.contains("outage")),
        other => panic!("expected Failed, got {other:?}"),
    }

    let working = StubProver { proof: Ok(vec![0xAA; 32]), delay: Duration::from_millis(1) };
    assert_eq!(working.prove(witness).await.unwrap(), vec![0xAA; 32]);
}

fn build_stub_witness() -> blobsitter_daemon::prover::CustodyWitness {
    blobsitter_daemon::prover::CustodyWitness {
        instance: [0u8; 20],
        provider_id: 1,
        seed: [0u8; 32],
        root: [0u8; 32],
        leaf_count: 1,
        k: 0,
        peaks: vec![],
        samples: vec![],
    }
}
