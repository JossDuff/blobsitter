//! The custody loop (test plan D11–D14): one binding `beginProof` per period, a
//! proof — succinct or escape-hatch — landed in the SAME period as its commit, and a
//! continuously tracked derived custody status whose degradations alarm long before
//! `lapse()` becomes callable.
//!
//! The decision logic is a PURE planner over `(chain time, on-chain provider view,
//! in-flight work)`, so every custody-status transition (CURRENT → STALE →
//! LAPSE_ELIGIBLE → LAPSABLE, and every cure) is unit-testable with a simulated
//! clock; the driver around it only executes plans. Custody needs no
//! persistent daemon state at all: the commit lives on chain, so a restarted daemon
//! reads `getProvider` and resumes exactly where the chain says it is.
//!
//! The escape hatch is SNARK-free forever (keccak + calldata; protocol invariant):
//! its path here goes `build_proof_set` → `submitProofEscape`, and no prover type
//! appears anywhere in it — a prover bug cannot take both paths down.

use std::sync::Arc;
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;

use blobsitter_reference::{custody_index, Hash};

use crate::abi::Blobsitter;
use crate::alarm::{AlarmSink, Severity};
use crate::proofs::build_proof_set;
use crate::prover::{CustodyProver, CustodyWitness, ProverError};
use crate::store::Reader;
use crate::tx::TxSender;

/// The custody-relevant slice of `getProvider`, read at the latest block each tick.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderView {
    pub active: bool,
    pub anchor: u64,
    /// The spec's `lastProven + 1` (0 encodes −1), exactly as the contract stores it.
    pub last_proven_plus_one: u64,
    pub commit: Option<Commit>,
}

impl From<&Blobsitter::Provider> for ProviderView {
    /// The one decoding of the on-chain record (including the plus-one commit
    /// convention) — production and tests must read the same view.
    fn from(p: &Blobsitter::Provider) -> Self {
        ProviderView {
            active: p.status == Blobsitter::ProviderStatus::ACTIVE,
            anchor: p.anchor,
            last_proven_plus_one: p.lastProvenPlusOne,
            commit: (p.commitPeriodPlusOne != 0).then(|| Commit {
                period: p.commitPeriodPlusOne - 1,
                seed: p.commitSeed.0,
                root: p.commitRoot.0,
                leaf_count: p.commitLeafCount,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Commit {
    pub period: u64,
    pub seed: Hash,
    pub root: Hash,
    pub leaf_count: u64,
}

/// Instance parameters the loop plans against (constructor constants, read once).
#[derive(Debug, Clone)]
pub struct CustodyParams {
    pub instance: Address,
    pub provider_id: u64,
    pub custody_period: u64,
    pub lapse_grace: u64,
    pub custody_k: u32,
    pub max_sample: u16,
    /// Remaining-period-time floor below which the loop stops trusting the prover
    /// and takes the escape hatch.
    pub escape_threshold: u64,
    pub proving_timeout: Duration,
}

/// The derived custody status — never stored, computed fresh from
/// `(now, anchor, lastProven)` exactly as the contract derives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedStatus {
    Current,
    Stale,
    LapseEligible,
    Lapsable,
}

pub fn derive_status(now: u64, anchor: u64, last_proven_plus_one: u64, params: &CustodyParams) -> DerivedStatus {
    // Saturating: a lagging RPC can serve `now` older than a freshly staked
    // provider's anchor, and that must read as CURRENT, not a wrapped LAPSABLE.
    let p = now.saturating_sub(anchor) / params.custody_period;
    let q_plus_one = last_proven_plus_one; // q = q_plus_one - 1, possibly -1
    if p <= q_plus_one {
        // p ≤ q + 1
        return DerivedStatus::Current;
    }
    if p == q_plus_one + 1 {
        // p == q + 2
        return DerivedStatus::Stale;
    }
    // p ≥ q + 3: T is the instant the second consecutive missed period completed.
    let t = anchor + (q_plus_one + 2) * params.custody_period;
    if now < t + params.lapse_grace {
        DerivedStatus::LapseEligible
    } else {
        DerivedStatus::Lapsable
    }
}

/// What the driver is already doing (a plan never duplicates in-flight work).
#[derive(Debug, Clone, Copy, Default)]
pub struct InFlight {
    pub begin: bool,
    pub proving: bool,
    pub submitting: bool,
}

/// One tick's decision.
#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    Idle,
    /// Open this period's proof window (`beginProof`).
    Begin { deadline: u64 },
    /// Start the prover against the committed snapshot.
    Prove { commit: Commit, deadline: u64 },
    /// Take the SNARK-free path for the committed snapshot.
    Escape { commit: Commit, deadline: u64 },
}

/// The pure heart of D11–D13. `prover_available` and `prover_failed_this_period`
/// route between the succinct and escape paths; `now` and the view do the rest.
pub fn plan(
    now: u64,
    view: &ProviderView,
    params: &CustodyParams,
    in_flight: InFlight,
    prover_available: bool,
    prover_failed_this_period: bool,
) -> Plan {
    if !view.active {
        // Custody obligations end at unbonding (D17); EXITED/SLASHED likewise.
        return Plan::Idle;
    }
    let p = now.saturating_sub(view.anchor) / params.custody_period;
    let period_end = view.anchor + (p + 1) * params.custody_period;

    match view.commit {
        // A commit for the CURRENT period: land a proof in it (D11: same period).
        Some(commit) if commit.period == p => {
            if in_flight.submitting {
                return Plan::Idle;
            }
            let remaining = period_end.saturating_sub(now);
            // The empty snapshot is provable only by the escape hatch (zero
            // reveals); the circuit has nothing to sample from nothing.
            let must_escape = commit.leaf_count == 0
                || !prover_available
                || prover_failed_this_period
                || remaining < params.escape_threshold;
            if must_escape {
                // Even with the prover still running: time (or trust) ran out, the
                // escape goes NOW — a late succinct proof is discarded harmlessly.
                return Plan::Escape { commit, deadline: period_end };
            }
            if in_flight.proving {
                return Plan::Idle;
            }
            Plan::Prove { commit, deadline: period_end }
        }
        // A stale commit (missed period) or none: open the current period's window,
        // unless it is already proven (q == p) — never re-roll a proven period. A
        // submission lingering across the period boundary also blocks: overlapping
        // it with a beginProof would race two episodes on one account.
        _ => {
            if in_flight.begin || in_flight.submitting || view.last_proven_plus_one > p {
                return Plan::Idle;
            }
            Plan::Begin { deadline: period_end }
        }
    }
}

/// A proving task in flight: the committed period it serves and its handle.
type ProvingTask = (u64, tokio::task::JoinHandle<Result<Vec<u8>, ProverError>>);

/// Executes plans and tracks in-flight work. One instance per provider.
pub struct CustodyDriver {
    params: CustodyParams,
    sender: Arc<TxSender>,
    prover: Arc<dyn CustodyProver>,
    alarm: Arc<dyn AlarmSink>,
    begin: Option<tokio::task::JoinHandle<()>>,
    proving: Option<ProvingTask>,
    submitting: Option<tokio::task::JoinHandle<()>>,
    prover_failed_period: Option<u64>,
    last_status: Option<DerivedStatus>,
}

impl CustodyDriver {
    pub fn new(
        params: CustodyParams,
        sender: Arc<TxSender>,
        prover: Arc<dyn CustodyProver>,
        alarm: Arc<dyn AlarmSink>,
    ) -> Self {
        Self {
            params,
            sender,
            prover,
            alarm,
            begin: None,
            proving: None,
            submitting: None,
            prover_failed_period: None,
            last_status: None,
        }
    }

    /// One tick: reap finished work, alarm on status transitions, execute the plan.
    pub async fn drive(&mut self, now: u64, view: &ProviderView, reader: Reader) {
        self.reap(view).await;
        if view.active {
            self.status_alarms(now, view);
        }

        let in_flight = InFlight {
            begin: self.begin.is_some(),
            proving: self.proving.is_some(),
            submitting: self.submitting.is_some(),
        };
        let prover_failed_this_period = view
            .commit
            .map(|c| self.prover_failed_period == Some(c.period))
            .unwrap_or(false);
        let decided = plan(
            now,
            view,
            &self.params,
            in_flight,
            self.prover.available(),
            prover_failed_this_period,
        );
        match decided {
            Plan::Idle => {}
            Plan::Begin { deadline } => self.spawn_begin(deadline),
            Plan::Prove { commit, deadline } => self.spawn_prove(commit, deadline, reader),
            Plan::Escape { commit, deadline } => self.spawn_escape(commit, deadline, reader),
        }
    }

    /// Collect finished background work. A finished prover run either hands its
    /// proof to a submit job or marks the period as prover-failed (escape next tick).
    async fn reap(&mut self, view: &ProviderView) {
        if self.begin.as_ref().is_some_and(|h| h.is_finished()) {
            let _ = self.begin.take().unwrap().await;
        }
        if self.submitting.as_ref().is_some_and(|h| h.is_finished()) {
            let _ = self.submitting.take().unwrap().await;
        }
        if self.proving.as_ref().is_some_and(|(_, h)| h.is_finished()) {
            let (period, handle) = self.proving.take().unwrap();
            match handle.await {
                Ok(Ok(proof)) => {
                    // Submit only if the commit is still the one we proved (never
                    // submit a proof for an expired commit) AND nothing else is
                    // already submitting — a proof finishing after the escape went
                    // out must be discarded, not raced against it on one account.
                    if view.commit.map(|c| c.period) == Some(period) && self.submitting.is_none()
                    {
                        let deadline =
                            view.anchor + (period + 1) * self.params.custody_period;
                        self.spawn_submit_proof(proof, period, deadline);
                    } else {
                        self.alarm.alarm(
                            Severity::Warning,
                            &format!(
                                "custody proof for period {period} finished after its \
                                 commit expired or was superseded; discarding"
                            ),
                        );
                    }
                }
                Ok(Err(e)) => {
                    self.alarm.alarm(
                        Severity::Warning,
                        &format!(
                            "custody prover failed for period {period}: {e}; falling \
                             back to the escape hatch"
                        ),
                    );
                    self.prover_failed_period = Some(period);
                }
                Err(join_err) => {
                    self.alarm.alarm(
                        Severity::Warning,
                        &format!(
                            "custody proving task died for period {period}: {join_err}; \
                             falling back to the escape hatch"
                        ),
                    );
                    self.prover_failed_period = Some(period);
                }
            }
        }
    }

    /// D14: every degradation is announced on TRANSITION (with escalating severity),
    /// not spammed every tick — and recovery is announced too.
    fn status_alarms(&mut self, now: u64, view: &ProviderView) {
        let status = derive_status(now, view.anchor, view.last_proven_plus_one, &self.params);
        if self.last_status == Some(status) {
            return;
        }
        match status {
            DerivedStatus::Current => {
                if self.last_status.is_some() {
                    tracing::info!("custody status recovered to CURRENT");
                }
            }
            DerivedStatus::Stale => self.alarm.alarm(
                Severity::Warning,
                "custody status STALE: one completed period unproven; proving immediately",
            ),
            DerivedStatus::LapseEligible => self.alarm.alarm(
                Severity::Critical,
                "custody status LAPSE_ELIGIBLE: inside the cure grace window — a proof \
                 (either path) must land NOW or the stake is gone",
            ),
            DerivedStatus::Lapsable => self.alarm.alarm(
                Severity::Critical,
                "custody status LAPSABLE: anyone may slash this provider at any moment",
            ),
        }
        self.last_status = Some(status);
    }

    fn spawn_begin(&mut self, deadline: u64) {
        let sender = self.sender.clone();
        let alarm = self.alarm.clone();
        let tx = TransactionRequest::default()
            .with_to(self.params.instance)
            .with_input(Bytes::from(
                Blobsitter::beginProofCall { providerId: self.params.provider_id }.abi_encode(),
            ));
        self.begin = Some(tokio::spawn(async move {
            if let Err(e) = sender.send_until(tx, "beginProof", Some(deadline)).await {
                alarm.alarm(Severity::Critical, &format!("beginProof failed: {e}"));
            }
        }));
    }

    fn spawn_prove(&mut self, commit: Commit, _deadline: u64, reader: Reader) {
        let params = self.params.clone();
        let prover = self.prover.clone();
        let timeout = self.params.proving_timeout;
        let handle = tokio::spawn(async move {
            // Witness cut at the COMMITTED leaf count (D12): the store may grow
            // mid-proving; the snapshot cannot.
            let witness = tokio::task::spawn_blocking(move || {
                build_witness(&params, &commit, &reader)
            })
            .await
            .map_err(|e| ProverError::Failed(format!("witness task died: {e}")))?
            .map_err(|e| ProverError::Failed(format!("witness build: {e}")))?;
            match tokio::time::timeout(timeout, prover.prove(witness)).await {
                Ok(result) => result,
                Err(_) => Err(ProverError::Failed(format!(
                    "prover exceeded its {timeout:?} budget (treating a hang like a failure)"
                ))),
            }
        });
        self.proving = Some((commit.period, handle));
    }

    fn spawn_submit_proof(&mut self, proof: Vec<u8>, period: u64, deadline: u64) {
        let sender = self.sender.clone();
        let alarm = self.alarm.clone();
        // Bounded by the period's end: a submit that would straddle the boundary
        // reverts on chain anyway (the commit expires with its period), so the
        // sender must not keep escalating past it.
        let period_end_deadline = Some(deadline);
        let tx = TransactionRequest::default()
            .with_to(self.params.instance)
            .with_input(Bytes::from(
                Blobsitter::submitProofCall {
                    providerId: self.params.provider_id,
                    proof: Bytes::from(proof),
                }
                .abi_encode(),
            ));
        self.submitting = Some(tokio::spawn(async move {
            match sender.send_until(tx, "submitProof", period_end_deadline).await {
                Ok(hash) => tracing::info!(period, %hash, "custody proof accepted (succinct)"),
                Err(e) => alarm.alarm(
                    Severity::Critical,
                    &format!("submitProof for period {period} failed: {e}"),
                ),
            }
        }));
    }

    fn spawn_escape(&mut self, commit: Commit, deadline: u64, reader: Reader) {
        let params = self.params.clone();
        let sender = self.sender.clone();
        let alarm = self.alarm.clone();
        self.submitting = Some(tokio::spawn(async move {
            let reveals = if commit.leaf_count == 0 {
                // Vacuous custody of the empty dataset: zero reveals, pin check only.
                Ok(crate::proofs::ProofSet { n: 0, peaks: vec![], proven: vec![] })
            } else {
                let params = params.clone();
                tokio::task::spawn_blocking(move || {
                    let indices = sample_indices(&params, &commit, params.max_sample as u64);
                    build_proof_set(&reader, &indices, commit.leaf_count, &commit.root)
                })
                .await
                .unwrap_or_else(|e| {
                    Err(crate::proofs::ProofError::PinMismatch {
                        n: commit.leaf_count,
                        expected: format!("task died: {e}"),
                        computed: String::new(),
                    })
                })
            };
            let set = match reveals {
                Ok(set) => set,
                Err(e) => {
                    alarm.alarm(
                        Severity::Critical,
                        &format!(
                            "escape-hatch reveal construction failed for period {}: {e} — \
                             the period CANNOT be proven from this store",
                            commit.period
                        ),
                    );
                    return;
                }
            };
            let tx = TransactionRequest::default()
                .with_to(params.instance)
                .with_input(Bytes::from(
                    Blobsitter::submitProofEscapeCall {
                        providerId: params.provider_id,
                        n: set.n,
                        pinnedPeaks: set.peaks.iter().map(|p| B256::from(*p)).collect(),
                        reveals: set.proven.iter().map(|pc| pc.to_abi()).collect(),
                    }
                    .abi_encode(),
                ));
            match sender.send_until(tx, "submitProofEscape", Some(deadline)).await {
                Ok(hash) => {
                    tracing::info!(period = commit.period, %hash, "custody proven via escape hatch")
                }
                Err(e) => alarm.alarm(
                    Severity::Critical,
                    &format!("submitProofEscape for period {} failed: {e}", commit.period),
                ),
            }
        }));
    }
}

/// The contract-derived sample positions for ordinals `[0, count)` against a commit
/// snapshot — ONE derivation for the circuit witness (k samples) and the escape
/// hatch (maxSample reveals).
pub fn sample_indices(params: &CustodyParams, commit: &Commit, count: u64) -> Vec<u64> {
    let instance20 = params.instance.into_array();
    (0..count)
        .map(|j| custody_index(&instance20, &commit.seed, params.provider_id, j, commit.leaf_count))
        .collect()
}

/// The full-k circuit witness against the committed snapshot (public: the D12 tests
/// drive it directly against a mid-growth store).
pub fn build_witness(
    params: &CustodyParams,
    commit: &Commit,
    reader: &Reader,
) -> Result<CustodyWitness, crate::proofs::ProofError> {
    let indices = sample_indices(params, commit, params.custody_k as u64);
    let set = build_proof_set(reader, &indices, commit.leaf_count, &commit.root)?;
    Ok(CustodyWitness {
        instance: params.instance.into_array(),
        provider_id: params.provider_id,
        seed: commit.seed,
        root: commit.root,
        leaf_count: commit.leaf_count,
        k: params.custody_k as u64,
        peaks: set.peaks,
        samples: set.proven,
    })
}
