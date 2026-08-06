//! The provider's enforcement duties, composed: the challenge responder and the
//! custody loop, driven off the follower's tick. Event intake (finalized, via the
//! follower's scan) feeds the challenge ledger; DECISIONS run against the latest
//! chain state — a challenge or a custody commit must be acted on now, not a
//! finality-lag later.

use alloy::providers::{DynProvider, Provider};

use crate::abi::Blobsitter;
use crate::alarm::{AlarmSink, Severity};
use crate::custody::{Commit, CustodyDriver, ProviderView};
use crate::responder::{OpenChallenge, Responder};
use crate::store::Reader;

/// D17: the earliest instant the store may be deleted after unbonding — challenges
/// may open until the delay expires, and the last one gets a full response window.
pub fn retention_deadline(unbonding_at: u64, unbonding_delay: u64, response_window: u64) -> u64 {
    unbonding_at + unbonding_delay + response_window
}

pub struct Enforcement {
    pub provider_id: u64,
    pub responder: Responder,
    pub custody: CustodyDriver,
    contract: Blobsitter::BlobsitterInstance<DynProvider>,
    alarm: std::sync::Arc<dyn AlarmSink>,
    unbonding_delay: u64,
    response_window: u64,
}

impl Enforcement {
    pub fn new(
        provider_id: u64,
        responder: Responder,
        custody: CustodyDriver,
        contract: Blobsitter::BlobsitterInstance<DynProvider>,
        alarm: std::sync::Arc<dyn AlarmSink>,
        unbonding_delay: u64,
        response_window: u64,
    ) -> Self {
        Self {
            provider_id,
            responder,
            custody,
            contract,
            alarm,
            unbonding_delay,
            response_window,
        }
    }

    /// Handle one finalized enforcement event (the follower already decoded and
    /// filtered by contract address). Errors BLOCK the scan cursor — a ledger write
    /// must land before the event is considered consumed.
    pub fn on_challenge_opened(&mut self, challenge: OpenChallenge) -> Result<(), String> {
        self.responder.on_opened(challenge)
    }

    pub fn on_challenge_resolved(&mut self, id: u64, timed_out: bool) -> Result<(), String> {
        self.responder.on_resolved(id, timed_out)
    }

    pub fn on_slashed(&mut self, cause: u8) {
        self.alarm.alarm(
            Severity::Critical,
            &format!(
                "provider {} has been SLASHED (cause {}) — the stake is gone; the daemon \
                 keeps serving reads but has no protocol duties left",
                self.provider_id,
                if cause == 0 { "challenge timeout" } else { "custody lapse" }
            ),
        );
    }

    /// `unbonding_at` is the initiating block's timestamp (== the contract's
    /// `unbondingAt`).
    pub fn on_unbonding(&mut self, unbonding_at: u64) {
        let keep_until =
            retention_deadline(unbonding_at, self.unbonding_delay, self.response_window);
        self.alarm.alarm(
            Severity::Warning,
            &format!(
                "provider {} is UNBONDING: custody obligations have ended; challenges \
                 remain answerable and the store MUST be retained until chain time \
                 {keep_until} (unbondingAt + unbondingDelay + responseWindow)",
                self.provider_id
            ),
        );
    }

    /// One tick, at the latest chain state.
    pub async fn drive(&mut self, reader: Reader) -> Result<(), String> {
        let latest = self
            .contract
            .provider()
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no latest block")?;
        let now = latest.header.timestamp;

        let p = self
            .contract
            .getProvider(self.provider_id)
            .call()
            .await
            .map_err(|e| e.to_string())?;
        let view = ProviderView {
            active: p.status == Blobsitter::ProviderStatus::ACTIVE,
            anchor: p.anchor,
            last_proven_plus_one: p.lastProvenPlusOne,
            commit: (p.commitPeriodPlusOne != 0).then(|| Commit {
                period: p.commitPeriodPlusOne - 1,
                seed: p.commitSeed.0,
                root: p.commitRoot.0,
                leaf_count: p.commitLeafCount,
            }),
        };

        self.custody.drive(now, &view, reader.clone()).await;
        self.responder.drive(now, &reader);
        Ok(())
    }
}
