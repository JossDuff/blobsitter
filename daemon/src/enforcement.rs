//! The provider's enforcement duties, composed: the challenge responder and the
//! custody loop, driven off the follower's tick. Event intake (finalized, via the
//! follower's scan) feeds the challenge ledger; DECISIONS run against the latest
//! chain state — a challenge or a custody commit must be acted on now, not a
//! finality-lag later.

use alloy::providers::{DynProvider, Provider};

use crate::abi::Blobsitter;
use crate::alarm::{AlarmSink, Severity};
use crate::custody::{CustodyDriver, ProviderView};
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
    /// Ticks in a row the chain's open-challenge count exceeded the ledger's.
    intake_deficit_streak: u32,
    rescan_requested: bool,
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
            intake_deficit_streak: 0,
            rescan_requested: false,
        }
    }

    /// True once per requested replay of the enforcement event scan (the follower
    /// rewinds its enforcement cursor to deployment and clears the request).
    pub fn take_rescan_request(&mut self) -> bool {
        std::mem::take(&mut self.rescan_requested)
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
        let view = ProviderView::from(&p);

        // Dropped-event detection: the contract counts challenges without a
        // confirmed response; so does the ledger (entries not yet responded). A
        // persistent chain-side surplus means an RPC provider dropped a
        // ChallengeOpened log from a getLogs page — the index set exists only in
        // that event, so replay the whole scan. A short streak absorbs the benign
        // lag between a challenge landing and its event finalizing.
        let ledger_open = self.responder.unresponded_count() as u32;
        if p.openChallenges > ledger_open {
            self.intake_deficit_streak += 1;
            if self.intake_deficit_streak >= 5 {
                self.alarm.alarm(
                    Severity::Critical,
                    &format!(
                        "the chain reports {} open challenge(s) but the ledger holds                          {ledger_open}: an event was missed — rescanning from deployment",
                        p.openChallenges
                    ),
                );
                self.rescan_requested = true;
                self.intake_deficit_streak = 0;
            }
        } else {
            self.intake_deficit_streak = 0;
        }

        self.custody.drive(now, &view, reader.clone()).await;
        self.responder.drive(now, &reader);
        Ok(())
    }
}
