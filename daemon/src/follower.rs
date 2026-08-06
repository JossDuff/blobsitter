//! The chain follower: the thin shim between an execution client and the ingest
//! pipeline. It scans `Declared` logs up to the FINALIZED block only — reorg safety
//! by construction: ingest and the store never see a declaration that can still be
//! reorged away, so there is nothing to unwind. (Near-head prefetch is permitted by
//! the test plan as an optimization; with an 18-day repair budget against a ~13-minute
//! finality lag it buys nothing yet, so it deliberately doesn't exist.)
//!
//! Everything protocol-shaped lives in ingest; this module only speaks RPC. Its own
//! persistent state is one scan cursor, and losing it is harmless — old events are
//! redelivered and ignored by nonce.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;

use crate::abi::Blobsitter;
use crate::alarm::{AlarmSink, Severity};
use crate::enforcement::Enforcement;
use crate::ingest::{DeclaredEvent, IngestError, Ingestor};

#[derive(Debug, thiserror::Error)]
pub enum FollowerError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("cursor file error: {0}")]
    Cursor(String),
    #[error("ingest halted at declaration {nonce}: {reason}")]
    Halted { nonce: u64, reason: String },
}

/// Consecutive failed ticks before the follower escalates from log-level noise to a
/// real alarm. At the default 12 s poll this is ~2 minutes of a dead RPC — long
/// enough to skip transient blips, far inside every protocol window.
const TICK_FAILURES_BEFORE_ALARM: u32 = 10;

/// Poll-interval multiplier while ticks keep failing: doubles per failure, capped at
/// 32× (a day-long outage retries a few dozen times, not thousands), snapping back
/// to 1 on the first healthy tick.
pub fn backoff_multiplier(consecutive_failures: u32) -> u32 {
    1u32 << consecutive_failures.min(5)
}

/// The event topics this daemon consumes — the getLogs filter is bounded to these so
/// page sizes track relevant traffic, not everything the instance emits.
const CONSUMED_TOPICS: [alloy::primitives::B256; 7] = [
    Blobsitter::Declared::SIGNATURE_HASH,
    Blobsitter::ChallengeOpened::SIGNATURE_HASH,
    Blobsitter::ChallengeAnswered::SIGNATURE_HASH,
    Blobsitter::ChallengeRefunded::SIGNATURE_HASH,
    Blobsitter::ChallengeTimedOut::SIGNATURE_HASH,
    Blobsitter::Slashed::SIGNATURE_HASH,
    Blobsitter::UnbondingInitiated::SIGNATURE_HASH,
];

/// The follower's operating parameters (all from daemon config).
pub struct FollowerConfig {
    pub instance: Address,
    /// Bounds the very first scan; the persisted cursor takes over afterwards.
    pub deployment_block: u64,
    pub poll_interval: Duration,
    /// Maximum block span per `eth_getLogs` call.
    pub log_page: u64,
    pub data_dir: PathBuf,
}

pub struct Follower<P: Provider> {
    provider: P,
    instance: Address,
    ingestor: Ingestor,
    /// Present when this daemon serves a bonded provider; archive-only daemons
    /// follow and ingest with no duties and no keys.
    enforcement: Option<Enforcement>,
    alarm: Arc<dyn AlarmSink>,
    cursor_path: PathBuf,
    /// Last block whose declarations are fully ingested; scanning resumes after it.
    cursor: u64,
    /// Where a full rescan starts (block before deployment); the cursor never goes
    /// below this, and a detected event gap rewinds all the way here.
    scan_floor: u64,
    poll_interval: Duration,
    /// Configured getLogs page ceiling.
    log_page: u64,
    /// Live page size: halved on provider getLogs failures, doubled back on success.
    current_page: u64,
    consecutive_failures: u32,
}

impl<P: Provider> Follower<P> {
    pub fn new(
        provider: P,
        ingestor: Ingestor,
        enforcement: Option<Enforcement>,
        alarm: Arc<dyn AlarmSink>,
        config: FollowerConfig,
    ) -> Result<Self, FollowerError> {
        let cursor_path = config.data_dir.join("scan-cursor.json");
        let cursor = match std::fs::read_to_string(&cursor_path) {
            Ok(s) => s.trim().parse::<u64>().map_err(|e| FollowerError::Cursor(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                config.deployment_block.saturating_sub(1)
            }
            Err(e) => return Err(FollowerError::Cursor(e.to_string())),
        };
        Ok(Self {
            provider,
            instance: config.instance,
            ingestor,
            enforcement,
            alarm,
            cursor_path,
            cursor,
            scan_floor: config.deployment_block.saturating_sub(1),
            poll_interval: config.poll_interval,
            log_page: config.log_page,
            current_page: config.log_page,
            consecutive_failures: 0,
        })
    }

    pub fn ingestor(&self) -> &Ingestor {
        &self.ingestor
    }

    /// Follow forever (or until the task is cancelled). RPC failures and halted
    /// declarations are both retried on the next tick — the follower's job under
    /// every fault is to keep trying and keep alarming, never to skip. Consecutive
    /// failures back the poll off exponentially (capped at 32× the interval), so a
    /// day-long outage doesn't hammer rate-limited fallback sources thousands of
    /// times; recovery snaps the cadence back instantly.
    pub async fn run(&mut self) -> ! {
        loop {
            self.poll_once().await;
            tokio::time::sleep(self.poll_interval * backoff_multiplier(self.consecutive_failures))
                .await;
        }
    }

    /// One tick plus its failure accounting (the loop body of [`Self::run`], public
    /// so liveness tests can drive it directly). A single failed tick is log noise;
    /// a RUN of them means the daemon is not meeting its duties (dead RPC, revoked
    /// key, persistent halt) and must page a human — re-alarming on every further
    /// threshold multiple so the page cannot be missed while the condition lasts.
    pub async fn poll_once(&mut self) {
        match self.tick().await {
            Ok(()) => self.consecutive_failures = 0,
            Err(err) => {
                tracing::warn!("follower tick failed (will retry): {err}");
                self.consecutive_failures += 1;
                if self.consecutive_failures.is_multiple_of(TICK_FAILURES_BEFORE_ALARM) {
                    self.alarm.alarm(
                        Severity::Critical,
                        &format!(
                            "follower has failed {} consecutive ticks; the daemon is NOT \
                             following the chain. Last error: {err}",
                            self.consecutive_failures
                        ),
                    );
                }
            }
        }
    }

    /// One poll: scan new finalized blocks (declarations → ingest, the rest →
    /// enforcement intake), then drive enforcement decisions. Enforcement runs EVEN
    /// WHEN THE SCAN HALTS: a declaration blocked on an unfetchable blob must never
    /// starve the challenge responder or the custody loop — deadlines don't wait for
    /// blobs, and everything already ingested stays answerable.
    pub async fn tick(&mut self) -> Result<(), FollowerError> {
        let scan = self.scan().await;
        let drive = self.drive_enforcement().await;
        scan.and(drive)
    }

    async fn scan(&mut self) -> Result<(), FollowerError> {
        let rpc = |e: alloy::transports::TransportError| FollowerError::Rpc(e.to_string());
        let finalized = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await
            .map_err(rpc)?
            .ok_or_else(|| FollowerError::Rpc("no finalized block available".into()))?
            .header
            .number;

        while self.cursor < finalized {
            let from = self.cursor + 1;
            let to = finalized.min(self.cursor + self.current_page);
            // Filtered to exactly the topics this daemon consumes — an address-only
            // query would grow with everyone's traffic — and paged ADAPTIVELY: a
            // provider-side getLogs cap (too many logs, response too large) halves
            // the page for the retry instead of wedging on a fixed range forever;
            // successful pages grow back toward the configured maximum.
            let filter = Filter::new()
                .address(self.instance)
                .event_signature(CONSUMED_TOPICS.to_vec())
                .from_block(from)
                .to_block(to);
            let logs = match self.provider.get_logs(&filter).await {
                Ok(logs) => {
                    self.current_page = (self.current_page * 2).min(self.log_page);
                    logs
                }
                Err(e) => {
                    self.current_page = (self.current_page / 2).max(1);
                    return Err(rpc(e));
                }
            };

            let mut timestamps: HashMap<u64, u64> = HashMap::new();
            for log in &logs {
                self.dispatch(log, &mut timestamps).await?;
            }
            self.set_cursor(to)?;
        }

        self.check_root(finalized).await
    }

    /// Route one finalized log. Failures leave the cursor before the log's block, so
    /// the event is redelivered until its consumer durably accepts it.
    async fn dispatch(
        &mut self,
        log: &Log,
        timestamps: &mut HashMap<u64, u64>,
    ) -> Result<(), FollowerError> {
        let Some(&topic0) = log.topic0() else { return Ok(()) };

        if topic0 == Blobsitter::Declared::SIGNATURE_HASH {
            let event = self.declared_event(log, timestamps).await?;
            return match self.ingestor.ingest(&event).await {
                Ok(_) => Ok(()),
                Err(IngestError::NonceGap { expected, got }) => {
                    // The missing nonce's log is in a block we already scanned PAST
                    // (a provider dropped it from a getLogs page), so rewinding near
                    // this event can never recover it. Rewind to the floor: the full
                    // rescan is cheap insurance — every already-committed nonce dies
                    // on the redelivery check.
                    self.set_cursor(self.scan_floor)?;
                    Err(FollowerError::Halted {
                        nonce: expected,
                        reason: format!(
                            "nonce {got} observed while {expected} was never seen; \
                             rescanning from deployment"
                        ),
                    })
                }
                Err(err) => {
                    // Halt AT this declaration: commit the cursor to just before its
                    // block so every later tick re-lands here until the blockage
                    // clears. The alarm already fired inside ingest.
                    self.set_cursor(event.block_number.saturating_sub(1))?;
                    Err(FollowerError::Halted { nonce: event.nonce, reason: err.to_string() })
                }
            };
        }

        // Fetched before enforcement is mutably borrowed (only unbonding needs it:
        // the initiating block's timestamp IS the contract's unbondingAt).
        let unbonding_at = if topic0 == Blobsitter::UnbondingInitiated::SIGNATURE_HASH {
            Some(self.block_timestamp(log, timestamps).await?)
        } else {
            None
        };
        let Some(enforcement) = &mut self.enforcement else { return Ok(()) };
        let ours = enforcement.provider_id;
        let halt = |reason: String, block: u64| FollowerError::Halted { nonce: 0, reason: format!("enforcement event at block {block}: {reason}") };
        let block = log.block_number.unwrap_or_default();

        if topic0 == Blobsitter::ChallengeOpened::SIGNATURE_HASH {
            let e = Blobsitter::ChallengeOpened::decode_log(&log.inner)
                .map_err(|e| FollowerError::Rpc(format!("undecodable ChallengeOpened: {e}")))?;
            if e.providerId == ours {
                let entry = crate::responder::OpenChallenge {
                    challenge_id: e.challengeId,
                    indices: e.indices.clone(),
                    pinned_root: e.pinnedRoot.0,
                    pinned_leaf_count: e.pinnedLeafCount,
                    deadline: e.deadline,
                    responded_tx: None,
                };
                if let Err(reason) = enforcement.on_challenge_opened(entry) {
                    self.set_cursor(block.saturating_sub(1))?;
                    return Err(halt(reason, block));
                }
            }
        } else if topic0 == Blobsitter::ChallengeAnswered::SIGNATURE_HASH {
            let e = Blobsitter::ChallengeAnswered::decode_log(&log.inner)
                .map_err(|e| FollowerError::Rpc(e.to_string()))?;
            if let Err(reason) = enforcement.on_challenge_resolved(e.challengeId, false) {
                self.set_cursor(block.saturating_sub(1))?;
                return Err(halt(reason, block));
            }
        } else if topic0 == Blobsitter::ChallengeRefunded::SIGNATURE_HASH {
            let e = Blobsitter::ChallengeRefunded::decode_log(&log.inner)
                .map_err(|e| FollowerError::Rpc(e.to_string()))?;
            if let Err(reason) = enforcement.on_challenge_resolved(e.challengeId, false) {
                self.set_cursor(block.saturating_sub(1))?;
                return Err(halt(reason, block));
            }
        } else if topic0 == Blobsitter::ChallengeTimedOut::SIGNATURE_HASH {
            let e = Blobsitter::ChallengeTimedOut::decode_log(&log.inner)
                .map_err(|e| FollowerError::Rpc(e.to_string()))?;
            if let Err(reason) = enforcement.on_challenge_resolved(e.challengeId, true) {
                self.set_cursor(block.saturating_sub(1))?;
                return Err(halt(reason, block));
            }
        } else if topic0 == Blobsitter::Slashed::SIGNATURE_HASH {
            let e = Blobsitter::Slashed::decode_log(&log.inner)
                .map_err(|e| FollowerError::Rpc(e.to_string()))?;
            if e.providerId == ours {
                enforcement.on_slashed(e.cause as u8);
            }
        } else if topic0 == Blobsitter::UnbondingInitiated::SIGNATURE_HASH {
            let e = Blobsitter::UnbondingInitiated::decode_log(&log.inner)
                .map_err(|e| FollowerError::Rpc(e.to_string()))?;
            if e.providerId == ours {
                enforcement.on_unbonding(unbonding_at.unwrap_or_default());
            }
        }
        Ok(())
    }

    /// Enforcement decisions run every tick against the LATEST chain state; the
    /// store reader snapshots the committed frontier for background proof jobs.
    async fn drive_enforcement(&mut self) -> Result<(), FollowerError> {
        let Some(enforcement) = &mut self.enforcement else { return Ok(()) };
        let reader = self
            .ingestor
            .store()
            .reader()
            .map_err(|e| FollowerError::Rpc(format!("store reader: {e}")))?;
        enforcement.drive(reader).await.map_err(FollowerError::Rpc)
    }

    /// A log's block timestamp, cached per scan batch.
    async fn block_timestamp(
        &self,
        log: &Log,
        timestamps: &mut HashMap<u64, u64>,
    ) -> Result<u64, FollowerError> {
        let rpc = |e: alloy::transports::TransportError| FollowerError::Rpc(e.to_string());
        let block_number = log
            .block_number
            .ok_or_else(|| FollowerError::Rpc("log without block number".into()))?;
        if let Some(&ts) = timestamps.get(&block_number) {
            return Ok(ts);
        }
        let ts = self
            .provider
            .get_block_by_number(block_number.into())
            .await
            .map_err(rpc)?
            .ok_or_else(|| FollowerError::Rpc(format!("block {block_number} missing")))?
            .header
            .timestamp;
        timestamps.insert(block_number, ts);
        Ok(ts)
    }

    async fn declared_event(
        &self,
        log: &Log,
        timestamps: &mut HashMap<u64, u64>,
    ) -> Result<DeclaredEvent, FollowerError> {
        let block_number = log
            .block_number
            .ok_or_else(|| FollowerError::Rpc("log without block number".into()))?;
        let block_timestamp = self.block_timestamp(log, timestamps).await?;
        let decoded = Blobsitter::Declared::decode_log(&log.inner)
            .map_err(|e| FollowerError::Rpc(format!("undecodable Declared log: {e}")))?;
        Ok(DeclaredEvent {
            nonce: decoded.nonce,
            new_leaf_count: decoded.newLeafCount,
            blob_versioned_hashes: decoded.blobVersionedHashes.iter().map(|h| h.0).collect(),
            new_subtree_peaks: decoded.newSubtreePeaks.iter().map(|h| h.0).collect(),
            block_number,
            block_timestamp,
        })
    }

    /// The end-to-end invariant behind every duty: the local store IS the dataset the
    /// contract committed to. Compared at the finalized block the scan just reached,
    /// so contract state and cursor describe the same instant.
    async fn check_root(&self, finalized: u64) -> Result<(), FollowerError> {
        if finalized < self.cursor {
            // A lagging or freshly rotated RPC node whose finalized tag is behind
            // state we already ingested: comparing against its older view would
            // fire a false "store disagrees with L1" — the one alarm that must
            // never cry wolf. Skip; the check runs again when the node catches up.
            return Ok(());
        }
        let contract = Blobsitter::new(self.instance, &self.provider);
        let at = alloy::eips::BlockId::number(finalized);
        let chain_leaf_count = contract
            .leafCount()
            .block(at)
            .call()
            .await
            .map_err(|e| FollowerError::Rpc(e.to_string()))?;
        let chain_root = contract
            .root()
            .block(at)
            .call()
            .await
            .map_err(|e| FollowerError::Rpc(e.to_string()))?;

        let local = self.ingestor.store().mmr();
        if local.leaf_count() != chain_leaf_count || local.root() != chain_root.0 {
            self.alarm.alarm(
                Severity::Critical,
                &format!(
                    "local store disagrees with L1 at finalized block {finalized}: \
                     local (leafCount {}, root 0x{}) vs chain (leafCount {}, root {})",
                    local.leaf_count(),
                    hex::encode(local.root()),
                    chain_leaf_count,
                    chain_root
                ),
            );
        }
        Ok(())
    }

    fn set_cursor(&mut self, block: u64) -> Result<(), FollowerError> {
        // Plain write, no fsync ceremony: a stale or lost cursor only causes a rescan,
        // which the nonce check absorbs.
        std::fs::write(&self.cursor_path, block.to_string())
            .map_err(|e| FollowerError::Cursor(e.to_string()))?;
        self.cursor = block;
        Ok(())
    }
}
