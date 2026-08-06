//! Operator transaction submission with fee escalation — the muscle behind every
//! deadline duty (challenge responses, custody proofs). One rule: while chain time
//! is inside the deadline, keep replacing the transaction with higher fees; a
//! transient failure is never a reason to stop, only a reason to bump.
//!
//! Deadlines are CHAIN time (block timestamps), never wall time: compressed-window
//! tests warp the chain clock, and production RPC nodes are the authority on when a
//! window closes.

use std::sync::Arc;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, TxHash};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::TransactionRequest;

use crate::alarm::{AlarmSink, Severity};

/// How many fee bumps before giving up (each is +25%; ~9× fees at the cap — if that
/// isn't landing, the problem is not the fee).
const MAX_ATTEMPTS: u32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("transaction would revert or reverted on chain: {0}")]
    Reverted(String),
    #[error("chain deadline {deadline} passed before confirmation (chain time {now})")]
    DeadlinePassed { deadline: u64, now: u64 },
    #[error("gave up after {attempts} attempts: {last_error}")]
    Exhausted { attempts: u32, last_error: String },
}

pub struct TxSender {
    provider: DynProvider,
    operator: Address,
    alarm: Arc<dyn AlarmSink>,
    confirm_timeout: Duration,
}

impl TxSender {
    /// `provider` must already carry the operator wallet (its fillers sign and set
    /// gas); `operator` is that wallet's address.
    pub fn new(
        provider: DynProvider,
        operator: Address,
        alarm: Arc<dyn AlarmSink>,
        confirm_timeout: Duration,
    ) -> Self {
        Self { provider, operator, alarm, confirm_timeout }
    }

    pub fn operator(&self) -> Address {
        self.operator
    }

    async fn chain_now(&self) -> Result<u64, String> {
        Ok(self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no latest block")?
            .header
            .timestamp)
    }

    /// Submit `tx` and escalate until it confirms, the chain deadline passes, or the
    /// attempt budget runs out. Success = a receipt with status true.
    pub async fn send_until(
        &self,
        mut tx: TransactionRequest,
        label: &str,
        chain_deadline: Option<u64>,
    ) -> Result<TxHash, SendError> {
        // One nonce for the whole episode: every retry REPLACES the previous
        // attempt instead of queueing behind it.
        let nonce = self
            .provider
            .get_transaction_count(self.operator)
            .pending()
            .await
            .map_err(|e| SendError::Exhausted { attempts: 0, last_error: e.to_string() })?;
        tx.nonce = Some(nonce);

        let base_fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(|e| SendError::Exhausted { attempts: 0, last_error: e.to_string() })?;

        let mut submitted: Vec<TxHash> = Vec::new();
        let mut last_error = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if let Some(deadline) = chain_deadline {
                let now = self.chain_now().await.unwrap_or(0);
                if now >= deadline {
                    return Err(SendError::DeadlinePassed { deadline, now });
                }
            }

            // +25% compounding per attempt, applied to BOTH fee components (a
            // replacement must beat the pool's floor on each).
            let bump = |fee: u128| -> u128 {
                let mut f = fee.max(1);
                for _ in 0..attempt {
                    f = f + f / 4;
                }
                f
            };
            tx.max_fee_per_gas = Some(bump(base_fees.max_fee_per_gas));
            tx.max_priority_fee_per_gas = Some(bump(base_fees.max_priority_fee_per_gas));
            if attempt > 0 {
                self.alarm.alarm(
                    Severity::Warning,
                    &format!("{label}: fee-escalation attempt {attempt} (nonce {nonce})"),
                );
            }

            let pending = match self.provider.send_transaction(tx.clone()).await {
                Ok(p) => p,
                Err(e) => {
                    let msg = e.to_string();
                    // An earlier attempt may have landed while we were bumping: a
                    // stale nonce is only an error if none of our hashes confirmed.
                    if msg.contains("nonce too low") || msg.contains("already known") {
                        if let Some(hash) = self.any_confirmed(&submitted).await {
                            return Ok(hash);
                        }
                    }
                    if msg.contains("revert") {
                        return Err(SendError::Reverted(msg));
                    }
                    last_error = msg;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };
            let hash = *pending.tx_hash();
            submitted.push(hash);

            match pending.with_timeout(Some(self.confirm_timeout)).get_receipt().await {
                Ok(receipt) if receipt.status() => return Ok(hash),
                Ok(_) => {
                    return Err(SendError::Reverted(format!("receipt status 0 for {hash}")));
                }
                Err(e) => {
                    // Timeout or transport hiccup: check nothing landed, then bump.
                    if let Some(hash) = self.any_confirmed(&submitted).await {
                        return Ok(hash);
                    }
                    last_error = e.to_string();
                }
            }
        }
        Err(SendError::Exhausted { attempts: MAX_ATTEMPTS, last_error })
    }

    /// Did any of this episode's replacement candidates already confirm?
    async fn any_confirmed(&self, hashes: &[TxHash]) -> Option<TxHash> {
        for &hash in hashes {
            if let Ok(Some(receipt)) = self.provider.get_transaction_receipt(hash).await {
                if receipt.status() {
                    return Some(hash);
                }
            }
        }
        None
    }
}
