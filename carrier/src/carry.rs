//! Carriage (test plan C4–C6): run the whole pipeline over one package and — unless
//! told to stop short — submit and report what the receipt actually says, never what
//! we hoped. The reimbursement outcome comes from the paymaster's own events:
//! `Reimbursed(amount)` or `ReimbursementSkipped(requested, bucket, available)`.

use alloy::primitives::{Address, TxHash};
use alloy::providers::{DynProvider, Provider};
use alloy::sol_types::SolEvent;

use blobsitter_abi::{Blobsitter, BlobsitterPaymaster};
use blobsitter_intents::{validate, IntentPackage, ValidateError};

use crate::preflight::{preflight, PreflightError};
use crate::solvency::{check as check_solvency, SolvencyError, SolvencyReport};

#[derive(Debug, thiserror::Error)]
pub enum CarryError {
    #[error("package rejected: {0}")]
    Invalid(#[from] ValidateError),
    #[error("preflight failed: {0}")]
    Preflight(#[from] PreflightError),
    #[error(transparent)]
    Solvency(#[from] SolvencyError),
    #[error(
        "the paymaster cannot cover the expected reimbursement of {expected} wei \
         (bucket {bucket}, available {available}); pass --force to carry for free"
    )]
    Insolvent { expected: u128, bucket: u128, available: u128 },
    #[error("submission failed: {0}")]
    Submission(String),
    #[error("transaction {0} reverted on chain")]
    Reverted(TxHash),
}

/// What the chain said happened.
#[derive(Debug)]
pub struct CarryReport {
    pub tx_hash: TxHash,
    pub block_number: u64,
    pub gas_used: u64,
    /// `Some(amount)` if the paymaster reimbursed; `None` with `skipped` set if it
    /// took the all-or-nothing skip (bucket/balance moved between simulation and
    /// inclusion, or the carriage was forced while insolvent).
    pub reimbursed: Option<u128>,
    pub skipped: Option<SkipInfo>,
    pub solvency: SolvencyReport,
}

/// The paymaster's own account of a skip: the full amount it was ASKED for, and what
/// it actually had (the shortfall is `requested − min(bucket, available)`).
#[derive(Debug)]
pub struct SkipInfo {
    pub requested: u128,
    pub bucket_level: u128,
    pub available: u128,
}

pub struct CarryOptions {
    /// Stop after preflight + solvency: full verification, zero transactions.
    pub dry_run: bool,
    /// Carry even when the solvency check says the reimbursement won't be paid.
    pub force_insolvent: bool,
}

/// The full pipeline. On `dry_run` the returned report carries the solvency numbers
/// with a zero tx hash.
pub async fn carry(
    provider: &DynProvider,
    package: &IntentPackage,
    carrier: Address,
    options: &CarryOptions,
) -> Result<CarryReport, CarryError> {
    let validated = validate(package)?;
    let flight = preflight(provider, package, &validated, carrier).await?;
    let solvency = check_solvency(
        provider,
        Address::from(package.instance),
        flight.gas_estimate,
        flight.calldata_len,
        flight.num_blobs,
        flight.is_declaration,
    )
    .await?;

    // A dry run submits nothing, so it can always REPORT safely — including the
    // uncovered case the insolvency refusal below exists to stop.
    if options.dry_run {
        return Ok(CarryReport {
            tx_hash: TxHash::ZERO,
            block_number: 0,
            gas_used: flight.gas_estimate,
            reimbursed: None,
            skipped: None,
            solvency,
        });
    }
    if !solvency.covered && !options.force_insolvent {
        return Err(CarryError::Insolvent {
            expected: solvency.expected_reimbursement,
            bucket: solvency.bucket_level,
            available: solvency.available_balance,
        });
    }

    let instance = Address::from(package.instance);
    let paymaster = Blobsitter::new(instance, provider.clone())
        .paymaster()
        .call()
        .await
        .map_err(|e| CarryError::Submission(e.to_string()))?;

    let receipt = provider
        .send_transaction(flight.tx)
        .await
        .map_err(|e| CarryError::Submission(e.to_string()))?
        .get_receipt()
        .await
        .map_err(|e| CarryError::Submission(e.to_string()))?;
    if !receipt.status() {
        return Err(CarryError::Reverted(receipt.transaction_hash));
    }

    // The receipt is the truth about reimbursement — read the paymaster's events.
    let mut reimbursed = None;
    let mut skipped = None;
    for log in receipt.logs() {
        if log.address() != paymaster {
            continue;
        }
        if let Ok(e) = BlobsitterPaymaster::Reimbursed::decode_log(&log.inner) {
            reimbursed = Some(e.amount.try_into().unwrap_or(u128::MAX));
        } else if let Ok(e) = BlobsitterPaymaster::ReimbursementSkipped::decode_log(&log.inner) {
            skipped = Some(SkipInfo {
                requested: e.amount.try_into().unwrap_or(u128::MAX),
                bucket_level: e.bucketLevel.try_into().unwrap_or(u128::MAX),
                available: e.available.try_into().unwrap_or(u128::MAX),
            });
        }
    }

    Ok(CarryReport {
        tx_hash: receipt.transaction_hash,
        block_number: receipt.block_number.unwrap_or_default(),
        gas_used: receipt.gas_used,
        reimbursed,
        skipped,
        solvency,
    })
}
