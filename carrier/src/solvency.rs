//! Solvency simulation (test plan C3). Reimbursement is ALL-OR-NOTHING: if the
//! paymaster's token bucket or its available balance can't cover the full amount,
//! the carrier gets zero — so the expected amount is computed with the contract's
//! own formula at current base fees and checked against BOTH limits before a wei of
//! gas moves. Everything here deliberately over-approximates the reimbursable
//! amount slightly, because a false "insolvent" costs a retry while a false
//! "solvent" costs the whole carriage.

use alloy::providers::{DynProvider, Provider};

use blobsitter_abi::{Blobsitter, BlobsitterPaymaster};

/// Mirror of the contract's provisional post-measurement remainder (frozen before
/// audit; must track the contract's constant).
pub const TAIL: u128 = 25_000;

/// Bytes per blob at the fee level (EIP-7516 accounting).
const BLOB_BYTES: u128 = 131_072;

#[derive(Debug)]
pub struct SolvencyReport {
    /// Blob fee + execution fee + tip + subsidy, priced ABOVE current base fees:
    /// both fee terms carry headroom for the worst-case per-block rise between this
    /// check and inclusion.
    pub expected_reimbursement: u128,
    pub bucket_level: u128,
    pub available_balance: u128,
    pub covered: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("rpc error during solvency check: {0}")]
pub struct SolvencyError(pub String);

/// Compute the expected reimbursement and the paymaster's capacity to pay it.
pub async fn check(
    provider: &DynProvider,
    instance: alloy::primitives::Address,
    gas_estimate: u64,
    calldata_len: usize,
    num_blobs: usize,
    is_declaration: bool,
) -> Result<SolvencyReport, SolvencyError> {
    let rpc = |e: String| SolvencyError(e);
    let contract = Blobsitter::new(instance, provider.clone());
    let paymaster_address =
        contract.paymaster().call().await.map_err(|e| rpc(e.to_string()))?;
    let paymaster = BlobsitterPaymaster::new(paymaster_address, provider.clone());

    let latest = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .map_err(|e| rpc(e.to_string()))?
        .ok_or_else(|| rpc("no latest block".into()))?;
    let base_fee = latest.header.base_fee_per_gas.unwrap_or_default() as u128;
    let blob_base_fee = provider.get_blob_base_fee().await.map_err(|e| rpc(e.to_string()))?;

    let tip: u128 = contract
        .carrierTipWei()
        .call()
        .await
        .map_err(|e| rpc(e.to_string()))?
        .try_into()
        .unwrap_or(u128::MAX);
    let subsidy: u128 = if is_declaration {
        contract
            .provingSubsidyWei()
            .call()
            .await
            .map_err(|e| rpc(e.to_string()))?
            .try_into()
            .unwrap_or(u128::MAX)
    } else {
        0
    };

    // The contract pays (measuredGas + 21_000 + 16·calldata + TAIL) · basefee; our
    // simulation's total estimate already contains the intrinsic and calldata gas,
    // so adding them again on top errs on the generous side — exactly the side a
    // coverage check should err on. Both fee terms are then padded 25%: each can
    // rise up to 12.5% PER BLOCK between this check and inclusion, and a covered=true
    // that inclusion-time fees falsify means carrying for free (the skip is
    // all-or-nothing).
    let headroom = |fee_term: u128| fee_term + fee_term / 4;
    let execution = headroom(
        (gas_estimate as u128 + 21_000 + 16 * calldata_len as u128 + TAIL) * base_fee,
    );
    let blob_fee = headroom(num_blobs as u128 * BLOB_BYTES * blob_base_fee);
    let expected_reimbursement = blob_fee + execution + tip + subsidy;

    let bucket_level: u128 = paymaster
        .bucketLevel()
        .call()
        .await
        .map_err(|e| rpc(e.to_string()))?
        .try_into()
        .unwrap_or(u128::MAX);
    let available_balance: u128 = paymaster
        .availableBalance()
        .call()
        .await
        .map_err(|e| rpc(e.to_string()))?
        .try_into()
        .unwrap_or(u128::MAX);

    let covered =
        expected_reimbursement <= bucket_level && expected_reimbursement <= available_balance;
    Ok(SolvencyReport { expected_reimbursement, bucket_level, available_balance, covered })
}
