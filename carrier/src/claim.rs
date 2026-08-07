//! Pull-claims (test plan C6): a payout whose push failed sits in the claimable
//! ledger of whichever contract owed it — the paymaster for reimbursements, the
//! instance for bonds — and `claim()` drains it. Both sinks are checked; only
//! nonzero balances are claimed.

use alloy::primitives::Address;
use alloy::providers::DynProvider;

use blobsitter_abi::{Blobsitter, BlobsitterPaymaster};

#[derive(Debug)]
pub struct ClaimReport {
    /// (contract label, address, amount claimed) per sink that paid out.
    pub claimed: Vec<(&'static str, Address, u128)>,
    /// Parked balances found (may be zero).
    pub paymaster_claimable: u128,
    pub instance_claimable: u128,
}

#[derive(Debug, thiserror::Error)]
#[error("claim failed: {0}")]
pub struct ClaimError(pub String);

pub async fn claim_all(
    provider: &DynProvider,
    instance_address: Address,
    carrier: Address,
) -> Result<ClaimReport, ClaimError> {
    let rpc = |e: String| ClaimError(e);
    let instance = Blobsitter::new(instance_address, provider.clone());
    let paymaster_address =
        instance.paymaster().call().await.map_err(|e| rpc(e.to_string()))?;
    let paymaster = BlobsitterPaymaster::new(paymaster_address, provider.clone());

    let paymaster_claimable: u128 = paymaster
        .claimable(carrier)
        .call()
        .await
        .map_err(|e| rpc(e.to_string()))?
        .try_into()
        .unwrap_or(u128::MAX);
    let instance_claimable: u128 = instance
        .claimable(carrier)
        .call()
        .await
        .map_err(|e| rpc(e.to_string()))?
        .try_into()
        .unwrap_or(u128::MAX);

    let mut claimed = Vec::new();
    if paymaster_claimable > 0 {
        let receipt = paymaster
            .claim()
            .send()
            .await
            .map_err(|e| rpc(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| rpc(e.to_string()))?;
        if !receipt.status() {
            return Err(ClaimError(format!("paymaster claim reverted: {}", receipt.transaction_hash)));
        }
        claimed.push(("paymaster", paymaster_address, paymaster_claimable));
    }
    if instance_claimable > 0 {
        let receipt = instance
            .claim()
            .send()
            .await
            .map_err(|e| rpc(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| rpc(e.to_string()))?;
        if !receipt.status() {
            return Err(ClaimError(format!("instance claim reverted: {}", receipt.transaction_hash)));
        }
        claimed.push(("instance", instance_address, instance_claimable));
    }
    Ok(ClaimReport { claimed, paymaster_claimable, instance_claimable })
}
