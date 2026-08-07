//! The carrier: any EOA that wraps a publisher's signed intent in a transaction,
//! fronts the gas, and is reimbursed atomically by the paymaster plus a fixed tip.
//! It cannot alter what the publisher signed; its entire risk is submitting
//! something that reverts or won't be reimbursed. So the one discipline this crate
//! enforces everywhere: NOTHING is submitted that verification and simulation have
//! not already shown to succeed AND to pay.
//!
//! Pipeline for every package: static validation (the intents crate — blob identity,
//! canonical packing) → chain preflight (nonce, deadline, designation, signature
//! acceptance, openings against the recomputed evaluation point, gas simulation) →
//! solvency simulation (the reimbursement formula vs the paymaster's bucket and
//! balance) → assembly and submission → report what the receipt actually says.

pub mod carry;
pub mod claim;
pub mod preflight;
pub mod solvency;

/// The environment variable holding the carrier's key (0x-prefixed hex). Never a
/// flag, never config: process arguments and files leak.
pub const CARRIER_KEY_ENV: &str = "BLOBSITTER_CARRIER_KEY";

pub fn carrier_key() -> Result<alloy::signers::local::PrivateKeySigner, String> {
    let raw = std::env::var(CARRIER_KEY_ENV)
        .map_err(|_| format!("{CARRIER_KEY_ENV} is not set (the carrier key comes only from the environment)"))?;
    raw.trim().parse().map_err(|_| format!("{CARRIER_KEY_ENV} is not a valid key"))
}
