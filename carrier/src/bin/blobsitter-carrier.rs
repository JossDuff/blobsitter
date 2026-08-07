//! The carrier CLI. `carry` runs the whole verify → simulate → submit pipeline over
//! one signed-intent package; `claim` drains parked payouts; `status` shows what the
//! paymaster could pay right now. The carrier key comes only from the
//! `BLOBSITTER_CARRIER_KEY` environment variable.

use std::path::PathBuf;

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use clap::{Parser, Subcommand};

use blobsitter_abi::{Blobsitter, BlobsitterPaymaster};
use blobsitter_carrier::carry::{carry, CarryOptions};
use blobsitter_carrier::claim::claim_all;
use blobsitter_carrier::carrier_key;
use blobsitter_intents::IntentPackage;

#[derive(Parser)]
#[command(name = "blobsitter-carrier", version, about)]
struct Cli {
    /// Execution-layer JSON-RPC endpoint.
    #[arg(long, env = "BLOBSITTER_RPC")]
    rpc: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a signed-intent package and carry it on chain.
    Carry {
        /// Path to the package JSON (the instance and chain are pinned inside it).
        package: PathBuf,
        /// Run every check and simulation, submit nothing.
        #[arg(long)]
        dry_run: bool,
        /// Carry even when the paymaster cannot cover the reimbursement.
        #[arg(long)]
        force: bool,
    },
    /// Drain any parked (push-failed) payouts owed to this carrier.
    Claim {
        /// The BlobsitterInstance address.
        #[arg(long)]
        instance: Address,
    },
    /// Show the paymaster's capacity: bucket level, available balance, claimables.
    Status {
        /// The BlobsitterInstance address.
        #[arg(long)]
        instance: Address,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    let key = carrier_key()?;
    let carrier = key.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(key))
        .connect(&cli.rpc)
        .await?
        .erased();

    match cli.command {
        Command::Carry { package, dry_run, force } => {
            let raw = std::fs::read_to_string(&package)?;
            let package = IntentPackage::from_json(&raw)?;
            let options = CarryOptions { dry_run, force_insolvent: force };
            let report = carry(&provider, &package, carrier, &options).await?;

            println!(
                "solvency: expected reimbursement {} wei (bucket {}, available {}) — {}",
                report.solvency.expected_reimbursement,
                report.solvency.bucket_level,
                report.solvency.available_balance,
                if report.solvency.covered { "covered" } else { "NOT covered" },
            );
            if dry_run {
                println!(
                    "dry run: package is carriable as {carrier} (simulated gas {})",
                    report.gas_used
                );
                return Ok(());
            }
            println!(
                "carried: tx {} in block {} (gas used {})",
                report.tx_hash, report.block_number, report.gas_used
            );
            match (report.reimbursed, report.skipped) {
                (Some(amount), _) => println!("reimbursed: {amount} wei"),
                (None, Some(skip)) => println!(
                    "REIMBURSEMENT SKIPPED: {} wei requested, bucket {} / available {} — \
                     this carriage was not paid",
                    skip.requested, skip.bucket_level, skip.available
                ),
                (None, None) => println!("no reimbursement event found in the receipt"),
            }
        }
        Command::Claim { instance } => {
            let report = claim_all(&provider, instance, carrier).await?;
            if report.claimed.is_empty() {
                println!(
                    "nothing to claim (paymaster {} wei, instance {} wei)",
                    report.paymaster_claimable, report.instance_claimable
                );
            }
            for (label, address, amount) in report.claimed {
                println!("claimed {amount} wei from the {label} ({address})");
            }
        }
        Command::Status { instance } => {
            let contract = Blobsitter::new(instance, provider.clone());
            let paymaster_address = contract.paymaster().call().await?;
            let paymaster = BlobsitterPaymaster::new(paymaster_address, provider.clone());
            println!("carrier:            {carrier}");
            println!("carrier balance:    {} wei", provider.get_balance(carrier).await?);
            println!("paymaster:          {paymaster_address}");
            println!("bucket level:       {} wei", paymaster.bucketLevel().call().await?);
            println!("available balance:  {} wei", paymaster.availableBalance().call().await?);
            println!(
                "claimable (paymaster/instance): {} / {} wei",
                paymaster.claimable(carrier).call().await?,
                contract.claimable(carrier).call().await?
            );
        }
    }
    Ok(())
}
