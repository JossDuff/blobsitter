//! The storage daemon binary. M1 surface: follow L1, ingest declared blobs, keep the
//! canonical chunk store verified against the contract's root. It holds no keys and
//! sends no transactions yet; enforcement duties (challenge response, custody loop)
//! arrive in the next milestone.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::providers::ProviderBuilder;

use blobsitter_daemon::alarm::LogAlarm;
use blobsitter_daemon::config::Config;
use blobsitter_daemon::follower::{Follower, FollowerConfig};
use blobsitter_daemon::ingest::Ingestor;
use blobsitter_daemon::source::{beacon::BeaconSource, blobscan::BlobscanSource};
use blobsitter_daemon::source::{BlobSource, SourceChain};
use blobsitter_daemon::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: blobsitterd <config.toml>")?;
    let config = Config::load(&config_path)?;

    let store = Store::open(&config.data_dir)?;
    tracing::info!(
        nonce = store.frontier().nonce,
        leaf_count = store.frontier().leaf_count,
        "store opened"
    );

    let mut sources: Vec<Box<dyn BlobSource>> = vec![Box::new(BeaconSource::new(
        config.beacon.endpoints.clone(),
        config.beacon.genesis_time,
        config.beacon.seconds_per_slot,
    ))];
    if let Some(blobscan) = &config.blobscan {
        sources.push(Box::new(BlobscanSource::new(blobscan.url.clone())));
    }

    let alarm = Arc::new(LogAlarm);
    let ingestor = Ingestor::new(store, SourceChain::new(sources), alarm.clone());
    let provider = ProviderBuilder::new().connect(&config.execution_rpc).await?;
    let mut follower = Follower::new(
        provider,
        ingestor,
        alarm,
        FollowerConfig {
            instance: config.instance.parse()?,
            deployment_block: config.deployment_block,
            poll_interval: Duration::from_secs(config.poll_interval_secs),
            log_page: config.log_page_blocks,
            data_dir: config.data_dir.clone(),
        },
    )?;

    tokio::select! {
        _ = follower.run() => unreachable!("follower loop never returns"),
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}
