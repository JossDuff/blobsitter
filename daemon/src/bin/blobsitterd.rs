//! The storage daemon binary: follow L1, ingest declared blobs, keep the canonical
//! chunk store verified against the contract's root — and, when a `[provider]`
//! section is configured, run the provider's enforcement duties: challenge responses
//! and the custody-proof loop. Without one it is a keyless archive-only follower.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};

use blobsitter_daemon::abi::Blobsitter;
use blobsitter_daemon::alarm::{AlarmSink, DedupAlarm, LogAlarm};
use blobsitter_daemon::config::{effective_escape_threshold, Config, ProviderConfig};
use blobsitter_daemon::custody::{CustodyDriver, CustodyParams};
use blobsitter_daemon::enforcement::Enforcement;
use blobsitter_daemon::follower::{Follower, FollowerConfig};
use blobsitter_daemon::ingest::Ingestor;
use blobsitter_daemon::prover::{CustodyProver, NoProver};
use blobsitter_daemon::responder::{Ledger, Responder};
use blobsitter_daemon::source::{beacon::BeaconSource, blobscan::BlobscanSource};
use blobsitter_daemon::source::{BlobSource, SourceChain};
use blobsitter_daemon::store::Store;
use blobsitter_daemon::tx::TxSender;

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
    let instance: Address = config.instance.parse()?;

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

    // One page per condition per five minutes; changing detail always passes.
    let alarm: Arc<dyn AlarmSink> =
        Arc::new(DedupAlarm::new(LogAlarm, Duration::from_secs(300)));
    let ingestor = Ingestor::new(store, SourceChain::new(sources), alarm.clone());

    let enforcement = match &config.provider {
        Some(provider_config) => Some(
            build_enforcement(&config, provider_config, instance, alarm.clone()).await?,
        ),
        None => {
            tracing::info!("no [provider] section: running archive-only (no keys, no duties)");
            None
        }
    };

    let provider = ProviderBuilder::new().connect(&config.execution_rpc).await?;
    let mut follower = Follower::new(
        provider,
        ingestor,
        enforcement,
        alarm,
        FollowerConfig {
            instance,
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

/// Assemble the enforcement stack: operator wallet (key from the environment ONLY),
/// instance parameters read from the chain, persistent challenge ledger reconciled
/// against on-chain resolution state, and the configured prover backend.
async fn build_enforcement(
    config: &Config,
    provider_config: &ProviderConfig,
    instance: Address,
    alarm: Arc<dyn AlarmSink>,
) -> Result<Enforcement, Box<dyn std::error::Error>> {
    let key = provider_config.operator_key()?;
    let operator = key.address();
    let op_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(key))
        .connect(&config.execution_rpc)
        .await?
        .erased();
    let contract = Blobsitter::new(instance, op_provider.clone());

    // Sanity: the configured providerId must actually be operated by our key.
    let record = contract.getProvider(provider_config.id).call().await?;
    if record.operator != operator {
        return Err(format!(
            "provider {} is operated by {}, but the configured key controls {operator}",
            provider_config.id, record.operator
        )
        .into());
    }

    let response_window = contract.responseWindow().call().await?;
    let unbonding_delay = contract.unbondingDelay().call().await?;
    let custody_period = contract.custodyPeriod().call().await?;
    let params = CustodyParams {
        instance,
        provider_id: provider_config.id,
        custody_period,
        lapse_grace: contract.lapseGrace().call().await?,
        custody_k: contract.custodyK().call().await?,
        max_sample: contract.maxSample().call().await?,
        escape_threshold: effective_escape_threshold(
            provider_config.escape_threshold_secs,
            custody_period,
        )?,
        proving_timeout: Duration::from_secs(provider_config.proving_timeout_secs),
    };

    let sender = Arc::new(TxSender::new(
        op_provider.clone(),
        operator,
        alarm.clone(),
        Duration::from_secs(provider_config.confirm_timeout_secs),
    ));
    let ledger = Ledger::open(&config.data_dir)?;
    let mut responder = Responder::new(
        provider_config.id,
        instance,
        response_window,
        ledger,
        sender.clone(),
        contract.clone(),
        alarm.clone(),
    );
    responder.reconcile(&contract).await?;

    let prover = build_prover(provider_config)?;
    tracing::info!(
        provider = provider_config.id,
        %operator,
        prover = prover.name(),
        "enforcement duties enabled"
    );
    let custody = CustodyDriver::new(params, sender, prover, alarm.clone());
    Ok(Enforcement::new(
        provider_config.id,
        responder,
        custody,
        contract,
        alarm,
        unbonding_delay,
        response_window,
    ))
}

#[allow(unused_variables)]
fn build_prover(
    provider_config: &ProviderConfig,
) -> Result<Arc<dyn CustodyProver>, Box<dyn std::error::Error>> {
    #[cfg(feature = "sp1")]
    if let Some(path) = &provider_config.custody_elf {
        let elf = std::fs::read(path)?;
        return Ok(Arc::new(blobsitter_daemon::prover::sp1::Sp1Prover::new(elf)));
    }
    #[cfg(not(feature = "sp1"))]
    if provider_config.custody_elf.is_some() {
        tracing::warn!(
            "custody_elf is configured but this daemon was built WITHOUT the `sp1` \
             feature; every period will be proven through the escape hatch"
        );
    }
    Ok(Arc::new(NoProver))
}
