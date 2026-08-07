//! Daemon configuration: one TOML file. Endpoint URLs may embed `${VAR}` references,
//! expanded from the environment at load time — hosted-provider URLs carry API keys,
//! and credentials live in the environment, never in config files (and never in this
//! struct's Debug output: URLs are deliberately opaque).

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("cannot parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config references undefined environment variable {0}")]
    MissingEnv(String),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The BlobsitterInstance address this daemon serves.
    pub instance: String,
    /// Execution-layer JSON-RPC endpoint.
    pub execution_rpc: String,
    /// Where the chunk store and daemon state live.
    pub data_dir: PathBuf,
    /// Block the instance was deployed at; the first scan starts here.
    pub deployment_block: u64,
    #[serde(default = "default_poll_secs")]
    pub poll_interval_secs: u64,
    /// Maximum block span per eth_getLogs call.
    #[serde(default = "default_log_page")]
    pub log_page_blocks: u64,
    pub beacon: BeaconConfig,
    pub blobscan: Option<BlobscanConfig>,
    /// Present = this daemon serves a bonded provider (enforcement duties on).
    /// Absent = archive-only mode: follow and ingest, no keys, no transactions.
    pub provider: Option<ProviderConfig>,
}

/// Enforcement configuration. Deliberately absent: any private key (the operator key
/// comes ONLY from the environment, see [`ProviderConfig::operator_key`]) and the
/// withdrawal address (the daemon has no business knowing it — `stake` and `withdraw`
/// are cold-key operations outside the daemon's scope).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// The providerId this daemon answers for.
    pub id: u64,
    /// When the custody period's remaining time drops below this, the loop abandons
    /// the prover and takes the escape hatch (chunk reveals, SNARK-free). Defaults
    /// to a quarter of the instance's custody period (read from the chain at
    /// startup); an explicit value must be smaller than the period or the prover
    /// would silently never run.
    pub escape_threshold_secs: Option<u64>,
    /// How long one submission attempt waits for confirmation before a fee bump.
    #[serde(default = "default_confirm_timeout_secs")]
    pub confirm_timeout_secs: u64,
    /// The pinned custody guest ELF, needed only when the daemon is built with the
    /// `sp1` feature and expected to produce succinct proofs; without it the loop
    /// proves every period through the escape hatch.
    pub custody_elf: Option<PathBuf>,
    /// Hard ceiling on how long one proving attempt may run before it counts as a
    /// failure (and triggers the escape fallback).
    #[serde(default = "default_proving_timeout_secs")]
    pub proving_timeout_secs: u64,
}

/// Resolve the effective escape threshold against the chain-read custody period:
/// default a quarter of the period (generous margin for the escape transaction even
/// after a badly stuck proving pipeline), and reject a configured value that would
/// swallow the whole period — the prover would silently never be used.
pub fn effective_escape_threshold(
    configured: Option<u64>,
    custody_period: u64,
) -> Result<u64, ConfigError> {
    let threshold = configured.unwrap_or(custody_period / 4);
    if threshold >= custody_period {
        return Err(ConfigError::Invalid(format!(
            "escape_threshold_secs ({threshold}) must be smaller than the instance's \
             custody period ({custody_period}); as configured the prover would never run"
        )));
    }
    Ok(threshold)
}

/// The environment variable holding the operator's hot key (0x-prefixed hex).
pub const OPERATOR_KEY_ENV: &str = "BLOBSITTER_OPERATOR_KEY";

impl ProviderConfig {
    /// Load the operator key from the environment — never from the config file, and
    /// the returned signer is never logged. A compromised config must not be a
    /// compromised key.
    pub fn operator_key(&self) -> Result<alloy::signers::local::PrivateKeySigner, ConfigError> {
        let raw = std::env::var(OPERATOR_KEY_ENV)
            .map_err(|_| ConfigError::MissingEnv(OPERATOR_KEY_ENV.to_string()))?;
        raw.trim()
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("{OPERATOR_KEY_ENV} is not a valid key")))
    }
}

fn default_confirm_timeout_secs() -> u64 {
    90
}

fn default_proving_timeout_secs() -> u64 {
    6 * 3600
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeaconConfig {
    /// Beacon-API endpoints in priority order (primary first). A self-hosted node
    /// must be at least a semi-supernode to serve full blobs post-PeerDAS.
    pub endpoints: Vec<String>,
    /// Beacon-chain genesis time, for the timestamp → slot mapping
    /// (mainnet: 1606824023).
    pub genesis_time: u64,
    #[serde(default = "default_seconds_per_slot")]
    pub seconds_per_slot: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobscanConfig {
    /// API base, e.g. `https://api.blobscan.com`.
    pub url: String,
}

fn default_poll_secs() -> u64 {
    12
}

fn default_log_page() -> u64 {
    5_000
}

fn default_seconds_per_slot() -> u64 {
    12
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.into(), e))?;
        let mut config: Config = toml::from_str(&raw)?;
        if config.beacon.seconds_per_slot == 0 {
            return Err(ConfigError::Invalid("beacon.seconds_per_slot must be nonzero".into()));
        }
        if config.beacon.endpoints.is_empty() {
            return Err(ConfigError::Invalid("beacon.endpoints must not be empty".into()));
        }
        config.execution_rpc = expand_env(&config.execution_rpc)?;
        for endpoint in &mut config.beacon.endpoints {
            *endpoint = expand_env(endpoint)?;
        }
        if let Some(blobscan) = &mut config.blobscan {
            blobscan.url = expand_env(&blobscan.url)?;
        }
        Ok(config)
    }
}

/// Expand every `${VAR}` in `s` from the environment; a missing variable is an error,
/// not an empty string, so a typo can't silently produce a keyless URL.
fn expand_env(s: &str) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| ConfigError::MissingEnv(format!("unclosed ${{ in '{s}'")))?;
        let var = &after[..end];
        out.push_str(&rest[..start]);
        out.push_str(
            &std::env::var(var).map_err(|_| ConfigError::MissingEnv(var.to_string()))?,
        );
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
