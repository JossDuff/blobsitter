//! Anvil with the real contract artifacts: spawn a node, deploy the publisher's
//! ERC-1271 wallet and the BlobsitterInstance (compressed windows), and plant the
//! MockSP1Verifier's runtime code at the template's pinned verifier address via
//! `anvil_setCode` — the node-level equivalent of the forge suite's `vm.etch`.
//!
//! Artifacts are loaded from `contracts/out`, so `forge build` must have run; callers
//! that want to self-skip instead of fail can check [`artifacts_present`] first.

use std::path::PathBuf;

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;

/// The single ABI transcription every Rust consumer shares.
pub use blobsitter_daemon::abi::Blobsitter as Instance;

/// The template constant `BlobsitterInstance.SP1_VERIFIER`.
pub const SP1_VERIFIER: Address =
    alloy::primitives::address!("0x3B6041173B80E77f038f3F2C0f9744f04837185e");

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("artifact error: {0}")]
    Artifact(String),
    #[error("rpc/deploy error: {0}")]
    Rpc(String),
}

fn contracts_out() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/out")
}

/// True when `forge build` artifacts and the anvil binary are available — the
/// preconditions Layer-2 tests self-skip on.
pub fn preconditions_met() -> bool {
    let artifacts = contracts_out().join("BlobsitterInstance.sol/BlobsitterInstance.json");
    let anvil_on_path = std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join("anvil").is_file())
    });
    let anvil_in_home = dirs_foundry_anvil().is_some();
    artifacts.is_file() && (anvil_on_path || anvil_in_home)
}

fn dirs_foundry_anvil() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let p = PathBuf::from(home).join(".foundry/bin/anvil");
    p.is_file().then_some(p)
}

fn artifact_bytecode(name: &str, field: &str) -> Result<Vec<u8>, HarnessError> {
    let path = contracts_out().join(format!("{name}.sol/{name}.json"));
    let text = std::fs::read_to_string(&path).map_err(|e| {
        HarnessError::Artifact(format!("{} (run `forge build` in contracts/): {e}", path.display()))
    })?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| HarnessError::Artifact(e.to_string()))?;
    let hex_str = json[field]["object"]
        .as_str()
        .ok_or_else(|| HarnessError::Artifact(format!("{name}: missing {field}.object")))?;
    hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| HarnessError::Artifact(e.to_string()))
}

pub struct Harness {
    /// Held for its Drop (kills the node).
    _anvil: AnvilInstance,
    pub provider: DynProvider,
    pub endpoint: String,
    pub chain_id: u64,
    pub instance: Address,
    pub instance_deploy_block: u64,
    /// EOA behind the ERC-1271 publisher wallet; signs declarations off-chain.
    pub publisher_key: PrivateKeySigner,
    /// The deployed ERC1271Wallet address — the instance's `publisher`.
    pub publisher_wallet: Address,
    /// The 32-byte proof the mock verifier accepts.
    pub valid_proof: Bytes,
}

impl Harness {
    /// Spawn anvil + deploy the rig with default (mildly compressed) windows.
    pub async fn spawn() -> Result<Self, HarnessError> {
        Self::spawn_with(|_| {}).await
    }

    /// Spawn anvil + deploy the rig. Hardfork pinned to prague: the harness submits
    /// classic EIP-4844 blob sidecars, not the post-Fusaka cell-proof variant.
    /// `--slots-in-an-epoch 1` gives the tightest finality anvil offers
    /// (finalized = latest − 2), so finality-gated behavior is testable in real time.
    /// `tune` edits the instance's constructor parameters before deployment —
    /// enforcement tests compress the protocol windows to seconds.
    pub async fn spawn_with(tune: impl FnOnce(&mut Instance::Params)) -> Result<Self, HarnessError> {
        let mut anvil = Anvil::new().args(["--slots-in-an-epoch", "1", "--hardfork", "prague"]);
        if let Some(bin) = dirs_foundry_anvil() {
            anvil = anvil.path(bin);
        }
        let anvil = anvil.try_spawn().map_err(|e| HarnessError::Rpc(e.to_string()))?;

        // anvil's first funded dev key carries all deployments and blob txs.
        let carrier: PrivateKeySigner = anvil.keys()[0].clone().into();
        let publisher_key: PrivateKeySigner = anvil.keys()[1].clone().into();
        let endpoint = anvil.endpoint();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(carrier))
            .connect_http(endpoint.parse().unwrap())
            .erased();
        let chain_id =
            provider.get_chain_id().await.map_err(|e| HarnessError::Rpc(e.to_string()))?;

        // Mock verifier at the pinned address: runtime code straight from the
        // artifact (the contract is stateless, so no constructor run is needed).
        let mock_runtime = artifact_bytecode("MockSP1Verifier", "deployedBytecode")?;
        provider
            .raw_request::<_, ()>(
                "anvil_setCode".into(),
                (SP1_VERIFIER, Bytes::from(mock_runtime)),
            )
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?;
        let valid_proof = Bytes::from(keccak256(b"blobsitter.test.valid-proof").to_vec());

        let publisher_wallet = deploy(
            &provider,
            artifact_bytecode("ERC1271Wallet", "bytecode")?,
            publisher_key.address().abi_encode(),
        )
        .await?
        .0;

        let mut params = Instance::Params {
            publisher: publisher_wallet,
            stakeWei: U256::from(2u64) * U256::from(10u64).pow(U256::from(18)),
            responseWindow: 60,
            unbondingDelay: 120,
            custodyPeriod: 300,
            lapseGrace: 60,
            custodyK: 64,
            maxSample: 8,
            bountyBps: 1500,
            carrierTipWei: U256::from(2u64) * U256::from(10u64).pow(U256::from(14)),
            provingSubsidyWei: U256::from(5u64) * U256::from(10u64).pow(U256::from(14)),
            bucketRateWeiPerDay: U256::from(5u64) * U256::from(10u64).pow(U256::from(16)),
            bucketCapWei: U256::from(15u64) * U256::from(10u64).pow(U256::from(17)),
            dormancyWindow: 86_400,
            dormancyMinChunks: 32_768,
        };
        tune(&mut params);
        let (instance, instance_deploy_block) = deploy(
            &provider,
            artifact_bytecode("BlobsitterInstance", "bytecode")?,
            params.abi_encode(),
        )
        .await?;

        Ok(Self {
            _anvil: anvil,
            provider,
            endpoint,
            chain_id,
            instance,
            instance_deploy_block,
            publisher_key,
            publisher_wallet,
            valid_proof,
        })
    }

    pub fn instance_contract(&self) -> Instance::BlobsitterInstance<DynProvider> {
        Instance::new(self.instance, self.provider.clone())
    }

    /// One of anvil's pre-funded dev keys (0 and 1 are taken: carrier and publisher).
    pub fn dev_key(&self, index: usize) -> PrivateKeySigner {
        self._anvil.keys()[index].clone().into()
    }

    /// Mine `n` empty blocks (advances finality: finalized = latest − 2).
    pub async fn mine(&self, n: u64) -> Result<(), HarnessError> {
        self.provider
            .raw_request::<_, ()>("anvil_mine".into(), (U256::from(n),))
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))
    }

    pub async fn block_timestamp(&self, number: u64) -> Result<u64, HarnessError> {
        Ok(self
            .provider
            .get_block_by_number(number.into())
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?
            .ok_or_else(|| HarnessError::Rpc(format!("block {number} missing")))?
            .header
            .timestamp)
    }

    /// Warp chain time forward and mine, so time-window transitions (custody
    /// periods, response deadlines, unbonding delays) run in test time.
    pub async fn warp(&self, seconds: u64) -> Result<(), HarnessError> {
        self.provider
            .raw_request::<_, serde_json::Value>("evm_increaseTime".into(), (U256::from(seconds),))
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?;
        self.mine(1).await
    }

    /// Give an address gas money (the operator hot wallet in daemon tests).
    pub async fn fund(&self, address: Address, wei: U256) -> Result<(), HarnessError> {
        self.provider
            .raw_request::<_, ()>("anvil_setBalance".into(), (address, wei))
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))
    }

    /// Toggle automine — off lets response transactions sit pending, driving the
    /// fee-escalation paths.
    pub async fn set_automine(&self, on: bool) -> Result<(), HarnessError> {
        self.provider
            .raw_request::<_, ()>("evm_setAutomine".into(), (on,))
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))
    }

    /// Stake a new provider (2 ETH from the harness's funded key) and return its id.
    pub async fn stake(&self, operator: Address, withdrawal: Address) -> Result<u64, HarnessError> {
        let contract = self.instance_contract();
        let stake_wei = U256::from(2u64) * U256::from(10u64).pow(U256::from(18));
        let id = contract
            .stake(operator, withdrawal)
            .value(stake_wei)
            .call()
            .await
            .map_err(|e| HarnessError::Rpc(format!("stake preview: {e}")))?;
        let receipt = contract
            .stake(operator, withdrawal)
            .value(stake_wei)
            .send()
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?;
        if !receipt.status() {
            return Err(HarnessError::Rpc("stake reverted".into()));
        }
        Ok(id)
    }

    /// Open a challenge against `provider_id` from the harness's funded key, with a
    /// comfortably sufficient bond at the current basefee. Returns the challengeId.
    pub async fn open_challenge(
        &self,
        provider_id: u64,
        indices: Vec<u64>,
    ) -> Result<u64, HarnessError> {
        // bond ≥ 3 · (k · RESPONSE_GAS_PER_CHUNK + RESPONSE_BASE_GAS) · basefee;
        // pay double at the latest basefee so a fee drift never underfunds it.
        let basefee = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?
            .and_then(|b| b.header.base_fee_per_gas)
            .unwrap_or(1_000_000_000) as u128;
        let bond = 2u128 * 3 * (indices.len() as u128 * 38_680 + 21_000) * basefee;

        let contract = self.instance_contract();
        let id = contract
            .challenge(provider_id, indices.clone())
            .value(U256::from(bond))
            .call()
            .await
            .map_err(|e| HarnessError::Rpc(format!("challenge preview: {e}")))?;
        let receipt = contract
            .challenge(provider_id, indices)
            .value(U256::from(bond))
            .send()
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?;
        if !receipt.status() {
            return Err(HarnessError::Rpc("challenge reverted".into()));
        }
        Ok(id)
    }

    /// Resolve an expired challenge (slashes the provider if unanswered).
    pub async fn resolve_timeout(&self, challenge_id: u64) -> Result<(), HarnessError> {
        let receipt = self
            .instance_contract()
            .resolveTimeout(challenge_id)
            .send()
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| HarnessError::Rpc(e.to_string()))?;
        if !receipt.status() {
            return Err(HarnessError::Rpc("resolveTimeout reverted".into()));
        }
        Ok(())
    }
}

async fn deploy(
    provider: &DynProvider,
    bytecode: Vec<u8>,
    constructor_args: Vec<u8>,
) -> Result<(Address, u64), HarnessError> {
    let mut input = bytecode;
    input.extend_from_slice(&constructor_args);
    let tx =
        TransactionRequest::default().with_deploy_code(Bytes::from(input));
    let receipt = provider
        .send_transaction(tx)
        .await
        .map_err(|e| HarnessError::Rpc(e.to_string()))?
        .get_receipt()
        .await
        .map_err(|e| HarnessError::Rpc(e.to_string()))?;
    if !receipt.status() {
        return Err(HarnessError::Rpc("deployment reverted".into()));
    }
    Ok((
        receipt
            .contract_address
            .ok_or_else(|| HarnessError::Rpc("no contract address in receipt".into()))?,
        receipt.block_number.unwrap_or_default(),
    ))
}
