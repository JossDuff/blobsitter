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
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolValue;

/// The template constant `BlobsitterInstance.SP1_VERIFIER`.
pub const SP1_VERIFIER: Address =
    alloy::primitives::address!("0x3B6041173B80E77f038f3F2C0f9744f04837185e");

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract Instance {
        struct Params {
            address publisher;
            uint256 stakeWei;
            uint64 responseWindow;
            uint64 unbondingDelay;
            uint64 custodyPeriod;
            uint64 lapseGrace;
            uint32 custodyK;
            uint16 maxSample;
            uint16 bountyBps;
            uint256 carrierTipWei;
            uint256 provingSubsidyWei;
            uint256 bucketRateWeiPerDay;
            uint256 bucketCapWei;
            uint64 dormancyWindow;
            uint64 dormancyMinChunks;
        }

        struct Declaration {
            uint64 nonce;
            uint64 deadline;
            bytes32[] blobVersionedHashes;
            bytes32[] newSubtreePeaks;
            uint64 newLeafCount;
            address designatedCarrier;
            bytes32 appPointer;
        }

        struct BlobOpening {
            bytes32 y;
            bytes commitment;
            bytes kzgProof;
        }

        function declareFor(
            Declaration d,
            bytes publisherSig,
            BlobOpening[] openings,
            bytes equivalenceProof
        ) external;

        function leafCount() external view returns (uint64);
        function declarationNonce() external view returns (uint64);
        function allPeaks() external view returns (bytes32[] memory);
        function root() external view returns (bytes32);
    }
}

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
    /// Spawn anvil + deploy the rig. Hardfork pinned to prague: the harness submits
    /// classic EIP-4844 blob sidecars, not the post-Fusaka cell-proof variant.
    /// `--slots-in-an-epoch 1` gives the tightest finality anvil offers
    /// (finalized = latest − 2), so finality-gated behavior is testable in real time.
    pub async fn spawn() -> Result<Self, HarnessError> {
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

        let params = Instance::Params {
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

    pub fn instance_contract(&self) -> Instance::InstanceInstance<DynProvider> {
        Instance::new(self.instance, self.provider.clone())
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

/// Compile-time-visible B256 helper for tests.
pub fn b256(bytes: [u8; 32]) -> B256 {
    B256::from(bytes)
}
