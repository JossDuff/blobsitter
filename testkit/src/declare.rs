//! Real declarations end to end: pattern chunks packed into canonical blobs, real KZG
//! commitments/openings (embedded Ethereum setup — no ceremony), the EIP-712 intent
//! signed by the publisher EOA behind the ERC-1271 wallet, and a REAL type-3 blob
//! transaction carrying it all into the instance on anvil. The mock is confined to
//! the SP1 proof; every other byte is production-shaped.

use alloy::eips::eip4844::BlobTransactionSidecar;
use alloy::eips::eip7594::BlobTransactionSidecarVariant;
use alloy::network::TransactionBuilder;
use alloy::network::TransactionBuilder4844;
use alloy::primitives::{Address, Bytes, FixedBytes, B256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::SignerSync;
use alloy::sol_types::SolCall;

use blobsitter_reference::{blob, eip712, fs_z, testvec, update_subtree_roots, Chunk, Hash};

use crate::anvil::{Harness, HarnessError, Instance};
use crate::beacon_stub::BeaconStub;

pub use blobsitter_reference::blob::BLOB_BYTES;

/// What a completed declaration left behind — everything a test needs to feed blob
/// sources and check daemon state against.
#[derive(Debug, Clone)]
pub struct DeclarationOutcome {
    pub nonce: u64,
    pub prior_leaf_count: u64,
    pub chunk_count: u64,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub versioned_hashes: Vec<Hash>,
    pub blobs: Vec<Vec<u8>>,
}

/// Declare `m` pattern chunks (`testvec::chunk` at the global index) on top of the
/// instance's current state — packed by the reference's canonical rule — and register
/// the blobs with the beacon stub so the daemon's production adapter can fetch them.
pub async fn declare_pattern(
    harness: &Harness,
    stub: &BeaconStub,
    m: u64,
) -> Result<DeclarationOutcome, HarnessError> {
    let rpc = |e: String| HarnessError::Rpc(e);
    let contract = harness.instance_contract();
    let nonce = contract.declarationNonce().call().await.map_err(|e| rpc(e.to_string()))?;
    let n0 = contract.leafCount().call().await.map_err(|e| rpc(e.to_string()))?;
    let prior_peaks: Vec<Hash> = contract
        .allPeaks()
        .call()
        .await
        .map_err(|e| rpc(e.to_string()))?
        .into_iter()
        .map(|p| p.0)
        .collect();

    let chunks: Vec<Chunk> = (n0..n0 + m).map(testvec::chunk).collect();
    let blobs = blob::pack(&chunks);
    let new_subtree_peaks = update_subtree_roots(n0, &chunks);

    // Real KZG: commitment → versioned hash, then the opening at the Fiat–Shamir
    // point z the contract will derive for exactly this declaration.
    let settings = c_kzg::ethereum_kzg_settings(0);
    let mut versioned_hashes = Vec::with_capacity(blobs.len());
    let mut commitments = Vec::with_capacity(blobs.len());
    for raw in &blobs {
        let kzg_blob = c_kzg::Blob::from_bytes(raw).map_err(|e| rpc(e.to_string()))?;
        let commitment =
            settings.blob_to_kzg_commitment(&kzg_blob).map_err(|e| rpc(e.to_string()))?;
        versioned_hashes.push(blob::versioned_hash(&commitment.to_bytes().into_inner()));
        commitments.push(commitment.to_bytes());
    }

    let instance20: [u8; 20] = harness.instance.into_array();
    let z = fs_z(&instance20, &versioned_hashes, &prior_peaks, &new_subtree_peaks, n0, n0 + m);
    let z_point = c_kzg::Bytes32::from_bytes(&z).map_err(|e| rpc(e.to_string()))?;

    let mut openings = Vec::with_capacity(blobs.len());
    let mut sidecar_proofs = Vec::with_capacity(blobs.len());
    for (raw, commitment) in blobs.iter().zip(&commitments) {
        let kzg_blob = c_kzg::Blob::from_bytes(raw).map_err(|e| rpc(e.to_string()))?;
        let (opening_proof, y) =
            settings.compute_kzg_proof(&kzg_blob, &z_point).map_err(|e| rpc(e.to_string()))?;
        openings.push(Instance::BlobOpening {
            y: B256::from_slice(y.as_slice()),
            commitment: Bytes::copy_from_slice(commitment.as_slice()),
            kzgProof: Bytes::copy_from_slice(opening_proof.to_bytes().as_slice()),
        });
        // The sidecar wants the network blob proof (blob vs commitment), a different
        // proof than the point opening the contract checks.
        let blob_proof = settings
            .compute_blob_kzg_proof(&kzg_blob, &c_kzg::Bytes48::from_bytes(commitment.as_slice()).unwrap())
            .map_err(|e| rpc(e.to_string()))?;
        sidecar_proofs.push(blob_proof.to_bytes());
    }

    // The signed intent: EIP-712 digest from the reference implementation, ECDSA by
    // the publisher EOA, accepted on-chain by the ERC-1271 wallet.
    let latest_ts = harness
        .provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .map_err(|e| rpc(e.to_string()))?
        .map(|b| b.header.timestamp)
        .unwrap_or_default();
    let declaration = eip712::Declaration {
        nonce,
        deadline: latest_ts + 3_600,
        blob_versioned_hashes: versioned_hashes.clone(),
        new_subtree_peaks: new_subtree_peaks.clone(),
        new_leaf_count: n0 + m,
        designated_carrier: [0u8; 20],
        app_pointer: [0u8; 32],
    };
    let domain = eip712::domain_separator(harness.chain_id, &instance20);
    let digest = eip712::digest(&domain, &declaration.struct_hash());
    let signature = harness
        .publisher_key
        .sign_hash_sync(&B256::from(digest))
        .map_err(|e| rpc(e.to_string()))?;
    let mut sig_bytes = signature.as_bytes();
    if sig_bytes[64] < 27 {
        // The ERC-1271 wallet feeds ecrecover directly, which wants v ∈ {27, 28}.
        sig_bytes[64] += 27;
    }

    let call = Instance::declareForCall {
        d: Instance::Declaration {
            nonce,
            deadline: declaration.deadline,
            blobVersionedHashes: versioned_hashes.iter().map(|h| B256::from(*h)).collect(),
            newSubtreePeaks: new_subtree_peaks.iter().map(|h| B256::from(*h)).collect(),
            newLeafCount: n0 + m,
            designatedCarrier: Address::ZERO,
            appPointer: B256::ZERO,
        },
        publisherSig: Bytes::from(sig_bytes.to_vec()),
        openings,
        equivalenceProof: harness.valid_proof.clone(),
    };

    let sidecar = BlobTransactionSidecar::new(
        blobs
            .iter()
            .map(|raw| FixedBytes::<BLOB_BYTES>::from_slice(raw))
            .collect(),
        commitments
            .iter()
            .map(|c| FixedBytes::<48>::from_slice(c.as_slice()))
            .collect(),
        sidecar_proofs
            .iter()
            .map(|p| FixedBytes::<48>::from_slice(p.as_slice()))
            .collect(),
    );
    let tx = TransactionRequest::default()
        .with_to(harness.instance)
        .with_input(call.abi_encode())
        // Pre-Fusaka sidecar variant, matching the harness's pinned prague hardfork.
        .with_blob_sidecar(BlobTransactionSidecarVariant::Eip4844(sidecar))
        .with_max_fee_per_blob_gas(10_000_000_000)
        .with_gas_limit(5_000_000);

    let receipt = harness
        .provider
        .send_transaction(tx)
        .await
        .map_err(|e| rpc(e.to_string()))?
        .get_receipt()
        .await
        .map_err(|e| rpc(e.to_string()))?;
    if !receipt.status() {
        return Err(HarnessError::Rpc(format!(
            "declareFor reverted (nonce {nonce}, m {m}): {:?}",
            receipt.transaction_hash
        )));
    }

    let block_number = receipt.block_number.unwrap_or_default();
    let block_timestamp = harness.block_timestamp(block_number).await?;
    // Stub slots are execution timestamps (the harness beacon config uses
    // genesis_time 0, seconds_per_slot 1, so the daemon derives slot == timestamp).
    stub.register(
        block_timestamp,
        versioned_hashes.iter().copied().zip(blobs.iter().cloned()).collect(),
    );

    Ok(DeclarationOutcome {
        nonce,
        prior_leaf_count: n0,
        chunk_count: m,
        block_number,
        block_timestamp,
        versioned_hashes,
        blobs,
    })
}
