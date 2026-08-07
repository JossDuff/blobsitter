//! Real declarations end to end: pattern chunks packed into canonical blobs, real KZG
//! commitments/openings (embedded Ethereum setup — no ceremony), the EIP-712 intent
//! signed by the publisher EOA behind the ERC-1271 wallet, and a REAL type-3 blob
//! transaction carrying it all into the instance on anvil. The mock is confined to
//! the SP1 proof; every other byte is production-shaped.

use alloy::eips::eip4844::BlobTransactionSidecar;
use alloy::eips::eip7594::BlobTransactionSidecarVariant;
use alloy::network::TransactionBuilder;
use alloy::network::TransactionBuilder4844;
use alloy::primitives::{Bytes, FixedBytes, B256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::SignerSync;
use alloy::sol_types::SolCall;

use blobsitter_reference::{blob, fs_z, testvec, update_subtree_roots, Chunk, Hash};

use blobsitter_intents::{
    AppPointerIntent, DeclarationIntent, IntentBody, IntentPackage, Opening, PACKAGE_VERSION,
};

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
    let package = build_declaration_package(harness, m, alloy::primitives::Address::ZERO).await?;
    submit_package(harness, stub, &package, m).await
}

/// Carry a declaration package with the harness's own funded key: calldata and
/// sidecar are assembled from the package exactly as a carrier would, submitted as a
/// real type-3 transaction, and the blobs registered with the beacon stub.
pub async fn submit_package(
    harness: &Harness,
    stub: &BeaconStub,
    package: &blobsitter_intents::IntentPackage,
    m: u64,
) -> Result<DeclarationOutcome, HarnessError> {
    let rpc = |e: String| HarnessError::Rpc(e);
    let IntentBody::Declaration { intent, blobs, openings, equivalence_proof } = &package.body
    else {
        return Err(HarnessError::Rpc("submit_package takes a declaration".into()));
    };

    let settings = c_kzg::ethereum_kzg_settings(0);
    let mut commitments = Vec::with_capacity(blobs.len());
    let mut sidecar_proofs = Vec::with_capacity(blobs.len());
    for (raw, opening) in blobs.iter().zip(openings) {
        let kzg_blob = c_kzg::Blob::from_bytes(raw).map_err(|e| rpc(e.to_string()))?;
        let blob_proof = settings
            .compute_blob_kzg_proof(
                &kzg_blob,
                &c_kzg::Bytes48::from_bytes(&opening.commitment).unwrap(),
            )
            .map_err(|e| rpc(e.to_string()))?;
        commitments.push(opening.commitment);
        sidecar_proofs.push(blob_proof.to_bytes().into_inner());
    }

    let call = Instance::declareForCall {
        d: Instance::Declaration {
            nonce: intent.nonce,
            deadline: intent.deadline,
            blobVersionedHashes: intent
                .blob_versioned_hashes
                .iter()
                .map(|h| B256::from(*h))
                .collect(),
            newSubtreePeaks: intent.new_subtree_peaks.iter().map(|h| B256::from(*h)).collect(),
            newLeafCount: intent.new_leaf_count,
            designatedCarrier: alloy::primitives::Address::from(intent.designated_carrier),
            appPointer: B256::from(intent.app_pointer),
        },
        publisherSig: Bytes::from(package.signature.clone()),
        openings: openings
            .iter()
            .map(|o| Instance::BlobOpening {
                y: B256::from(o.y),
                commitment: Bytes::copy_from_slice(&o.commitment),
                kzgProof: Bytes::copy_from_slice(&o.kzg_proof),
            })
            .collect(),
        equivalenceProof: Bytes::from(equivalence_proof.clone()),
    };

    let sidecar = BlobTransactionSidecar::new(
        blobs.iter().map(|raw| FixedBytes::<BLOB_BYTES>::from_slice(raw)).collect(),
        commitments.iter().map(|c| FixedBytes::<48>::from_slice(c)).collect(),
        sidecar_proofs.iter().map(|p| FixedBytes::<48>::from_slice(p)).collect(),
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
            "declareFor reverted (nonce {}, m {m}): {:?}",
            intent.nonce, receipt.transaction_hash
        )));
    }

    let block_number = receipt.block_number.unwrap_or_default();
    let block_timestamp = harness.block_timestamp(block_number).await?;
    // Stub slots are execution timestamps (the harness beacon config uses
    // genesis_time 0, seconds_per_slot 1, so the daemon derives slot == timestamp).
    stub.register(
        block_timestamp,
        intent.blob_versioned_hashes.iter().copied().zip(blobs.iter().cloned()).collect(),
    );

    Ok(DeclarationOutcome {
        nonce: intent.nonce,
        prior_leaf_count: intent.new_leaf_count - m,
        chunk_count: m,
        block_number,
        block_timestamp,
        versioned_hashes: intent.blob_versioned_hashes.clone(),
        blobs: blobs.clone(),
    })
}

/// The PUBLISHER side of carriage, packaged: everything `declare_pattern` computes,
/// wrapped as a signed-intent package for a carrier instead of being submitted by
/// the harness itself. `designated_carrier` = zero means anyone may carry.
pub async fn build_declaration_package(
    harness: &Harness,
    m: u64,
    designated_carrier: alloy::primitives::Address,
) -> Result<IntentPackage, HarnessError> {
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

    let settings = c_kzg::ethereum_kzg_settings(0);
    let mut versioned_hashes = Vec::with_capacity(blobs.len());
    let mut commitments = Vec::with_capacity(blobs.len());
    for raw in &blobs {
        let kzg_blob = c_kzg::Blob::from_bytes(raw).map_err(|e| rpc(e.to_string()))?;
        let commitment =
            settings.blob_to_kzg_commitment(&kzg_blob).map_err(|e| rpc(e.to_string()))?;
        versioned_hashes.push(blob::versioned_hash(&commitment.to_bytes().into_inner()));
        commitments.push(commitment.to_bytes().into_inner());
    }

    let instance20: [u8; 20] = harness.instance.into_array();
    let z = fs_z(&instance20, &versioned_hashes, &prior_peaks, &new_subtree_peaks, n0, n0 + m);
    let z_point = c_kzg::Bytes32::from_bytes(&z).map_err(|e| rpc(e.to_string()))?;
    let mut openings = Vec::with_capacity(blobs.len());
    for (raw, commitment) in blobs.iter().zip(&commitments) {
        let kzg_blob = c_kzg::Blob::from_bytes(raw).map_err(|e| rpc(e.to_string()))?;
        let (proof, y) =
            settings.compute_kzg_proof(&kzg_blob, &z_point).map_err(|e| rpc(e.to_string()))?;
        openings.push(Opening {
            y: y.as_slice().try_into().unwrap(),
            commitment: *commitment,
            kzg_proof: proof.to_bytes().into_inner(),
        });
    }

    let intent = DeclarationIntent {
        nonce,
        deadline: harness
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .map_err(|e| rpc(e.to_string()))?
            .map(|b| b.header.timestamp)
            .unwrap_or_default()
            + 3_600,
        blob_versioned_hashes: versioned_hashes,
        new_subtree_peaks,
        new_leaf_count: n0 + m,
        designated_carrier: designated_carrier.into_array(),
        app_pointer: [0u8; 32],
    };
    let mut package = IntentPackage {
        version: PACKAGE_VERSION,
        chain_id: harness.chain_id,
        instance: instance20,
        body: IntentBody::Declaration {
            intent,
            blobs,
            openings,
            equivalence_proof: harness.valid_proof.to_vec(),
        },
        signature: vec![],
    };
    package.signature = sign_package_digest(harness, package.signing_digest())?;
    Ok(package)
}

/// A signed setAppPointer package on the current appPointer nonce.
pub async fn build_app_pointer_package(
    harness: &Harness,
    pointer: Hash,
) -> Result<IntentPackage, HarnessError> {
    let rpc = |e: String| HarnessError::Rpc(e);
    let contract = harness.instance_contract();
    let nonce = contract.appPointerNonce().call().await.map_err(|e| rpc(e.to_string()))?;
    let deadline = harness
        .provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .map_err(|e| rpc(e.to_string()))?
        .map(|b| b.header.timestamp)
        .unwrap_or_default()
        + 3_600;
    let mut package = IntentPackage {
        version: PACKAGE_VERSION,
        chain_id: harness.chain_id,
        instance: harness.instance.into_array(),
        body: IntentBody::SetAppPointer {
            intent: AppPointerIntent { nonce, deadline, pointer },
        },
        signature: vec![],
    };
    package.signature = sign_package_digest(harness, package.signing_digest())?;
    Ok(package)
}

/// ECDSA by the publisher EOA over the recomputed digest, in the 65-byte r‖s‖v form
/// the ERC-1271 wallet accepts.
fn sign_package_digest(harness: &Harness, digest: Hash) -> Result<Vec<u8>, HarnessError> {
    let signature = harness
        .publisher_key
        .sign_hash_sync(&B256::from(digest))
        .map_err(|e| HarnessError::Rpc(e.to_string()))?;
    let mut bytes = signature.as_bytes();
    if bytes[64] < 27 {
        bytes[64] += 27;
    }
    Ok(bytes.to_vec())
}
