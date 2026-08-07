//! Chain preflight (test plan C2): every check the contract will run, run first —
//! against live state, before any gas leaves the carrier. A failing preflight names
//! its check; a passing one hands back the fully assembled transaction request with
//! a real gas figure, so what was simulated is byte-for-byte what gets sent.

use alloy::network::{TransactionBuilder, TransactionBuilder4844};
use alloy::primitives::{Address, Bytes, FixedBytes, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;

use blobsitter_abi::{Blobsitter, IERC1271};
use blobsitter_intents::{IntentBody, IntentPackage, Validated};
use blobsitter_reference::{blob, decompose, fs_z};

/// ERC-1271's acceptance value for `isValidSignature`.
const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("package targets chain {package} but the RPC serves chain {rpc}")]
    WrongChain { package: u64, rpc: u64 },
    #[error("intent deadline {deadline} has passed (chain time {now})")]
    Expired { deadline: u64, now: u64 },
    #[error("intent nonce {intent} but the contract expects {contract}")]
    NonceMismatch { intent: u64, contract: u64 },
    #[error("intent designates carrier {designated}; this carrier is {us}")]
    NotDesignated { designated: Address, us: Address },
    #[error("the publisher wallet rejected the signature (ERC-1271 staticcall)")]
    SignatureRejected,
    #[error("newLeafCount {new} does not extend the chain's leafCount {current}")]
    DoesNotExtend { new: u64, current: u64 },
    #[error("{blobs} blob(s) for {m} chunks; the contract requires {required}")]
    BlobCountMismatch { blobs: usize, m: u64, required: usize },
    #[error("{got} subtree peak(s); the decomposition of (n0={n0}, m={m}) requires {required}")]
    SubtreeCountMismatch { got: usize, n0: u64, m: u64, required: usize },
    #[error("final blob has nonzero bytes past the declared {m} chunks (element {element})")]
    NonZeroTail { m: u64, element: usize },
    #[error("opening {index} fails KZG verification at the recomputed evaluation point")]
    OpeningInvalid { index: usize },
    #[error("transaction simulation failed: {0}")]
    Simulation(String),
    #[error("rpc error: {0}")]
    Rpc(String),
}

/// A preflighted, ready-to-send transaction: the request carries the sidecar (for
/// declarations), calldata, and the simulated gas limit.
pub struct Preflighted {
    pub tx: TransactionRequest,
    pub gas_estimate: u64,
    /// Blob count (0 for non-declaration intents) — solvency needs it.
    pub num_blobs: usize,
    /// Encoded calldata length — solvency needs it.
    pub calldata_len: usize,
    pub is_declaration: bool,
}

/// Run the full preflight for `package` as `carrier`. `validated` is the output of
/// the static validation (recomputed commitments).
pub async fn preflight(
    provider: &DynProvider,
    package: &IntentPackage,
    validated: &Validated,
    carrier: Address,
) -> Result<Preflighted, PreflightError> {
    let rpc = |e: String| PreflightError::Rpc(e);
    let chain_id = provider.get_chain_id().await.map_err(|e| rpc(e.to_string()))?;
    if chain_id != package.chain_id {
        return Err(PreflightError::WrongChain { package: package.chain_id, rpc: chain_id });
    }
    let instance = Address::from(package.instance);
    let contract = Blobsitter::new(instance, provider.clone());

    let now = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .map_err(|e| rpc(e.to_string()))?
        .ok_or_else(|| rpc("no latest block".into()))?
        .header
        .timestamp;
    // The contract accepts `block.timestamp <= deadline`; the NEXT block's timestamp
    // will be at least now + 1, so submitting at now == deadline already loses.
    if now >= package.deadline() {
        return Err(PreflightError::Expired { deadline: package.deadline(), now });
    }

    // The publisher wallet must accept the recomputed digest TODAY — not when the
    // package was built (multisig owners rotate).
    let digest = B256::from(package.signing_digest());
    let publisher = contract.publisher().call().await.map_err(|e| rpc(e.to_string()))?;
    let wallet = IERC1271::new(publisher, provider.clone());
    let magic = wallet
        .isValidSignature(digest, Bytes::from(package.signature.clone()))
        .call()
        .await
        .map_err(|_| PreflightError::SignatureRejected)?;
    if magic.0 != ERC1271_MAGIC {
        return Err(PreflightError::SignatureRejected);
    }

    let (calldata, num_blobs, sidecar) = match &package.body {
        IntentBody::Declaration { intent, blobs, openings, equivalence_proof } => {
            let contract_nonce =
                contract.declarationNonce().call().await.map_err(|e| rpc(e.to_string()))?;
            if intent.nonce != contract_nonce {
                return Err(PreflightError::NonceMismatch {
                    intent: intent.nonce,
                    contract: contract_nonce,
                });
            }
            if intent.designated_carrier != [0u8; 20]
                && Address::from(intent.designated_carrier) != carrier
            {
                return Err(PreflightError::NotDesignated {
                    designated: Address::from(intent.designated_carrier),
                    us: carrier,
                });
            }

            // Shape against LIVE state: the declaration must extend the current
            // tree by ≥ 1 chunk with exactly the required blob and subtree counts.
            let n0 = contract.leafCount().call().await.map_err(|e| rpc(e.to_string()))?;
            let m = intent.new_leaf_count.saturating_sub(n0);
            if m == 0 {
                return Err(PreflightError::DoesNotExtend {
                    new: intent.new_leaf_count,
                    current: n0,
                });
            }
            let required = (m as usize).div_ceil(blob::FIELD_ELEMENTS_PER_BLOB);
            if blobs.len() != required {
                return Err(PreflightError::BlobCountMismatch { blobs: blobs.len(), m, required });
            }
            let heights = decompose(n0, m);
            if intent.new_subtree_peaks.len() != heights.len() {
                return Err(PreflightError::SubtreeCountMismatch {
                    got: intent.new_subtree_peaks.len(),
                    n0,
                    m,
                    required: heights.len(),
                });
            }
            // Tail of the final blob must be zero past the declared chunks (the
            // equivalence circuit enforces it; a bad tail means a doomed tx).
            let tail_start = (m as usize) % blob::FIELD_ELEMENTS_PER_BLOB;
            if tail_start != 0 {
                let last = &blobs[blobs.len() - 1];
                for element in tail_start..blob::FIELD_ELEMENTS_PER_BLOB {
                    if last[element * 32..(element + 1) * 32].iter().any(|&b| b != 0) {
                        return Err(PreflightError::NonZeroTail { m, element });
                    }
                }
            }

            // The evaluation point the contract will derive, from CURRENT peaks —
            // and every opening verified against it with the precompile's own math.
            let prior_peaks: Vec<_> = contract
                .allPeaks()
                .call()
                .await
                .map_err(|e| rpc(e.to_string()))?
                .into_iter()
                .map(|p| p.0)
                .collect();
            let z = fs_z(
                &package.instance,
                &intent.blob_versioned_hashes,
                &prior_peaks,
                &intent.new_subtree_peaks,
                n0,
                intent.new_leaf_count,
            );
            let settings = c_kzg::ethereum_kzg_settings(0);
            let z_point = c_kzg::Bytes32::from_bytes(&z)
                .map_err(|e| PreflightError::Simulation(e.to_string()))?;
            for (index, opening) in openings.iter().enumerate() {
                let ok = settings
                    .verify_kzg_proof(
                        &c_kzg::Bytes48::from_bytes(&opening.commitment).unwrap(),
                        &z_point,
                        &c_kzg::Bytes32::from_bytes(&opening.y).unwrap(),
                        &c_kzg::Bytes48::from_bytes(&opening.kzg_proof).unwrap(),
                    )
                    .unwrap_or(false);
                if !ok {
                    return Err(PreflightError::OpeningInvalid { index });
                }
            }

            let call = Blobsitter::declareForCall {
                d: Blobsitter::Declaration {
                    nonce: intent.nonce,
                    deadline: intent.deadline,
                    blobVersionedHashes: intent
                        .blob_versioned_hashes
                        .iter()
                        .map(|h| B256::from(*h))
                        .collect(),
                    newSubtreePeaks: intent
                        .new_subtree_peaks
                        .iter()
                        .map(|h| B256::from(*h))
                        .collect(),
                    newLeafCount: intent.new_leaf_count,
                    designatedCarrier: Address::from(intent.designated_carrier),
                    appPointer: B256::from(intent.app_pointer),
                },
                publisherSig: Bytes::from(package.signature.clone()),
                openings: openings
                    .iter()
                    .map(|o| Blobsitter::BlobOpening {
                        y: B256::from(o.y),
                        commitment: Bytes::copy_from_slice(&o.commitment),
                        kzgProof: Bytes::copy_from_slice(&o.kzg_proof),
                    })
                    .collect(),
                equivalenceProof: Bytes::from(equivalence_proof.clone()),
            }
            .abi_encode();
            let sidecar = build_sidecar(blobs, &validated.commitments)?;
            (call, blobs.len(), Some(sidecar))
        }
        IntentBody::SetAppPointer { intent } => {
            let contract_nonce =
                contract.appPointerNonce().call().await.map_err(|e| rpc(e.to_string()))?;
            if intent.nonce != contract_nonce {
                return Err(PreflightError::NonceMismatch {
                    intent: intent.nonce,
                    contract: contract_nonce,
                });
            }
            let call = Blobsitter::setAppPointerCall {
                nonce: intent.nonce,
                deadline: intent.deadline,
                pointer: B256::from(intent.pointer),
                sig: Bytes::from(package.signature.clone()),
            }
            .abi_encode();
            (call, 0, None)
        }
        IntentBody::SetSuccessor { intent } => {
            let contract_nonce =
                contract.successorNonce().call().await.map_err(|e| rpc(e.to_string()))?;
            if intent.nonce != contract_nonce {
                return Err(PreflightError::NonceMismatch {
                    intent: intent.nonce,
                    contract: contract_nonce,
                });
            }
            let call = Blobsitter::setSuccessorCall {
                nonce: intent.nonce,
                deadline: intent.deadline,
                target: Address::from(intent.target),
                sig: Bytes::from(package.signature.clone()),
            }
            .abi_encode();
            (call, 0, None)
        }
    };

    let calldata_len = calldata.len();
    let is_declaration = sidecar.is_some();
    let mut tx = TransactionRequest::default()
        .with_from(carrier)
        .with_to(instance)
        .with_input(calldata);
    if let Some(sidecar) = sidecar {
        tx = tx
            .with_blob_sidecar(alloy::eips::eip7594::BlobTransactionSidecarVariant::Eip4844(
                sidecar,
            ))
            .with_max_fee_per_blob_gas(10_000_000_000);
    }

    // The simulation IS the equivalence-proof check (the verifier runs inside it) —
    // the one predicate no local math can cover.
    let gas_estimate = provider
        .estimate_gas(tx.clone())
        .await
        .map_err(|e| PreflightError::Simulation(e.to_string()))?;
    tx.gas = Some(gas_estimate + gas_estimate / 4);

    Ok(Preflighted { tx, gas_estimate, num_blobs, calldata_len, is_declaration })
}

/// The network sidecar, from the blob BYTES and the commitments recomputed during
/// static validation — nothing sidecar-shaped is ever copied from the package.
fn build_sidecar(
    blobs: &[Vec<u8>],
    commitments: &[[u8; 48]],
) -> Result<alloy::eips::eip4844::BlobTransactionSidecar, PreflightError> {
    let settings = c_kzg::ethereum_kzg_settings(0);
    let mut proofs = Vec::with_capacity(blobs.len());
    for (raw, commitment) in blobs.iter().zip(commitments) {
        let kzg_blob = c_kzg::Blob::from_bytes(raw)
            .map_err(|e| PreflightError::Simulation(e.to_string()))?;
        let proof = settings
            .compute_blob_kzg_proof(&kzg_blob, &c_kzg::Bytes48::from_bytes(commitment).unwrap())
            .map_err(|e| PreflightError::Simulation(e.to_string()))?;
        proofs.push(FixedBytes::<48>::from_slice(proof.to_bytes().as_slice()));
    }
    Ok(alloy::eips::eip4844::BlobTransactionSidecar::new(
        blobs.iter().map(|raw| FixedBytes::from_slice(raw)).collect(),
        commitments.iter().map(|c| FixedBytes::<48>::from_slice(c)).collect(),
        proofs,
    ))
}
