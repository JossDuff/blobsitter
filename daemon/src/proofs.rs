//! Store-backed proof construction: the bridge from the flat chunk file to the
//! `(chunk, path)` payloads that challenge responses, the custody escape hatch, and
//! the custody prover witness all consume. Handles HISTORICAL pins: a challenge
//! against an unbonding provider is answered at its exit snapshot, and a custody
//! proof at its commit snapshot — both arbitrary past leaf counts, reconstructed
//! from the file alone.
//!
//! Every set is checked before it leaves this module — the peak list against the
//! expected pinned root, and every path against those peaks with the exact verifier
//! the contract runs — so an invalid response can never be submitted: if the store
//! cannot reproduce the pin, the caller gets an error to alarm on, not calldata
//! that would burn the response window.

use std::cell::RefCell;

use blobsitter_reference::{root, verify, Chunk, Hash, PathBuilder};

use crate::store::{Reader, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("index {index} is at or past the pinned leaf count {n}")]
    IndexOutOfRange { index: u64, n: u64 },
    #[error("pinned leaf count {n} exceeds the committed store frontier {frontier}")]
    BeyondFrontier { n: u64, frontier: u64 },
    #[error(
        "store cannot reproduce the pinned root at leaf count {n}: expected 0x{expected}, \
         recomputed 0x{computed} — the local store disagrees with the on-chain pin"
    )]
    PinMismatch { n: u64, expected: String, computed: String },
    #[error("constructed proof for index {index} failed local verification")]
    SelfCheckFailed { index: u64 },
}

/// One proven chunk: the raw bytes plus the sibling path, bottom level first —
/// the exact shape of the contract's `ChunkProof` and the circuit's `CustodySample`.
#[derive(Debug, Clone)]
pub struct ProvenChunk {
    pub chunk: Chunk,
    pub path: Vec<Hash>,
}

/// Everything a pinned-state response needs: the peak list to re-bag on chain and
/// the per-index proofs, in the caller's index order (duplicates included).
#[derive(Debug, Clone)]
pub struct ProofSet {
    pub n: u64,
    pub peaks: Vec<Hash>,
    pub proven: Vec<ProvenChunk>,
}

/// Build peaks and inclusion proofs at leaf count `n` (≤ the committed frontier),
/// verified end to end before returning.
pub fn build_proof_set(
    reader: &Reader,
    indices: &[u64],
    n: u64,
    pinned_root: &Hash,
) -> Result<ProofSet, ProofError> {
    let frontier = reader.leaf_count();
    if n > frontier {
        return Err(ProofError::BeyondFrontier { n, frontier });
    }
    if let Some(&index) = indices.iter().find(|&&i| i >= n) {
        return Err(ProofError::IndexOutOfRange { index, n });
    }

    // The revealed chunks, read up front so a read failure is a plain error.
    let chunks: Vec<Chunk> =
        indices.iter().map(|&i| reader.chunk(i)).collect::<Result<_, _>>()?;

    // The builder wants an infallible chunk source; IO errors during interior
    // hashing are parked in a cell and re-raised after the batch (a zero chunk can
    // only make the checks below fail, never fabricate a passing proof).
    let io_error: RefCell<Option<StoreError>> = RefCell::new(None);
    let chunk_at = |i: u64| -> Chunk {
        match reader.chunk(i) {
            Ok(c) => c,
            Err(e) => {
                io_error.borrow_mut().get_or_insert(e);
                [0u8; 31]
            }
        }
    };
    let mut builder = PathBuilder::new(chunk_at);
    let peaks = builder.peaks_at(n);
    let paths: Vec<Vec<Hash>> =
        indices.iter().map(|&i| builder.prove(i, n).1).collect();
    drop(builder);
    if let Some(e) = io_error.into_inner() {
        return Err(ProofError::Store(e));
    }

    let computed = root(n, &peaks);
    if computed != *pinned_root {
        return Err(ProofError::PinMismatch {
            n,
            expected: hex::encode(pinned_root),
            computed: hex::encode(computed),
        });
    }
    // Final self-check with the contract's own verifier logic: nothing that fails
    // on chain may leave this function.
    for ((&index, chunk), path) in indices.iter().zip(&chunks).zip(&paths) {
        if !verify(chunk, index, path, n, &peaks) {
            return Err(ProofError::SelfCheckFailed { index });
        }
    }

    let proven = chunks
        .into_iter()
        .zip(paths)
        .map(|(chunk, path)| ProvenChunk { chunk, path })
        .collect();
    Ok(ProofSet { n, peaks, proven })
}
