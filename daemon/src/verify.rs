//! Verify-before-write: the ONLY gate through which fetched bytes become store
//! candidates. Every blob source is untrusted — a hosted API, a public archive,
//! another provider — so a blob is admitted purely on cryptographic identity: its
//! recomputed KZG commitment must hash to the versioned hash the L1 event declared.
//! Corruption is therefore impossible to smuggle in; the only failure mode any source
//! retains is withholding.

use blobsitter_reference::{Chunk, Hash};
use sha2::{Digest, Sha256};

use crate::{RawBlob, BLOB_BYTES};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("blob is not a valid field-element array: {0}")]
    InvalidBlob(String),
    #[error("field element {index} has a nonzero high byte — not canonical chunk encoding")]
    NonCanonicalElement { index: usize },
    #[error("trailing element {index} past the declared chunk count is nonzero")]
    NonZeroPadding { index: usize },
    #[error("declaration needs {expected} blobs for its chunk count but carries {got}")]
    BlobCountMismatch { expected: usize, got: usize },
}

/// The versioned hash a blob would have on chain: `0x01 ‖ sha256(commitment)[1:]`.
/// Computing the commitment is the expensive step (~ms per blob) and is exactly the
/// check that makes every source trustless.
pub fn versioned_hash(blob: &RawBlob) -> Result<Hash, VerifyError> {
    let settings = c_kzg::ethereum_kzg_settings(0);
    let blob = c_kzg::Blob::from_bytes(blob.as_slice())
        .map_err(|e| VerifyError::InvalidBlob(e.to_string()))?;
    let commitment = settings
        .blob_to_kzg_commitment(&blob)
        .map_err(|e| VerifyError::InvalidBlob(e.to_string()))?;
    let mut vh: Hash = Sha256::digest(commitment.to_bytes().as_slice()).into();
    vh[0] = 0x01;
    Ok(vh)
}

/// Unpack an update's `m` chunks from its verified blobs: local chunk `u` sits in blob
/// `⌊u/4096⌋`, field element `u mod 4096`, high byte zero, trailing elements of the
/// final blob zero. The equivalence proof already forced all of this on chain, so a
/// violation here means the blob bytes we verified are not the bytes the chain
/// committed to — a protocol-level contradiction the caller must treat as loud, not
/// as bad input to skip.
pub fn chunks_from_blobs(blobs: &[RawBlob], m: u64) -> Result<Vec<Chunk>, VerifyError> {
    let expected = (m as usize).div_ceil(4096);
    if blobs.len() != expected {
        return Err(VerifyError::BlobCountMismatch { expected, got: blobs.len() });
    }
    let mut chunks = Vec::with_capacity(m as usize);
    for (b, blob) in blobs.iter().enumerate() {
        for e in 0..4096 {
            let u = b * 4096 + e;
            let element = &blob[e * 32..(e + 1) * 32];
            if (u as u64) < m {
                if element[0] != 0 {
                    return Err(VerifyError::NonCanonicalElement { index: u });
                }
                chunks.push(Chunk::try_from(&element[1..32]).expect("31 bytes"));
            } else if element.iter().any(|&x| x != 0) {
                return Err(VerifyError::NonZeroPadding { index: u });
            }
        }
    }
    debug_assert_eq!(chunks.len() as u64, m);
    debug_assert_eq!(BLOB_BYTES, 4096 * 32);
    Ok(chunks)
}
