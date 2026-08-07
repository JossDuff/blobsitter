//! Static package verification (test plan C1) — everything checkable with zero chain
//! interaction, run BEFORE a carrier spends anything: byte identity between the
//! blobs in the file and the versioned hashes the publisher signed, canonical
//! packing, and count coherence. A package that fails here is not "risky", it is
//! unsubmittable: the transaction would revert on chain and burn the carrier's gas.

use blobsitter_reference::blob;

use crate::{IntentBody, IntentPackage, BLOB_BYTES};

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    #[error("package is not valid JSON for this format: {0}")]
    Malformed(String),
    #[error("unsupported package version {0}")]
    UnsupportedVersion(u32),
    #[error("declaration must carry at least one blob")]
    NoBlobs,
    #[error(
        "count mismatch: {hashes} signed versioned hash(es), {blobs} blob(s), \
         {openings} opening(s) — all three must agree"
    )]
    CountMismatch { hashes: usize, blobs: usize, openings: usize },
    #[error("blob {index} is {len} bytes, not {BLOB_BYTES}")]
    WrongBlobLength { index: usize, len: usize },
    #[error(
        "blob {index}, field element {element}: nonzero high byte — not canonically \
         packed chunk data"
    )]
    NonCanonical { index: usize, element: usize },
    #[error(
        "blob {index} does not match its signed versioned hash: the package's bytes \
         hash to {computed}, the publisher signed {signed}"
    )]
    BlobIdentity { index: usize, computed: String, signed: String },
    #[error(
        "opening {index} carries a commitment that does not match the blob's \
         recomputed one"
    )]
    OpeningCommitment { index: usize },
    #[error("signature is {0} bytes; the wallet-accepted form is 65 (r ‖ s ‖ v)")]
    SignatureLength(usize),
    #[error("blob {index} is not a valid field-element array: {reason}")]
    InvalidBlob { index: usize, reason: String },
}

/// What static validation proves about a declaration package, with the recomputed
/// commitments handed onward (the carrier reuses them for the sidecar rather than
/// hashing twice).
#[derive(Debug)]
pub struct Validated {
    /// KZG commitment per blob, recomputed from the package's bytes.
    pub commitments: Vec<[u8; 48]>,
}

/// Statically validate a package of any kind. For non-declaration intents there is
/// nothing blob-shaped to check beyond the signature's shape.
pub fn validate(package: &IntentPackage) -> Result<Validated, ValidateError> {
    if package.signature.len() != 65 {
        return Err(ValidateError::SignatureLength(package.signature.len()));
    }
    let IntentBody::Declaration { intent, blobs, openings, .. } = &package.body else {
        return Ok(Validated { commitments: vec![] });
    };

    if blobs.is_empty() {
        return Err(ValidateError::NoBlobs);
    }
    if intent.blob_versioned_hashes.len() != blobs.len()
        || openings.len() != blobs.len()
    {
        return Err(ValidateError::CountMismatch {
            hashes: intent.blob_versioned_hashes.len(),
            blobs: blobs.len(),
            openings: openings.len(),
        });
    }

    let settings = c_kzg::ethereum_kzg_settings(0);
    let mut commitments = Vec::with_capacity(blobs.len());
    for (index, raw) in blobs.iter().enumerate() {
        if raw.len() != BLOB_BYTES {
            return Err(ValidateError::WrongBlobLength { index, len: raw.len() });
        }
        // Canonical packing: every field element's high byte is zero. (Whether the
        // TAIL past the declared chunk count is zero needs the prior leaf count —
        // chain state — and belongs to the carrier's preflight.)
        for element in 0..blob::FIELD_ELEMENTS_PER_BLOB {
            if raw[element * 32] != 0 {
                return Err(ValidateError::NonCanonical { index, element });
            }
        }
        let kzg_blob = c_kzg::Blob::from_bytes(raw)
            .map_err(|e| ValidateError::InvalidBlob { index, reason: e.to_string() })?;
        let commitment = settings
            .blob_to_kzg_commitment(&kzg_blob)
            .map_err(|e| ValidateError::InvalidBlob { index, reason: e.to_string() })?
            .to_bytes()
            .into_inner();

        // Identity: the bytes in the file ARE the bytes the publisher signed for.
        let computed = blob::versioned_hash(&commitment);
        let signed = intent.blob_versioned_hashes[index];
        if computed != signed {
            return Err(ValidateError::BlobIdentity {
                index,
                computed: format!("0x{}", hex::encode(computed)),
                signed: format!("0x{}", hex::encode(signed)),
            });
        }
        if openings[index].commitment != commitment {
            return Err(ValidateError::OpeningCommitment { index });
        }
        commitments.push(commitment);
    }
    Ok(Validated { commitments })
}
