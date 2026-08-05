//! The guest logic of both circuits, as plain host-buildable Rust. The SP1 guest
//! binaries are thin wrappers: read the input, call the function here, commit the
//! returned public values. Everything a guest asserts lives in this crate, so the
//! native test suite (run against the golden vectors, no zkVM involved) exercises the
//! exact code that gets proven.
//!
//! Every assertion is a plain panic: inside the zkVM a panic makes the execution — and
//! therefore any proof — impossible, which is precisely the statement "no witness".

use blobsitter_reference::{
    blob, custody_index, fs_z_preimage, keccak256, public_values, root, update_subtree_roots,
    verify, Chunk, Hash,
};
use serde::{Deserialize, Serialize};

pub const FIELD_ELEMENTS_PER_BLOB: usize = blob::FIELD_ELEMENTS_PER_BLOB;
pub const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * 32;

/// Witness + bound quantities for one declaration. The subtree peaks are deliberately
/// NOT an input: the guest derives them from the blob bytes — that derivation is the
/// content half of the statement.
#[derive(Serialize, Deserialize)]
pub struct EquivalenceInput {
    pub instance: [u8; 20],
    pub blob_versioned_hashes: Vec<Hash>,
    pub prior_peaks: Vec<Hash>,
    pub prior_leaf_count: u64,
    pub new_leaf_count: u64,
    /// Raw blob bytes, 131_072 each, transaction blob order.
    pub blobs: Vec<Vec<u8>>,
}

/// Prove one declaration: the blobs are canonical, their chunks produce exactly the
/// declared subtree peaks, and each blob evaluates at the Fiat–Shamir point to the
/// y the contract's precompile check pinned. Returns the committed public values:
/// `H(z-preimage) ‖ y_0 ‖ … ‖ y_{B-1}`.
pub fn equivalence(input: &EquivalenceInput) -> Vec<u8> {
    assert!(input.new_leaf_count > input.prior_leaf_count, "empty update");
    let m = (input.new_leaf_count - input.prior_leaf_count) as usize;
    let b = m.div_ceil(FIELD_ELEMENTS_PER_BLOB);
    assert_eq!(input.blobs.len(), b, "blob count");
    assert_eq!(input.blob_versioned_hashes.len(), b, "versioned-hash count");

    // Canonical form: byte 0 of every element zero; data elements carry the chunks
    // with no gaps; every element past the data is fully zero.
    let mut chunks: Vec<Chunk> = Vec::with_capacity(m);
    for (j, blob_bytes) in input.blobs.iter().enumerate() {
        assert_eq!(blob_bytes.len(), BYTES_PER_BLOB, "blob size");
        for e in 0..FIELD_ELEMENTS_PER_BLOB {
            let el = &blob_bytes[e * 32..(e + 1) * 32];
            let local = j * FIELD_ELEMENTS_PER_BLOB + e;
            if local < m {
                assert_eq!(el[0], 0, "canonical form: high byte");
                chunks.push(el[1..32].try_into().unwrap());
            } else {
                assert!(el.iter().all(|&x| x == 0), "trailing element not zero");
            }
        }
    }

    // Content: the chunks, appended at the prior count, must reproduce the declared
    // subtree peaks under the deterministic decomposition.
    let subtrees = update_subtree_roots(input.prior_leaf_count, &chunks);

    // The Fiat–Shamir preimage binds everything; its hash IS the first public word,
    // and z is its reduction into Fr.
    let preimage = fs_z_preimage(
        &input.instance,
        &input.blob_versioned_hashes,
        &input.prior_peaks,
        &subtrees,
        input.prior_leaf_count,
        input.new_leaf_count,
    );
    let preimage_hash = keccak256(&preimage);
    let z = blobsitter_reference::fs_z(
        &input.instance,
        &input.blob_versioned_hashes,
        &input.prior_peaks,
        &subtrees,
        input.prior_leaf_count,
        input.new_leaf_count,
    );

    // Evaluation: each blob, in evaluation form over the bit-reversed domain, at z.
    let mut ys: Vec<Hash> = Vec::with_capacity(b);
    for blob_bytes in &input.blobs {
        let elements: Vec<[u8; 32]> = blob_bytes.chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
        ys.push(blob::barycentric_eval(&elements, &z));
    }

    public_values::equivalence(&preimage_hash, &ys)
}

/// One custody sample: the raw chunk and its sibling path against the pinned state.
#[derive(Serialize, Deserialize)]
pub struct CustodySample {
    pub chunk: Chunk,
    pub path: Vec<Hash>,
}

/// Witness + bound quantities for one custody proof.
#[derive(Serialize, Deserialize)]
pub struct CustodyInput {
    pub instance: [u8; 20],
    pub provider_id: u64,
    pub seed: Hash,
    pub root: Hash,
    pub leaf_count: u64,
    pub k: u64,
    /// Canonical peak list; re-bagged against `root`.
    pub peaks: Vec<Hash>,
    /// Exactly k samples; sample j must sit at the contract-derived index for j.
    pub samples: Vec<CustodySample>,
}

/// Prove one custody period: the peak list bags to the pinned root, and for every
/// ordinal the sampled chunk verifies at the derived index. Returns the committed
/// packed public values.
pub fn custody(input: &CustodyInput) -> Vec<u8> {
    assert!(input.leaf_count > 0, "empty snapshot admits no witness");
    assert_eq!(root(input.leaf_count, &input.peaks), input.root, "peak list != pinned root");
    assert_eq!(input.samples.len(), input.k as usize, "sample count");

    for (j, sample) in input.samples.iter().enumerate() {
        let idx = custody_index(
            &input.instance,
            &input.seed,
            input.provider_id,
            j as u64,
            input.leaf_count,
        );
        assert!(
            verify(&sample.chunk, idx, &sample.path, input.leaf_count, &input.peaks),
            "sample failed inclusion"
        );
    }

    public_values::custody(
        &input.instance,
        input.provider_id,
        &input.seed,
        &input.root,
        input.leaf_count,
        input.k,
    )
}
