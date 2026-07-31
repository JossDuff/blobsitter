//! Reference implementation of `spec/normative.md` §1–10.
//!
//! This crate is the authoritative executable form of the normative spec: every public
//! function cites the section it implements, and the test suite checks the crate against
//! the golden vectors in `vectors/` value-for-value. Contract, circuit, and daemon code
//! must agree with this crate; where they can't share code, they share the vectors.

use num_bigint::BigUint;
use tiny_keccak::{Hasher, Keccak};

/// Domain-separation tags (normative §2). Every keccak invocation the protocol defines
/// is prefixed with exactly one of these.
pub mod tag {
    pub const LEAF: u8 = 0x00;
    pub const NODE: u8 = 0x01;
    pub const ROOT: u8 = 0x02;
    pub const FS_Z: u8 = 0x03;
    pub const CUSTODY: u8 = 0x04;
}

/// A 31-byte chunk (normative §3): the protocol's only unit of data.
pub type Chunk = [u8; 31];
/// A 32-byte hash: leaves, nodes, peaks, roots, seeds, versioned hashes.
pub type Hash = [u8; 32];

/// BLS12-381 scalar field modulus (normative §1) — the field EIP-4844 blob polynomials
/// live in; the Fiat–Shamir point `z` is reduced into it.
pub const R_BLS_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

/// keccak-256 (normative §1) — original Keccak padding, as Ethereum's KECCAK256 opcode.
pub fn keccak256(data: &[u8]) -> Hash {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Leaf hash (normative §5.1): `H(0x00 ‖ chunk)`.
pub fn leaf(chunk: &Chunk) -> Hash {
    let mut buf = [0u8; 32];
    buf[0] = tag::LEAF;
    buf[1..].copy_from_slice(chunk);
    keccak256(&buf)
}

/// Interior node hash (normative §5.1): `H(0x01 ‖ left ‖ right)`.
/// `left` always covers the lower (older) leaf indices.
pub fn node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 65];
    buf[0] = tag::NODE;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    keccak256(&buf)
}

/// Bagged root (normative §5.3): `H(0x02 ‖ u64be(n) ‖ peaks…)`, peaks in canonical
/// (descending-height) order. Defined for the empty MMR too.
pub fn root(leaf_count: u64, peaks: &[Hash]) -> Hash {
    let mut buf = Vec::with_capacity(9 + 32 * peaks.len());
    buf.push(tag::ROOT);
    buf.extend_from_slice(&leaf_count.to_be_bytes());
    for p in peaks {
        buf.extend_from_slice(p);
    }
    keccak256(&buf)
}

/// Peak heights at leaf count `n` (normative §5.2): the set bits of `n`, tallest first.
pub fn peak_heights(n: u64) -> Vec<u32> {
    (0..64).rev().filter(|h| (n >> h) & 1 == 1).collect()
}

/// Update decomposition (normative §6.1): split `m` leaves appended after leaf count `n`
/// into the height sequence of maximal aligned perfect subtrees. Deterministic in
/// `(n, m)`; heights are never transmitted — verifiers recompute this.
pub fn decompose(n: u64, m: u64) -> Vec<u32> {
    assert!(m >= 1, "update must append at least one chunk");
    let mut heights = Vec::new();
    let mut pos = n;
    let mut remaining = m;
    while remaining > 0 {
        let h_align = if pos == 0 { 63 } else { pos.trailing_zeros() };
        let h_size = 63 - remaining.leading_zeros(); // floor(log2(remaining))
        let h = h_align.min(h_size);
        heights.push(h);
        pos += 1u64 << h;
        remaining -= 1u64 << h;
    }
    heights
}

/// The MMR state a verifier holds (normative §5): leaf count + one peak per height,
/// exactly mirroring the on-chain storage.
#[derive(Debug, Clone, Default)]
pub struct Mmr {
    /// peak per height; at most one entry per height (binary-counter invariant)
    peaks: std::collections::BTreeMap<u32, Hash>,
    leaf_count: u64,
}

impl Mmr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Peaks in canonical order: descending height = oldest leaves first (normative §5.2).
    pub fn peaks(&self) -> Vec<Hash> {
        self.peaks.iter().rev().map(|(_, p)| *p).collect()
    }

    /// Bagged root of the current state (normative §5.3).
    pub fn root(&self) -> Hash {
        root(self.leaf_count, &self.peaks())
    }

    /// Apply an update of `m` chunks given its subtree peaks in §6.1 order — the
    /// contract's merge algorithm (normative §6.2).
    pub fn apply_update(&mut self, subtree_peaks: &[Hash], m: u64) -> Result<(), &'static str> {
        let heights = decompose(self.leaf_count, m);
        if subtree_peaks.len() != heights.len() {
            return Err("subtree peak count does not match decomposition");
        }
        for (&h0, &peak) in heights.iter().zip(subtree_peaks) {
            debug_assert_eq!(self.leaf_count % (1u64 << h0), 0, "alignment invariant");
            let mut h = h0;
            let mut p = peak;
            // binary-counter carry: existing peak covers older leaves => LEFT child
            while let Some(existing) = self.peaks.remove(&h) {
                p = node(&existing, &p);
                h += 1;
            }
            self.peaks.insert(h, p);
            self.leaf_count += 1u64 << h0;
        }
        Ok(())
    }

    /// Append a single chunk (a height-0 update) — the slow, obviously-correct path
    /// that batched updates are tested against.
    pub fn append_leaf(&mut self, chunk: &Chunk) {
        self.apply_update(&[leaf(chunk)], 1).expect("single-leaf update cannot fail");
    }
}

/// Locate the peak covering leaf `i` at leaf count `n` (normative §7.1).
/// Returns `(peak_index, subtree_start_leaf, peak_height)`.
pub fn locate(i: u64, n: u64) -> (usize, u64, u32) {
    assert!(i < n, "leaf index out of range");
    let mut start = 0u64;
    for (k, h) in peak_heights(n).into_iter().enumerate() {
        if i < start + (1u64 << h) {
            return (k, start, h);
        }
        start += 1u64 << h;
    }
    unreachable!("peak_heights covers all leaves below n")
}

/// Inclusion-proof verification against stored peaks (normative §7.2) — the exact check
/// the contract runs for challenge responses and the custody escape hatch. The
/// possession-evidencing element is `chunk` itself: it is hashed before the climb.
pub fn verify(chunk: &Chunk, i: u64, path: &[Hash], n: u64, peaks: &[Hash]) -> bool {
    if i >= n {
        return false;
    }
    let (k, start, h) = locate(i, n);
    if path.len() != h as usize || peaks.len() != peak_heights(n).len() {
        return false;
    }
    let off = i - start;
    let mut acc = leaf(chunk);
    for (lvl, sib) in path.iter().enumerate() {
        acc = if (off >> lvl) & 1 == 0 { node(&acc, sib) } else { node(sib, &acc) };
    }
    acc == peaks[k]
}

/// Fiat–Shamir preimage (normative §8): `0x03 ‖ instance ‖ vh… ‖ priorPeaks… ‖
/// newSubtreePeaks… ‖ u64be(n0) ‖ u64be(n1)`.
pub fn fs_z_preimage(
    instance: &[u8; 20],
    blob_versioned_hashes: &[Hash],
    prior_peaks: &[Hash],
    new_subtree_peaks: &[Hash],
    prior_leaf_count: u64,
    new_leaf_count: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(tag::FS_Z);
    buf.extend_from_slice(instance);
    for vh in blob_versioned_hashes {
        buf.extend_from_slice(vh);
    }
    for p in prior_peaks {
        buf.extend_from_slice(p);
    }
    for p in new_subtree_peaks {
        buf.extend_from_slice(p);
    }
    buf.extend_from_slice(&prior_leaf_count.to_be_bytes());
    buf.extend_from_slice(&new_leaf_count.to_be_bytes());
    buf
}

/// Fiat–Shamir evaluation point `z` (normative §8), as a 32-byte big-endian field
/// element: `keccak(preimage) mod r`.
pub fn fs_z(
    instance: &[u8; 20],
    blob_versioned_hashes: &[Hash],
    prior_peaks: &[Hash],
    new_subtree_peaks: &[Hash],
    prior_leaf_count: u64,
    new_leaf_count: u64,
) -> Hash {
    let preimage = fs_z_preimage(
        instance,
        blob_versioned_hashes,
        prior_peaks,
        new_subtree_peaks,
        prior_leaf_count,
        new_leaf_count,
    );
    let h = BigUint::from_bytes_be(&keccak256(&preimage));
    let r = BigUint::parse_bytes(R_BLS_HEX.as_bytes(), 16).expect("valid modulus");
    let z = h % r;
    let bytes = z.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Custody sample-index derivation (normative §9):
/// `uint256(H(0x04 ‖ instance ‖ seed ‖ u64be(providerId) ‖ u64be(j))) mod leafCount`.
/// Sampling is with replacement; `j ∈ [0, 32)` is also the escape-hatch set.
pub fn custody_index(
    instance: &[u8; 20],
    seed: &Hash,
    provider_id: u64,
    j: u64,
    leaf_count: u64,
) -> u64 {
    assert!(leaf_count > 0, "cannot sample an empty dataset");
    let mut buf = Vec::with_capacity(1 + 20 + 32 + 8 + 8);
    buf.push(tag::CUSTODY);
    buf.extend_from_slice(instance);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&provider_id.to_be_bytes());
    buf.extend_from_slice(&j.to_be_bytes());
    let h = keccak256(&buf);
    // Reduce the 256-bit big-endian hash mod leaf_count by streaming bytes through a
    // u128 accumulator (remainder stays < 2^64, so (rem << 8) + byte fits in u128).
    let m = leaf_count as u128;
    let mut rem: u128 = 0;
    for &b in h.iter() {
        rem = ((rem << 8) | b as u128) % m;
    }
    rem as u64
}

/// Test-data helpers shared by the vector tests and (later) the Rust vector generator.
/// These implement the *publisher's* side: synthesizing chunks and computing the subtree
/// roots that go into declarations. Pattern per normative §10.
pub mod testvec {
    use super::*;

    /// Deterministic test chunk: byte `b` of chunk `i` is `(31·i + b) mod 256`.
    pub fn chunk(i: u64) -> Chunk {
        core::array::from_fn(|b| (31u64.wrapping_mul(i).wrapping_add(b as u64) % 256) as u8)
    }

    /// Root of the perfect subtree of height `h` over global leaves `[start, start+2^h)`.
    pub fn subtree_root(start: u64, h: u32) -> Hash {
        if h == 0 {
            return leaf(&chunk(start));
        }
        let half = 1u64 << (h - 1);
        node(&subtree_root(start, h - 1), &subtree_root(start + half, h - 1))
    }

    /// Build the MMR over the first `n` test chunks, leaf by leaf.
    pub fn build(n: u64) -> Mmr {
        let mut mmr = Mmr::new();
        for i in 0..n {
            mmr.append_leaf(&chunk(i));
        }
        mmr
    }

    /// Produce an inclusion proof for test leaf `i` at leaf count `n` (normative §7):
    /// `(peak_index, path bottom-first)`.
    pub fn prove(i: u64, n: u64) -> (usize, Vec<Hash>) {
        let (k, start, h) = locate(i, n);
        let off = i - start;
        let mut path = Vec::with_capacity(h as usize);
        for lvl in 0..h {
            let width = 1u64 << lvl;
            let sib_off = (off >> lvl) ^ 1;
            path.push(subtree_root(start + sib_off * width, lvl));
        }
        (k, path)
    }
}
