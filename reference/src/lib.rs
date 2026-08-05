//! Reference implementation of the normative spec (`spec/normative.md`): the protocol's
//! hashing rules, MMR commitment structure, update decomposition, inclusion proofs,
//! Fiat–Shamir evaluation point, custody sampling, and the EIP-712 digests.
//!
//! This crate is the authoritative executable form of that spec, and the test suite checks
//! the crate against the golden vectors in `vectors/` value-for-value. Contract, circuit,
//! and daemon code must agree with this crate; where they can't share code, they share the
//! vectors.

use num_bigint::BigUint;
use tiny_keccak::{Hasher, Keccak};

pub mod eip712;

/// Domain-separation tags. Every keccak invocation the protocol defines is prefixed with
/// exactly one of these, so a hash computed in one context can never be replayed in, or
/// forged from, another.
pub mod tag {
    pub const LEAF: u8 = 0x00;
    pub const NODE: u8 = 0x01;
    pub const ROOT: u8 = 0x02;
    pub const FS_Z: u8 = 0x03;
    pub const CUSTODY: u8 = 0x04;
}

/// A 31-byte chunk: the protocol's only unit of data (one chunk fills one blob field
/// element, with a zero high byte keeping it below the BLS modulus).
pub type Chunk = [u8; 31];
/// A 32-byte hash: leaves, nodes, peaks, roots, seeds, versioned hashes.
pub type Hash = [u8; 32];

/// BLS12-381 scalar field modulus — the field EIP-4844 blob polynomials live in; the
/// Fiat–Shamir point `z` is reduced into it.
pub const R_BLS_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

/// keccak-256 with original Keccak padding, exactly Ethereum's KECCAK256 opcode — not
/// NIST SHA-3, which differs in a single padding byte and would change every hash.
pub fn keccak256(data: &[u8]) -> Hash {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Hash a 31-byte chunk into a leaf: `H(0x00 ‖ chunk)`. Leaf and interior-node hashes
/// use different domain tags so one can never be forged from the other.
pub fn leaf(chunk: &Chunk) -> Hash {
    let mut buf = [0u8; 32];
    buf[0] = tag::LEAF;
    buf[1..].copy_from_slice(chunk);
    keccak256(&buf)
}

/// Interior node hash: `H(0x01 ‖ left ‖ right)`.
/// `left` always covers the lower (older) leaf indices.
pub fn node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 65];
    buf[0] = tag::NODE;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    keccak256(&buf)
}

/// Bagged root: `H(0x02 ‖ u64be(n) ‖ peaks…)`, peaks in canonical (descending-height)
/// order. Hashing the leaf count in pins the full structure, and gives the empty MMR
/// (n = 0, no peaks) a well-defined root too.
pub fn root(leaf_count: u64, peaks: &[Hash]) -> Hash {
    let mut buf = Vec::with_capacity(9 + 32 * peaks.len());
    buf.push(tag::ROOT);
    buf.extend_from_slice(&leaf_count.to_be_bytes());
    for p in peaks {
        buf.extend_from_slice(p);
    }
    keccak256(&buf)
}

/// Peak heights at leaf count `n`: the set bits of `n`, tallest first. The peak forest
/// behaves like a binary counter, so a peak of height `h` exists exactly when bit `h`
/// of `n` is set.
pub fn peak_heights(n: u64) -> Vec<u32> {
    (0..64).rev().filter(|h| (n >> h) & 1 == 1).collect()
}

/// Update decomposition: split `m` leaves appended after leaf count `n` into the height
/// sequence of maximal aligned perfect subtrees (a subtree of height `h` may only start
/// at a leaf index divisible by 2^h). Deterministic in `(n, m)`; heights are never
/// transmitted — verifiers recompute this, so a publisher cannot lie about structure.
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

/// The MMR state a verifier holds: leaf count + one peak per height, exactly mirroring
/// the on-chain storage.
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

    /// Peaks in canonical order: descending height, which equals oldest leaves first.
    pub fn peaks(&self) -> Vec<Hash> {
        self.peaks.iter().rev().map(|(_, p)| *p).collect()
    }

    /// Bagged root of the current state.
    pub fn root(&self) -> Hash {
        root(self.leaf_count, &self.peaks())
    }

    /// Apply an update of `m` chunks given its subtree peaks in [`decompose`] order —
    /// the contract's merge algorithm: while a peak of the incoming height already
    /// exists, merge the two and carry the result up one height, then insert.
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

/// Locate the peak covering leaf `i` at leaf count `n`, walking the peaks tallest-first
/// and accumulating how many leaves each covers.
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

/// Inclusion-proof verification against stored peaks — the exact check the contract
/// runs for challenge responses and the custody escape hatch. The
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

/// Fiat–Shamir preimage for the blob evaluation point: `0x03 ‖ instance ‖ vh… ‖
/// priorPeaks… ‖ newSubtreePeaks… ‖ u64be(n0) ‖ u64be(n1)`. Binding the instance
/// address and the full state transition makes `z` specific to this exact declaration.
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

/// Fiat–Shamir evaluation point `z`, as a 32-byte big-endian field element:
/// `keccak(preimage) mod r`, reduced into the BLS12-381 scalar field so it is a valid
/// blob-polynomial evaluation point.
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

/// Custody sample-index derivation:
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

/// Root of a perfect subtree over an arbitrary (power-of-two-length) chunk slice —
/// the publisher/circuit side of an update: real data, not the test pattern.
pub fn chunk_subtree_root(chunks: &[Chunk]) -> Hash {
    assert!(chunks.len().is_power_of_two(), "perfect subtrees only");
    if chunks.len() == 1 {
        return leaf(&chunks[0]);
    }
    let half = chunks.len() / 2;
    node(&chunk_subtree_root(&chunks[..half]), &chunk_subtree_root(&chunks[half..]))
}

/// The declared subtree peaks for an update of `chunks` appended at prior leaf count
/// `n0`: the decomposition's heights, each subtree hashed over its slice of the data.
/// This is what the equivalence circuit must reproduce from the blob bytes.
pub fn update_subtree_roots(n0: u64, chunks: &[Chunk]) -> Vec<Hash> {
    let heights = decompose(n0, chunks.len() as u64);
    let mut out = Vec::with_capacity(heights.len());
    let mut off = 0usize;
    for h in heights {
        let size = 1usize << h;
        out.push(chunk_subtree_root(&chunks[off..off + size]));
        off += size;
    }
    debug_assert_eq!(off, chunks.len());
    out
}

/// EIP-4844 blob evaluation (used by the equivalence circuit). A blob stores a
/// polynomial by its evaluations over the 4096 roots of unity in Fr, in bit-reversed
/// order; `barycentric_eval` evaluates it at an arbitrary point without ever forming
/// coefficients: y = (z^4096 − 1)/4096 · Σ eᵢ·wᵢ/(z − wᵢ).
pub mod blob {
    use super::{BigUint, Chunk};

    pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

    fn modulus() -> BigUint {
        BigUint::parse_bytes(super::R_BLS_HEX.as_bytes(), 16).expect("valid modulus")
    }

    /// The canonical blob for local chunks of an update (single blob): byte 0 zero,
    /// bytes 1..31 the chunk, zero elements beyond the data.
    pub fn elements_from_chunks(chunks: &[Chunk]) -> Vec<[u8; 32]> {
        assert!(chunks.len() <= FIELD_ELEMENTS_PER_BLOB);
        let mut out = vec![[0u8; 32]; FIELD_ELEMENTS_PER_BLOB];
        for (i, c) in chunks.iter().enumerate() {
            out[i][1..].copy_from_slice(c);
        }
        out
    }

    /// The bit-reversed evaluation domain: 7 generates Fr*, so 7^((r−1)/4096) generates
    /// the 4096th roots of unity; the consensus spec stores blobs over the bit-reversed
    /// permutation of that subgroup.
    pub fn bit_reversed_domain() -> Vec<BigUint> {
        let r = modulus();
        let root = BigUint::from(7u32).modpow(&((&r - 1u32) / 4096u32), &r);
        let mut powers = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
        let mut acc = BigUint::from(1u32);
        for _ in 0..FIELD_ELEMENTS_PER_BLOB {
            powers.push(acc.clone());
            acc = acc * &root % &r;
        }
        (0..FIELD_ELEMENTS_PER_BLOB)
            .map(|i| powers[(i as u16).reverse_bits() as usize >> 4].clone())
            .collect()
    }

    /// The slow, dependency-light num-bigint implementation — kept as a cross-check
    /// backend (the production path below must agree with it byte-for-byte; tests and
    /// the c-kzg/Python triangulation enforce that).
    pub fn barycentric_eval_bigint(elements: &[[u8; 32]], z: &[u8; 32]) -> [u8; 32] {
        assert_eq!(elements.len(), FIELD_ELEMENTS_PER_BLOB);
        let r = modulus();
        let z = BigUint::from_bytes_be(z) % &r;
        let domain = bit_reversed_domain();
        let els: Vec<BigUint> = elements.iter().map(|e| BigUint::from_bytes_be(e)).collect();

        // z on the domain: the evaluation is stored directly.
        if let Some(i) = domain.iter().position(|w| *w == z) {
            return to32(&els[i]);
        }

        // Montgomery batch inversion: invert all 4096 denominators (and the width)
        // with a SINGLE Fermat inversion — per-term inversions would each cost a full
        // modpow, which dominates guest cycle counts.
        let mut denoms: Vec<BigUint> =
            domain.iter().map(|w| (&r + &z - w) % &r).collect();
        denoms.push(BigUint::from(4096u32));
        let mut prefix = Vec::with_capacity(denoms.len() + 1);
        prefix.push(BigUint::from(1u32));
        for d in &denoms {
            let last = prefix.last().unwrap() * d % &r;
            prefix.push(last);
        }
        let two = BigUint::from(2u32);
        let mut inv_all = prefix.last().unwrap().modpow(&(&r - &two), &r);
        let mut invs = vec![BigUint::from(0u32); denoms.len()];
        for i in (0..denoms.len()).rev() {
            invs[i] = &prefix[i] * &inv_all % &r;
            inv_all = inv_all * &denoms[i] % &r;
        }
        let inv_width = invs.pop().unwrap();

        let mut acc = BigUint::from(0u32);
        for ((e, w), d_inv) in els.iter().zip(domain.iter()).zip(invs.iter()) {
            acc = (acc + e * w % &r * d_inv) % &r;
        }
        let z_pow = z.modpow(&BigUint::from(4096u32), &r);
        let factor = (&r + &z_pow - 1u32) % &r * inv_width % &r;
        to32(&(acc * factor % &r))
    }

    /// Evaluate a blob at `z` (32-byte big-endian field element), returning y
    /// likewise. Production backend: `bls12_381::Scalar` — the crate whose SP1 patch
    /// accelerates this exact arithmetic in-guest. Its multiplicative generator is 7,
    /// so `ROOT_OF_UNITY^(2^20)` is precisely the consensus spec's
    /// `7^((r−1)/4096)` — the same domain as the bigint/Python/c-kzg legs.
    pub fn barycentric_eval(elements: &[[u8; 32]], z: &[u8; 32]) -> [u8; 32] {
        use bls12_381::Scalar;
        assert_eq!(elements.len(), FIELD_ELEMENTS_PER_BLOB);

        let from_be = |b: &[u8; 32]| -> Scalar {
            let mut le = *b;
            le.reverse();
            Option::<Scalar>::from(Scalar::from_bytes(&le))
                .expect("input is a canonical field element")
        };
        let to_be = |s: &Scalar| -> [u8; 32] {
            let mut b = s.to_bytes();
            b.reverse();
            b
        };

        let z = from_be(z);
        let els: Vec<Scalar> = elements.iter().map(|e| from_be(e)).collect();

        // The bit-reversed evaluation domain over the 4096th roots of unity:
        // w = 7^((r−1)/4096), the consensus spec's derivation (7 generates Fr*).
        // The exponent's little-endian limbs are (r−1) >> 12; the subgroup facts
        // (w^4096 = 1, w^2048 ≠ 1) are asserted by the cross-check tests.
        let w = Scalar::from(7u64).pow(&[
            0xbfef_ffff_fff0_0000,
            0x8055_3bda_402f_ffe5,
            0xd483_339d_8080_9a1d,
            0x0007_3eda_7532_99d7,
        ]);
        let mut powers = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
        let mut acc = Scalar::one();
        for _ in 0..FIELD_ELEMENTS_PER_BLOB {
            powers.push(acc);
            acc *= w;
        }
        let domain: Vec<Scalar> = (0..FIELD_ELEMENTS_PER_BLOB)
            .map(|i| powers[(i as u16).reverse_bits() as usize >> 4])
            .collect();

        // z on the domain: the evaluation is stored directly.
        if let Some(i) = domain.iter().position(|wi| *wi == z) {
            return to_be(&els[i]);
        }

        // Montgomery batch inversion: one field inversion for all denominators + width.
        let mut denoms: Vec<Scalar> = domain.iter().map(|wi| z - wi).collect();
        denoms.push(Scalar::from(4096u64));
        let mut prefix = Vec::with_capacity(denoms.len() + 1);
        prefix.push(Scalar::one());
        for d in &denoms {
            let last = *prefix.last().unwrap() * d;
            prefix.push(last);
        }
        let mut inv_all = Option::<Scalar>::from(prefix.last().unwrap().invert())
            .expect("nonzero: z is off-domain and the width is nonzero");
        let mut invs = vec![Scalar::zero(); denoms.len()];
        for i in (0..denoms.len()).rev() {
            invs[i] = prefix[i] * inv_all;
            inv_all *= denoms[i];
        }
        let inv_width = invs.pop().unwrap();

        let mut sum = Scalar::zero();
        for ((e, wi), d_inv) in els.iter().zip(domain.iter()).zip(invs.iter()) {
            sum += *e * wi * d_inv;
        }
        let z_pow = z.pow(&[4096, 0, 0, 0]);
        to_be(&(sum * (z_pow - Scalar::one()) * inv_width))
    }

    fn to32(x: &BigUint) -> [u8; 32] {
        let b = x.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        out
    }
}

/// Circuit public-value encodings (normative §14): fixed-width big-endian
/// concatenation, no length prefixes. What the guests commit and the contract compares.
pub mod public_values {
    use super::Hash;

    /// Equivalence: `H(z-preimage) ‖ y_0 ‖ … ‖ y_{B-1}`.
    pub fn equivalence(preimage_hash: &Hash, ys: &[Hash]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 * ys.len());
        out.extend_from_slice(preimage_hash);
        for y in ys {
            out.extend_from_slice(y);
        }
        out
    }

    /// Custody: `A ‖ u64be(providerId) ‖ seed ‖ root ‖ u64be(leafCount) ‖ u64be(k)`.
    pub fn custody(
        instance: &[u8; 20],
        provider_id: u64,
        seed: &Hash,
        root: &Hash,
        leaf_count: u64,
        k: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(108);
        out.extend_from_slice(instance);
        out.extend_from_slice(&provider_id.to_be_bytes());
        out.extend_from_slice(seed);
        out.extend_from_slice(root);
        out.extend_from_slice(&leaf_count.to_be_bytes());
        out.extend_from_slice(&k.to_be_bytes());
        out
    }
}

/// Test-data helpers shared by the vector tests and (later) the Rust vector generator.
/// These implement the *publisher's* side: synthesizing chunks and computing the subtree
/// roots that go into declarations. The chunk pattern is fixed by the normative spec so
/// every implementation can synthesize identical test data without shipping it.
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

    /// Produce an inclusion proof for test leaf `i` at leaf count `n`: the covering
    /// peak's index plus the sibling hashes from the leaf up, bottom level first.
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
