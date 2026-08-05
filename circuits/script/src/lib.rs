//! Witness builders and ELF plumbing shared by the script binaries.

use blobsitter_circuits_common::{CustodyInput, CustodySample, EquivalenceInput};
use blobsitter_reference::{custody_index, locate, node, peak_heights, root, testvec, Chunk, Hash};

// These paths mirror `cargo prove build`'s output layout, INCLUDING the target triple —
// which has changed across SP1 major versions before. On a toolchain bump, re-check the
// build output ("cargo:rustc-env=SP1_ELF_… " lines) and update these together.
pub const EQUIVALENCE_ELF_PATH: &str =
    "../equivalence/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/blobsitter-equivalence-guest";
pub const CUSTODY_ELF_PATH: &str =
    "../custody/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/blobsitter-custody-guest";

pub fn load_elf(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!("read {path}: {e} — build the guest first (cargo prove build)")
    })
}

/// An equivalence witness over pattern chunks: `m` chunks appended at `n0`, laid out
/// canonically into ceil(m/4096) blobs, with synthetic versioned hashes (the executor
/// measures cycles; hash binding is the contract's precompile business).
pub fn equivalence_input(n0: u64, m: u64) -> EquivalenceInput {
    let chunks: Vec<Chunk> = (n0..n0 + m).map(testvec::chunk).collect();
    let b = (m as usize).div_ceil(4096);
    let mut blobs = vec![vec![0u8; 4096 * 32]; b];
    for (u, c) in chunks.iter().enumerate() {
        let (j, e) = (u / 4096, u % 4096);
        blobs[j][e * 32 + 1..(e + 1) * 32].copy_from_slice(c);
    }
    let vhs = (0..b)
        .map(|j| {
            let mut vh = blobsitter_reference::keccak256(&(j as u64).to_be_bytes());
            vh[0] = 0x01;
            vh
        })
        .collect();
    EquivalenceInput {
        instance: [0x22; 20],
        blob_versioned_hashes: vhs,
        prior_peaks: testvec::build(n0).peaks(),
        prior_leaf_count: n0,
        new_leaf_count: n0 + m,
        blobs,
    }
}

/// Every level of every peak's perfect subtree, memoized — so a full-scale custody
/// witness (k paths over a ~million-leaf MMR) is built in seconds instead of re-hashing
/// a subtree per sample.
pub struct MemoTree {
    n: u64,
    /// peak -> levels -> nodes (level 0 = leaf hashes).
    peaks: Vec<(u64, Vec<Vec<Hash>>)>, // (start leaf, levels)
}

impl MemoTree {
    pub fn build(n: u64) -> Self {
        let mut peaks = Vec::new();
        let mut start = 0u64;
        for h in peak_heights(n) {
            let size = 1u64 << h;
            let mut levels = Vec::with_capacity(h as usize + 1);
            let leaves: Vec<Hash> = (start..start + size)
                .map(|i| blobsitter_reference::leaf(&testvec::chunk(i)))
                .collect();
            levels.push(leaves);
            for lvl in 0..h as usize {
                let prev = &levels[lvl];
                let next: Vec<Hash> =
                    prev.chunks_exact(2).map(|p| node(&p[0], &p[1])).collect();
                levels.push(next);
            }
            peaks.push((start, levels));
            start += size;
        }
        Self { n, peaks }
    }

    pub fn peaks(&self) -> Vec<Hash> {
        self.peaks.iter().map(|(_, levels)| levels.last().unwrap()[0]).collect()
    }

    pub fn root(&self) -> Hash {
        root(self.n, &self.peaks())
    }

    pub fn path(&self, i: u64) -> Vec<Hash> {
        let (k, start, h) = locate(i, self.n);
        let levels = &self.peaks[k].1;
        let mut off = (i - start) as usize;
        (0..h as usize)
            .map(|lvl| {
                let sib = levels[lvl][off ^ 1];
                off >>= 1;
                sib
            })
            .collect()
    }
}

/// A custody witness at full protocol scale (or any smaller k / n).
pub fn custody_input(n: u64, k: u64) -> CustodyInput {
    let instance = [0x22u8; 20];
    let seed = blobsitter_reference::keccak256(b"bench seed");
    let tree = MemoTree::build(n);
    let samples = (0..k)
        .map(|j| {
            let idx = custody_index(&instance, &seed, 1, j, n);
            CustodySample { chunk: testvec::chunk(idx), path: tree.path(idx) }
        })
        .collect();
    CustodyInput {
        instance,
        provider_id: 1,
        seed,
        root: tree.root(),
        leaf_count: n,
        k,
        peaks: tree.peaks(),
        samples,
    }
}
