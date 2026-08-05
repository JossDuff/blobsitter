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

/// The fork-replayable witness pair, derived from the genesis KZG fixture so the
/// proofs bind exactly the declaration and custody state the fork test replays:
/// the genesis equivalence (n₀ = 0, m = 8, the REAL versioned hash from the fixture)
/// and a full-k custody proof over the resulting n = 8 state at a fixed seed.
pub fn fixture_inputs(genesis_fixture_path: &str) -> (EquivalenceInput, CustodyInput) {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(genesis_fixture_path).unwrap()).unwrap();
    let unhex = |s: &str| -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let instance: [u8; 20] = unhex(json["instance"].as_str().unwrap()).try_into().unwrap();
    let vh: Hash = unhex(json["blobVersionedHashes"][0].as_str().unwrap()).try_into().unwrap();
    let n1 = json["newLeafCount"].as_u64().unwrap();
    assert_eq!(json["priorLeafCount"].as_u64().unwrap(), 0, "genesis fixture expected");

    let chunks: Vec<Chunk> = (0..n1).map(testvec::chunk).collect();
    let mut blob = vec![0u8; 4096 * 32];
    for (u, c) in chunks.iter().enumerate() {
        blob[u * 32 + 1..(u + 1) * 32].copy_from_slice(c);
    }
    let equivalence = EquivalenceInput {
        instance,
        blob_versioned_hashes: vec![vh],
        prior_peaks: vec![],
        prior_leaf_count: 0,
        new_leaf_count: n1,
        blobs: vec![blob],
    };

    // Custody over the post-genesis state, at the seed the fork test replays via
    // vm.prevrandao. Full protocol k; sampling with replacement over 8 leaves is valid.
    let seed = blobsitter_reference::keccak256(b"fork custody seed");
    let tree = MemoTree::build(n1);
    let samples = (0..16_384u64)
        .map(|j| {
            let idx = custody_index(&instance, &seed, 1, j, n1);
            CustodySample { chunk: testvec::chunk(idx), path: tree.path(idx) }
        })
        .collect();
    let custody = CustodyInput {
        instance,
        provider_id: 1,
        seed,
        root: tree.root(),
        leaf_count: n1,
        k: 16_384,
        peaks: tree.peaks(),
        samples,
    };
    (equivalence, custody)
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
