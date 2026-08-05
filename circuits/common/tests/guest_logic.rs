//! The guest logic against the golden vectors — natively, no zkVM. What passes here is
//! byte-for-byte the code the guests prove; the committed public values must equal the
//! vectors the contract and reference already conform to.

use blobsitter_circuits_common::{custody, equivalence, CustodyInput, CustodySample, EquivalenceInput};
use blobsitter_reference::{testvec, Hash};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../vectors/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn from_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hash(v: &Value) -> Hash {
    from_hex(v.as_str().unwrap()).try_into().unwrap()
}

fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array().unwrap().iter().map(hash).collect()
}

/// The fs_z declaration as the equivalence guest sees it: pattern chunks laid into a
/// canonical blob.
fn fs_z_input() -> EquivalenceInput {
    let fsz = load("fs_z.json");
    let n0 = fsz["priorLeafCount"].as_u64().unwrap();
    let n1 = fsz["newLeafCount"].as_u64().unwrap();
    let mut blob = vec![0u8; 4096 * 32];
    for (u, i) in (n0..n1).enumerate() {
        blob[u * 32 + 1..(u + 1) * 32].copy_from_slice(&testvec::chunk(i));
    }
    EquivalenceInput {
        instance: from_hex(fsz["instance"].as_str().unwrap()).try_into().unwrap(),
        blob_versioned_hashes: hashes(&fsz["blobVersionedHashes"]),
        prior_peaks: hashes(&fsz["priorPeaks"]),
        prior_leaf_count: n0,
        new_leaf_count: n1,
        blobs: vec![blob],
    }
}

#[test]
fn equivalence_matches_public_values_vector() {
    let want = from_hex(load("public_values.json")["equivalence"]["publicValues"].as_str().unwrap());
    assert_eq!(equivalence(&fs_z_input()), want, "guest output != golden vector");
}

#[test]
#[should_panic(expected = "blob count")]
fn equivalence_rejects_wrong_blob_count() {
    let mut input = fs_z_input();
    input.blobs.push(vec![0u8; 4096 * 32]); // one blob too many for m = 3
    equivalence(&input);
}

#[test]
#[should_panic(expected = "versioned-hash count")]
fn equivalence_rejects_wrong_versioned_hash_count() {
    let mut input = fs_z_input();
    input.blob_versioned_hashes.push([0u8; 32]);
    equivalence(&input);
}

#[test]
#[should_panic(expected = "canonical form")]
fn equivalence_rejects_noncanonical_high_byte() {
    let mut input = fs_z_input();
    input.blobs[0][0] = 1; // first element's high byte
    equivalence(&input);
}

#[test]
#[should_panic(expected = "trailing element not zero")]
fn equivalence_rejects_dirty_tail() {
    let mut input = fs_z_input();
    input.blobs[0][100 * 32 + 5] = 7; // past the 3 data elements
    equivalence(&input);
}

#[test]
fn equivalence_tampered_chunk_changes_nothing_but_everything() {
    // A tampered data byte doesn't panic — it changes the derived subtree peaks, hence
    // the preimage hash, hence the committed public values: the contract's compare
    // fails instead. Assert the commitment actually moves.
    let honest = equivalence(&fs_z_input());
    let mut input = fs_z_input();
    input.blobs[0][1] ^= 0xff; // first chunk byte
    assert_ne!(equivalence(&input), honest, "tamper must change the commitment");
}

fn custody_input(n: u64, k: u64) -> CustodyInput {
    let instance: [u8; 20] = [0x11; 20];
    let seed: Hash = blobsitter_reference::keccak256(b"guest test seed");
    let mmr = testvec::build(n);
    let peaks = mmr.peaks();
    let samples = (0..k)
        .map(|j| {
            let idx = blobsitter_reference::custody_index(&instance, &seed, 7, j, n);
            let (_, path) = testvec::prove(idx, n);
            CustodySample { chunk: testvec::chunk(idx), path }
        })
        .collect();
    CustodyInput {
        instance,
        provider_id: 7,
        seed,
        root: mmr.root(),
        leaf_count: n,
        k,
        peaks,
        samples,
    }
}

#[test]
fn custody_produces_packed_public_values() {
    let input = custody_input(50, 8);
    let pv = custody(&input);
    assert_eq!(pv.len(), 108);
    assert_eq!(
        pv,
        blobsitter_reference::public_values::custody(
            &input.instance,
            7,
            &input.seed,
            &input.root,
            50,
            8
        )
    );
}

#[test]
#[should_panic(expected = "sample count")]
fn custody_rejects_wrong_sample_count() {
    let mut input = custody_input(50, 8);
    input.samples.pop(); // 7 samples against k = 8
    custody(&input);
}

#[test]
#[should_panic(expected = "sample failed inclusion")]
fn custody_rejects_wrong_chunk() {
    let mut input = custody_input(50, 8);
    input.samples[3].chunk = testvec::chunk(999); // wrong preimage at sample 3
    custody(&input);
}

#[test]
#[should_panic(expected = "peak list != pinned root")]
fn custody_rejects_wrong_root() {
    let mut input = custody_input(50, 8);
    input.root = blobsitter_reference::keccak256(b"not the root");
    custody(&input);
}

#[test]
#[should_panic(expected = "empty snapshot")]
fn custody_rejects_empty_snapshot() {
    let mut input = custody_input(50, 8);
    input.leaf_count = 0;
    custody(&input);
}
