//! Golden-vector conformance tests: this crate vs `vectors/*.json`, value for value.
//! A failure here means the reference implementation and the vector generator disagree
//! about the normative spec — investigate which one is wrong; never "fix" a vector.

use blobsitter_reference::{
    custody_index, decompose, eip712, fs_z, fs_z_preimage, keccak256, leaf, peak_heights, root,
    testvec, verify, Chunk, Hash,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../vectors/{}", env!("CARGO_MANIFEST_DIR"), name);
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&data).unwrap()
}

fn from_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").expect("hex strings are 0x-prefixed");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hash(v: &Value) -> Hash {
    from_hex(v.as_str().unwrap()).try_into().unwrap()
}

fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array().unwrap().iter().map(hash).collect()
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Dual-anchor keccak validation (normative §1): the Ethereum empty-hash constant proves
/// we use Keccak padding; the NIST SHA3-256 constant proves the permutation machinery
/// independently. If only the SHA3 one passes, someone swapped in the wrong padding.
#[test]
fn keccak_dual_anchor() {
    assert_eq!(
        hex_of(&keccak256(b"")),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    let mut sha3 = [0u8; 32];
    {
        use tiny_keccak::{Hasher, Sha3};
        let mut h = Sha3::v256();
        h.update(b"");
        h.finalize(&mut sha3);
    }
    assert_eq!(
        hex_of(&sha3),
        "0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn keccak_sanity_vectors() {
    let v = load("keccak_sanity.json");
    assert_eq!(hex_of(&keccak256(b"")), v["keccak256_empty"].as_str().unwrap());
    assert_eq!(hex_of(&keccak256(b"abc")), v["keccak256_abc"].as_str().unwrap());
    let chunk0 = testvec::chunk(0);
    assert_eq!(hex_of(&chunk0), v["chunk_0"].as_str().unwrap());
    assert_eq!(hex_of(&leaf(&chunk0)), v["leaf_of_chunk_0"].as_str().unwrap());
}

#[test]
fn mmr_roots_vectors() {
    let v = load("mmr_roots.json");
    for case in v["cases"].as_array().unwrap() {
        let n = case["leafCount"].as_u64().unwrap();
        let mmr = testvec::build(n);
        let expected_heights: Vec<u32> = case["peakHeights"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(peak_heights(n), expected_heights, "peak heights, n={n}");
        assert_eq!(mmr.peaks(), hashes(&case["peaks"]), "peaks, n={n}");
        assert_eq!(mmr.root(), hash(&case["root"]), "root, n={n}");
        // root() as a free function must agree with the state form
        assert_eq!(root(n, &mmr.peaks()), hash(&case["root"]));
    }
}

#[test]
fn append_decomposition_vectors() {
    let v = load("append_decomposition.json");
    for case in v["cases"].as_array().unwrap() {
        let n = case["priorLeafCount"].as_u64().unwrap();
        let m = case["updateChunks"].as_u64().unwrap();
        let expected_heights: Vec<u32> = case["heights"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_u64().unwrap() as u32)
            .collect();
        let heights = decompose(n, m);
        assert_eq!(heights, expected_heights, "decompose({n},{m})");

        // Publisher side: recompute the submitted subtree roots.
        let mut subtrees = Vec::new();
        let mut pos = n;
        for &h in &heights {
            subtrees.push(testvec::subtree_root(pos, h));
            pos += 1u64 << h;
        }
        assert_eq!(subtrees, hashes(&case["newSubtreePeaks"]), "subtrees ({n},{m})");

        // Contract side: merge into the prior state; must equal leaf-by-leaf build.
        let mut mmr = testvec::build(n);
        mmr.apply_update(&subtrees, m).unwrap();
        assert_eq!(mmr.leaf_count(), n + m);
        assert_eq!(mmr.peaks(), hashes(&case["resultPeaks"]), "peaks ({n},{m})");
        assert_eq!(mmr.root(), hash(&case["resultRoot"]), "root ({n},{m})");
        assert_eq!(mmr.peaks(), testvec::build(n + m).peaks(), "batch != leaf-by-leaf");
    }
}

#[test]
fn inclusion_proof_vectors() {
    let v = load("inclusion_proofs.json");
    let n = 13;
    let peaks = testvec::build(n).peaks();
    assert_eq!(peaks, hashes(&v["peaks_for_n13"]));
    for case in v["cases"].as_array().unwrap() {
        let i = case["index"].as_u64().unwrap();
        let chunk: Chunk = from_hex(case["chunk"].as_str().unwrap()).try_into().unwrap();
        assert_eq!(chunk, testvec::chunk(i), "chunk pattern, i={i}");
        let (k, path) = testvec::prove(i, n);
        assert_eq!(k as u64, case["peakIndex"].as_u64().unwrap(), "peak index, i={i}");
        assert_eq!(path, hashes(&case["path"]), "path, i={i}");
        assert!(verify(&chunk, i, &path, n, &peaks), "valid proof rejected, i={i}");
        // A verifier that accepts wrong data would pass everything above.
        let wrong = testvec::chunk(i + 1);
        assert!(!verify(&wrong, i, &path, n, &peaks), "wrong chunk accepted, i={i}");
    }
}

#[test]
fn fs_z_vector() {
    let v = load("fs_z.json");
    let instance: [u8; 20] = from_hex(v["instance"].as_str().unwrap()).try_into().unwrap();
    let n0 = v["priorLeafCount"].as_u64().unwrap();
    let n1 = v["newLeafCount"].as_u64().unwrap();
    let vhs = hashes(&v["blobVersionedHashes"]);

    // Rebuild both peak sets from the pattern and confirm they match the file's inputs.
    let prior_peaks = testvec::build(n0).peaks();
    assert_eq!(prior_peaks, hashes(&v["priorPeaks"]));
    let mut subtrees = Vec::new();
    let mut pos = n0;
    for h in decompose(n0, n1 - n0) {
        subtrees.push(testvec::subtree_root(pos, h));
        pos += 1u64 << h;
    }
    assert_eq!(subtrees, hashes(&v["newSubtreePeaks"]));

    // Byte-exact preimage, then the reduced field element.
    let preimage = fs_z_preimage(&instance, &vhs, &prior_peaks, &subtrees, n0, n1);
    assert_eq!(hex_of(&preimage), v["preimage"].as_str().unwrap());
    let z = fs_z(&instance, &vhs, &prior_peaks, &subtrees, n0, n1);
    // The vector stores z as a minimal hex integer (no leading zeros); compare as ints.
    let z_expected = num_bigint::BigUint::parse_bytes(
        v["z"].as_str().unwrap().strip_prefix("0x").unwrap().as_bytes(),
        16,
    )
    .unwrap();
    assert_eq!(num_bigint::BigUint::from_bytes_be(&z), z_expected);
}

#[test]
fn eip712_vectors() {
    let v = load("eip712.json");

    // Typehash strings must match the file exactly, and their keccaks the recorded hashes
    // — a whitespace slip in any component would silently change every digest.
    for (s, key) in [
        (eip712::EIP712_DOMAIN_TYPE, &v["domain"]["typehashString"]),
        (eip712::DECLARATION_TYPE, &v["typehashes"]["declaration"]["string"]),
        (eip712::SET_APP_POINTER_TYPE, &v["typehashes"]["setAppPointer"]["string"]),
        (eip712::SET_SUCCESSOR_TYPE, &v["typehashes"]["setSuccessor"]["string"]),
    ] {
        assert_eq!(s, key.as_str().unwrap(), "typehash string");
    }
    assert_eq!(
        hex_of(&keccak256(eip712::DECLARATION_TYPE.as_bytes())),
        v["typehashes"]["declaration"]["hash"].as_str().unwrap()
    );
    assert_eq!(
        hex_of(&keccak256(eip712::SET_APP_POINTER_TYPE.as_bytes())),
        v["typehashes"]["setAppPointer"]["hash"].as_str().unwrap()
    );
    assert_eq!(
        hex_of(&keccak256(eip712::SET_SUCCESSOR_TYPE.as_bytes())),
        v["typehashes"]["setSuccessor"]["hash"].as_str().unwrap()
    );

    let d = &v["domain"];
    assert_eq!(d["name"].as_str().unwrap(), eip712::DOMAIN_NAME);
    assert_eq!(d["version"].as_str().unwrap(), eip712::DOMAIN_VERSION);
    let chain_id = d["chainId"].as_u64().unwrap();
    let instance: [u8; 20] = from_hex(d["verifyingContract"].as_str().unwrap()).try_into().unwrap();
    let sep = eip712::domain_separator(chain_id, &instance);
    assert_eq!(hex_of(&sep), d["separator"].as_str().unwrap(), "domain separator");

    let addr20 = |val: &Value| -> [u8; 20] { from_hex(val.as_str().unwrap()).try_into().unwrap() };

    for case in v["declarations"].as_array().unwrap() {
        let decl = eip712::Declaration {
            nonce: case["nonce"].as_u64().unwrap(),
            deadline: case["deadline"].as_u64().unwrap(),
            blob_versioned_hashes: hashes(&case["blobVersionedHashes"]),
            new_subtree_peaks: hashes(&case["newSubtreePeaks"]),
            new_leaf_count: case["newLeafCount"].as_u64().unwrap(),
            designated_carrier: addr20(&case["designatedCarrier"]),
            app_pointer: hash(&case["appPointer"]),
        };
        let sh = decl.struct_hash();
        assert_eq!(sh, hash(&case["structHash"]), "declaration struct hash");
        assert_eq!(eip712::digest(&sep, &sh), hash(&case["digest"]), "declaration digest");
    }

    let case = &v["setAppPointer"];
    let sh = eip712::SetAppPointer {
        nonce: case["nonce"].as_u64().unwrap(),
        deadline: case["deadline"].as_u64().unwrap(),
        app_pointer: hash(&case["appPointer"]),
    }
    .struct_hash();
    assert_eq!(sh, hash(&case["structHash"]), "setAppPointer struct hash");
    assert_eq!(eip712::digest(&sep, &sh), hash(&case["digest"]), "setAppPointer digest");

    let case = &v["setSuccessor"];
    let sh = eip712::SetSuccessor {
        nonce: case["nonce"].as_u64().unwrap(),
        deadline: case["deadline"].as_u64().unwrap(),
        successor: addr20(&case["successor"]),
    }
    .struct_hash();
    assert_eq!(sh, hash(&case["structHash"]), "setSuccessor struct hash");
    assert_eq!(eip712::digest(&sep, &sh), hash(&case["digest"]), "setSuccessor digest");
}

#[test]
fn custody_index_vectors() {
    let v = load("custody_indices.json");
    let instance: [u8; 20] = from_hex(v["instance"].as_str().unwrap()).try_into().unwrap();
    let seed = hash(&v["seed"]);
    let provider_id = v["providerId"].as_u64().unwrap();
    let leaf_count = v["leafCount"].as_u64().unwrap();
    let expected: Vec<u64> = v["indices_j0_to_j15"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    for (j, &want) in expected.iter().enumerate() {
        let got = custody_index(&instance, &seed, provider_id, j as u64, leaf_count);
        assert_eq!(got, want, "custody index j={j}");
    }
}
