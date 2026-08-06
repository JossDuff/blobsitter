//! D1 — store integrity: flat file, chunk `i` at offset `31·i`, append-only; after any
//! declaration sequence the locally recomputed `(peaks, Root, leafCount)` equal the
//! chain's expectation.

mod common;

use blobsitter_reference::{testvec, Mmr};
use common::*;
use serde_json::Value;

fn transcript() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/ingest_transcript.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hash_of(v: &Value) -> [u8; 32] {
    let bytes = hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
    bytes.try_into().unwrap()
}

/// Drive the full pipeline through the golden transcript — blobs constructed from the
/// vector's chunk pattern, frontier checked against the vector after every commit.
#[tokio::test]
async fn d1_transcript_vector_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let v = transcript();
    let steps = v["steps"].as_array().unwrap();

    let declarations: Vec<_> = steps
        .iter()
        .map(|s| {
            declaration(
                s["nonce"].as_u64().unwrap(),
                s["priorLeafCount"].as_u64().unwrap(),
                s["updateChunks"].as_u64().unwrap(),
            )
        })
        .collect();
    let mut rig = rig_serving(dir.path(), &declarations);

    for (step, (event, blobs)) in steps.iter().zip(&declarations) {
        // The vector must agree with the reference computation the event was built from.
        let expected_subtrees: Vec<_> =
            step["newSubtreePeaks"].as_array().unwrap().iter().map(hash_of).collect();
        assert_eq!(event.new_subtree_peaks, expected_subtrees, "event vs vector subtree roots");
        assert_eq!(blobs.len() as u64, step["blobCount"].as_u64().unwrap());

        assert!(rig.ingestor.ingest(event).await.unwrap());

        let f = rig.ingestor.store().frontier();
        assert_eq!(f.nonce, event.nonce + 1);
        assert_eq!(f.leaf_count, step["newLeafCount"].as_u64().unwrap());
        let expected_peaks: Vec<_> =
            step["resultPeaks"].as_array().unwrap().iter().map(hash_of).collect();
        assert_eq!(f.peaks, expected_peaks, "peaks after nonce {}", event.nonce);
        assert_eq!(rig.ingestor.store().mmr().root(), hash_of(&step["resultRoot"]));
    }
    assert!(rig.alarm.entries().is_empty(), "clean transcript must not alarm");
}

/// Chunk `i` readable at exactly offset `31·i`: check the raw file bytes, not just the
/// store's own read path.
#[tokio::test]
async fn d1_flat_file_layout() {
    let dir = tempfile::tempdir().unwrap();
    let declarations = vec![declaration(0, 0, 5), declaration(1, 5, 8)];
    let mut rig = rig_serving(dir.path(), &declarations);
    for (event, _) in &declarations {
        rig.ingestor.ingest(event).await.unwrap();
    }

    let raw = std::fs::read(dir.path().join("chunks.dat")).unwrap();
    assert_eq!(raw.len(), 13 * 31, "file holds exactly the committed chunks");
    for i in 0..13u64 {
        let expected = testvec::chunk(i);
        assert_eq!(&raw[(i as usize) * 31..(i as usize + 1) * 31], expected.as_slice());
        assert_eq!(rig.ingestor.store().chunk(i).unwrap(), expected);
    }
    assert!(rig.ingestor.store().chunk(13).is_err(), "reads are bounded by the frontier");
}

/// A declaration whose two blobs are byte-identical (legal opaque data) carries the
/// same versioned hash twice; one verified blob must serve both copies and the store
/// must commit all 8192 chunks.
#[tokio::test]
async fn d1_duplicate_blob_declaration() {
    use blobsitter_daemon::ingest::DeclaredEvent;
    use blobsitter_daemon::verify;
    use blobsitter_reference::update_subtree_roots;

    let dir = tempfile::tempdir().unwrap();
    let chunks: Vec<_> =
        (0..4096).map(testvec::chunk).chain((0..4096).map(testvec::chunk)).collect();
    let blobs = pack_blobs(&chunks);
    assert_eq!(blobs[0], blobs[1], "identical content must produce identical blobs");
    let vh = verify::versioned_hash(&blobs[0]).unwrap();

    let event = DeclaredEvent {
        nonce: 0,
        new_leaf_count: 8192,
        blob_versioned_hashes: vec![vh, vh],
        new_subtree_peaks: update_subtree_roots(0, &chunks),
        block_number: 1_000,
        block_timestamp: 1_700_000_000,
    };
    let mut r = rig(
        dir.path(),
        vec![Box::new(MockSource::serving("primary", [(vh, blobs[0].clone())]))],
    );
    assert!(r.ingestor.ingest(&event).await.unwrap());
    let store = r.ingestor.store();
    assert_eq!(store.frontier().leaf_count, 8192);
    assert_eq!(store.chunk(4096 + 7).unwrap(), testvec::chunk(7), "second copy readable");
    assert!(r.alarm.criticals().is_empty());
}

/// Random declaration shapes (m, blob count, partial final blobs): the batched ingest
/// path must land on exactly the state of the obviously-correct leaf-by-leaf build.
#[tokio::test]
async fn d1_random_shapes_fuzz() {
    // xorshift64*: deterministic, dependency-free; reseed here only deliberately.
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let dir = tempfile::tempdir().unwrap();
    let mut declarations = Vec::new();
    let mut n0 = 0u64;
    for nonce in 0..12 {
        // Sizes biased small for speed but crossing every shape class: single chunks,
        // misaligned tails, full blobs, and multi-blob with a partial final.
        let m = match next() % 5 {
            0 => 1,
            1 => 1 + next() % 60,
            2 => 4096,
            3 => 4000 + next() % 200,
            _ => 4097 + next() % 100,
        };
        declarations.push(declaration(nonce, n0, m));
        n0 += m;
    }

    let mut rig = rig_serving(dir.path(), &declarations);
    for (event, _) in &declarations {
        rig.ingestor.ingest(event).await.unwrap();
    }

    let mut slow = Mmr::new();
    for i in 0..n0 {
        slow.append_leaf(&testvec::chunk(i));
    }
    let store = rig.ingestor.store();
    assert_eq!(store.frontier().leaf_count, n0);
    assert_eq!(store.frontier().peaks, slow.peaks());
    assert_eq!(store.mmr().root(), slow.root());
    for _ in 0..64 {
        let i = next() % n0;
        assert_eq!(store.chunk(i).unwrap(), testvec::chunk(i), "chunk {i}");
    }
}
