//! C1 — package integrity: a package is rejected before ANY chain interaction unless
//! it is internally coherent. These are pure offline checks (the intents crate);
//! carrier gas is real money and nothing invalid may get near a wallet.

use blobsitter_intents::{
    validate, DeclarationIntent, IntentBody, IntentPackage, Opening, ValidateError,
    PACKAGE_VERSION,
};
use blobsitter_reference::{blob, testvec, update_subtree_roots, Chunk};

/// A coherent declaration package over `m` pattern chunks (offline: junk signature
/// digest inputs are fine — C1 checks shape and identity, not chain acceptance).
fn package(m: u64) -> IntentPackage {
    let chunks: Vec<Chunk> = (0..m).map(testvec::chunk).collect();
    let blobs = blob::pack(&chunks);
    let settings = c_kzg::ethereum_kzg_settings(0);
    let mut versioned_hashes = Vec::new();
    let mut openings = Vec::new();
    for raw in &blobs {
        let commitment = settings
            .blob_to_kzg_commitment(&c_kzg::Blob::from_bytes(raw).unwrap())
            .unwrap()
            .to_bytes()
            .into_inner();
        versioned_hashes.push(blob::versioned_hash(&commitment));
        openings.push(Opening { y: [0u8; 32], commitment, kzg_proof: [0u8; 48] });
    }
    IntentPackage {
        version: PACKAGE_VERSION,
        chain_id: 1,
        instance: [0x11; 20],
        body: IntentBody::Declaration {
            intent: DeclarationIntent {
                nonce: 0,
                deadline: 2_000_000_000,
                blob_versioned_hashes: versioned_hashes,
                new_subtree_peaks: update_subtree_roots(0, &chunks),
                new_leaf_count: m,
                designated_carrier: [0u8; 20],
                app_pointer: [0u8; 32],
            },
            blobs,
            openings,
            equivalence_proof: vec![0xAA; 32],
        },
        signature: vec![0x22; 65],
    }
}

fn body_mut(
    package: &mut IntentPackage,
) -> (&mut DeclarationIntent, &mut Vec<Vec<u8>>, &mut Vec<Opening>) {
    match &mut package.body {
        IntentBody::Declaration { intent, blobs, openings, .. } => (intent, blobs, openings),
        _ => unreachable!(),
    }
}

#[test]
fn c1_coherent_package_validates_and_roundtrips() {
    let package = package(4_097);
    let validated = validate(&package).expect("coherent package");
    assert_eq!(validated.commitments.len(), 2);

    // The wire roundtrip is exact.
    let reparsed = IntentPackage::from_json(&package.to_json()).unwrap();
    validate(&reparsed).unwrap();
    assert_eq!(reparsed.signing_digest(), package.signing_digest());
}

#[test]
fn c1_corrupt_blob_is_named_by_identity() {
    let mut package = package(10);
    body_mut(&mut package).1[0][40] ^= 0x01;
    match validate(&package) {
        Err(ValidateError::BlobIdentity { index: 0, .. }) => {}
        other => panic!("expected BlobIdentity, got {other:?}"),
    }
}

#[test]
fn c1_mislabeled_hash_is_rejected() {
    let mut package = package(10);
    body_mut(&mut package).0.blob_versioned_hashes[0][31] ^= 0x01;
    assert!(matches!(validate(&package), Err(ValidateError::BlobIdentity { .. })));
}

#[test]
fn c1_count_mismatch_is_rejected() {
    let mut package_short = package(10);
    body_mut(&mut package_short).2.pop();
    assert!(matches!(validate(&package_short), Err(ValidateError::CountMismatch { .. })));

    let mut package_extra = package(10);
    body_mut(&mut package_extra).0.blob_versioned_hashes.push([0xCC; 32]);
    assert!(matches!(validate(&package_extra), Err(ValidateError::CountMismatch { .. })));
}

#[test]
fn c1_non_canonical_packing_is_rejected() {
    let mut package = package(10);
    body_mut(&mut package).1[0][0] = 0x01; // element 0 high byte
    assert!(matches!(
        validate(&package),
        Err(ValidateError::NonCanonical { index: 0, element: 0 })
    ));
}

#[test]
fn c1_wrong_blob_length_is_rejected() {
    let mut package = package(10);
    body_mut(&mut package).1[0].truncate(1_000);
    assert!(matches!(validate(&package), Err(ValidateError::WrongBlobLength { .. })));
}

#[test]
fn c1_opening_commitment_must_match_recomputed() {
    let mut package = package(10);
    body_mut(&mut package).2[0].commitment[10] ^= 0x01;
    assert!(matches!(validate(&package), Err(ValidateError::OpeningCommitment { index: 0 })));
}

#[test]
fn c1_unknown_version_and_bad_signature_shape() {
    let mut raw: serde_json::Value = serde_json::from_str(&package(1).to_json()).unwrap();
    raw["version"] = serde_json::json!(99);
    assert!(matches!(
        IntentPackage::from_json(&raw.to_string()),
        Err(ValidateError::UnsupportedVersion(99))
    ));

    let mut package = package(1);
    package.signature.pop();
    assert!(matches!(validate(&package), Err(ValidateError::SignatureLength(64))));
}
