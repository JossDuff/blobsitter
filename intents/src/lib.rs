//! The signed-intent PACKAGE: the wire format between a publisher (who signs intents
//! and never holds ETH) and a carrier (any EOA that wraps them in transactions and
//! fronts the gas). One versioned, self-contained JSON document per intent: the
//! intent struct, the publisher's EIP-712 signature, and — for declarations — the
//! raw blobs, the per-blob KZG openings, and the equivalence proof.
//!
//! A package is UNTRUSTED input to a carrier, and carrier gas is real money, so this
//! crate also owns the static half of package verification: everything checkable
//! without a chain connection (blob↔hash identity, canonical packing, count
//! coherence). Chain-dependent checks — nonce, deadline, the Fiat–Shamir point,
//! signature acceptance — are the carrier's preflight, built on top of this.
//!
//! All hashing/encoding truth lives in `blobsitter-reference`; this crate only
//! carries bytes and converts them into the reference types at use sites.

use blobsitter_reference::{blob, eip712, Hash};
use serde::{Deserialize, Serialize};

pub mod encode;
pub mod validate;

pub use validate::{validate, Validated, ValidateError};

/// Bumped on any incompatible change to the JSON shape; readers reject unknown
/// versions rather than guessing.
pub const PACKAGE_VERSION: u32 = 1;

/// One signed intent, self-contained. `chain_id` and `instance` pin exactly where
/// this may be carried — a carrier must refuse anything aimed elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IntentPackage {
    pub version: u32,
    pub chain_id: u64,
    #[serde(with = "encode::hex20")]
    pub instance: [u8; 20],
    pub body: IntentBody,
    /// 65-byte `r ‖ s ‖ v` over the EIP-712 digest, as the publisher wallet
    /// (ERC-1271) accepts it.
    #[serde(with = "encode::hex_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum IntentBody {
    #[serde(rename_all = "camelCase")]
    Declaration {
        intent: DeclarationIntent,
        /// Raw 131072-byte blobs, in versioned-hash order.
        #[serde(with = "encode::hex_bytes_vec")]
        blobs: Vec<Vec<u8>>,
        /// One KZG opening per blob at the declaration's Fiat–Shamir point.
        openings: Vec<Opening>,
        /// The SP1 equivalence proof `declareFor` verifies.
        #[serde(with = "encode::hex_bytes")]
        equivalence_proof: Vec<u8>,
    },
    #[serde(rename_all = "camelCase")]
    SetAppPointer { intent: AppPointerIntent },
    #[serde(rename_all = "camelCase")]
    SetSuccessor { intent: SuccessorIntent },
}

/// Mirrors the contract's `Declaration` struct field for field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeclarationIntent {
    pub nonce: u64,
    pub deadline: u64,
    #[serde(with = "encode::hex_hashes")]
    pub blob_versioned_hashes: Vec<Hash>,
    #[serde(with = "encode::hex_hashes")]
    pub new_subtree_peaks: Vec<Hash>,
    pub new_leaf_count: u64,
    #[serde(with = "encode::hex20")]
    pub designated_carrier: [u8; 20],
    #[serde(with = "encode::hex_hash")]
    pub app_pointer: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppPointerIntent {
    pub nonce: u64,
    pub deadline: u64,
    #[serde(with = "encode::hex_hash")]
    pub pointer: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SuccessorIntent {
    pub nonce: u64,
    pub deadline: u64,
    #[serde(with = "encode::hex20")]
    pub target: [u8; 20],
}

/// One blob's KZG opening at the declaration's evaluation point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Opening {
    #[serde(with = "encode::hex_hash")]
    pub y: Hash,
    #[serde(with = "encode::hex48")]
    pub commitment: [u8; 48],
    #[serde(with = "encode::hex48")]
    pub kzg_proof: [u8; 48],
}

impl IntentPackage {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("packages always serialize")
    }

    pub fn from_json(raw: &str) -> Result<Self, ValidateError> {
        let package: IntentPackage =
            serde_json::from_str(raw).map_err(|e| ValidateError::Malformed(e.to_string()))?;
        if package.version != PACKAGE_VERSION {
            return Err(ValidateError::UnsupportedVersion(package.version));
        }
        Ok(package)
    }

    /// The EIP-712 digest the publisher signed — recomputed from the package's own
    /// fields via the reference implementation, never carried in the file.
    pub fn signing_digest(&self) -> Hash {
        let domain = eip712::domain_separator(self.chain_id, &self.instance);
        let struct_hash = match &self.body {
            IntentBody::Declaration { intent, .. } => eip712::Declaration {
                nonce: intent.nonce,
                deadline: intent.deadline,
                blob_versioned_hashes: intent.blob_versioned_hashes.clone(),
                new_subtree_peaks: intent.new_subtree_peaks.clone(),
                new_leaf_count: intent.new_leaf_count,
                designated_carrier: intent.designated_carrier,
                app_pointer: intent.app_pointer,
            }
            .struct_hash(),
            IntentBody::SetAppPointer { intent } => eip712::SetAppPointer {
                nonce: intent.nonce,
                deadline: intent.deadline,
                app_pointer: intent.pointer,
            }
            .struct_hash(),
            IntentBody::SetSuccessor { intent } => eip712::SetSuccessor {
                nonce: intent.nonce,
                deadline: intent.deadline,
                successor: intent.target,
            }
            .struct_hash(),
        };
        eip712::digest(&domain, &struct_hash)
    }

    /// The intent's deadline (every kind has one).
    pub fn deadline(&self) -> u64 {
        match &self.body {
            IntentBody::Declaration { intent, .. } => intent.deadline,
            IntentBody::SetAppPointer { intent } => intent.deadline,
            IntentBody::SetSuccessor { intent } => intent.deadline,
        }
    }
}

/// Sanity guard used by validation: one blob is exactly this many bytes.
pub const BLOB_BYTES: usize = blob::BLOB_BYTES;
