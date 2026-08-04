//! EIP-712 typed-data hashing for publisher intents.
//!
//! The publisher never sends transactions; every publisher action is one of the three
//! typed structs below, signed and verified on-chain via ERC-1271. This module is the
//! reference form of the digests: the contract and the publisher toolchain must agree
//! with it bit-for-bit (`vectors/eip712.json`).

use crate::{keccak256, Hash};

/// Typehash strings — exact, single-line, no whitespace (the normative spec wraps them
/// across lines for display only).
pub const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
pub const DECLARATION_TYPE: &str = "Declaration(uint64 nonce,uint64 deadline,\
     bytes32[] blobVersionedHashes,bytes32[] newSubtreePeaks,uint64 newLeafCount,\
     address designatedCarrier,bytes32 appPointer)";
pub const SET_APP_POINTER_TYPE: &str =
    "SetAppPointer(uint64 nonce,uint64 deadline,bytes32 appPointer)";
pub const SET_SUCCESSOR_TYPE: &str =
    "SetSuccessor(uint64 nonce,uint64 deadline,address successor)";

/// Domain name and version; chain id + verifying contract bind instance and chain, so
/// the structs carry no explicit instance field.
pub const DOMAIN_NAME: &str = "blobsitter";
pub const DOMAIN_VERSION: &str = "1";

/// A uint64 as the 32-byte big-endian word EIP-712 encodes every atomic value as.
fn u256(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

/// A 20-byte address left-padded to a 32-byte word.
fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(a);
    out
}

/// EIP-712 array encoding: keccak of the concatenated 32-byte elements.
fn hash_array(items: &[Hash]) -> Hash {
    keccak256(&items.concat())
}

/// Domain separator for an instance deployed at `verifying_contract` on `chain_id`.
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> Hash {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&keccak256(EIP712_DOMAIN_TYPE.as_bytes()));
    buf.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
    buf.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    buf.extend_from_slice(&u256(chain_id));
    buf.extend_from_slice(&addr_word(verifying_contract));
    keccak256(&buf)
}

/// The standard `keccak256(0x1901 ‖ domainSeparator ‖ structHash)` digest the instance
/// passes to `isValidSignature`.
pub fn digest(domain_separator: &Hash, struct_hash: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain_separator);
    buf.extend_from_slice(struct_hash);
    keccak256(&buf)
}

/// `Declaration` — the signed intent behind `declareFor`.
pub struct Declaration {
    pub nonce: u64,
    pub deadline: u64,
    pub blob_versioned_hashes: Vec<Hash>,
    pub new_subtree_peaks: Vec<Hash>,
    pub new_leaf_count: u64,
    pub designated_carrier: [u8; 20],
    pub app_pointer: Hash,
}

impl Declaration {
    pub fn struct_hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&keccak256(DECLARATION_TYPE.as_bytes()));
        buf.extend_from_slice(&u256(self.nonce));
        buf.extend_from_slice(&u256(self.deadline));
        buf.extend_from_slice(&hash_array(&self.blob_versioned_hashes));
        buf.extend_from_slice(&hash_array(&self.new_subtree_peaks));
        buf.extend_from_slice(&u256(self.new_leaf_count));
        buf.extend_from_slice(&addr_word(&self.designated_carrier));
        buf.extend_from_slice(&self.app_pointer);
        keccak256(&buf)
    }
}

/// `SetAppPointer` — the signed intent that sets the protocol-inert app-layer pointer.
pub struct SetAppPointer {
    pub nonce: u64,
    pub deadline: u64,
    pub app_pointer: Hash,
}

impl SetAppPointer {
    pub fn struct_hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&keccak256(SET_APP_POINTER_TYPE.as_bytes()));
        buf.extend_from_slice(&u256(self.nonce));
        buf.extend_from_slice(&u256(self.deadline));
        buf.extend_from_slice(&self.app_pointer);
        keccak256(&buf)
    }
}

/// `SetSuccessor` — the signed intent that sets the write-once successor pointer.
pub struct SetSuccessor {
    pub nonce: u64,
    pub deadline: u64,
    pub successor: [u8; 20],
}

impl SetSuccessor {
    pub fn struct_hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&keccak256(SET_SUCCESSOR_TYPE.as_bytes()));
        buf.extend_from_slice(&u256(self.nonce));
        buf.extend_from_slice(&u256(self.deadline));
        buf.extend_from_slice(&addr_word(&self.successor));
        keccak256(&buf)
    }
}
