//! FFI oracle for the forge differential fuzz test (test-plan I12).
//!
//! Usage: `mmr_oracle <leafCount>` — builds the MMR over the first `leafCount` §10
//! pattern chunks leaf by leaf and prints `abi.encode(bytes32[] peaks, bytes32 root)`
//! as 0x-prefixed hex on stdout, which `vm.ffi` hands back to Solidity as raw bytes.
//! The contract's batched-merge state must match this crate's answer exactly.

use blobsitter_reference::testvec;

fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .expect("usage: mmr_oracle <leafCount>")
        .parse()
        .expect("leafCount must be a u64");
    let mmr = testvec::build(n);
    let peaks = mmr.peaks();

    // abi.encode(bytes32[], bytes32): [offset of array = 0x40][root][array len][elems…]
    let mut out: Vec<u8> = Vec::with_capacity(96 + 32 * peaks.len());
    let word = |x: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&x.to_be_bytes());
        w
    };
    out.extend_from_slice(&word(0x40));
    out.extend_from_slice(&mmr.root());
    out.extend_from_slice(&word(peaks.len() as u64));
    for p in &peaks {
        out.extend_from_slice(p);
    }

    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    print!("0x{hex}");
}
