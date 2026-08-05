//! The custody guest: everything it proves lives in blobsitter-circuits-common
//! (tested natively against the golden vectors); this wrapper only moves bytes across
//! the zkVM boundary.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: blobsitter_circuits_common::CustodyInput = sp1_zkvm::io::read();
    let public_values = blobsitter_circuits_common::custody(&input);
    sp1_zkvm::io::commit_slice(&public_values);
}
