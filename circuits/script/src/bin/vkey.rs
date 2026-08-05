//! Print both guests' verifying keys. Derived locally (no proving, no wrap-artifact
//! download); PROVISIONAL until freeze — vkeys change with every toolchain or guest
//! change, which is exactly why the freeze policy pins one release forever.

use blobsitter_circuits_script as script;
use sp1_sdk::{HashableKey, Prover, ProverClient, ProvingKey};

#[tokio::main]
async fn main() {
    let client = ProverClient::builder().mock().build().await;
    for (name, path) in [
        ("EQUIVALENCE_VKEY", script::EQUIVALENCE_ELF_PATH),
        ("CUSTODY_VKEY", script::CUSTODY_ELF_PATH),
    ] {
        let elf = script::load_elf(path);
        let pk = client.setup(elf.into()).await.expect("setup");
        println!("{name} = {}", pk.verifying_key().bytes32());
    }
}
