//! Request real proofs — from the Succinct network when SP1_PROVER=network is set
//! (read from the repo's .env or the environment), or from the local CPU prover
//! otherwise. Every proof is verified locally against the guest's vkey before being
//! reported or written.
//!
//! Usage: cargo run --release --bin prove -- <equivalence|custody> <core|compressed|plonk|groth16> [--fixture]
//!
//! Plain runs use the benchmark witnesses (full protocol scale) and just report
//! latency/size. `--fixture` uses the fork-replayable witness pair derived from the
//! genesis KZG fixture and writes the wrapped proof + public values + vkey to
//! contracts/test/fixtures/proofs/<circuit>_<mode>.json for the RealProof fork test
//! (which skips itself if its embedded vkey no longer matches the current guest).

use blobsitter_circuits_script as script;
use sp1_sdk::{
    HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofMode, SP1Stdin,
};

fn hx(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[tokio::main]
async fn main() {
    // Credentials live in the repo root's .env (gitignored); never on the command line.
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.env"));

    let args: Vec<String> = std::env::args().skip(1).collect();
    let which = args.first().expect("usage: prove <equivalence|custody> <mode> [--fixture]");
    let mode_arg = args.get(1).map(String::as_str).unwrap_or("plonk");
    let fixture = args.iter().any(|a| a == "--fixture");

    let mode = match mode_arg {
        "core" => SP1ProofMode::Core,
        "compressed" => SP1ProofMode::Compressed,
        "plonk" => SP1ProofMode::Plonk,
        "groth16" => SP1ProofMode::Groth16,
        other => panic!("unknown mode {other:?}"),
    };

    let genesis = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/test/fixtures/kzg_opening_genesis.json"
    );
    let mut stdin = SP1Stdin::new();
    let (elf, native_pv) = match (which.as_str(), fixture) {
        ("equivalence", true) => {
            let (input, _) = script::fixture_inputs(genesis);
            let pv = blobsitter_circuits_common::equivalence(&input);
            stdin.write(&input);
            (script::load_elf(script::EQUIVALENCE_ELF_PATH), pv)
        }
        ("equivalence", false) => {
            let input = script::equivalence_input(0, 6 * 4096);
            let pv = blobsitter_circuits_common::equivalence(&input);
            stdin.write(&input);
            (script::load_elf(script::EQUIVALENCE_ELF_PATH), pv)
        }
        ("custody", true) => {
            let (_, input) = script::fixture_inputs(genesis);
            let pv = blobsitter_circuits_common::custody(&input);
            stdin.write(&input);
            (script::load_elf(script::CUSTODY_ELF_PATH), pv)
        }
        ("custody", false) => {
            eprintln!("building full-scale witness…");
            let input = script::custody_input(1_000_003, 16_384);
            let pv = blobsitter_circuits_common::custody(&input);
            stdin.write(&input);
            (script::load_elf(script::CUSTODY_ELF_PATH), pv)
        }
        _ => panic!("unknown circuit {which:?}"),
    };

    let prover_kind = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into());
    eprintln!("prover: {prover_kind}; requesting {which} / {mode_arg} (fixture={fixture})…");

    let client = ProverClient::from_env().await;
    let pk = client.setup(elf.into()).await.expect("setup");
    let vkey = pk.verifying_key().bytes32();
    eprintln!("vkey: {vkey}");

    let start = std::time::Instant::now();
    let proof = client.prove(&pk, stdin).mode(mode).await.expect("proving failed");
    let latency = start.elapsed();

    client.verify(&proof, pk.verifying_key(), None).expect("local verification failed");
    assert_eq!(
        proof.public_values.as_slice(),
        native_pv.as_slice(),
        "proof public values != native computation"
    );

    let onchain = matches!(mode, SP1ProofMode::Plonk | SP1ProofMode::Groth16);
    let proof_bytes = if onchain { proof.bytes() } else { vec![] };
    println!("circuit:          {which}");
    println!("mode:             {mode_arg}");
    println!("latency:          {latency:?}   (request -> verified proof in hand)");
    println!("public values:    {} bytes, match native", native_pv.len());
    if onchain {
        println!("onchain proof:    {} bytes", proof_bytes.len());
    }

    if fixture {
        assert!(onchain, "--fixture needs an onchain-verifiable mode (plonk|groth16)");
        let out = serde_json::json!({
            "_purpose": "REAL network proof for the RealProof fork test; regenerate with `prove <circuit> <mode> --fixture` after any guest/toolchain change",
            "circuit": which,
            "mode": mode_arg,
            "vkey": vkey,
            "publicValues": hx(native_pv.as_slice()),
            "proofBytes": hx(&proof_bytes),
        });
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/test/fixtures/proofs");
        std::fs::create_dir_all(dir).unwrap();
        let path = format!("{dir}/{which}_{mode_arg}.json");
        std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&out).unwrap()))
            .expect("write proof fixture");
        println!("fixture written:  contracts/test/fixtures/proofs/{which}_{mode_arg}.json");
    }
}
