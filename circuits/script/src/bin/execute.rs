//! Executor benchmarks: run a guest in the SP1 executor (no proof) and report the
//! cycle count — the number that decides proving cost and latency. The committed
//! public values are cross-checked against the native computation, so every executor
//! run is also a zkVM-vs-native conformance test.
//!
//! Usage: cargo run --release --bin execute -- <equivalence|custody> [scale]
//!   equivalence scales: smoke (m=3, the fs_z shape) | full (m=24576, 6 blobs)
//!   custody scales:     smoke (n=50, k=8)           | full (n=1_000_003, k=16384)

use blobsitter_circuits_script as script;
use sp1_sdk::{Prover, ProverClient, SP1Stdin};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next().expect("usage: execute <equivalence|custody> [smoke|full]");
    let scale = args.next().unwrap_or_else(|| "smoke".into());

    let client = ProverClient::from_env().await;
    let mut stdin = SP1Stdin::new();

    let (elf, native_pv, label) = match (which.as_str(), scale.as_str()) {
        ("equivalence", "smoke") => {
            let input = script::equivalence_input(5, 3);
            let pv = blobsitter_circuits_common::equivalence(&input);
            stdin.write(&input);
            (script::load_elf(script::EQUIVALENCE_ELF_PATH), pv, "equivalence m=3 B=1")
        }
        ("equivalence", "full") => {
            let input = script::equivalence_input(0, 6 * 4096);
            let pv = blobsitter_circuits_common::equivalence(&input);
            stdin.write(&input);
            (script::load_elf(script::EQUIVALENCE_ELF_PATH), pv, "equivalence m=24576 B=6")
        }
        ("custody", "smoke") => {
            let input = script::custody_input(50, 8);
            let pv = blobsitter_circuits_common::custody(&input);
            stdin.write(&input);
            (script::load_elf(script::CUSTODY_ELF_PATH), pv, "custody n=50 k=8")
        }
        ("custody", "full") => {
            eprintln!("building full-scale witness (1M-leaf memoized tree)…");
            let input = script::custody_input(1_000_003, 16_384);
            let pv = blobsitter_circuits_common::custody(&input);
            stdin.write(&input);
            (script::load_elf(script::CUSTODY_ELF_PATH), pv, "custody n=1_000_003 k=16384")
        }
        other => panic!("unknown bench {other:?}"),
    };

    eprintln!("executing {label}…");
    let start = std::time::Instant::now();
    let (public_values, report) =
        client.execute(elf.into(), stdin).await.expect("execution failed");
    let wall = start.elapsed();

    assert_eq!(
        public_values.as_slice(),
        native_pv.as_slice(),
        "zkVM public values != native computation"
    );

    println!("bench:            {label}");
    println!("total cycles:     {}", report.total_instruction_count());
    println!("wall (executor):  {wall:?}");
    println!("public values ok: {} bytes, match native", native_pv.len());
}
