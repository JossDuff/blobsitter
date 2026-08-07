//! The custody prover abstraction (D15): proving lives behind a trait with real
//! backends and a test mock, and a backend failure is a FALLBACK TRIGGER for the
//! escape hatch — never a panic, never a missed period.
//!
//! The real SP1 backend sits behind the non-default `sp1` cargo feature: neither the
//! SP1 SDK nor network credentials are required to build or test the daemon, and an
//! escape-hatch-only deployment (no feature, no ELF) is fully functional. With the
//! feature on, `SP1_PROVER=network` (the default posture) proves on the Succinct
//! network and `SP1_PROVER=cpu` proves locally — both configured purely through the
//! environment, exactly like the proving-spike tooling in `circuits/script`.

use blobsitter_reference::Hash;

use crate::proofs::ProvenChunk;

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("no prover is configured (escape-hatch-only deployment)")]
    Unavailable,
    #[error("proving failed: {0}")]
    Failed(String),
}

/// Everything the custody circuit binds, plus the witness — content-identical to the
/// circuit's `CustodyInput` (the sp1 backend converts type-for-type at its boundary).
#[derive(Debug, Clone)]
pub struct CustodyWitness {
    pub instance: [u8; 20],
    pub provider_id: u64,
    pub seed: Hash,
    pub root: Hash,
    pub leaf_count: u64,
    pub k: u64,
    pub peaks: Vec<Hash>,
    /// Exactly `k` samples; sample `j` at the contract-derived index for `j`.
    pub samples: Vec<ProvenChunk>,
}

#[async_trait::async_trait]
pub trait CustodyProver: Send + Sync {
    fn name(&self) -> &str;
    /// True when this backend can be asked at all — false routes straight to the
    /// escape hatch without building the (expensive) witness.
    fn available(&self) -> bool {
        true
    }
    async fn prove(&self, witness: CustodyWitness) -> Result<Vec<u8>, ProverError>;
}

/// The escape-hatch-only backend: always unavailable.
pub struct NoProver;

#[async_trait::async_trait]
impl CustodyProver for NoProver {
    fn name(&self) -> &str {
        "none"
    }
    fn available(&self) -> bool {
        false
    }
    async fn prove(&self, _witness: CustodyWitness) -> Result<Vec<u8>, ProverError> {
        Err(ProverError::Unavailable)
    }
}

/// Test backend: returns fixed proof bytes (the harness pairs it with the mock
/// verifier's sentinel) after an optional simulated latency, or fails on demand to
/// drive the fallback paths.
pub struct StubProver {
    pub proof: Result<Vec<u8>, String>,
    pub delay: std::time::Duration,
}

#[async_trait::async_trait]
impl CustodyProver for StubProver {
    fn name(&self) -> &str {
        "stub"
    }
    async fn prove(&self, _witness: CustodyWitness) -> Result<Vec<u8>, ProverError> {
        tokio::time::sleep(self.delay).await;
        self.proof.clone().map_err(ProverError::Failed)
    }
}

#[cfg(feature = "sp1")]
pub mod sp1 {
    //! The real SP1 backend. `ProverClient::from_env` reads `SP1_PROVER`
    //! (network | cpu) and, for the network, `NETWORK_PRIVATE_KEY` — credentials
    //! stay in the environment, never in daemon state.

    use sp1_sdk::{ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin};

    use super::{CustodyProver, CustodyWitness, ProverError};

    pub struct Sp1Prover {
        elf: Vec<u8>,
    }

    impl Sp1Prover {
        /// `elf` is the pinned custody guest binary (config `custody_elf`).
        pub fn new(elf: Vec<u8>) -> Self {
            Self { elf }
        }

        fn to_circuit_input(w: &CustodyWitness) -> blobsitter_circuits_common::CustodyInput {
            blobsitter_circuits_common::CustodyInput {
                instance: w.instance,
                provider_id: w.provider_id,
                seed: w.seed,
                root: w.root,
                leaf_count: w.leaf_count,
                k: w.k,
                peaks: w.peaks.clone(),
                samples: w
                    .samples
                    .iter()
                    .map(|s| blobsitter_circuits_common::CustodySample {
                        chunk: s.chunk,
                        path: s.path.clone(),
                    })
                    .collect(),
            }
        }
    }

    #[async_trait::async_trait]
    impl CustodyProver for Sp1Prover {
        fn name(&self) -> &str {
            "sp1"
        }

        async fn prove(&self, witness: CustodyWitness) -> Result<Vec<u8>, ProverError> {
            let input = Self::to_circuit_input(&witness);
            // Run the guest logic natively first: a witness the circuit would reject
            // must fail HERE (cheap, debuggable), not after minutes of proving.
            let expected_pv = std::panic::catch_unwind(|| blobsitter_circuits_common::custody(&input))
                .map_err(|_| ProverError::Failed("witness rejected by native guest logic".into()))?;

            let mut stdin = SP1Stdin::new();
            stdin.write(&input);
            let client = ProverClient::from_env().await;
            let pk = client
                .setup(self.elf.clone().into())
                .await
                .map_err(|e| ProverError::Failed(format!("setup: {e}")))?;
            let proof = client
                .prove(&pk, stdin)
                .mode(SP1ProofMode::Plonk)
                .await
                .map_err(|e| ProverError::Failed(format!("prove: {e}")))?;
            if proof.public_values.as_slice() != expected_pv.as_slice() {
                return Err(ProverError::Failed("proof public values != native computation".into()));
            }
            Ok(proof.bytes())
        }
    }
}
