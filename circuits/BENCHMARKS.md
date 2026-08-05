# Circuit executor benchmarks

Cycle counts from the SP1 executor (no proving) — the primary input to proving cost and
latency decisions. Reproduce with `circuits/script`: build both guests
(`cargo prove build` in each guest dir), then
`cargo run --release --bin execute -- <equivalence|custody> [smoke|full]`.
Every run cross-checks the zkVM-committed public values against the native computation.

**Conditions (2026-08-05):** SP1 v6.3.1 (cargo-prove `8252c29`), Hypercube; guests built
with the SP1-patched tiny-keccak (`patch-2.0.2-sp1-6.0.0`); Fr arithmetic via num-bigint
(unaccelerated — see finding below); executor on a desktop CPU, throughput observed
~70–85M cycles/s.

| bench | total cycles | executor wall |
|---|---:|---:|
| custody, n = 50, k = 8 (smoke) | 190,663 | 25 ms |
| **custody, n = 1,000,003, k = 16,384 (protocol scale)** | **863,043,844** | 13.3 s |
| equivalence, m = 3, B = 1 (the fs_z shape) | 2,270,679,446 | 31.9 s |
| equivalence, m = 24,576, B = 6 (max declaration) | 13,898,300,185 | 163.5 s |

## Findings

1. **Custody beats its estimate.** 863M cycles at full protocol scale (~53k
   cycles/sample at ~20-deep paths) versus the research estimate of 1–2.5B. The spec's
   custody targets (sub-hour on 4090-class hardware; cents per proof on the network)
   hold with margin. The keccak patch makes this workload almost entirely
   precompile-bound.
2. **Equivalence is dominated by unaccelerated field arithmetic — the headline
   optimization target.** ~2.3B cycles PER BLOB (vs the 0.1–0.4B total estimate), and
   the profile is squarely the barycentric evaluation's num-bigint Fr arithmetic (the
   keccak side of the statement is a few million cycles). num-bigint is the right
   *reference* implementation (portable, matches the Python generator and c-kzg), but
   the guest must switch its Fr math to the SP1-patched `bls12_381` (the `kzg-rs`
   approach — that crate's full KZG verify measures ~27M cycles/blob, suggesting
   roughly a 100× reduction here). Scheduled for the proving-spike milestone; the
   statement, layouts, and vectors are unaffected — only the arithmetic backend swaps.
3. **Batch inversion already applied.** The evaluator uses Montgomery batch inversion
   (one Fermat inversion per evaluation instead of 4096); the numbers above include it.

## Provisional vkeys (2026-08-05 — churn with every toolchain/guest change; see the
freeze policy in the circuit spec)

```
EQUIVALENCE_VKEY = 0x004ac7b99d5e2e1d99c91145ed1a77d2f6b425bb64933c8a2763748a9119d434
CUSTODY_VKEY     = 0x00ce5edf75d8b4192fb617f0c291bbca4dad9c37fecb75d1529237a6bd8032af
```
