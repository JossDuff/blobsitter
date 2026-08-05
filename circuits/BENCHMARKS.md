# Circuit executor benchmarks

Cycle counts from the SP1 executor (no proving) — the primary input to proving cost and
latency decisions. Reproduce with `circuits/script`: build both guests
(`cargo prove build` in each guest dir), then
`cargo run --release --bin execute -- <equivalence|custody> [smoke|full]`.
Every run cross-checks the zkVM-committed public values against the native computation.

**Conditions (2026-08-05, post field-arithmetic swap):** SP1 v6.3.1 (cargo-prove
`8252c29`), Hypercube; guests built with the SP1-patched tiny-keccak
(`patch-2.0.2-sp1-6.0.0`) and the SP1-patched bls12_381 (`patch-0.8.0-sp1-6.2.0`);
Fr arithmetic via `bls12_381::Scalar`; executor on a desktop CPU.

| bench | total cycles | executor wall |
|---|---:|---:|
| custody, n = 50, k = 8 (smoke) | 190,663 | 25 ms |
| **custody, n = 1,000,003, k = 16,384 (protocol scale)** | **863,174,916** | 15.2 s |
| equivalence, m = 3, B = 1 (the fs_z shape) | 8,191,583 | — |
| **equivalence, m = 24,576, B = 6 (max declaration)** | **102,569,159** | 3.0 s |

Pre-swap numbers for the record (num-bigint Fr arithmetic): equivalence was
2,270,679,446 cycles at B = 1 and 13,898,300,185 at B = 6 — the swap to the patched
`bls12_381::Scalar` delivered a measured **~135–277× reduction**. Custody is unchanged
(keccak-bound; the swap doesn't touch it).

## Findings

1. **Custody beats its estimate.** 863M cycles at full protocol scale (~53k
   cycles/sample at ~20-deep paths) versus the research estimate of 1–2.5B. The spec's
   custody targets (sub-hour on 4090-class hardware; cents per proof on the network)
   hold with margin. The keccak patch makes this workload almost entirely
   precompile-bound.
2. **Equivalence is now comfortably cheap.** With the `bls12_381::Scalar` backend
   (SP1-patched in-guest), a maximum 6-blob declaration is ~103M cycles — an order of
   magnitude UNDER the original 0.1–0.4B-per-declaration research estimate. Both
   circuits sit in the cheapest network pricing tier.
3. **Batch inversion applied in both backends** (one field inversion per evaluation);
   the num-bigint implementation survives as a test-only cross-check, and agreement is
   four-way: Scalar / bigint / Python / c-kzg.

## Provisional vkeys (2026-08-05, post-swap — churn with every toolchain/guest change;
see the freeze policy in the circuit spec)

```
EQUIVALENCE_VKEY = 0x00ca78aee8a6e7b631f5ee0c343d214660840ed2b30e943d048436e74cc75dcb
CUSTODY_VKEY     = 0x00519b27817c44dfdf576169fab4e5f3af1b40a16ab5b28cdb854bd6e8b4e91c
```
