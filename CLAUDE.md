# blobsitter

Implementation of the Verifiable Bonded Persistence Protocol — a generic, dataset-agnostic
protocol for persisting datasets on Ethereum L1: EIP-4844 blob publication, an append-only
MMR commitment, SP1 validity proofs (equivalence at declaration, monthly custody proofs),
and bonded storage providers accountable via challenges and slashing.

## Source of truth

- `spec/verifiable-bonded-persistence-protocol.md` — the design spec (the WHY). All economic
  constants and windows live in its §10 table.
- `spec/normative.md` + `vectors/` (once they exist) — the implementation spec and golden
  test vectors (the WHAT). Implement against them exactly.
- **If anything is ambiguous, or two documents disagree: STOP and surface the conflict.**
  Never invent an encoding, hash rule, constant, or state transition silently. This protocol
  is immutable post-deployment; a silent guess becomes permanent.

## Non-negotiable invariants

1. **Dataset-agnostic.** No domain/subject-matter references anywhere in protocol code,
   specs, or comments.
2. **The contract template is immutable.** No upgradeability, no governance, no admin roles,
   no pausing. Verifying keys are template constants.
3. **The publisher never holds or spends ETH.** Publication is EIP-712-signed intents
   submitted by carrier EOAs (blob txs must be EOA-originated); the paymaster reimburses
   carriers, never the publisher.
4. **Slashing-relevant response paths are SNARK-free forever** (challenge response, custody
   escape hatch): keccak + calldata only. No circuit dependency may ever be added to them.
5. **The storage daemon never parses record contents.** App-layer decoding lives only in the
   crash-isolated materializer.
6. **Protocol code never interprets `appPointer` or `successor`** — both are informational.
7. **Chunk = 31 bytes = one blob field element.** Fixed, not configurable.
8. **The stake can only ever be paid to the provider's withdrawal address.**
9. **No trusted-setup ceremony is ever run by or for this protocol.** SP1's pre-existing
   setups only (PLONK/Ignition wrap, decided 2026-08-06).

## Stack (decided 2026-07-29)

- Contracts: Solidity + Foundry.
- Circuits: SP1 zkVM — pin the exact version at contract freeze; PLONK wrap (decided
  2026-08-06 for Ignition-ceremony provenance; the instance pins the PLONK gateway).
- Off-chain (daemon, carrier, publisher tooling, reference implementation): Rust.

## Commands

- `cargo test --workspace` — build + run all Rust tests: the golden-vector conformance
  suite (`reference/tests/vectors.rs`) and the daemon behavior suite
  (`daemon/tests/d*.rs`, IDs from `spec/daemon-test-plan.md`). Must pass before any
  commit. The Layer-2 anvil tests (`daemon/tests/l2_*.rs`) self-skip unless anvil
  and `contracts/out` artifacts exist — run `forge build` first to enable them.
- `./scripts/check_daemon_opacity.sh` — D6: the daemon crate must never depend on an
  app-layer workspace crate (CI-enforced).
- `PROTOC=<v21+ protoc> cargo check -p blobsitter-daemon --features sp1` — the real
  SP1 proving backends (network default via `SP1_PROVER=network`, local CPU opt-in).
  OFF by default and never required for build/test (D15); an escape-hatch-only daemon
  is fully functional. The operator key always comes from `BLOBSITTER_OPERATOR_KEY`.
- `python3 scripts/gen_vectors.py` — regenerate `vectors/` (only after a deliberate
  normative-spec change; CI fails if committed vectors don't match the generator).
- `cargo build -p blobsitter-reference --bin mmr_oracle && (cd contracts && forge test)` —
  the contract suite (vector conformance, negatives, invariants). The oracle build comes
  first: the I12 differential fuzz test calls it via `vm.ffi`.
- `cargo run -p kzg-fixture` — regenerate `contracts/test/fixtures/kzg_opening.json`
  (real c-kzg opening; CI fails if the committed fixture doesn't match). Never hand-edit.
- `ETH_RPC_URL=<url> forge test --match-path "test/fork/*"` (from `contracts/`) — the
  Layer-4 mainnet-fork tests (precompile parity, real-Safe ERC-1271). They self-skip
  without the URL; CI runs them once the `ETH_RPC_URL` repo secret is configured.
- `cargo test --manifest-path circuits/Cargo.toml` — the guest logic natively against
  the vectors (no SP1 toolchain; this is what CI runs).
- Executor benchmarks / vkeys (local only; needs `sp1up` + `cargo prove build` in each
  guest dir first): from `circuits/script/`, `cargo run --release --bin execute --
  <equivalence|custody> [smoke|full]` and `--bin vkey`. Results and conditions are
  recorded in `circuits/BENCHMARKS.md`. Building `circuits/script` also needs a protoc
  with the well-known-type includes (v21+; distro 3.x fails with "empty.proto not
  found") — grab a protoc release and point `PROTOC=<path>/bin/protoc` at it.

## Layout

- `spec/` — design spec (WHY) + normative spec (WHAT) + the contract and daemon test
  plans (named invariant/behavior IDs that test names must reference).
- `vectors/` — golden test vectors (cross-component truth).
- `scripts/gen_vectors.py` — vector generator (interim; Rust reference will take over).
- `reference/` — Rust reference implementation of normative §1–10 + §11 EIP-712 digests;
  `src/bin/mmr_oracle.rs` is the forge suite's ffi differential oracle.
- `contracts/` — Foundry project: the COMPLETE contract surface (publication, provider
  lifecycle, challenges, custody proofs, paymaster) + mocks, tests, and generated
  fixtures (`test/fixtures/`, never hand-edited). The unit/invariant suites etch an
  interface-exact mock at the pinned verifier address; the RealProof fork suite runs
  the real deployed verifier with real network proofs.
- `tools/kzg-fixture/` — generates the real-KZG test fixture from c-kzg's embedded
  Ethereum setup (no ceremony is ever run by or for this protocol).
- `circuits/` — the SP1 circuits: `common/` holds ALL guest logic as a host-buildable
  library (native tests, no toolchain); `equivalence/` and `custody/` are thin guest
  wrappers (standalone workspaces, committed lockfiles — determinism is what the vkeys
  hash); `script/` is host tooling (executor benches, vkey derivation). Proving is
  deferred to the network-spike milestone.
- `abi/` — the ONE contract-ABI transcription (instance, paymaster, ERC-1271) every
  Rust consumer shares: daemon, testkit, carrier, publisher.
- `intents/` — the signed-intent package: the wire format between publisher and
  carrier (versioned JSON: intent + signature + blobs + openings + equivalence
  proof) and its static validation.
- `carrier/` — the carrier CLI (`blobsitter-carrier`): verify a package, prove the
  carriage will succeed AND pay (preflight simulation + §15.2 solvency vs the
  paymaster), assemble the blob tx, submit, report the receipt's reimbursement
  events; `claim` drains parked payouts. Key via `BLOBSITTER_CARRIER_KEY` only.
- `daemon/` — the storage daemon. M1: chain follower at finality, blob source chain,
  verify-before-write ingest, crash-safe flat-file chunk store. M2: enforcement —
  challenge responder with a persistent ledger (`responder.rs`), custody loop with a
  pure planner (`custody.rs`), prover trait with the SP1 backend behind the `sp1`
  feature (`prover.rs`), fee-escalating operator tx sender (`tx.rs`), store-backed
  proof construction incl. historical pins (`proofs.rs`). Consumes
  `blobsitter-reference` for every protocol primitive; never parses record contents;
  archive-only mode (no `[provider]` config) runs with no keys and no duties.
- `testkit/` — the anvil integration harness (Layer 2): real contract artifacts, real
  type-3 blob declarations, mock verifier via `anvil_setCode`, beacon-shaped blob
  stub, staking/challenger drivers, chain-time warping. Every milestone's end-to-end
  tests build on it.
- Planned: `publisher/` — see the off-chain phase plan below.

## Off-chain phase plan (adopted 2026-08-06)

All protocol decisions are closed (wrap mode = PLONK, source data = raw opaque bytes);
this phase builds the operational tooling. One milestone per PR, `/code-review` each,
test plans updated in the same commit as any new mechanism. Milestones:

- **M1 — daemon core** (SHIPPED, PR #8): chain follower, blob ingest behind a source
  trait, flat-file chunk store (chunk i at offset 31·i), root verification against
  L1, crash/reorg safety, plus the anvil integration harness (real contracts + real
  blob txs + mock prover) that every later milestone reuses. Test plan:
  `spec/daemon-test-plan.md` (behaviors D1–D6, D18, Layer 2).
- **M2 — daemon enforcement duties** (SHIPPED, PR #9): challenge responder and
  custody-proof loop (prover trait: network default, local opt-in, escape hatch as
  the prover-free fallback). The slashing-critical milestone — D7–D17. Layer-3 fault
  injection beyond what M2 covers (RPC flaps mid-response, kill-point fuzz on the
  responder) and the Layer-4 soak run remain follow-ups after M3/M4.
- **M3 — carrier CLI:** intent intake (the signed-intent package format in
  `intents/`), verify-then-carry with solvency simulation, blob-tx assembly and
  submission, reimbursement claims. Test plan: C1–C7.
- **M4 — publisher CLI:** EIP-712 intent signing, batch planning, appPointer and
  successor flows. The publisher signs; it never holds ETH or submits.
- **M5 — container format:** normative spec + golden vectors FIRST (extend
  `gen_vectors.py`), then the library: framing, batch manifests, codec-ID +
  dictionary hooks (v1 always stored/raw), tombstones, index snapshots.
- **M6 — materializer + IPFS:** crash-isolated decoder, view materialization with
  manifest-digest verification, per-blob pinning, appPointer publication.

M1–M2 are the critical path. Standing rules for this phase: the daemon crate consumes
`blobsitter-reference` for every protocol primitive (no reimplementations); the daemon
never parses record contents (materializer only, M6); the daemon holds only the
operator key; prover/network credentials live in the environment, never in code,
config files, or test fixtures.

**Blob sourcing (decided 2026-08-06;** research in
`spec/research/blob-sourcing-2026-08.md`**):** the daemon is its own archive — it
ingests every declared blob at head and persists it; the ~18-day network retention
window is only the budget for repairing gaps. Source trait chain: configured beacon
`/eth/v1/beacon/blobs` endpoints (primary + fallbacks, one adapter; post-Fusaka this
endpoint replaces the deprecated `blob_sidecars` and takes a `versioned_hashes`
filter) → Blobscan-style archive adapter. Bootstrap after the window: existing
providers / IPFS pins AND public blob archives (few providers is the realistic case).
All sources are untrusted — every blob verifies against its on-chain versioned hash
before any byte is stored. Ops docs must say: a self-hosted beacon node needs
semi-supernode config (post-PeerDAS, default nodes cannot serve full blobs).

## Working rules

- Golden vectors in `vectors/` are cross-component truth: contract, circuit, daemon, and
  reference-implementation tests all consume the same files. **Never edit a vector to make a
  test pass** — regenerate it from the reference implementation and explain the diff.
- **Code comments are for humans and must stand alone.** Explain the rule or rationale in
  plain language inline; never cite spec section numbers (§X.Y) — a pointer that makes the
  reader open a second file fractures understanding. (Test-plan invariant IDs in test names
  are the exception: coverage is audited against them.)
- Prefer Foundry invariant/fuzz tests for the provider/challenge/unbonding state machine.
- Small, scoped commits; spec changes and code changes in separate commits.

## Pre-audit freeze checklist

- Calibrate and freeze `TAIL` (spec §15.2; the gas-snapshot test in
  `Reimbursement.t.sol` measured ~25.3k against the provisional 25_000 — nearly exact)
  and `REIMBURSE_GAS_CAP` (provisional 200_000) in `BlobsitterInstance`.
- Re-verify the pinned PLONK gateway address at the freeze block (wrap mode is decided;
  the address and SP1 release are provisional until freeze) and freeze the final vkeys.
- Re-measure `RESPONSE_GAS_PER_CHUNK`/`RESPONSE_BASE_GAS` against the final respond().
- Decide a `forge coverage` gate threshold; consider mutation testing before audit.
