# blobsitter

Implementation of the Verifiable Bonded Persistence Protocol — a generic, dataset-agnostic
protocol for persisting datasets on Ethereum L1: EIP-4844 blob publication, an append-only
MMR commitment, SP1 validity proofs (equivalence at declaration, monthly custody proofs),
and bonded storage providers accountable via challenges and slashing.

## Source of truth

- `spec/verifiable-bonded-persistence-protocol.md` — the design spec (the WHY). All economic
  constants and windows live in its §10 table; cite the section when using one in code.
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
   setups only (PLONK/Ignition default).

## Stack (decided 2026-07-29)

- Contracts: Solidity + Foundry.
- Circuits: SP1 zkVM — pin the exact version at contract freeze; PLONK wrap default.
- Off-chain (daemon, carrier, publisher tooling, reference implementation): Rust.

## Working rules

- Golden vectors in `vectors/` are cross-component truth: contract, circuit, daemon, and
  reference-implementation tests all consume the same files. **Never edit a vector to make a
  test pass** — regenerate it from the reference implementation and explain the diff.
- Prefer Foundry invariant/fuzz tests for the provider/challenge/unbonding state machine.
- Small, scoped commits; spec changes and code changes in separate commits.
