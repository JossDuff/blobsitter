# Storage daemon test plan — named behaviors and required test layers

Companion to `normative.md` §12–§13 for the off-chain phase. Same discipline as the
contract test plan: each behavior has a stable ID; Rust tests MUST reference these IDs
in their names (e.g. `d7_response_differential`) so coverage is auditable against this
list. A new daemon mechanism means new IDs here in the same commit. Carrier and
publisher CLIs get their own sections here when their milestones start.

The daemon is the provider's agent: it ingests every declared blob, holds the full
chunk stream, answers challenges, and runs the custody-proof loop. Two of its duties
are slashing-critical — a missed challenge response or a lapsed custody clock costs
the provider their entire stake — so the deadline paths get the heaviest testing.

## Layer 0 — vector conformance (shared truth)

The daemon consumes `blobsitter-reference` for all protocol primitives, so the golden
vectors already bind it: blob→chunk mapping, MMR peaks/roots, inclusion-proof
construction (the off-chain §7.3 form AND the on-chain §7.2 form it must produce for
`respond`), custody sample indices, and z preimages. Daemon-specific vector needs
(e.g. a multi-declaration ingest transcript) are added to `vectors/` via
`scripts/gen_vectors.py`, never hand-written.

## Layer 1 — behavior tests (unit / component)

### Ingest and the chunk store

- **D1 — store integrity:** the canonical store is a flat file, chunk `i` at offset
  `31·i`, append-only. After ingesting any declaration sequence, locally recomputed
  `(peaks, Root, leafCount)` equal the contract's. Fuzz over random declaration shapes
  (m, B, partial final blobs).
- **D2 — verify before write:** every blob fetched from any source is verified against
  its on-chain versioned hash (commitment → versioned-hash check) before a single byte
  enters the store. A corrupted or wrong blob is rejected and refetched from the next
  source; it must be impossible for unverified bytes to become store state.
- **D3 — no holes, no skips:** `Declared` events are processed exactly once, in nonce
  order. If a blob cannot be obtained, ingest HALTS at that declaration and alarms —
  it never skips ahead (a hole in the stream would silently break every later
  inclusion proof and challenge response).
- **D4 — reorg safety:** only finalized declarations become permanent store state; a
  declaration observed and then reorged away never leaves residue. (Near-head
  declarations may be prefetched, but the store's committed frontier follows
  finality.)
- **D5 — crash consistency:** kill the daemon at any point during ingest (fuzz the
  kill point); on restart it recovers to a consistent state and re-ingest is
  idempotent — no partial blob is ever visible as committed store content.
- **D6 — opacity:** the daemon never parses record contents (protocol invariant). No
  app-layer/container imports in the daemon crate; enforced by review and a
  dependency check in CI.

### Challenge response (slashing-critical)

- **D7 — response differential:** for any challenge `(indices, pin)`, the
  daemon-constructed `respond` calldata is accepted by the real contract. Driven as a
  differential fuzz test against the forge suite's instance on anvil: random index
  sets including duplicates, index 0, the last leaf, single-leaf trees, and
  `maxSample`-sized sets.
- **D8 — historical pins:** responses verify against the pinned root, which for an
  UNBONDING provider is the exit snapshot `(exitRoot, exitLeafCount)` — an arbitrary
  PAST tree state. The daemon must reconstruct peaks at any historical leafCount from
  the store alone. Tested at random snapshot points, not just the current head.
- **D9 — deadline discipline:** a challenge observed at any point inside
  `responseWindow` produces a submitted, confirmed response with time to spare;
  submission retries with fee escalation on transient failure; inability to respond
  raises the loudest alarm the daemon has. Tested under compressed windows with
  injected RPC failures.
- **D10 — pending-obligation recovery:** restart with an open challenge (or an
  in-flight response transaction) resumes and completes the response inside the
  window. The challenge ledger is persistent state, not memory.

### Custody loop (slashing-critical)

- **D11 — period discipline:** exactly one `beginProof` per period (the first commit
  is binding — never attempt a re-roll); `submitProof*` lands in the SAME period as
  its commit; a proof for an expired commit is never submitted.
- **D12 — snapshot proving:** the custody proof is generated against the committed
  `(seed, root, leafCount)` snapshot even while new declarations extend the store
  mid-proving. The prover input is cut at `leafCount`, not at the current tip.
- **D13 — escape-hatch fallback:** if the prover fails or the period's remaining time
  drops below a configured threshold, the daemon falls back to `submitProofEscape`
  with the `maxSample` on-chain-derived reveals — including the empty-snapshot case
  (`commit.leafCount == 0` → empty reveals array). The fallback path shares no code
  with the prover, so a prover bug cannot take both paths down.
- **D14 — cure before lapse:** the daemon tracks derived custody status continuously:
  STALE triggers an alarm and an immediate proof attempt; LAPSE_ELIGIBLE uses the
  grace (when only the provider can act) to cure via either proof path. Simulated
  clock tests walk every status transition.
- **D15 — prover abstraction:** proving is behind a trait with network and local
  backends plus a test mock; backend failure is a fallback trigger (D13), never a
  panic. Network credentials come from the environment; they are never persisted by
  the daemon or required at build/test time.

### Lifecycle and keys

- **D16 — key separation:** the daemon holds ONLY the operator key. The withdrawal
  key never touches daemon config, state, or logs; `stake` and `withdraw` are
  explicitly out of the daemon's scope (operator-key-only surface).
- **D17 — unbonding behavior:** after `initiateUnbonding`, the custody loop stops
  (obligations end) but the store is retained and challenges remain answerable until
  `unbondingAt + unbondingDelay + responseWindow` has passed; the daemon refuses to
  delete data before that instant.
- **D18 — source redundancy:** blob acquisition is behind a source trait with an
  ordered fallback chain (decided 2026-08-06). Near-head ingest: N configured beacon
  `/eth/v1/beacon/blobs` endpoints through one adapter (primary + fallbacks — the
  same shape lets a self-hosted blob-archiver deployment slot in), then a
  Blobscan-style archive adapter as last resort. Bootstrap of a provider joining
  after the retention window: existing providers / per-blob IPFS pins AND public
  blob archives — few providers is the realistic case, so archives are a first-class
  bootstrap source, not an extra. Every source is untrusted; D2's verify-before-write
  applies identically to all of them. Tests drive primary failure, full near-head
  chain exhaustion (alarm, D3), and a bootstrap fill from an archive-only source set.

## Layer 2 — anvil integration harness

The end-to-end rig every later milestone builds on (`testkit/`): anvil with the REAL
contracts deployed (same artifacts the forge suite tests), real type-3 blob-carrying
declarations driven by the test harness, the daemon running as a real process against
it, and the mock verifier planted at the pinned address (`anvil_setCode`, the node
equivalent of `vm.etch`). Blob contents reach the daemon through a beacon-SHAPED stub
server (anvil has no beacon API): the harness serves `/eth/v1/beacon/blobs/{block_id}`
and the daemon's PRODUCTION beacon adapter is what the tests exercise — which also
demonstrates D18's claim that a self-hosted archiver behind the same API shape slots
in unchanged. Core scenarios: declare → ingest → verify root; challenge → respond →
bond paid; custody commit → escape-hatch proof; the lapse race (cure lands first).
The instance's window parameters are constructor arguments, so the harness deploys
with compressed windows and real time (anvil `--slots-in-an-epoch 1` gives
finalized = latest − 2, tight enough to test finality gating in real time).

## Layer 3 — fault injection

Process kill at fuzzing-chosen points (extends D5/D10), RPC endpoint flaps and
timeouts, a prover that hangs vs errors vs returns garbage, blob sources returning
corrupt data (D2), and anvil-driven reorgs of unfinalized declarations (D4). The
daemon's job under every fault is the same: never corrupt the store, never miss a
deadline it could have met, alarm loudly when it can't.

## Layer 4 — soak

A compressed-time soak: many custody periods, interleaved declarations, random
challenges, one unbonding — asserting the provider ends the run unslashed with a
byte-identical store. Run in CI nightly rather than per-commit.

## Layer 5 — process

- `/code-review` on every PR; the remaining ultra review stays reserved for the
  pre-audit freeze.
- The daemon crate depends on `blobsitter-reference` for every protocol primitive —
  no reimplementations (one MMR, one index derivation, one z preimage).
- Slashing-critical paths (challenge response, escape hatch) follow the contract
  rule: no SNARK/circuit dependency, ever.
