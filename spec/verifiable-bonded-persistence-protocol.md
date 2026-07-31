# Verifiable Bonded Persistence Protocol

**v2 — validity-proof design**

A generic, dataset-agnostic protocol for persisting arbitrary datasets in a publicly
verifiable way, using Ethereum L1 for economic security and commitment, EIP-4844 blobs for
publication, and succinct validity proofs (SNARKs) for commitment integrity and storage
attestation. The protocol has no knowledge of what any dataset means.

> **Version note.** This design supersedes the v1 optimistic design (archived at
> `verifiable-bonded-persistence-protocol-v1-optimistic.md`). v1's one-opening fraud proof was
> found unconstructible: a fraudulent declared tree's leaves are known only to the publisher, so
> no third party can build the inclusion-proof witness needed to prove fraud on-chain. The same
> hole enabled a poisoned-root attack in which a publisher could ratify a root with one secretly
> altered leaf and then slash every bonded provider on the unanswerable index. v2 replaces the
> entire optimistic apparatus — dispute window, publisher fraud bond, root stacking and
> truncation, watcher role — with a proof of equivalence verified at declaration time.

> **Normative companion.** Exact byte-level definitions — hashing rules, encodings,
> algorithms, test vectors — live in `normative.md`. This document is the rationale; where
> the two disagree, stop and resolve rather than picking one.

**Deployment model:** the protocol is a single canonical, **immutable contract template**.
Each publisher **deploys their own instance** — no central registry, no registration step. A
dataset's identity is its contract address (the ERC-20 pattern: every instance is its own
contract).

## Standing assumptions

These are design axioms, stated so the mechanism can be judged against what it is actually
trying to do:

- **Storage providers are altruistic.** They have little to gain and are assumed not to act
  maliciously. Bonds exist so that a provider can *opt into* financial accountability for
  losing the data — a voluntary, credible commitment — not to deter provider attacks.
  Anti-provider game-theoretic defenses are deliberately minimal; residual manipulation
  windows are quantified and accepted rather than engineered away.
- **The publisher is a contract wallet (multisig/DAO) that never holds ETH.** All publication
  gas is fronted by third-party carriers and reimbursed from a donated endowment.
- **Ethereum L1 only.** No alternate L1s or external DA layers anywhere in the trust path.
- **The dataset is public.** Nothing here provides confidentiality.

## Guarantee (stated honestly)

The protocol does **not** guarantee availability. It guarantees:

1. **Verifiability** — anyone holding a piece of a dataset can prove whether it is canonical,
   against an on-chain commitment. This is the defence against silent corruption and bit-rot:
   a bad chunk is detected instantly by its consumer, at zero protocol cost.
2. **Root integrity — unconditional.** A state root inconsistent with the published blob bytes
   can never exist on-chain, even transiently: every declaration carries a validity proof of
   equivalence between the blob contents and the new commitment, checked before the root is
   accepted. There is no optimistic window and nothing to watch. Genesis is no exception —
   the initial dataset enters through the same proven declarations.
3. **Freshness** — every bonded provider attests possession of the full dataset on a fixed
   schedule with a succinct custody proof covering thousands of randomly sampled chunks.
   Staleness is an objective on-chain fact, readable for free.
4. **Accountability on demand** — anyone willing to post a challenge bond can force any bonded
   provider to produce named chunks on-chain within a fixed window, or be slashed.
5. **Recoverability substrate** — the on-chain record (blob versioned-hash log + root) is
   sufficient to re-fetch and re-verify the full dataset from any source that still has the
   bytes, with no dependence on a specific operator.

## Roles

- **Publisher** — the authority for a single deployed instance. A contract wallet that *signs*
  declarations (EIP-712, verified on-chain via ERC-1271) but never sends transactions and never
  holds ETH. Authoritative for its own dataset only.
- **Carrier** — any EOA. Blob transactions must be EOA-originated, so carriers submit the
  publisher's signed declarations as type-3 transactions, fronting the gas. The paymaster
  reimburses the carrier atomically in the same transaction, plus a fixed tip, making carriage
  self-incentivized (an intent/order-flow pattern: searchers and builders are natural carriers).
  Carriers need no trust: they cannot alter what the publisher signed.
- **Storage Provider** — permissionless and altruistic. Two tiers, no further menu:
  - **Mirror** — no stake. Announces itself for discovery, serves data best-effort, has no
    on-chain obligations and no on-chain standing.
  - **Bonded** — posts the stake and thereby accepts *both* obligations: answering challenges
    on demand *and* submitting a periodic custody proof. There is exactly one bonded flavor.
- **Challenger** — anyone. Posts a bond to demand that a bonded provider produce named chunks
  on-chain.
- **Funder** — anyone. Sends ETH to the instance's paymaster to cover publication and carriage
  costs. Requires no permission, confers no authority.
- **Anyone** — reads commitments, verifies held data, fetches from blobs or archives.

## Deployment & trust anchoring (no registry)

- **Dataset identity = contract address.** No registry, no `datasetId`.
- **Configuration is constructor state**, fixed forever at deployment (see
  [Parameter sizing](#parameter-sizing)). Verifying keys for the two circuits are template
  constants, not constructor parameters.
- **Immutability is the trust anchor.** The template is non-upgradeable so a publisher cannot
  later rewrite challenge/slash rules to rug staked providers.
- **Verify bytecode *and* constructor parameters.** Before staking, a provider checks that the
  instance's bytecode matches the canonical audited template and that the constructor
  parameters are sane (a one-block response window or a zero stake is template-compatible but
  pathological). Both checks are mechanical.
- **Discovery is off-chain.** The publisher advertises its contract address; nothing in the
  mechanism needs a global view.

## Commitments

- **Blob KZG commitments** — each published blob's versioned hash (read on-chain via
  `BLOBHASH`, openable via the point-evaluation precompile `0x0A`). Used at declaration time to
  prove root↔blob equivalence. The accumulated log of blob versioned hashes is the permanent
  recovery manifest.
- **State root — an append-only Merkle Mountain Range (MMR) over fixed-size chunks** — the
  permanent commitment. The contract stores the peak list and leaf count; "the root" is the
  peaks bagged (hashed left-to-right), computed on demand. The protocol treats a dataset as an
  **opaque ordered stream of fixed-size chunks**; meaning lives entirely in the application
  layer.

**Why an MMR:** O(log n) inclusion proofs for any chunk; appends cost O(log n) on-chain
regardless of batch size (peak-merging, below); appends never invalidate existing proofs; old
roots are provable prefixes of new ones. Amortized structural cost is ~2 hashes per leaf, all
off-chain.

### Chunk = one blob field element (31 bytes)

Fixed by the template, not a constructor parameter. A blob holds 4096 field elements →
**exactly 4096 chunks per blob**; chunk *i* of an update is field element *i* mod 4096 of blob
⌊*i*/4096⌋, packed densely from element 0 of the first blob (31 data bytes per element, high
byte zero — the circuit enforces this canonical form). Each update declares its chunk count, so
a partially filled final blob is unambiguous.

Why 31 bytes ([§1](#1-chunk-size-31-bytes)): it sits at the optimum of on-chain bytes per
sampled chunk; it makes the chunk↔blob mapping trivial for the equivalence circuit (leaf =
field element, no repacking layer to prove); and it makes the leaf-hash set *larger than the
data itself*, so "store the hashes, drop the data" is never an economical way to cheat custody
sampling.

### Append verification is peak-merging, not leaf submission

The publisher never submits leaves. An update of *m* chunks arrives as the peaks of the perfect
subtrees covering the new leaves (the binary decomposition of *m*: ~⌈log₂ m⌉ hashes) plus the
new leaf count; the contract merges them into the stored peaks in O(log n) hash operations
(binary-counter carries). Structural validity is enforced by construction; *content* validity —
that those subtree peaks were really built from the posted blob bytes — is exactly what the
equivalence proof establishes. The contract rejects any update whose declared chunk count
exceeds 4096 × (number of blobs in the transaction).

## Publication lifecycle (proven declarations)

Publication is an **intent**: the publisher signs, anyone submits, the paymaster reimburses.
The publisher's multisig never holds or spends ETH at any point in the system's life.

1. **Off-chain:** the publisher computes the update's blobs, their KZG commitments and
   versioned hashes, and the new MMR subtree peaks; then signs an EIP-712 declaration:

   ```
   Declaration {
     address   instance;          // domain separation
     uint64    nonce;             // strictly sequential
     uint64    deadline;          // declaration expires unsubmitted
     bytes32[] blobVersionedHashes;
     bytes32[] newSubtreePeaks;
     uint64    newLeafCount;
     address   designatedCarrier; // 0 = anyone may carry
     bytes32   appPointer;        // 0 = no update; opaque, protocol-inert
   }
   ```

   The publisher (or any prover — the statement is publicly provable from the blob data)
   generates the **equivalence proof** π. The intent payload {declaration, signature, blob
   data, π} is broadcast off-chain — an HTTP endpoint, IPFS, direct order flow to a builder.

2. **Carriage:** any EOA (or the designated carrier, if set) wraps the payload in a type-3
   blob transaction calling `declareFor(declaration, signature, π, kzgProofs)`. A reverted
   type-3 transaction still burns blob gas, so open broadcast should be used with either a
   designated carrier or exclusive order flow to one builder at a time; the `designatedCarrier`
   field exists to make the race impossible when desired.

3. **On-chain checks, all in one transaction:**
   - ERC-1271 signature check against the publisher, nonce and deadline valid;
   - `BLOBHASH(j)` equals the signed `blobVersionedHashes[j]` for every j — the carrier cannot
     substitute blobs;
   - peak merge is structurally valid; declared chunk count ≤ 4096 × blob count;
   - **equivalence proof verifies** (next section);
   - versioned hashes appended to the recovery log; peaks and leaf count updated;
   - if `appPointer ≠ 0`, stored and emitted (see
     [The application pointer](#the-application-pointer));
   - the paymaster reimburses `msg.sender` (the carrier): blob cost + execution cost + tip
     + proving subsidy (see [Paymaster](#externally-funded-publication-the-paymaster)).

4. **The root is final immediately.** There is no dispute window, no provisional state, no
   ratification, and no publisher bond. **New chunks are challengeable immediately**: a
   challenge grants a 7-day response window and consensus guarantees blob retrievability for
   18.2 days, so even a provider challenged in the same block as a declaration has a full week
   to fetch bytes that are guaranteed available. The response window *is* the ingestion grace.

### The application pointer

A single mutable `bytes32 appPointer` in instance state, which **the protocol never
interprets**. It exists because applications built on this substrate need a canonical,
cheaply-readable pointer to their current derived state — typically the digest of a CID for a
materialized current-state view — and because an immutable template cannot add one later.

- **Set on the final declaration of a batch.** A logical update spans many declarations (a
  42 MB update is ~56), and between the first and last the committed stream ends mid-record:
  derived state is incoherent. Carrying `appPointer = 0` on intermediate declarations and the
  real value on the last makes **batch completion an on-chain fact**, which is what consumers
  and materializers need in order to know when the stream is safe to interpret.
- **Standalone updates:** `setAppPointer(pointer, nonce, deadline, signature)` — the same
  signed-intent/carrier pattern on its own nonce space, paymaster-reimbursed, no blobs. Needed
  because a derived view can change without the data changing (a decoder fix re-materializes to
  a different CID), and the publisher holds no ETH and cannot self-submit.
- **Cost:** ~5k gas as a declaration field, ~50k standalone — negligible either way.
- **Trust status — an assertion, not a proof.** No circuit can verify that a derived view is a
  correct decoding of the committed stream; that is application logic outside the protocol. The
  pointer is signed by the publisher, so it proves *what the publisher asserted*, and lets a
  consumer detect a provider serving a stale or wrong view by comparing digests. It does **not**
  prove the view faithfully represents the data. The verifying path remains: fetch the stream,
  check it against the MMR root, derive locally. Consumers wanting a trust-minimized read should
  do exactly that; the pointer is a convenience and an integrity check against intermediaries,
  not a substitute for verification.
- **Protocol-inert:** nothing in enforcement, custody, challenges, slashing, or the paymaster
  reads it. A garbage pointer harms only consumers who trust it without verifying.

### The successor pointer

A write-once `address successor` in instance state, initially zero, settable exactly once by
the publisher via the same signed-intent/carrier pattern (`setSuccessor(target, nonce,
deadline, signature)` on its own nonce space, paymaster-reimbursed). Purely informational:

- **It is the migration breadcrumb** for the end-of-life cases this design accepts as the
  price of immutability — hardfork drift, proving-stack rot, an application-layer
  re-founding. The instance address is the dataset's identity (cited, pinned, hard-coded by
  consumers); when a successor deployment eventually exists, tooling resolving the old
  address discovers it mechanically, forever, instead of dead-ending.
- **It confers no authority and moves nothing.** No stake, obligation, challenge, or
  paymaster balance is affected. Providers and funders evaluate the successor exactly as they
  did the original — verify bytecode, verify data, then stake — and follow with their feet,
  or don't.
- **Write-once**, so a later-compromised signer cannot redirect an already-announced
  migration; a wrong pointer can only be corrected socially, which is where successor trust
  lives anyway.

### The equivalence proof

The statement binds the two commitment schemes — the blob's KZG polynomial commitment and the
MMR's keccak hash tree — over the same bytes, via a Fiat–Shamir random-evaluation argument:

- The contract derives the evaluation point
  `z = keccak(tag ‖ instanceAddress ‖ blobVersionedHashes ‖ priorPeaks ‖ newSubtreePeaks ‖
  priorLeafCount ‖ newLeafCount) mod r` (exact byte layout: `normative.md` §8; the instance
  address makes proofs instance-bound). Neither side of the equivalence can be chosen after
  `z` is known.
- **Blob side (native):** for each blob j, the point-evaluation precompile verifies
  `p_j(z) = y_j` against the blob's versioned hash, using the KZG opening proof supplied in
  calldata (50k gas per blob).
- **Tree side (SNARK):** π proves, with public inputs `(z, y_1..y_m, newSubtreePeaks,
  newLeafCount)`: *"there exist 31-byte chunks in canonical field-element form which (a) hash
  into exactly these subtree peaks under the MMR rules with this leaf count, and (b) for each
  blob j, barycentrically interpolated as 4096 field elements, evaluate to y_j at z."*

Two different polynomials of degree 4095 agree at a random point with probability ≈ 4096/r —
cryptographically negligible — so matching evaluations at `z` on both sides means the tree
peaks commit to exactly the posted blob bytes. A declaration for which no valid proof exists
cannot be submitted at all; guarantee 2 is unconditional.

**Costs:** SNARK verification ~300k gas + 50k gas per blob + append/logging logic. A 1-blob
declaration ≈ 420k gas (~$13 at reference prices); a full declaration at the L1
per-transaction blob cap (~6 blobs, ~762 KB) ≈ 670k (~$20). **An update larger than one
transaction's blob allowance is a batch of sequential declarations** — e.g. a 42 MB monthly
update is ~56 six-blob declarations ≈ 37M gas (~$1,125 at 10 gwei execution). Proving is a
zkVM workload of ~8k keccaks + one non-native BLS barycentric evaluation per blob — minutes
per declaration on
commodity hardware, subsidized by the paymaster. (A flat-cost batched verification path via
EIP-2537 is a deferred optimization; per-blob precompile calls are simpler and fine at the
design update rate.)

**Proof system — no protocol-run trusted setup.** Both circuits (equivalence and custody) are
proven in a transparent zkVM, then wrapped for cheap on-chain verification in a pairing-based
SNARK over BN254. The requirement (clarified 2026-07-29) is exactly this: **no ceremony is
ever run by or for this protocol** — any pre-existing, public, independently verifiable setup
is acceptable. There is a preference gradient among them: **universal public ceremonies**
(Aztec Ignition — 176 participants, 2019, consumed directly by SP1's gnark PLONK wrap; the EF
Perpetual Powers of Tau — OpenVM's halo2 wrap) are preferred, since they are the most widely
reused and one SRS covers both circuits and any successor deployment's circuits;
**pre-existing vendor-run circuit-specific Groth16 ceremonies** (RISC Zero 2024, 238
contributions; Succinct 2024, 18 participants) are acceptable fallbacks where benchmarks
justify them, at a step down in participant count and public reuse. Every candidate is a
one-honest-participant assumption, milder in kind than the EIP-4844 KZG-ceremony assumption
(~141k participants) already embedded in the point-evaluation precompile this protocol
depends on. **Selected (2026-07-29): SP1**, version pinned at contract freeze, with the
PLONK/Ignition wrap as default per the universal-setup preference (Groth16/Succinct-ceremony
as fallback should the feasibility spike reveal a compelling advantage). RISC Zero and OpenVM
remain documented fallbacks if SP1 fails the spike.

### Genesis: published through blobs, proven like everything else

> **Decision (2026-07-29):** genesis is published through ordinary blob declarations. The
> earlier out-of-band-snapshot design (constructor peaks + URL/SHA-256 manifest + a
> permissionless `proveGenesis` upgrade path) is superseded — its infeasibility argument
> ("years of contended capacity, $31k–$310k") predated the Fusaka BPO forks. Adopting blob
> genesis deletes `proveGenesis`, the manifest, the `genesisProven` flag, and the
> genesis-trust residue — and with them the hardest circuit (a recursive SHA-256 proof over
> gigabytes) that would otherwise have had to be built and audited *before deployment*, since
> verifying keys are immutable template constants.

- **The instance deploys empty** (no peaks, leaf count 0). The initial dataset arrives as a
  **genesis campaign**: an ordinary batch of sequential declarations, each carrying the
  equivalence proof. Every byte the contract ever commits to — genesis included — enters
  through the same proven path; guarantee 2 has no exceptions.
- **Feasibility (post-BPO2, Jan 2026 — blob target 14 / max 21 per block, ~100k blobs/day at
  target):** 5 GB ≈ 39,400 blobs ≈ ~6,600 six-blob declarations, drip-fed at 1–3 blobs/block
  over ~2–5 days with blob fees staying near the floor. The binding cost is execution gas,
  not blob gas: ~4.4B gas — **~$13k at 1 gwei basefee, ~$132k at 10 gwei** (schedule the
  campaign for a quiet fee regime) — plus ~6,600 equivalence proofs (a few GPU-days,
  embarrassingly parallel, generatable ahead of submission).
- **Funded outside the paymaster.** The token bucket (1.5 ETH / 30 d) is sized for steady
  state and deliberately does not cover a ~14–54 ETH campaign; pre-loading the paymaster for
  it would only raise the compromised-signer ceiling. The deploying community direct-funds
  the carrier(s) running the campaign. The publisher property is untouched: the multisig
  still only signs; carriers still submit.
- **Decide compression first.** The campaign is the single largest publication the dataset
  will ever make, and committed bytes can never be recompressed — a ratio-R codec divides
  blob count, declaration count, and execution gas by ≈R. See
  [Compression](#compression-deferred).
- **Batch semantics apply:** the campaign is one logical batch — `appPointer` is set on its
  final declaration, and the stream is interpretable only from that point.
- What no proof can establish is that the published bytes are the *socially right* data. That
  residue is irreducible and rests on public verification during and after the campaign,
  before providers stake.
- **Implied rate ceiling (steady state):** the design remains sized for growth of roughly
  **1–30 MB/day**. Faster-growing datasets need a different publication rail.

## Persistence layers (defense in depth)

1. **Ethereum consensus** — blobs are network-guaranteed for ~18.2 days.
2. **Public blob archives** — explorers and archivers retain history best-effort and
   permissionlessly; the on-chain versioned-hash log makes them usable for trustless recovery.
3. **Bonded storage providers** — the accountable layer: attesting on schedule, challengeable
   on demand, slashed on failure.

## Enforcement

Bonded providers carry two obligations. **Custody proofs** are the heartbeat — scheduled,
self-submitted, covering thousands of sampled chunks for ~$10/month. **Challenges** are the
on-demand lever — permissionless, adversary-priced, forcing named chunks onto the chain. The
health signal comes from the former; emergency retrieval and third-party spot-checks from the
latter.

### Challenges (single mode: challenger-named indices)

> **Design note (change from v1):** v1 had two modes, `challengeRandom` (on-chain randomness,
> the health signal) and `challengeChosen` (named indices, excluded from the signal because
> sham challenges could fake health). With mandatory custody proofs as the health signal,
> on-chain challenge randomness no longer serves a purpose: a challenger wanting statistical
> assurance simply samples indices client-side, and no reading of challenge history is needed
> for health. One mode remains: the challenger names the indices. All challenges are logged.

- **Open:** challenger names up to `maxSample` indices and posts the bond
  (`3 · (k · 38,680 + 21,000) · block.basefee`, [§3](#3-challenge-bonds-are-basefee-indexed)). The
  challenge pins the root and leaf count the provider is answerable for, so later declarations
  cannot invalidate a response in flight: the **current** root normally, or — if the provider
  has initiated unbonding — the **snapshot recorded at initiation** (an exiting provider owes
  nothing declared after that point; see [Provider lifecycle](#provider-lifecycle)). Named
  indices must be below the pinned leaf count.
- **Response:** within the **7-day response window**, the provider submits the named chunks
  with MMR inclusion proofs against the pinned root. This path is deliberately SNARK-free —
  plain keccak and calldata — so it works forever regardless of any proving-stack failure.
- **Provider answers →** the bond is forfeited **to the provider**, covering response gas with
  margin. Challenge spam is just paying providers.
- **Provider times out →** the resolution transaction (callable by anyone, self-funding) pays
  the **bounty fraction (15%)** of the stake to the challenger and sends the **remainder (85%)
  to the instance's paymaster endowment** (v1 burned it; under the altruism assumption the
  anti-collusion rationale for burning is moot, and failures funding future publication is the
  better loop). There is no "invalid proof" slash — an invalid response simply fails to satisfy
  the challenge.
- If the provider was already slashed when a challenge would resolve, the challenger's bond is
  **refunded** — watchdogs are not punished for piling onto a dying provider.
- Challenge economics: +EV iff `P(provider fails) > bond/bounty` ≈ 3.3% as sized
  ([§6](#6-provider-stake-and-bounty-fraction)) — a tunable suspicion threshold. Blind
  challenging is a donation; informed challenging is profitable. With custody proofs carrying
  routine assurance, challenges are expected to be rare: exit-window final checks, follow-ups
  on stale custody flags, and forced retrieval of specific chunks.

### Custody proofs (the heartbeat)

Every bonded provider must, once per **custody period (30 days)**, prove possession of
`k = 16,384` pseudo-randomly sampled chunks. Periods are anchored per-provider at stake time.

**Flow — two transactions, both the provider's own; no external caller anywhere:**

1. **`beginProof()`** — the provider's first call in a period snapshots
   `(seed = block.prevrandao, root, leafCount)` (~45k gas). **One commit per period; the first
   is binding.** The seed cannot be re-rolled.
2. Off-chain, the provider derives indices `idx_j = H(tag ‖ instance ‖ seed ‖ providerId ‖
   j) mod leafCount` (exact byte layout: `normative.md` §9), reads those chunks from disk,
   regenerates their Merkle paths (top levels cached,
   ~2.5 MB; bottom levels recomputed from raw data — an incidental check that the disk still
   reads), and proves in-circuit: *"I know chunks and paths at exactly these indices verifying
   against this root."* Public inputs: `(root, leafCount, seed, providerId, k)`. ~475k
   in-circuit keccaks ≈ under an hour on one consumer GPU.
3. **`submitProof(π)`** — verified on-chain (~330k gas ≈ $10) before the period deadline.

The provider-identity and instance-address salts in the index derivation are load-bearing:
without them, one proof per period could be shared by every provider on the instance — or
across instances of the same dataset that pin the same root and seed (prevrandao is
chain-global, so two instances' periods can share a seed).

**Escape hatch (SNARK-free forever):** a provider may instead satisfy any period by revealing
the first `maxSample` (32) seed-derived chunks raw on-chain with inclusion proofs — the
challenge-response path applied to the period seed (~1.26M gas ≈ $38). Degraded assurance for
that period, flagged as such — and against a deliberately grinding provider, no assurance at
all (see the seed-timing residual below) — but it means no proving-toolchain failure, verifier bug, or
hardware problem can ever march providers into deadline slashes. The deadline is satisfiable
with keccak and calldata alone, indefinitely.

**Misses:** one missed period → the provider is flagged **stale** (informational, free to
read). Two *consecutive* missed periods → the provider becomes **lapse-eligible**, which opens
a **7-day cure grace**: during the grace, `lapse()` cannot yet be called, and the provider can
clear the counter entirely by submitting any valid proof (SNARK or escape hatch). The grace is
what makes cure real rather than rhetorical — without it, the 0.3 ETH `lapse()` bounty would
be claimed by a bot in the first eligible block and no returning provider could ever beat it.
Once the grace expires uncured, the stake is forfeit: anyone may call `lapse()`, which pays
the caller the bounty fraction (15%) and sends the remainder to the paymaster endowment.
**Initiating unbonding cancels lapse eligibility** — the stake punishes failing to exit
properly, and a provider mid-exit remains fully challengeable, which is the appropriate final
check (stale flags are public; a watchdog suspicious of an exiting stale provider challenges
it during the exit window). `lapse()` is one-shot cleanup, not periodic work; nothing anywhere
in the protocol requires a scheduled external caller.

**During unbonding:** no new custody period starts after unbonding is initiated, and any
pending lapse eligibility is cancelled (above); challenges cover the exit window.

**What custody proofs buy** ([§4](#4-detection-math)): a monthly k = 16,384 proof detects loss
of 0.1% of a 10 GB dataset with ~100% probability per period, 1 MB of loss at ~81% per period,
and a single lost blob (ρ ≈ 1.3×10⁻⁵) at ~19% per period — >90% within a year — all for ~$10
of gas. The v1 challenge-only design priced single-lost-blob detection at ~$160,000. The
"silent decay" non-guarantee of v1 is closed by mechanism, not by hoping watchdogs stay funded.

**Accepted residual — seed timing:** `prevrandao` is known one slot ahead, and the provider
chooses when to call `beginProof`, so a *malicious* provider can shop for a favorable seed.
The two proof paths differ sharply:

- **SNARK path (k = 16,384):** over a 30-day window (~216k candidate blocks), grinding only
  helps while `(1−ρ)^k > 1/216,000`, i.e. **ρ below ~0.08%**; loss above 0.1% has per-seed
  pass probability ~10⁻⁷ and no amount of timing helps.
- **Escape hatch (k = 32): grindable at any ρ.** Even at 20% loss, each candidate seed passes
  with probability 0.8³² ≈ 0.08% — thousands of passing blocks per window. A provider willing
  to lie can therefore satisfy every period via the hatch while missing arbitrarily much data.
  This is accepted deliberately: the hatch exists for slash-protection under toolchain
  failure, not for assurance, and hatch-satisfied periods are flagged **degraded** on-chain
  precisely so that health readers assign them no evidentiary weight against a malicious
  provider.

An honest-but-decayed provider — the actual threat model — has no reason to time anything.
(Hardening would derive the seed from a block *after* the commit — a later blockhash, or that
block's `prevrandao` extracted via a header-preimage proof against EIP-2935, which serves
historical block **hashes**, not prevrandao values — at the cost of a tighter two-step
submission dance; deliberately not spent, per the altruism assumption.)

### The health signal

For each bonded provider the chain exposes, as view-only state: last proven period, degraded
(escape-hatch) flags, stale flag, and full challenge history with named indices. "Is this
dataset healthy" = "did every bonded provider prove custody recently" — an objective fact
requiring no transaction, no watchdog budget, and no interpretation of challenge provenance.

## Provider lifecycle

- **Mirror tier:** emit `announce(url)` / `retract()` events for discovery. No stake, no
  obligations, no protocol standing. Mirrors are how helpful parties contribute without opting
  into financial accountability.
- **Bonded — join:** fetch the dataset out-of-band (from a provider, mirror, or any public blob
  archive using the on-chain log as manifest), verify the full set against the on-chain root,
  post the stake (2 ETH), declaring an **operator address** and a **withdrawal address** (see
  Keys, below). The first custody period starts at stake time. Ongoing: watch L1 and
  ingest each update — blobs are consensus-guaranteed for 18.2 days, so ingestion is an
  operational habit, not a protocol window.
- **Serve:** submit custody proofs on schedule; answer challenges within the response window.
- **Keys — validator-style separation:** the daemon's duties require an automated, funded hot
  key on the server, so that key must not control the money. The **operator address** (hot)
  signs everything routine — `beginProof`, `submitProof`, challenge responses — and may also
  initiate unbonding, so winding down never requires cold storage. The **withdrawal address**
  (cold), fixed at stake time, is the only destination the stake can ever be paid to. A
  compromised daemon server can therefore at worst force an exit or cause slashable neglect —
  it can never redirect the 2 ETH.
- **Exit (two-step, bounded):** initiate unbonding as a public on-chain event; remain
  challengeable for the **unbonding delay (14 days)**; withdraw after the delay once all open
  challenges resolve. Three rules make exit sound *and* bounded:
  1. obligations extend only to roots declared **before** unbonding was initiated — enforced
     mechanically: initiation snapshots `(root, leafCount)`, and every challenge opened
     against the provider thereafter pins that snapshot rather than the current root, so an
     exiting provider can never be slashed over data it never owed;
  2. **no new challenge may be opened after the delay expires** — so exit completes within
     delay + response window (≤ 21 days) no matter what, and a griefer cannot hold a provider's
     stake and storage obligation hostage with $3.50/week of rolling challenges;
  3. withdrawal is blocked while any challenge opened in-window is unresolved — this, not the
     delay itself, is the safety property; the delay guarantees watchdogs a window to pose a
     final challenge (and be refunded if someone else's challenge already slashed the exiting
     provider). Withdrawal always pays the withdrawal address, regardless of caller.

## Verification by anyone

To verify a chunk they hold, a party checks an MMR inclusion proof against the on-chain root
(bagged peaks). No provider and no publisher need be trusted or online. This remains the
protocol's answer to bit-rot: consumers verify what they read, for free, and re-fetch bad
chunks from another source.

## Updates

Append-only. Revision and deletion are application-level tombstones (see
[The application layer](#the-application-layer-non-normative)); the protocol only ever appends
and bytes are never removed. Providers fetch only the newly appended chunks per update.
Each bonded provider stores and answers for the **entire dataset** (no sharding in v1).
Unbounded growth is accepted: providers are altruistic and storage is the cheap part.

## The application layer (non-normative)

Everything below sits **outside the protocol's trust boundary**. The contract enforces none of
it and has no knowledge of any of it; the protocol commits an opaque ordered stream of 31-byte
chunks and stops there. This section is included because the protocol is unusable without a
disciplined application layer, and because several application-layer choices become
**irreversible the moment data is committed** — an append-only stream under an immutable
contract forgives no format mistakes. These are design conclusions and their rationale, not
requirements the chain can check.

The layer has three jobs: **encode** a source dataset into the chunk stream, **decode** the
stream back into the publisher's artifact format, and **distribute** the result. Different
applications have entirely different semantics, so the recommended split is a **generic
container library** (framing, batching, indexing, tombstones, chunk mapping — identical for
every dataset) plus a thin **per-application codec** (schema, validation, artifact layout).
Without that split every application reimplements framing and gets torn-batch or tombstone
replay subtly wrong, permanently.

### Process separation: keep the application out of the slashing path

A bonded provider is slashed if it fails to answer a challenge within the response window, and
lapses after two missed custody periods. If the component that answers challenges shares a
failure domain with application code, an ordinary parsing bug on malformed input becomes a
stake loss. So a provider implementation should be **two isolated processes**:

- **Storage daemon — protocol-critical, application-agnostic.** Follows L1, ingests blobs,
  verifies against the root, maintains the canonical local store, answers challenges, produces
  custody proofs. It treats every byte as opaque and **must never parse a record.**
- **Materializer — application-specific, crash-isolated.** Reads a read-only snapshot of the
  chunk stream, decodes, writes the artifact view, publishes to the distribution layer. If it
  dies, the stake is untouched and the data is still served.

The **canonical local store should be a flat file with chunk *i* at offset 31·*i***. Custody
proving needs random reads of thousands of arbitrary chunks plus a full hash pass to regenerate
the lower tree levels; an application-native database or a remote content-addressed store as
the working copy makes that impractical within the window. Every other artifact — decoded view,
indexes, distribution blocks — is derived and rebuildable. Budget roughly 2–2.5× dataset size
on disk.

### Container format

The protocol supplies no framing whatsoever, so the container is entirely the application's
responsibility. The pieces that experience says are mandatory:

- **Header record** at stream position 0: magic, container version, codec ID, schema ID.
- **Length-prefixed, self-delimiting records.** A record will freely straddle chunk, blob, and
  declaration boundaries; nothing in the protocol aligns to record structure.
- **Batch manifest record** terminating every logical update (see next subsection).
- **Periodic full index snapshots.** Because deletion is by tombstone, computing the live set
  is a full replay by construction. A full index every N batches turns cold start into "read
  the last index, then the batches after it" instead of replaying all history.
- **A codec ID in every batch manifest**, even when only one value is ever written. This is the
  hook that keeps encoding decisions reversible; see [Compression](#compression-deferred).
- **A reserved record type for codec dictionaries**, even if unused.
- **Explicit version discipline:** decoders must refuse unknown major versions loudly rather
  than guess. There is no way to fix a mis-decoded artifact after the fact except by appending
  a correction.

**Optional alignment.** Padding records — or at least batches — to 31-byte chunk boundaries
costs ~15 bytes per record on average and buys a clean map from record to contiguous chunk
range. That is what makes "prove you hold record X" expressible as a challenge, and it is the
precondition for the deferred range-challenge feature to be usable at the application level.
Worthwhile for large records, wasteful for very small ones; decide once, permanently, per
application. Aligning batches to whole blobs additionally makes blob-level recovery and
content-addressed chunking line up.

### Batch atomicity versus declaration finality

**This is the interaction most likely to be missed.** The protocol finalizes state **per
declaration**, but application semantics are **per batch**. Any update larger than one
transaction's blob allowance is many sequential declarations; between the first and the last,
the root is final and challengeable while the committed stream ends mid-record. A materializer
that naively decodes to the current leaf count will produce torn output.

Two mechanisms resolve it, and an implementation should use both:

1. **In-stream:** the batch manifest is the commit marker. Materialize only up to the last
   complete manifest.
2. **On-chain:** the publisher sets [`appPointer`](#the-application-pointer) on the final
   declaration of a batch and leaves it zero on intermediate ones, making batch completion an
   objective on-chain fact that requires no stream parsing to observe.

### Revision, deletion, and monotonic growth

The protocol never removes or rewrites a byte, so revision and deletion are **application-level
tombstones**: to revise, append a new version; to delete, append a tombstone referencing the
target. Current state is what a consumer computes by replaying the stream with later records
superseding earlier ones. Consequences worth stating plainly to anyone adopting this:

- **Storage is monotonic.** Superseded and deleted bytes are stored, custody-proved, and
  challengeable forever. A revision-heavy dataset grows by its churn, not by its live size, and
  churn consumes the publication rate ceiling like any other data.
- **History is permanent and provable.** Prior versions remain provable forever. For some
  applications that is the point; for others it is a hazard.
- **Nothing can be expunged.** Content that must legally or ethically disappear cannot be
  removed. The only remedy is ceasing to serve it and, in the limit, a successor deployment
  with a re-founded dataset. Adopters must accept this before publishing.

### Deterministic decoding

If the requirement is **byte-exact reproduction** of artifacts an existing pipeline already
publishes, that imposes a condition upstream: the artifact layout must be a **pure function of
the current record set**. The usual things that break it:

- record ordering taken from storage-engine return order rather than a stable sort key;
- generation timestamps, version banners, or counts embedded in artifact headers;
- non-canonical number formatting, key ordering, trailing newlines, line endings;
- **compressed wrappers**, which typically embed an mtime and encoder-dependent output, making
  byte-exactness a claim about the compressor rather than the data.

Three options when a pipeline is not deterministic: make it canonical at the source (best);
define byte-exactness against the **uncompressed** artifact and treat any wrapper as a
regenerable distribution detail (good pragmatic middle path); or commit whole artifact
snapshots rather than deltas, which achieves byte-exactness trivially and destroys the
economics, since every release re-publishes the entire dataset.

Whatever the choice, **embed the expected digest of each materialized artifact in the batch
manifest**. Because those digests are inside the committed stream, any party can verify that
their locally materialized output is exactly what the publisher intended — turning decoder
drift, version skew, and silent divergence between providers from an undetectable class of bug
into a one-line check, without trusting anyone.

### Distribution

Content-addressed distribution networks are the natural mirror layer, and the recommended shape
is two tiers:

- **Per-blob pinning as the canonical tier.** Blob contents are immutable, so each blob's
  content address is stable forever, dedups perfectly across providers, and maps one-to-one
  onto the on-chain versioned-hash log — the recovery manifest becomes an address list.
- **Materialized view snapshots as a convenience tier**, republished per batch, located via
  [`appPointer`](#the-application-pointer).

Three cautions. **Content addresses must be reproducible:** they depend on chunker, layout,
address version, and hash function, so an exact profile has to be pinned in the format spec or
two honest providers will publish different addresses for identical data and lose both dedup
and cross-checking. **The distribution layer is not the working copy:** its random-read latency
makes custody proving and challenge response infeasible on that path. And **mirroring makes the
outsourcing non-guarantee easier to exercise** — a provider can satisfy obligations by fetching
from someone else's copy — which is consistent with the stated trust model but should be
understood rather than discovered.

**Consumers should verify by default.** Fetching a view by pointer and trusting it is a
publisher-trust operation; the trust-minimized path is fetch stream → verify against the root →
decode locally, optionally confirming the result against the digests in the batch manifest. A
materializer implementation should verify as its default behavior and require an explicit flag
to skip.

### Compression (deferred)

Compression is an application-layer transform applied **before** chunking: the committed stream
is the compressed bytes and the protocol never knows. It is deliberately **not used in v1** —
it adds dictionary lifecycle management and a format dependency before the core protocol is
settled — but the container **must reserve the hooks described above** (per-batch codec ID, a
dictionary record type), because compression is a per-batch property and raw and compressed
batches can then coexist in one append-only stream forever. With the hooks, enabling
compression later is a new codec ID in new batches; without them it is a container migration
that can never be applied retroactively.

The economics, stated generically: every publication cost scales with committed bytes, so a
compression ratio R divides blob fees, declaration count, and the dominant per-declaration
verification gas by approximately R, and multiplies the sustainable data rate by R. Ratios are
entirely dataset-dependent and should be measured, never assumed. Two consequences shape *when*
to enable it: bytes already committed can never be recompressed, so any delay is permanently
sunk for data published in the meantime; and — with genesis now published through blobs — the
single largest publication happens at launch, so **the compression decision must land before
the genesis campaign, not after**: 5 GB raw is ~39,400 blobs and ~$13k–$132k of execution
gas, both divided by ≈R under a ratio-R codec.

When revisited, the dictionary guidance is: **commit dictionaries in-stream, never in contract
state** (contract storage costs roughly two orders of magnitude more, can exceed a block's gas
limit for a typical dictionary, and buys nothing — a dictionary without its dataset is
worthless, whereas in-stream it is covered by the root, the equivalence proof, and every
custody proof). **Dictionaries should be append-only, not one-time:** encoders reference them
by ID per frame, corpora drift, and an immutable template cannot add the capability later. The
cost is that **every dictionary ever used must be retained forever**, since replay decodes
historical batches — a bookkeeping requirement rather than a meaningful storage cost.

## Externally funded publication (the paymaster)

Publication is the one recurring cost the protocol cannot make free: it costs real money —
blob + execution + proving, roughly $1k–$18k/yr at the design profile
([§9](#9-paymaster-sizing)) — and, in the carrier model, someone must front it. For a
public-good dataset the natural funders are its beneficiaries. The template ships a
**paymaster**: an immutable, permissionlessly fundable contract that reimburses publication
costs, and whose lack of funds is simply a no-op.

**Deployed by the instance, bound one-way.** The instance's constructor deploys
`new Paymaster(address(this))` — atomic binding, no governance, no chicken-and-egg. Anyone
funds it by sending ETH.

**Reimburses the carrier, not the publisher.** At the end of a successful `declareFor` — after
all state changes, behind a reentrancy guard, via a gas-capped call whose failure is ignored —
the instance asks the paymaster to pay `msg.sender`:

- **Blob cost** = `numBlobs × 131,072 × block.blobbasefee` (EIP-7516 exposes the blob base fee).
- **Execution cost** = `(measuredGas + FIXED_OVERHEAD) × block.basefee`.
- **Carrier tip** = fixed (0.0002 ETH per declaration) — what makes permissionless carriage
  worth racing for.
- **Proving subsidy** = fixed (0.0005 ETH per declaration) — covers GPU time for the
  equivalence proof, claimable by the carrier (who either proved or paid the prover for the
  payload). Both constants are sized for batch cadence: across the ~6,600 declarations of the
  full 5 → 10 GB growth they total ~4.6 ETH. (The earlier daily-update sizing of 0.0015
  ETH/declaration would have cost 9.8 ETH lifetime — nearly double the blob fees themselves.)

Priced at **`block.basefee`, never `tx.gasprice`** — otherwise a carrier could self-deal an
enormous priority fee through a colluding builder and drain via the tip channel. Anything above
the fixed allowances is the carrier's own cost. Blob gas carries no priority fee and is burned,
so donated funds are never captured by a validator. If the paymaster is unfunded or reverts,
nothing happens — the carrier simply ate the cost (which is why carriers simulate solvency
before submitting). **Publication never depends on the paymaster.** Push-with-pull fallback for
transfer failures.

**Rate limiting bounds a compromised publisher.** The signer chooses what gets published, so
the paymaster immutably enforces a **token bucket (0.05 ETH/day, 30-day cap of 1.5 ETH)** —
the on-chain expression of the design range. The 30-day cap is sized so a monthly publication
batch (10–100 MB ≈ 14–132 declarations ≈ 0.1–1.1 ETH all-in) is reimbursable in one burst; no
protocol-side per-declaration blob cap is needed, since the L1 per-transaction blob limit (~6)
already bounds each declaration. During a blob-fee spike the bucket drains and carriage stops
being reimbursed, which is the intended degradation: the endowment is not emptied at the worst
price. Maximum drain by a fully malicious signer: **18.25 ETH/yr**, unchanged by the larger
cap.

**Slash inflows.** The 85% remainder of any provider slash (challenge timeout or custody lapse)
flows into the paymaster, recycling failure into publication runway.

**Donations are irrevocable, with a dormancy escape:** if fewer than **32,768 chunks (~1 MB)**
of new data are declared over **365 days**, funders may reclaim pro-rata
(`balance × contribution / outstanding`). The threshold is measured in appended chunks, not
transaction count, so a dust declaration cannot reset the clock and strand donors behind a
zombie publisher; real publication at the design profile clears the bar by 10–100×.
Mechanically: a rolling activity checkpoint `(t₀, leafCount₀)` advances to the current block
whenever ≥ 32,768 chunks have been appended since it, and reclaim opens once the checkpoint
is older than 365 days. Not a withdrawal-at-will facility.

**Strictly non-load-bearing.** The paymaster can only pay ETH to carriers. It cannot touch
roots, stakes, challenges, or slashing; worst case is wasted donor funds, capped by the rate
limit. Every payout is exactly recomputable by donors from public quantities.

---

# Parameter sizing

Reference assumptions, stated so figures can be re-run when they move:

| Assumption | Value |
|---|---|
| Dataset size | 10 GB (scaling in [§8](#8-sensitivity-to-dataset-size)) |
| Design profile | 5 GB blob-published genesis → 10 GB eventual; ~monthly update batches of 10–100 MB |
| ETH price | $3,000 |
| Execution basefee | 10 gwei |
| Calldata cost | 40 gas/byte (EIP-7623 floor; proof data is effectively all non-zero) |
| Point-evaluation precompile | 50,000 gas |
| SNARK verification (BN254 wrap: PLONK ~300k / Groth16 ~270k) | ~300,000 gas incl. calldata |
| Blob | 4096 field elements = 126,976 usable bytes; 131,072 blob-gas |
| Blob retention | 4096 epochs = **18.2 days** |

## 1. Chunk size: 31 bytes

Detection probability depends on the *number* of chunks sampled, not their size, so the right
objective for the on-chain reveal path is bytes per sampled chunk:
`f(c) = c + 32·log₂(N/c)`, minimized at `c = 32/ln 2 ≈ 46 B`. For N = 10 GB:

| Chunk size | Tree depth | Proof | Bytes/sample (incl. 8 B index) |
|---|---|---|---|
| **31 B (1 field element)** | 29 | 928 B | **967 B** |
| 124 B | 27 | 864 B | 996 B |
| 512 B | 25 | 800 B | 1,320 B |
| 4 KB | 22 | 704 B | 4,808 B |

31 B sits essentially at the optimum, and three structural properties break the tie decisively:

1. **Leaf = field element.** The equivalence circuit maps blob elements to MMR leaves with no
   repacking layer — the cheapest possible statement, and the deterministic chunk↔blob mapping
   needs no extra bookkeeping.
2. **Anti-compression.** Leaf hashes (32 B) are larger than chunks (31 B), so storing hashes
   instead of data is never a saving — custody sampling therefore evidences possession of the
   actual bytes (modulo outsourcing, see non-guarantees).
3. Providers regenerate proof paths from raw data on demand (a full keccak pass over 10 GB is
   minutes, against a 7-day window; custody proving caches only the top ~2.5 MB of the tree)
   rather than storing a tree larger than the dataset.

## 2. Challenge response cost model

Per revealed chunk: 31 B data + 928 B proof + 8 B index = 967 B → **38,680 gas**.

| Sample size *k* | Response gas | Bond at 3× (10 gwei) | USD |
|---|---|---|---|
| 4 | 176k | 0.0053 ETH | $16 |
| **8 (typical)** | **330k** | **0.0099 ETH** | **$30** |
| 16 | 640k | 0.0192 ETH | $58 |
| 32 (`maxSample`) | 1.26M | 0.0378 ETH | $113 |

`maxSample = 32` caps a single response at ~1.26M gas, comfortably inside the block limit.

## 3. Challenge bonds are basefee-indexed

`requiredBond = 3 · (k · 38,680 + 21,000) · block.basefee`, computed at challenge time —
38,680 gas per revealed chunk plus the 21,000-gas base transaction cost of the response
(omitting the base cost under-covers the response by ~6% at k = 8).

The rationale is **compensation fairness, not incentive-compatibility** (v1 misstated this): a
rational provider always answers regardless of bond size, because the slash (2 ETH) dwarfs
response gas even at 1000 gwei (~0.33 ETH at k=8). Indexing exists so the forfeited bond
actually covers the provider's real cost with margin at prevailing prices — neither
under-compensating providers during fee spikes nor over-charging challengers during lulls. The
3× margin covers drift between challenge and response; the 7-day window doubles as a gas-spike
waiting room (the weekly minimum basefee is reliably far below any instantaneous spike).

## 4. Detection math

**Custody proofs (primary, scheduled).** A provider missing fraction ρ passes a k-sample proof
with probability `(1−ρ)^k ≈ e^(−kρ)`. Per monthly proof at k = 16,384:

| Loss ρ | Meaning at 10 GB | Detection / period | Within a year |
|---|---|---|---|
| 1% | 100 MB | ~100% | — |
| 0.1% | 10 MB | ~100% (1−e⁻¹⁶) | — |
| 10⁻⁴ | 1 MB (~8 blobs) | 80.6% | ~100% |
| 2.5×10⁻⁵ | one blob at 5 GB (initial size) | 34.0% | 99.3% |
| 1.3×10⁻⁵ | one blob at 10 GB | 18.8% | 92% |

On-chain cost is flat (~$10/period) regardless of k; k is a nearly free knob paid in provider
GPU-time (4× k ≈ 4× proving time, same gas). The v1 economics — $16/ρ of challenge bonds for
99% confidence, blind below ρ ≈ 0.1%, $160k to catch one lost blob — are obsolete for bonded
providers.

**Challenges (secondary, permissionless).** For third parties who won't wait for the custody
schedule or don't trust it: at $3.48 per sampled chunk (bond at k=1 equivalent), a challenge
campaign reaching confidence P costs **≈ $8/ρ at 90%, ≈ $16/ρ at 99%** — unchanged from v1,
now needed only for spot-checks, exit windows, and stale-flag follow-ups rather than routine
assurance.

Neither mechanism converts possession into *personal* storage (outsourcing, see
non-guarantees), and application-layer erasure coding does not close contiguous-loss gaps
(one lost 1 MB batch in 10 GB is still ρ = 10⁻⁴).

## 5. Windows & periods

| Window | Value | Binding constraint |
|---|---|---|
| **Response** | **7 days** | On-call reality (a weekend plus a working week) + the gas-spike waiting room of [§3](#3-challenge-bonds-are-basefee-indexed). Also the effective ingestion grace: blobs are retrievable from consensus for 18.2 d > 7 d, so chunks are safely challengeable from the moment of declaration. |
| **Unbonding delay** | **14 days** | ≥ response window + watchdog notice margin; exit is hard-bounded at delay + response window = 21 d by the no-new-challenges-after-expiry rule. |
| **Custody period** | **30 days** | Monthly ops cadence; staleness is visible at +30 d, lapse-eligible at +60 d (two consecutive misses), executable after a further 7-day cure grace. Anchored per provider at stake time. |
| **Lapse cure grace** | **7 days** | Makes cure-before-lapse real: without it, the 0.3 ETH `lapse()` bounty is botted in the first eligible block. `lapse()` uncallable during the grace; cancelled entirely by unbonding initiation. |
| **Declaration deadline** | per-intent | Signed into each declaration; an unsubmitted intent expires harmlessly. |

The v1 **dispute window is gone** — nothing is provisional. The only consensus-derived timing
constraint left is operational: providers should ingest updates within the 18.2-day blob
retention or fall back to public archives.

## 6. Provider stake and bounty fraction

The stake is a **negligence bond**, not a replacement-cost bond: an honest provider can always
exit free via unbonding, so the stake only punishes failing to exit properly — losing data
unnoticed, or going dark. It should exceed the multi-year cost of attentive operation
(monitoring, redundancy, timely response ≈ $100–500/yr), not the storage cost. **2 ETH
(~$6,000)** makes negligence clearly net-negative over a 3-year horizon and does not scale with
dataset size.

**Bounty fraction 15%** (0.3 ETH ≈ $900): sets the challenge suspicion threshold at
`bond/bounty ≈ 3.3%` for a $30 bond, trivially exceeds resolution gas so slashes always
execute, and applies identically to `lapse()` callers. The **85% remainder flows to the
paymaster endowment** (v1 burned it): with malicious-provider collusion assumed away, recycling
slashes into publication runway strictly beats destroying the value. No party can extract it —
the paymaster only ever pays cost-priced, rate-limited carriage.

## 7. Publication throughput: the binding constraint

Unchanged from v1. Blob gas per blob is 131,072 — $0.39 at 1 gwei blob basefee, spiking
readily to 10× that.

| Data | Blobs | Cost @1 gwei | Cost @10 gwei | Days @100 blobs/day |
|---|---|---|---|---|
| 1 MB | 8 | $3 | $31 | 0.08 |
| 1 GB | 7,876 | $3,100 | $31,000 | 79 |
| 10 GB | 78,755 | $31,000 | $310,000 | 788 |

Network capacity is target 14 / max 21 blobs per 12-second block (post-BPO2, Jan 2026), shared
with every rollup. Hence: genesis is a one-time multi-day drip campaign near the blob-fee floor
([Genesis](#genesis-published-through-blobs-proven-like-everything-else)), and the sustainable
steady-state update rate is **~1–30 MB/day** ($1k–$34k/yr of blob fees at 1 gwei; execution
and tips add a comparable amount or more — see [§9](#9-paymaster-sizing)).

## 8. Sensitivity to dataset size

Tree depth varies logarithmically; on-chain costs are remarkably flat:

| Dataset | Chunks | Depth | Bytes/sample | Response gas (k=8) | Custody proving (k=16,384) |
|---|---|---|---|---|---|
| 1 GB | 32.3M | 25 | 839 B | 289k | ~0.9× reference |
| **5 GB (initial)** | 161M | 28 | 935 B | 320k | ~0.97× reference |
| 10 GB | 323M | 29 | 967 B | 330k | reference (~1 GPU-hour) |
| 100 GB | 3.2B | 32 | 1,063 B | 361k | ~1.1× reference |

Custody proving scales with k × depth (in-circuit) plus a raw-disk sampling pass — near-flat in
dataset size. On-chain custody verification is exactly flat. The binding constraint at scale
remains publication throughput ([§7](#7-publication-throughput-the-binding-constraint)).

## 9. Paymaster sizing

Reimbursement is **blob fees + execution gas + tip/subsidy**, and at the design profile blob
fees are the *small* term (~10%): execution gas for the per-declaration SNARK verification
dominates. (An earlier revision sized the endowment on blob fees alone, understating costs
~4–10×.)

Daily budget **0.05 ETH/day** ($150), 30-day bucket cap **1.5 ETH**. Blob-fee headroom alone
at that rate:

| Blob base fee | Blobs/day funded | Data/day funded |
|---|---|---|
| 1 gwei | ~380 | 48 MB |
| 10 gwei | 38 | 4.8 MB |
| 100 gwei (spike) | 3.8 | 0.5 MB |

**Monthly batch cost, all-in** (blob basefee 1 gwei; tip + subsidy 0.0007 ETH/declaration):

| Update size | Blobs | Declarations | Total @1 gwei exec | Total @10 gwei exec |
|---|---|---|---|---|
| 10 MB | 79 | 14 | 0.030 ETH ($89) | 0.114 ETH ($342) |
| 42 MB | 331 | 56 | 0.120 ETH ($360) | 0.458 ETH ($1,373) |
| 83 MB | 654 | 109 | 0.235 ETH ($705) | 0.892 ETH ($2,677) |

Every design-profile batch fits inside the 1.5 ETH bucket cap in one burst. During fee spikes
the bucket drains and carriage degrades to unreimbursed (the publisher's community must then
decide whether publication is worth spot prices — the correct question to force). **Max
malicious drain: 18.25 ETH/yr** (~$55k), unchanged by the larger cap. Dormancy: ≥ 32,768
chunks (~1 MB) per 365 days — trivially satisfied by monthly cadence (one 10 MB batch is
~10× the bar). `maxPriorityFeeReimbursed`: dropped — carriage is
priced at basefee + fixed tip; priority is the carrier's bid from its own margin.

**Endowment sizing (design profile, all-in):** growing 5 GB → 10 GB is ~39,400 blobs ≈ 6,563
declarations lifetime, costing **~14 ETH ($43k) at 1 gwei execution basefee to ~54 ETH
($161k) at 10 gwei** (blob 5.2 ETH + execution 4.4–44 ETH + tip/subsidy 4.6 ETH). Reaching
10 GB over 5–10 years at monthly cadence: **plan 10–30 ETH ($30k–$90k) per 5 years** depending
on realized gas prices. Slash inflows extend runway. The genesis campaign (another ~39,400
blobs ≈ ~14–54 ETH) is funded separately, outside the paymaster
([Genesis](#genesis-published-through-blobs-proven-like-everything-else)).

## 10. Recommended parameter set

| Parameter | Value | Basis |
|---|---|---|
| Chunk size | **31 B** (template constant) | [§1](#1-chunk-size-31-bytes) |
| Equivalence + custody vkeys | template constants (BN254 wrap over a pre-existing setup) | audited once, identical in every instance; no protocol ceremony |
| Provider stake | **2 ETH** | [§6](#6-provider-stake-and-bounty-fraction) |
| Provider keys | operator (hot) + fixed withdrawal (cold) | server compromise ⇒ forced exit at worst, never stake theft |
| Custody period | **30 days**, per-provider anchor | [§5](#5-windows--periods) |
| Custody sample k | **16,384** | [§4](#4-detection-math); on-chain cost flat in k |
| Custody miss policy | 1 miss = stale; 2 consecutive = lapse-eligible after **7-day cure grace** | grace blocks `lapse()`; any valid proof cures; unbonding cancels eligibility |
| Custody escape hatch | raw reveal of 32 seed-derived chunks | SNARK-free forever, ~$38 |
| Min challenge bond | **3 · (k · 38,680 + 21,000) · basefee** | [§3](#3-challenge-bonds-are-basefee-indexed) |
| `maxSample` | **32** | [§2](#2-challenge-response-cost-model) |
| Response window | **7 days** | [§5](#5-windows--periods) |
| Bounty fraction | **15%**; 85% → paymaster | [§6](#6-provider-stake-and-bounty-fraction) |
| Unbonding delay | **14 days**; no new challenges after expiry | [§5](#5-windows--periods) |
| Paymaster daily budget / cap | **0.05 ETH/day / 1.5 ETH (30 d)** | [§9](#9-paymaster-sizing) |
| Per-declaration blob cap | L1 per-tx blob limit (~6) | no protocol cap needed |
| Carrier tip / proving subsidy | **0.0002 / 0.0005 ETH** per declaration | [§9](#9-paymaster-sizing) |
| Dormancy reclaim | **< 32,768 chunks (~1 MB) appended per 365 days** | [§9](#9-paymaster-sizing); chunk-denominated so dust cannot block reclaim |

**Expected steady-state economics (10 GB, 3 bonded providers, monthly custody proofs):**
each provider pays ~$135/yr in custody gas + ~$25/yr of GPU time — self-funded assurance with
no watchdog budget required (v1 needed ~$4,600/yr of beneficiary-funded challenges for far
weaker coverage). Publication: ~$1k–$18k/yr at the design profile (10–42 MB/month, execution
basefee 1–10 gwei), borne by the paymaster where funded.
Capital locked: 2 ETH per provider. Publisher capital: **zero** — no bond, no gas, ever.

---

## Trust assumptions & non-guarantees

- **Possession proofs prove retrievability, not personal storage.** Both custody proofs and
  challenge responses can be answered by fetching chunks from an archive or another provider
  (the classic outsourcing attack; preventing it requires sealed replica encoding à la
  Filecoin — out of scope). N bonded providers may back fewer than N physical copies. The
  enforced guarantee is *prompt retrievability by every bonded provider*.
- **The altruism assumption is load-bearing.** Seed-timing grinding (hides only ρ < ~0.08% on
  the SNARK path — the escape hatch is grindable at *any* ρ and provides assurance only
  against honest failure), slash-inflow recycling, the lapse cure grace, and
  unbonding-cancels-lapse are all safe *given* non-malicious providers. A deployment that
  cannot assume this should re-derive those choices.
- **Custody detection is probabilistic below ~10⁻⁴.** A single lost blob evades a given
  monthly proof with ~81% probability (and is still caught with 92% probability within a
  year). Consumer-side verification catches all corruption on read; the deep-tail middle is
  covered by provider count and archive redundancy.
- **No protocol-run trusted setup.** The SNARK layer is a transparent zkVM core wrapped in a
  pairing-based proof over a **pre-existing** setup (universal public SRS preferred; see the
  proof-system note). The setup assumptions are one honest participant in that ceremony and
  one in the EIP-4844 KZG ceremony (~141k) — both pre-existing and public; nothing was run by
  or for this protocol.
- **Verifier soundness bugs are forever.** The template is immutable; a soundness bug in the
  equivalence circuit would let a dishonest signer commit roots not matching blobs (providers
  still verify off-chain before ingesting and would refuse and raise the alarm — but on-chain
  finality would be wrong). A soundness bug in the custody circuit degrades the heartbeat to
  the challenge layer. Both slashing-relevant *response* paths (challenge response, custody
  escape hatch) are SNARK-free by construction, so no circuit bug can confiscate an honest
  provider's stake.
- **Proving-stack rot halts growth, not safety.** Publication *requires* an equivalence proof;
  if the toolchain becomes unmaintained and unrunnable, no new data can be declared (existing
  data, challenges, and exits are unaffected — they never touch a SNARK). The circuits are
  fixed and public; anyone can maintain a prover.
- **The application pointer is unverifiable by construction.** `appPointer` is a publisher
  assertion about derived state; no proof binds it to the committed bytes. Consumers who fetch a
  view by pointer instead of verifying the stream against the root are trusting the publisher.
- **Right data is not provable.** Every committed byte, genesis included, is proven
  equivalent to the root — but no proof can establish that the published dataset is the
  socially correct one. That rests on public verification and provider adoption before
  staking.
- **Availability is not guaranteed.** Challenges force retrievability of named chunks at
  ~$115 per KB of data ($3.48 bond per 31-byte chunk at reference prices) — a spot check and
  emergency extraction lever, not a retrieval rail. No one is obligated to serve bulk data
  cheaply.
- **Harsh liveness:** a provider unable to answer a challenge within 7 days — for any reason,
  including an honest outage — is slashed. Accepted by design; the custody path, by contrast,
  is deliberately gentler (60 days + a 7-day cure grace) because it is scheduled, not
  adversarial.
- **Carriage races cost real money.** A losing carrier's reverted type-3 transaction still
  burns blob gas. Use `designatedCarrier` or exclusive order flow; open broadcast is for
  liveness of last resort.
- **The paymaster funds whatever the signer signs,** bounded only by the rate limit (18.25
  ETH/yr max drain). Reimbursement is not an endorsement of the data.
- **Hardfork drift.** The template's constants embed today's consensus parameters: 18.2-day
  blob retention (the response-window-as-ingestion-grace argument needs retention > response
  window), precompile pricing, calldata pricing, blob count per block. Ethereum can change all
  of these. Most changes shift economics rather than break safety, but a retention period
  shortened below ~7 days would undermine immediate challengeability of fresh chunks. There is
  no upgrade path by design; the mitigation is a successor deployment and social migration,
  announced on-chain via the write-once
  [successor pointer](#the-successor-pointer).
- Guarantees are conditional on at least one bonded provider existing; nothing forces
  providers to exist. Publisher self-staking (via an EOA it controls) remains a legitimate
  degenerate case.

## Deferred

- **Batched equivalence verification** via EIP-2537 (random linear combination of blob
  commitments, one pairing check): flattens the 50k-per-blob term to ~700k gas total for any
  blob count. Worth it only if large updates become routine.
- **Range challenges** — contiguous-leaf multiproofs amortizing sibling paths, making forced
  retrieval of a blob's worth of data ~$460 (~$3.7/KB) instead of ~$14,300 at point-challenge
  pricing (~$115/KB) — a ~30× improvement.
- ~~Successor pointer~~ — **adopted into v1 2026-07-29**
  ([The successor pointer](#the-successor-pointer)).
- **Application-layer compression** — deferred from v1; the container reserves a per-batch
  codec ID and a dictionary record type so it can be enabled later without a format migration.
  See [The application layer](#the-application-layer-non-normative).
- **Declaration aggregation** — restructuring the campaign/batch flow so one recursive proof
  covers many blob transactions (log blobs first, prove once), amortizing the ~300k-gas
  verification that dominates genesis-campaign and large-batch cost. Not needed at the design
  update rate; would have cut the genesis campaign's execution gas severalfold.
- ~~Blob-published genesis~~ — **adopted 2026-07-29**; genesis is published through blobs
  ([Genesis](#genesis-published-through-blobs-proven-like-everything-else)). `proveGenesis`
  and the snapshot manifest are deleted.
- **Sharded storage** with per-shard stakes and custody proofs, for datasets too large for
  whole-dataset providers.
- **Custody k upsizing** — k is gas-flat; a future deployment could default to 65,536 (~57%
  single-blob detection per period) if provider GPU-hours prove cheap in practice.
- ~~Watchdog endowment~~ — obsoleted: custody proofs give routine assurance without external
  funding. Beneficiary challenges remain useful only for stale-flag follow-up and exits.
- ~~Validity proofs as v2~~ — this document.
