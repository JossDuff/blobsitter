# Blobsitter — Normative Implementation Specification

**Status: DRAFT v0.1 (2026-07-29). Sections 1–10 are proposed-final; sections 11+ are
reserved and unwritten.**

This document defines the exact byte-level rules every component — contract template,
equivalence circuit, custody circuit, storage daemon, publisher tooling, reference
implementation — MUST agree on. The design spec
(`verifiable-bonded-persistence-protocol.md`) is the rationale (the WHY); this document is
the WHAT. Where the two disagree, **stop and resolve the conflict**; do not pick one
silently.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in RFC 2119.

Every definition in sections 1–10 is exercised by golden test vectors in `vectors/`
(section 10). A change to any definition after vectors exist REQUIRES regenerating the
vectors in the same commit.

---

## 1. Conventions

- **H(x)** denotes **keccak-256** (the original Keccak-f[1600] with pad10\*1 / domain byte
  `0x01`, as used by Ethereum's `KECCAK256` opcode — NOT NIST SHA-3).
  Sanity anchors: `H("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
  (Ethereum's empty-code-hash constant), while NIST SHA3-256 of the empty string is
  `0xa7ffc6f8…f8434a` — if your implementation produces the latter, you are using the wrong
  padding.
- **‖** denotes byte-string concatenation.
- All integers are encoded **big-endian, fixed-width**. `u64be(x)` is the 8-byte big-endian
  encoding of a uint64. Chunk counts, leaf counts, chunk indices, sample ordinals, and
  provider IDs are uint64.
- Ethereum addresses are 20 bytes. Hashes, peaks, versioned hashes, and seeds are 32 bytes.
- `r` denotes the BLS12-381 scalar field modulus (the EIP-4844 blob field):
  `r = 52435875175126190479447740508185965837690552500527637822603658699938581184513`
  `  = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
- In JSON vectors, byte strings are lowercase `0x`-prefixed hex.

## 2. Domain-separation tag registry

Every keccak invocation defined by this protocol is prefixed with a single-byte domain tag.
Tags MUST NOT be reused for new purposes; new hash constructions MUST take the next free tag
and be recorded here.

| Tag | Purpose | Defined in |
|---|---|---|
| `0x00` | MMR leaf hash | §5.1 |
| `0x01` | MMR internal node | §5.1 |
| `0x02` | MMR root bagging | §5.3 |
| `0x03` | Fiat–Shamir evaluation point `z` | §8 |
| `0x04` | Custody/escape-hatch sample-index derivation | §9 |
| `0x05`–`0xff` | reserved, unassigned | — |

## 3. Chunks and the committed stream

- A **chunk** is exactly **31 bytes**. The protocol commits to an append-only ordered
  sequence of chunks; it has no notion of data at sub-chunk granularity. Applications MUST
  pad their payloads to whole chunks (padding semantics are the container format's concern
  and are invisible to the protocol).
- Chunks are numbered by **global chunk index** `i ∈ [0, leafCount)`, uint64, in append
  order. Chunk index and MMR leaf index are the same number.
- An **update** (one declaration) appends `m ≥ 1` chunks. Within an update, the **local
  index** `u ∈ [0, m)` maps to global index `priorLeafCount + u`.

## 4. Blob mapping

For an update of `m` chunks:

- The blob count MUST be exactly `B = ⌈m / 4096⌉`. (A declaration with more blobs than its
  chunk count requires is invalid.)
- Local chunk `u` is carried in **blob `⌊u / 4096⌋`, field element `u mod 4096`**, packed
  from element 0 of the first blob with no gaps.
- **Field-element encoding (canonical form):** each element is 32 bytes; byte 0 (the most
  significant) MUST be `0x00` and bytes 1..31 MUST be the chunk. (As a big-endian integer
  the element is `< 2^248 < r`, so it is always a valid EIP-4844 field element.)
- **Trailing elements MUST be zero:** if `m mod 4096 ≠ 0`, elements `m mod 4096` through
  `4095` of the final blob MUST be the 32-byte zero string. The equivalence circuit enforces
  both this and the canonical form; a blob violating either admits no valid proof.

## 5. The MMR

The commitment structure is a Merkle Mountain Range formalized as a **binary-counter hash
forest**: at any leaf count `n`, the state is a list of **peaks**, one perfect binary
subtree per set bit of `n`.

### 5.1 Leaf and node hashes

```
Leaf(c)     = H(0x00 ‖ c)          # c is a 31-byte chunk (33-byte preimage)
Node(a, b)  = H(0x01 ‖ a ‖ b)      # a, b are 32-byte child hashes (65-byte preimage);
                                   # a is the LEFT child (covers lower leaf indices)
```

### 5.2 Peaks

- A peak of **height `h`** is the root hash of a perfect subtree over `2^h` consecutive
  leaves whose starting leaf index is a multiple of `2^h`.
- At leaf count `n`, the peak heights are exactly the set bits of `n`, and the **canonical
  peak order** is **descending height** (equivalently: ascending leaf index; the peak
  covering the oldest leaves first). The peak list length is `popcount(n) ≤ 64`.
- The contract stores `(leafCount, peaks[])` in canonical order. There is never more than
  one peak per height.

### 5.3 Root (bagging)

```
Root(n, peaks) = H(0x02 ‖ u64be(n) ‖ peaks[0] ‖ … ‖ peaks[len-1])   # canonical order
Root(0, [])    = H(0x02 ‖ u64be(0))                                  # the empty MMR
```

The root is a pure function of stored state, computed on demand; it is never stored. All
single-value commitments (consumer verification, custody-circuit public input, challenge
pinning) use `Root`.

## 6. Update decomposition and peak-merge verification

An update never submits leaves. The publisher submits the roots of the perfect subtrees
covering the new leaf range; the contract merges them into the stored peaks.

### 6.1 Decomposition (deterministic in `(n, m)`)

For prior leaf count `n` and update size `m`, the subtree heights are produced by greedily
taking the largest aligned perfect subtree at each step:

```
decompose(n, m):
    heights = []
    pos = n
    remaining = m
    while remaining > 0:
        hAlign = (pos == 0) ? 63 : count_trailing_zero_bits(pos)
        hSize  = floor(log2(remaining))
        h = min(hAlign, hSize)
        heights.append(h)
        pos += 2^h
        remaining -= 2^h
    return heights            # length ≤ 2·⌈log2(m+1)⌉ + 1
```

The declaration's `newSubtreePeaks` array MUST contain exactly `len(heights)` hashes, in
this order: `newSubtreePeaks[k]` is the root of the perfect subtree over global leaves
`[posₖ, posₖ + 2^heights[k])` as produced by the algorithm. Heights are never transmitted;
the contract recomputes `decompose(n, m)`.

### 6.2 Merge (what the contract executes)

```
applyUpdate(peaks, n, newSubtreePeaks, m):
    heights = decompose(n, m)
    require len(newSubtreePeaks) == len(heights)
    for k in 0..len(heights)-1:
        h = heights[k]
        P = newSubtreePeaks[k]
        # alignment invariant: n mod 2^h == 0 holds by construction of decompose
        while peaks contains a peak of height h:
            P = Node(popPeak(h), P)      # existing peak is older ⇒ LEFT child
            h += 1
        insertPeak(h, P)                 # keeps canonical (descending-height) order
        n += 2^heights[k]
    return (peaks, n)                    # n == priorLeafCount + m
```

Structural validity is enforced by construction. Content validity — that each submitted
subtree root really commits the corresponding blob bytes — is exactly the equivalence
proof's statement (§8; circuit spec in a later section).

## 7. Inclusion proofs

### 7.1 Locating the covering peak

For leaf index `i` at leaf count `n` (`i < n`), with peak heights `h₀ > h₁ > …` (set bits of
`n`, descending):

```
locate(i, n):
    start = 0
    for k in 0..:
        if i < start + 2^hₖ: return (k, start)
        start += 2^hₖ
```

### 7.2 Verification against stored peaks (the on-chain form)

A proof for chunk `c` at index `i` is `path[]`, an array of exactly `hₖ` sibling hashes,
bottom level first:

```
verify(c, i, path, n, peaks):
    (k, start) = locate(i, n)
    require len(path) == hₖ
    off = i - start
    acc = Leaf(c)
    for lvl in 0..hₖ-1:
        if (off >> lvl) & 1 == 0:  acc = Node(acc, path[lvl])
        else:                       acc = Node(path[lvl], acc)
    require acc == peaks[k]
```

Challenge responses and the custody escape hatch use exactly this form against the pinned
`(n, peaks)`. It is SNARK-free by construction and MUST remain so.

> **What this proves.** The possession-evidencing element is `c` itself — the verifier hashes
> the raw chunk (`Leaf(c)`) before climbing the path. The siblings are connective tissue, not
> secrets: they cannot be read from chain state (the contract stores only `(n, peaks)`; no
> interior node is on-chain) and must be regenerated from the data, but even given all of
> them, producing a passing response still requires the true 31-byte preimage at index `i` —
> forgery is a keccak preimage attack. Storing hashes instead of data is both useless (hashes
> don't yield chunks) and uneconomical (a 32-byte leaf hash exceeds the 31-byte chunk it
> commits — the design-spec §1 anti-compression property). What the proof does NOT establish
> is *personal* storage: a responder may fetch `c` from any source within the window — the
> outsourcing residual accepted in the design spec's non-guarantees.

### 7.3 Verification against a bagged root (the off-chain form)

Identical, plus the full canonical peak list: verify `path` to `peaks[k]` as above, then
check `Root(n, peaks) == root`. Consumers holding only the 32-byte root use this form; the
proof carrier is `(c, i, path, n, peaks)`.

## 8. Fiat–Shamir evaluation point `z`

For a declaration on instance address `A` with prior state `(n₀, priorPeaks)`, new leaf
count `n₁ = n₀ + m`, blob versioned hashes `vh[0..B)` (transaction blob order), and
`newSubtreePeaks[0..S)` (§6.1 order):

```
z = uint256( H( 0x03
              ‖ A                      # 20 bytes
              ‖ vh[0] ‖ … ‖ vh[B-1]
              ‖ priorPeaks[0] ‖ … ‖ priorPeaks[P-1]     # canonical order
              ‖ newSubtreePeaks[0] ‖ … ‖ newSubtreePeaks[S-1]
              ‖ u64be(n₀) ‖ u64be(n₁) ) ) mod r
```

`B`, `P`, and `S` are each determined by `(n₀, n₁)`, so the preimage is unambiguous without
length prefixes. The instance address makes `z` (and hence proofs) instance-bound. Every
committed quantity of the declaration that the equivalence statement touches appears in the
preimage; neither side of the equivalence can be chosen after `z` is known.

The modular reduction's bias (`2^256 mod r ≠ 0`) is ≤ 4× on individual values and is
irrelevant to the soundness argument (which needs only high min-entropy of `z`).

## 9. Custody sample-index derivation

Providers are identified by **`providerId`**, a uint64 assigned sequentially from 1 at
stake time, unique per instance forever (never reused across re-staking; 0 means "none").
Given the period seed `seed` (32 bytes, snapshotted by `beginProof()`), the instance
address `A`, and the pinned `leafCount` from the same snapshot:

```
idx(j) = uint256( H( 0x04 ‖ A ‖ seed ‖ u64be(providerId) ‖ u64be(j) ) ) mod leafCount
```

- The custody proof covers `j ∈ [0, k)` with `k = 16,384`. Sampling is with replacement;
  duplicate indices are permitted and counted as sampled.
- The **escape hatch** reveals the chunks at `idx(0) … idx(31)` (`j < maxSample = 32`) with
  §7.2 inclusion proofs against the same snapshot.
- The salt is load-bearing twice over: `providerId` prevents one proof from being shared by
  providers on the same instance; `A` prevents sharing across instances of the same dataset
  that happen to pin identical roots and seeds (prevrandao is chain-global, so two
  instances' periods CAN share a seed).
- Modulo bias is ≤ 2⁻¹⁹² for any `leafCount < 2^64`: ignore it.

## 10. Golden test vectors

Location: `vectors/`. JSON, one file per area. Conventions: hex as in §1; the deterministic
test chunk pattern is `chunk(i)[b] = (31·i + b) mod 256` for `b ∈ [0, 31)`.

| File | Covers |
|---|---|
| `keccak_sanity.json` | keccak-256 anchors (guards against SHA-3 mixups) |
| `mmr_roots.json` | peaks + bagged root for a range of leaf counts (§5) |
| `append_decomposition.json` | `decompose(n, m)` height sequences and post-merge peaks equal to leaf-by-leaf construction (§6) |
| `inclusion_proofs.json` | §7.2 proofs, including first/last-leaf and cross-peak cases |
| `fs_z.json` | §8 preimages and reduced `z` values |
| `custody_indices.json` | §9 index derivations |

The current generator is `scripts/gen_vectors.py` (dependency-free, self-validating against
the §1 anchors). The Rust reference implementation, once written, becomes the authoritative
generator and MUST reproduce these files byte-for-byte; any diff is a finding, not a
regeneration.

---

## 11. EIP-712 structures

**Status: reviewed and accepted 2026-07-31 (as are §12–13).**

The publisher never sends transactions; every publisher action is an EIP-712 typed-data
signature verified on-chain via ERC-1271. All times are **unix timestamps in seconds**
(`block.timestamp` domain); the protocol never uses block numbers for windows.

### 11.1 Domain

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
  name              = "blobsitter"
  version           = "1"
  chainId           = the L1 chain id
  verifyingContract = the instance address
```

`verifyingContract` + `chainId` provide instance and chain binding, so signed structs carry
no explicit instance field. The digest is the standard
`keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.

### 11.2 Typed structs (exact typehash strings)

```
Declaration(uint64 nonce,uint64 deadline,bytes32[] blobVersionedHashes,
            bytes32[] newSubtreePeaks,uint64 newLeafCount,
            address designatedCarrier,bytes32 appPointer)

SetAppPointer(uint64 nonce,uint64 deadline,bytes32 appPointer)

SetSuccessor(uint64 nonce,uint64 deadline,address successor)
```

- Array fields are encoded per EIP-712 (keccak256 of the concatenated 32-byte elements).
- **Three independent, strictly sequential nonce spaces** (declaration / appPointer /
  successor), each starting at 0. A submitted struct MUST carry the exact next nonce of its
  space.
- `deadline`: the struct is submittable while `block.timestamp <= deadline`; an unsubmitted
  intent expires harmlessly.
- `designatedCarrier`: zero means anyone may carry; nonzero means `msg.sender` MUST equal it.
- `appPointer` inside `Declaration`: zero means "no update" (intermediate declarations of a
  batch); nonzero is stored and emitted (batch-final declarations).

### 11.3 Signature verification

The instance calls `publisher.isValidSignature(digest, signature)` (ERC-1271) and requires
the `0x1626ba7e` magic value. How the wallet validates internally is its own affair.
*Non-normative tooling note:* Safe wallets wrap external digests in their own `SafeMessage`
EIP-712 envelope before co-signing — the publisher toolchain must implement that flow; the
instance-side check above is unaffected.

## 12. Contract interface & state

Two contracts per deployment: the **instance** (immutable template) and its **paymaster**
(deployed by the instance constructor, bound one-way). This section fixes external
behavior and the semantic state; slot-level layout is implementation-free.

### 12.1 Constants and constructor parameters

Template constants (identical in every instance): chunk size 31, `EQUIVALENCE_VKEY`,
`CUSTODY_VKEY`, the SP1 verifier address, `RESPONSE_GAS_PER_CHUNK = 38_680`,
`RESPONSE_BASE_GAS = 21_000`, bond multiplier 3.

Constructor parameters (fixed forever at deployment; providers MUST sanity-check them
before staking): `publisher` (ERC-1271 wallet), `stake` (2 ETH), `responseWindow` (7 d),
`unbondingDelay` (14 d), `custodyPeriod` (30 d), `lapseGrace` (7 d), `custodyK` (16_384),
`maxSample` (32), `bountyBps` (1500), `carrierTip` (0.0002 ETH), `provingSubsidy`
(0.0005 ETH), paymaster bucket rate/cap (0.05 ETH/day, 1.5 ETH), `dormancyWindow` (365 d),
`dormancyMinChunks` (32_768).

### 12.2 Instance state (semantic)

```
leafCount            uint64
peaks                bytes32[]           # canonical order (§5.2)
declarationNonce     uint64
appPointerNonce      uint64
successorNonce       uint64
appPointer           bytes32
successor            address             # write-once
activityCheckpoint   (uint64 time, uint64 leafCountAtCheckpoint)   # §12.7 dormancy
nextProviderId       uint64              # starts at 1
providers            providerId => Provider
challenges           challengeId => Challenge     # challengeId: uint64 counter
```

```
Provider {
  operator      address    # immutable; hot key: proofs, responses, initiate unbonding
  withdrawal    address    # immutable; the ONLY address the stake can be paid to
  status        {ACTIVE, UNBONDING, EXITED, SLASHED}
  anchor        uint64     # stake time; custody periods count from here
  lastProven    int        # custody period index last proven; -1 at stake
                           # (implementations store lastProven+1 as uint64)
  lastDegraded  bool       # last accepted proof used the escape hatch
  commit        (uint64 period, bytes32 seed, bytes32 root, uint64 leafCount) | none
  unbondingAt   uint64     # 0 while ACTIVE
  exitRoot      bytes32    # Root(n,peaks) snapshotted at initiateUnbonding
  exitLeafCount uint64
  openChallenges uint32    # blocks withdraw() while nonzero
}

Challenge {
  providerId    uint64
  challenger    address
  bond          uint256
  openedAt      uint64
  pinnedRoot    bytes32    # Root(n,peaks) at open — or the provider's exitRoot
  pinnedLeafCount uint64
  indicesHash   bytes32    # keccak256(abi.encodePacked(uint64[] indices))
  k             uint16
  resolved      bool
}
```

**Pinning is by bagged root.** Wherever a historical `(leafCount, peaks)` must be fixed
(challenge open, unbonding snapshot, custody commit), the contract stores
`Root(leafCount, peaks)` (§5.3) — one word — and the later transaction that needs the peak
list supplies it as calldata, verified by re-bagging against the stored root. Interior
state is never stored twice.

### 12.3 Publication

```
declareFor(Declaration d, bytes publisherSig, BlobOpening[] openings, bytes equivalenceProof)
  BlobOpening { bytes32 y; bytes commitment /*48*/; bytes kzgProof /*48*/ }
```

Checks, in order (all MUST):
1. `block.timestamp <= d.deadline`; `d.nonce == declarationNonce`;
   `d.designatedCarrier ∈ {0, msg.sender}`; ERC-1271 signature valid (§11.3).
2. `m = d.newLeafCount − leafCount ≥ 1`; `B = ⌈m/4096⌉ == len(d.blobVersionedHashes)
   == len(openings)`; `blobhash(j) == d.blobVersionedHashes[j]` for `j < B` and
   `blobhash(B) == 0` (the transaction carries exactly the signed blobs);
   `len(d.newSubtreePeaks) == len(decompose(leafCount, m))` (§6.1).
3. Compute `z` (§8). For each blob `j`: call the point-evaluation precompile (0x0A) with
   `vh_j ‖ z ‖ y_j ‖ commitment_j ‖ kzgProof_j` (192 bytes); MUST succeed.
4. SP1 verifier: `verifyProof(EQUIVALENCE_VKEY, publicValues, equivalenceProof)` with
   `publicValues` per §14. MUST succeed.
5. Effects: merge peaks (§6.2); `leafCount = d.newLeafCount`; `declarationNonce += 1`;
   append `d.blobVersionedHashes` to the recovery log (event only — the log is not
   contract state); if `d.appPointer ≠ 0` store + emit it; advance the activity
   checkpoint if due (§12.7); emit `Declared`.
6. Reimburse `msg.sender` via the paymaster (§15): gas-capped call, failure ignored,
   reentrancy-guarded, after all state changes.

`setAppPointer(uint64 nonce, uint64 deadline, bytes32 pointer, bytes sig)` and
`setSuccessor(uint64 nonce, uint64 deadline, address target, bytes sig)`: same
pattern — deadline, own nonce, ERC-1271, effect, event, paymaster-reimbursed.
`setSuccessor` additionally requires `successor == 0` (write-once) and `target ≠ 0`.

### 12.4 Provider lifecycle entry points

```
stake(address operator, address withdrawal) payable → uint64 providerId
    msg.value == stake exactly; operator, withdrawal ≠ 0.
    Assigns nextProviderId++, status ACTIVE, anchor = now, lastProven = −1.
    Caller is irrelevant thereafter; the record is keyed by providerId.

initiateUnbonding(providerId)            # operator only; ACTIVE only
    status = UNBONDING; unbondingAt = now;
    exitRoot = Root(leafCount, peaks); exitLeafCount = leafCount;
    clears any custody commit; cancels lapse eligibility (custody obligations end).

withdraw(providerId)                     # anyone may call
    requires UNBONDING, now ≥ unbondingAt + unbondingDelay, openChallenges == 0.
    status = EXITED; transfers stake to withdrawal (push, pull-fallback on failure).

announce(string url) / retract()         # mirror tier: events only, no state, no stake
```

### 12.5 Challenges

```
challenge(providerId, uint64[] indices) payable → challengeId
```
- Provider MUST be ACTIVE, or UNBONDING with `now < unbondingAt + unbondingDelay`.
- `1 ≤ len(indices) ≤ maxSample`; every index `< pinnedLeafCount`, where the pin is
  `(Root(leafCount, peaks), leafCount)` for ACTIVE providers and
  `(exitRoot, exitLeafCount)` for UNBONDING ones (an exiting provider is never answerable
  for post-initiation data). Duplicate indices are permitted (they waste the challenger's
  bond).
- `msg.value ≥ 3 · (k · RESPONSE_GAS_PER_CHUNK + RESPONSE_BASE_GAS) · block.basefee`.
- Stores the record with `indicesHash`, increments `openChallenges`, emits
  `ChallengeOpened(challengeId, providerId, indices, deadline = openedAt + responseWindow)`.

```
respond(challengeId, uint64[] indices, uint64 n, bytes32[] peaks, ChunkProof[] proofs)
    ChunkProof { bytes31 chunk; bytes32[] path }
```
- Operator only; `now < openedAt + responseWindow`; challenge unresolved; provider not
  SLASHED. `keccak256(indices) == indicesHash`; `Root(n, peaks) == pinnedRoot` and
  `n == pinnedLeafCount`; for every `j`: `verify(chunk_j, indices[j], path_j, n, peaks)`
  (§7.2) MUST pass.
- Effects: resolved; `openChallenges −= 1`; **bond paid to the operator address** (it
  compensates response gas, which the hot wallet paid; this also keeps the hot wallet
  fueled without touching cold keys); emit `ChallengeAnswered`.

```
resolveTimeout(challengeId)              # anyone
```
- `now ≥ openedAt + responseWindow`, unresolved.
- If provider not yet SLASHED: status = SLASHED; bounty `stake · bountyBps / 10000` to the
  challenger, remainder to the paymaster; challenger's bond refunded; emit `Slashed`.
- If provider already SLASHED (by an earlier challenge or lapse): bond refunded only —
  watchdogs are not punished for piling onto a dying provider.
- Either way: resolved; `openChallenges −= 1`.

### 12.6 Custody proofs

Period index for a provider: `p(t) = (t − anchor) / custodyPeriod` (integer division).

```
beginProof(providerId)                   # operator only; ACTIVE only
    requires no commit for the current period (first commit is binding — the seed
    cannot be re-rolled).
    commit = (p(now), block.prevrandao, Root(leafCount, peaks), leafCount)
```

```
submitProof(providerId, bytes proof)     # operator only; ACTIVE only
    requires commit exists with commit.period == p(now)  (same period as beginProof).
    SP1 verifier: verifyProof(CUSTODY_VKEY, publicValues, proof), publicValues per §14
    (they bind instance, providerId, commit.seed, commit.root, commit.leafCount, custodyK).
    Effects: lastProven = p(now); lastDegraded = false; clears commit; emits CustodyProven.
```

```
submitProofEscape(providerId, uint64 n, bytes32[] peaks, ChunkProof[maxSample] reveals)
    Same window/guards as submitProof. Root(n, peaks) == commit.root, n == commit.leafCount.
    For j in [0, maxSample): idx = custody_index(instance, commit.seed, providerId, j, n)
    (§9, computed on-chain) and verify(reveals[j], idx, …, n, peaks) (§7.2) MUST pass.
    Effects: as submitProof but lastDegraded = true; emits CustodyProven(degraded=true).
```

```
lapse(providerId)                        # anyone
    requires ACTIVE (UNBONDING and SLASHED are immune) and
             now ≥ anchor + (lastProven + 3) · custodyPeriod + lapseGrace.
    status = SLASHED; bounty to caller, remainder to paymaster; emits Lapsed.
```

Health views (all free reads): `custodyStatus(providerId)` derives
CURRENT / STALE / LAPSE_ELIGIBLE / LAPSABLE from the formulas in §13.3; plus
`lastProven`, `lastDegraded`, and the full challenge log via events.

### 12.7 Paymaster & dormancy hooks (summary; accounting details in §15)

- The instance's activity checkpoint `(t₀, leafCount₀)` advances to
  `(now, leafCount)` whenever a declaration brings `leafCount − leafCount₀ ≥
  dormancyMinChunks`. Funder reclaim is open while `now − t₀ > dormancyWindow`.
- Slash remainders are sent to the paymaster but are NOT recorded as reclaimable
  contributions — on dormancy, donors' pro-rata claims cover the whole balance,
  slash inflows included.
- The paymaster pays only: carrier reimbursements requested by the instance
  (blob fee + execution fee at `block.basefee` + `carrierTip` + `provingSubsidy`,
  token-bucket-limited) and dormancy reclaims. Nothing else can move funds.

### 12.8 Events (the daemon's contract surface)

```
Declared(nonce, newLeafCount, blobVersionedHashes[], newSubtreePeaks[], appPointer, carrier)
AppPointerSet(nonce, pointer)            SuccessorSet(target)
Staked(providerId, operator, withdrawal) UnbondingInitiated(providerId, exitRoot, exitLeafCount)
Withdrawn(providerId)                    Slashed(providerId, cause, executor)
ChallengeOpened(challengeId, providerId, indices[], bond, pinnedRoot, pinnedLeafCount, deadline)
ChallengeAnswered(challengeId)           ChallengeRefunded(challengeId)
CustodyCommitted(providerId, period, seed, root, leafCount)
CustodyProven(providerId, period, degraded)
Lapsed(providerId, executor)             Announced(url) / Retracted()
```

## 13. State machines

Boundary convention, used everywhere: an action window is **open while `now < deadline`**
and its consequence becomes **available at `now ≥ deadline`**. No window is both.

### 13.1 Provider lifecycle

```
        stake()                    initiateUnbonding()              withdraw()
NONE ────────────► ACTIVE ────────────────────────► UNBONDING ────────────► EXITED
                     │                                   │
                     │ lapse()  [§13.3 lapsable]         │ resolveTimeout of an
                     │ resolveTimeout of an              │ in-window challenge
                     │ unanswered challenge              ▼
                     └─────────────────────────────► SLASHED   (terminal)
```

| Transition | Caller | Guards |
|---|---|---|
| NONE → ACTIVE | anyone (`stake`) | `msg.value == stake`; operator, withdrawal ≠ 0 |
| ACTIVE → UNBONDING | operator | — (always allowed; snapshots exit pin, ends custody obligations, cancels lapse eligibility) |
| UNBONDING → EXITED | anyone (`withdraw`) | `now ≥ unbondingAt + unbondingDelay` AND `openChallenges == 0`; stake → withdrawal address only |
| ACTIVE → SLASHED | anyone (`lapse`) | §13.3 LAPSABLE |
| ACTIVE/UNBONDING → SLASHED | anyone (`resolveTimeout`) | unanswered challenge past its response window |
| EXITED, SLASHED | — | terminal; no re-entry. Re-staking is a fresh `stake()` with a NEW providerId |

Exit is hard-bounded: challenges can be opened only while
`now < unbondingAt + unbondingDelay`, and each grants `responseWindow`, so EXITED is
reachable at latest `unbondingAt + unbondingDelay + responseWindow` (≤ 21 d as sized).

### 13.2 Challenge lifecycle

```
          challenge()             respond()  [valid, in window]
 (none) ─────────────► OPEN ───────────────────────────────► ANSWERED  bond → operator
                        │
                        │ resolveTimeout()  [now ≥ deadline]
                        ├──────── provider not yet slashed ─► TIMED_OUT  slash; bounty →
                        │                                     challenger; bond refunded
                        └──────── provider already slashed ─► REFUNDED   bond → challenger
```

| Rule | Value |
|---|---|
| Open allowed | provider ACTIVE, or UNBONDING while `now < unbondingAt + unbondingDelay` |
| Pin | ACTIVE: current `(Root, leafCount)`; UNBONDING: `(exitRoot, exitLeafCount)` |
| Respond window | `now < openedAt + responseWindow`; operator only; full index set in one call |
| An invalid response | reverts; the challenge stays OPEN (no partial credit, no penalty beyond gas) |
| After SLASHED | respond reverts; only refund resolution remains |

### 13.3 Custody status (derived, never stored)

With `p = p(now)`, `q = lastProven` (−1 at stake), all for ACTIVE providers only:

| Status | Condition | Meaning |
|---|---|---|
| CURRENT | `p ≤ q + 1` | no completed period unproven |
| STALE | `p == q + 2` | one completed period missed (informational flag) |
| LAPSE_ELIGIBLE | `p ≥ q + 3` and `now < T + lapseGrace` | two consecutive misses; **grace: only the provider can act** — `lapse()` reverts |
| LAPSABLE | `now ≥ T + lapseGrace` | anyone may `lapse()` |

where `T = anchor + (q + 3) · custodyPeriod` (the instant the second consecutive missed
period completed). Any accepted proof (SNARK or escape hatch) sets `q = p(now)`, which
restores CURRENT — cure is possible at every point before `lapse()` actually executes,
and is uncontested during the grace. UNBONDING/EXITED/SLASHED providers have no custody
status; `beginProof`/`submitProof*` revert and pending commits are void.

Proof-flow invariants: one `beginProof` per period (first is binding); `submitProof*`
MUST land in the same period as its commit; a commit without a same-period submission
expires worthless — the period is simply missed.

---

## 15. Paymaster accounting

**Status: reviewed and accepted 2026-07-31 (as is §16).**

The paymaster is strictly non-load-bearing: it can only (a) reimburse carriers when the
instance asks, (b) return funds to donors on dormancy, and (c) absorb slash remainders.
It can never touch roots, stakes, challenges, or custody, and its failure is always a
no-op for publication.

### 15.1 Funding and the contribution ledger

- **Donations:** plain ETH transfers (`receive()`) and an explicit `donate()` both credit
  `contributions[msg.sender] += value` and `outstanding += value`. Donations are
  irrevocable except via §15.4.
- **Slash inflows:** the instance sends slash remainders via `absorbSlash()` (instance
  only, payable). These are **not** recorded in the contribution ledger — no one can
  reclaim them individually; on dormancy they are covered by the donors' pro-rata sweep
  of the whole balance.
- Forced ETH (e.g. `SELFDESTRUCT`) is tolerated and behaves like a slash inflow:
  unattributed balance.

### 15.2 Carrier reimbursement

Only the instance may call `reimburse(carrier, amount, isDeclaration)`; the **instance**
computes the amount (it alone knows the transaction's shape), the paymaster only enforces
the bucket and pays. The amount for a declaration:

```
amount = numBlobs × 131_072 × block.blobbasefee                        # blob fee (EIP-7516)
       + (measuredGas + 21_000 + 16 × msg.data.length + TAIL) × block.basefee
       + carrierTip + provingSubsidy
```

- `measuredGas` is a `gasleft()` bracket from function entry to just before the paymaster
  call. The unmeasurable parts are covered explicitly: `21_000` intrinsic,
  `16 × msg.data.length` for calldata (deliberately treats every byte as non-zero — a
  small over-approximation on zero bytes, accepted for simplicity and bounded by the
  bucket), and `TAIL` for the post-measurement remainder (the reimbursement call itself
  and event emission). **`TAIL` is provisionally 25_000** — it MUST be calibrated against
  the real implementation and frozen before audit.
- `setAppPointer`/`setSuccessor` carriage: same formula with `numBlobs = 0` and
  **`carrierTip` only, no `provingSubsidy`** (there is no proof to subsidize).
- Priced at `block.basefee`/`block.blobbasefee`, never `tx.gasprice` (§9 of the design
  spec: no tip-channel self-dealing). Priority fees are the carrier's own cost.
- **All-or-nothing:** if the bucket or the balance cannot cover the full amount, nothing
  is paid (an event records the shortfall). No partial payouts — carriers simulate
  solvency before submitting, and partial payment would make that simulation ambiguous.

### 15.3 The token bucket

State: `(levelWei, lastUpdate)`. Continuous per-second refill:

```
level = min(capWei, levelWei + ratePerSecond × (now − lastUpdate))
```

with `ratePerSecond = 0.05 ETH / 86_400 s` and `capWei = 1.5 ETH` as sized. Only carrier
reimbursements draw from the bucket; reclaims (§15.4) and pull-claims (§15.5) do not.
A reimbursement request exceeding the current level pays nothing (§15.2 all-or-nothing);
a paid request subtracts its full amount.

### 15.4 Dormancy reclaim

- Gate: the instance's activity checkpoint (§12.7) — reclaim is open while
  `now − t₀ > dormancyWindow`, i.e. fewer than `dormancyMinChunks` chunks were declared
  in the past year.
- `reclaim()`: `payout = balance × contributions[msg.sender] / outstanding`, then
  `outstanding −= contributions[msg.sender]; contributions[msg.sender] = 0`, then pay
  (checks-effects-interactions). Sequential reclaimers each take their share of the
  balance *remaining at their call*; the arithmetic telescopes so that if every donor
  reclaims, the entire balance (slash inflows included) is returned.
- Reclaim does not close the paymaster: later donations recredit the ledger and a later
  declaration closes the gate again.

### 15.5 Payout mechanics (both contracts)

Every ETH payout in the system — carrier reimbursements, dormancy reclaims, stake
withdrawals, slash bounties, bond payments and refunds — uses one pattern:
**push with pull fallback**. Push: `call` with a **50_000 gas** stipend (enough for a
multisig `receive`, too little for reentrancy mischief under CEI ordering). On failure:
credit `claimable[recipient]` and emit; `claim()` pays the accumulated balance out later
(same gas cap; a failing `claim()` reverts and can be retried). Claimable balances are
outside the token bucket and survive indefinitely. No payout path can revert the
operation that triggered it.

## 16. Error taxonomy

Contracts MUST use these Solidity custom errors — no `require` strings, no silent
failures. The error *identity* is normative (tooling and tests match on selectors);
parameters are normative where listed. Grouped by area:

**Authorization & intents (§11, §12.3)**
```
BadSignature()                       ERC-1271 rejected the digest
WrongNonce(uint64 expected)          struct nonce ≠ next nonce of its space
IntentExpired(uint64 deadline)       block.timestamp > deadline
NotDesignatedCarrier(address want)   designatedCarrier set and ≠ msg.sender
NotOperator(uint64 providerId)       caller ≠ provider.operator
ZeroAddress()                        operator/withdrawal/successor target is zero
```

**Declarations (§12.3)**
```
EmptyUpdate()                        newLeafCount ≤ current leafCount
BlobCountMismatch(uint256 expected)  openings/versioned-hash count ≠ ⌈m/4096⌉
BlobHashMismatch(uint256 index)      blobhash(index) ≠ signed hash
UnexpectedExtraBlob()                blobhash(B) ≠ 0 — tx carries unsigned blobs
SubtreeCountMismatch(uint256 expected) newSubtreePeaks length ≠ decompose length
PointEvaluationFailed(uint256 blobIndex)
InvalidEquivalenceProof()            SP1 verifier rejected
SuccessorAlreadySet()                successor is write-once
```

**Staking & exit (§12.4, §13.1)**
```
WrongStakeAmount(uint256 expected)
UnknownProvider(uint64 providerId)
NotActive(uint64 providerId)         action requires status ACTIVE
NotUnbonding(uint64 providerId)      withdraw on a non-unbonding provider
UnbondingDelayActive(uint64 until)   withdraw before unbondingAt + delay
OpenChallengesRemain(uint32 count)   withdraw while challenges unresolved
```

**Challenges (§12.5, §13.2)**
```
ChallengeWindowClosed()              open attempt after unbonding-delay expiry
NoIndices() / TooManyIndices(uint16 max)
IndexOutOfRange(uint64 index, uint64 leafCount)
BondTooSmall(uint256 required)
UnknownChallenge(uint64 challengeId)
AlreadyResolved(uint64 challengeId)
ResponseWindowClosed(uint64 deadline)    respond at now ≥ deadline
ResponseWindowStillOpen(uint64 deadline) resolveTimeout at now < deadline
IndicesMismatch()                    supplied indices don't hash to indicesHash
PinMismatch()                        supplied (n, peaks) don't re-bag to the pinned root
InvalidInclusionProof(uint256 sampleIndex)
ProviderSlashed(uint64 providerId)   respond attempted after slash
```

**Custody (§12.6, §13.3)**
```
AlreadyCommitted(uint64 period)      second beginProof in one period
NoCommit()                           submitProof without a commit
CommitFromEarlierPeriod(uint64 committed, uint64 current)
InvalidCustodyProof()                SP1 verifier rejected
NotLapsable(uint64 lapsableAt)       lapse() before T + grace (covers grace + not-eligible;
                                     lapsableAt = 0 when not even eligible)
```

**Paymaster (§15)**
```
OnlyInstance()
NotDormant(uint64 dormantAt)
NothingToReclaim()
NothingClaimable()
```

Rule of construction: every MUST in §11–§15 maps to exactly one error above; a new guard
requires a new (or explicitly reused) entry here in the same commit.

---

## Reserved sections (unwritten — do not implement against guesses)

- **§14 Circuit statements & public-input encodings** — equivalence and custody circuits as
  implemented on SP1; exact byte layout of `publicValues` for both vkeys. Written when SP1
  integration starts; the mock verifier used before then MUST take (vkey, publicValues,
  proof) with the §12 call shapes so the swap is mechanical.
