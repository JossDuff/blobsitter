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

## Reserved sections (unwritten — do not implement against guesses)

- **§11 EIP-712 structures** — domain separator, `Declaration` / `SetAppPointer` /
  `SetSuccessor` typehashes and field encodings; ERC-1271 verification flow (Safe nesting).
- **§12 Contract interface & state layout** — full external ABI, storage structs
  (provider records incl. operator/withdrawal addresses and `providerId`, challenge
  records, custody state, unbonding snapshots), event schema.
- **§13 State machines** — provider lifecycle (bonded → stale → lapse-eligible → grace →
  lapsed / unbonding → withdrawn / slashed), challenge lifecycle, custody-period
  arithmetic (anchor + 30 d periods, 7 d grace), with exhaustive transition guards.
- **§14 Circuit statements & public-input encodings** — equivalence and custody circuits as
  implemented on the selected stack (SP1), byte layout of committed public inputs.
- **§15 Paymaster accounting** — token bucket, reimbursement formula and `FIXED_OVERHEAD`,
  activity checkpoint, pro-rata reclaim.
- **§16 Error taxonomy** — canonical revert errors for every MUST above.
