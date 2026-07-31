#!/usr/bin/env python3
"""Golden test-vector generator for spec/normative.md sections 1-10.

WHAT THIS IS
------------
This script computes "golden vectors": known-good input/output pairs for every
cryptographic primitive the protocol defines (hashing, the MMR commitment structure,
inclusion proofs, the Fiat-Shamir evaluation point, custody sampling). The Solidity
contracts, the SP1 circuits, the storage daemon, and the Rust reference implementation
will all run their own code against these same files in their test suites. If all four
implementations agree with the vectors, they agree with each other -- byte for byte.

It is deliberately dependency-free (it even carries its own keccak-256 implementation)
so it can run anywhere and can't drift because of a library upgrade. It validates its
keccak against two independent, well-known constants before emitting anything, and it
cross-checks its own outputs internally (see the assertions sprinkled below). This is
an interim tool: once the Rust reference implementation exists, that becomes the
authoritative generator and MUST reproduce these files byte-for-byte.
"""
import json
import os

# ============================================================================
# PART 1 -- keccak-256, implemented from scratch
#
# Ethereum uses the ORIGINAL Keccak algorithm, which differs from the final NIST
# SHA-3 standard in exactly one byte of padding (0x01 vs 0x06). Many libraries
# only offer NIST SHA-3, and using it by mistake is a classic bug -- every hash
# in the whole system would be wrong. That is why we implement Keccak directly
# and validate it against known answers below.
#
# How Keccak works, in one paragraph: the hash state is a 5x5 grid of 64-bit
# "lanes" (25 lanes = 1600 bits). The input message is padded, split into
# 136-byte blocks, and each block is XORed into the state, after which the state
# is scrambled by the "keccak-f" permutation (24 rounds of five mixing steps
# named theta, rho, pi, chi, iota). After all blocks are absorbed, the first 32
# bytes of the state are read out as the digest.
# ============================================================================

# One round constant per round; XORed into lane (0,0) in the "iota" step so that
# every round is different (otherwise the permutation would have symmetries an
# attacker could exploit). These are standard, published constants.
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# How far each of the 25 lanes gets bit-rotated in the "rho" step. Indexed by
# flat position [x + 5*y] in the 5x5 grid. Also standard, published constants.
_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
        18, 2, 61, 56, 14]

_M64 = (1 << 64) - 1  # mask that keeps a Python int within 64 bits


def _rol(v, n):
    """Rotate a 64-bit value left by n bits (bits that fall off the top wrap
    around to the bottom)."""
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def _keccak_f(s):
    """The keccak-f[1600] permutation: scramble the 25-lane state in place.

    `s` is a flat list of 25 ints; lane (x, y) lives at index x + 5*y.
    """
    for rc in _RC:  # 24 rounds
        # --- theta: mix each column with the parity of neighboring columns.
        # c[x] is the XOR of the whole column x; each lane then absorbs the
        # parity of the columns to its left and right. This diffuses every bit
        # across the state very quickly.
        c = [s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                s[x + 5 * y] ^= d[x]
        # --- rho + pi: rotate every lane by its fixed offset (rho), then move
        # it to a new grid position (pi). Rotation spreads bits within a lane;
        # the reshuffle spreads them between lanes.
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(s[x + 5 * y], _ROT[x + 5 * y])
        # --- chi: the only non-linear step. Each lane is XORed with a function
        # of the two lanes to its right in the same row ("if not the next one,
        # then the one after"). Non-linearity is what makes the hash one-way.
        for x in range(5):
            for y in range(5):
                s[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # --- iota: XOR in this round's constant so rounds aren't identical.
        s[0] ^= rc
    return s


def keccak256(msg: bytes) -> bytes:
    """keccak-256 of an arbitrary byte string (Ethereum's KECCAK256 opcode)."""
    rate = 136  # bytes absorbed per permutation call (1088 bits; the remaining
                # 512 bits of state are the "capacity" -- never touched by input,
                # which is where the security comes from)
    # Padding ("pad10*1"): append 0x01, then zeros until the length is a
    # multiple of 136, then set the top bit of the final byte. If the message
    # ends exactly one byte short of a block, 0x01 and 0x80 share one byte
    # (0x81) -- the code below handles that automatically because the |= hits
    # the byte just appended. NOTE: NIST SHA-3 uses 0x06 here instead of 0x01;
    # that single byte is the entire difference between the two hashes.
    padded = bytearray(msg)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] |= 0x80
    # Absorb: XOR each 136-byte block into the first 17 lanes (little-endian
    # within each 8-byte lane, per the Keccak spec), then permute.
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _keccak_f(state)
    # Squeeze: the digest is simply the first 32 bytes of the state.
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------------------
# Self-validation before we emit anything (spec section 1 anchors).
#
# Anchor 1: keccak256 of the empty string. This exact value (ending ...a470)
# appears all over Ethereum as the "empty code hash", so it is beyond doubt.
# Anchor 2: NIST SHA3-256 of the empty string, computed with the SAME permutation
# but the 0x06 padding byte. Passing BOTH proves two things independently: the
# permutation itself is correct, and we are using the correct (Keccak, not
# SHA-3) padding. If only the SHA-3 anchor passed, we'd have the padding bug
# described above.
# ---------------------------------------------------------------------------
assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def _sha3_256_empty_check():
    rate = 136
    p = bytearray(b"\x06")  # SHA-3's domain byte instead of Keccak's 0x01
    while len(p) % rate:
        p.append(0)
    p[-1] |= 0x80
    state = [0] * 25
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(p[8 * i:8 * i + 8], "little")
    state = _keccak_f(state)
    digest = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    assert digest.hex() == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"


_sha3_256_empty_check()

# ============================================================================
# PART 2 -- the protocol's primitives, exactly as spec/normative.md defines them
#
# Quick mental model of the commitment structure (an MMR, "Merkle Mountain
# Range"): the dataset is an append-only sequence of 31-byte chunks. Rather
# than one Merkle tree that gets rebuilt on every append, we keep a FOREST of
# perfect binary trees ("peaks"). The forest works exactly like a binary
# counter: appending a leaf adds a height-0 tree, and whenever two trees of
# equal height exist they merge into one tree one level taller (a "carry").
# Consequence: at leaf count n, the peak heights are exactly the set bits of n
# (e.g. n = 13 = 0b1101 -> peaks of heights 3, 2, 0 covering 8 + 4 + 1 leaves).
# Appending never touches existing interior nodes, so old inclusion proofs stay
# valid forever -- which is why this structure suits an append-only protocol.
# ============================================================================

# The BLS12-381 scalar field modulus -- the prime field that EIP-4844 blob
# polynomials live in. The Fiat-Shamir point z must be a member of this field.
R_BLS = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def u64be(x):
    """A uint64 as 8 big-endian bytes -- the only integer encoding the protocol
    uses inside hash preimages."""
    return x.to_bytes(8, "big")


def hx(b):
    """Bytes -> lowercase 0x-prefixed hex, the JSON convention for all vectors."""
    return "0x" + b.hex()


def chunk(i):
    """The deterministic test chunk pattern (spec section 10): chunk i is 31
    bytes whose byte b equals (31*i + b) mod 256. Arbitrary but fixed, so every
    implementation can synthesize identical test data without shipping it."""
    return bytes((31 * i + b) % 256 for b in range(31))


def leaf(c):
    """Hash a 31-byte chunk into a leaf. The 0x00 prefix is a domain tag: leaf
    hashes and interior-node hashes use different prefixes so a leaf can never
    be confused with (or forged from) an interior node, and vice versa."""
    return keccak256(b"\x00" + c)


def node(a, b):
    """Hash two child hashes into a parent. Domain tag 0x01. `a` is always the
    LEFT child -- the one covering the lower (older) leaf indices."""
    return keccak256(b"\x01" + a + b)


def root(n, peaks):
    """"Bag" the peaks into the single 32-byte root that consumers use.
    The leaf count is hashed in too, so the root pins the full structure, and
    the empty dataset (n=0, no peaks) still has a well-defined root."""
    return keccak256(b"\x02" + u64be(n) + b"".join(peaks))


def peak_heights(n):
    """The peak heights at leaf count n = the set bits of n, tallest first.
    Tallest-first is the canonical order: it equals oldest-leaves-first."""
    return [h for h in range(63, -1, -1) if (n >> h) & 1]


def decompose(n, m):
    """Split an update of m new leaves (appended after existing leaf count n)
    into perfect subtrees the publisher will submit (spec section 6.1).

    A perfect subtree of height h may only start at a leaf index that is a
    multiple of 2^h ("alignment") -- otherwise it wouldn't slot into the tree
    structure. So we walk left to right through the new range, each time taking
    the LARGEST subtree that is (a) aligned at the current position and
    (b) no bigger than what remains. The result is a short list of heights
    (at most ~2*log2(m)) that is fully determined by (n, m) -- which is why the
    heights are never transmitted: the contract recomputes them and the
    publisher cannot lie about structure.
    """
    heights, pos, remaining = [], n, m
    while remaining:
        # Largest height allowed by alignment: how many times 2 divides pos.
        # (pos = 0 is aligned for every height; 63 is the uint64 ceiling.)
        h_align = 63 if pos == 0 else (pos & -pos).bit_length() - 1
        # Largest height that fits in what's left: floor(log2(remaining)).
        h_size = remaining.bit_length() - 1
        heights.append(min(h_align, h_size))
        pos += 1 << heights[-1]
        remaining -= 1 << heights[-1]
    return heights


def subtree_root(start, h):
    """Root of the perfect subtree of height h over global leaves
    [start, start + 2^h), built directly from the test chunks. This plays the
    publisher's role: computing the subtree roots that go into a declaration."""
    if h == 0:
        return leaf(chunk(start))
    half = 1 << (h - 1)
    return node(subtree_root(start, h - 1), subtree_root(start + half, h - 1))


def apply_update(peaks_by_h, n, new_subtree_peaks, heights):
    """The contract's merge algorithm (spec section 6.2): fold submitted
    subtree roots into the stored peaks, binary-counter style.

    `peaks_by_h` maps height -> peak hash (at most one peak per height, exactly
    like at most one 1-bit per position in a binary number). For each incoming
    subtree: while a peak of the same height already exists, merge them (the
    existing peak covers older leaves, so it is the left child) and carry the
    result up one height. Then insert.
    """
    assert len(new_subtree_peaks) == len(heights)
    for h0, p in zip(heights, new_subtree_peaks):
        h = h0
        # decompose() guarantees alignment; this assert is the invariant check.
        assert n % (1 << h) == 0, "alignment invariant broken"
        while h in peaks_by_h:
            p = node(peaks_by_h.pop(h), p)  # existing peak is older => LEFT
            h += 1
        peaks_by_h[h] = p
        n += 1 << h0
    return peaks_by_h, n


def build(n):
    """Build the whole MMR one leaf at a time (each leaf = a height-0 update).
    This is the slow, obviously-correct construction that the batched update
    path is checked against. Returns peaks in canonical (tallest-first) order."""
    peaks_by_h = {}
    cnt = 0
    for i in range(n):
        peaks_by_h, cnt = apply_update(peaks_by_h, cnt, [leaf(chunk(i))], [0])
    return [peaks_by_h[h] for h in sorted(peaks_by_h, reverse=True)]


def prove(i, n):
    """Produce an inclusion proof for leaf i at leaf count n (spec section 7).

    Step 1: find which peak's subtree contains leaf i, by walking the peaks
    tallest-first and accumulating how many leaves each one covers.
    Step 2: collect the sibling hash at every level on the way up from the
    leaf to that peak, bottom level first. At each level, the sibling is the
    node covering the adjacent range (XOR the offset's bit at that level).
    Returns (index of the covering peak, list of sibling hashes).
    """
    heights = peak_heights(n)
    start = 0
    for k, h in enumerate(heights):
        if i < start + (1 << h):
            break
        start += 1 << h
    off = i - start  # position of leaf i inside its covering subtree
    path = []
    for lvl in range(h):
        width = 1 << lvl                # leaves covered per node at this level
        sib_off = (off >> lvl) ^ 1      # sibling's node-position at this level
        path.append(subtree_root(start + sib_off * width, lvl))
    return k, path


def verify(c, i, path, n, peaks):
    """Check an inclusion proof (the verifier's side -- what the contract runs
    for challenge responses). Recompute the path: hash the chunk into a leaf,
    then at each level combine with the supplied sibling -- on the left or
    right depending on that level's bit of the leaf's offset -- and compare
    the final result with the stored peak. Returns True iff the proof is valid."""
    heights = peak_heights(n)
    start = 0
    for k, h in enumerate(heights):
        if i < start + (1 << h):
            break
        start += 1 << h
    if len(path) != h:
        return False
    off = i - start
    acc = leaf(c)
    for lvl in range(h):
        # Offset bit 0 at this level means "I am the left child": my sibling
        # goes on the right. Bit 1 means the mirror image.
        acc = node(acc, path[lvl]) if not (off >> lvl) & 1 else node(path[lvl], acc)
    return acc == peaks[k]


# ============================================================================
# PART 3 -- emit the vector files
#
# Each block below builds one JSON file and, where possible, first PROVES the
# values are self-consistent (e.g. the batched update path must produce
# identical peaks to the leaf-by-leaf build) so that a bug in this script is
# far more likely to crash it than to emit plausible-but-wrong vectors.
# ============================================================================
OUT = os.path.join(os.path.dirname(__file__), "..", "vectors")
os.makedirs(OUT, exist_ok=True)


def emit(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    print(f"wrote vectors/{name}")


# --- keccak_sanity.json ------------------------------------------------------
# The two hash anchors plus one leaf hash. Purpose: if an implementation fails
# every other vector file, this one tells you in seconds whether the problem is
# "wrong hash function" (the classic SHA-3-instead-of-Keccak mixup) or
# something structural.
emit("keccak_sanity.json", {
    "_spec": "normative.md §1",
    "keccak256_empty": hx(keccak256(b"")),
    "keccak256_abc": hx(keccak256(b"abc")),
    "leaf_of_chunk_0": hx(leaf(chunk(0))),
    "chunk_0": hx(chunk(0)),
})

# --- mmr_roots.json ----------------------------------------------------------
# Peaks and bagged root for a spread of leaf counts. The counts are chosen to
# cover: the empty MMR (0), a single leaf (1), a single perfect tree (2, 4, 8),
# every peak-shape with up to three peaks (3, 5, 6, 7, 13), and two larger
# multi-peak cases (33 = 0b100001, 100 = 0b1100100).
cases = []
for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 33, 100]:
    peaks = build(n)
    cases.append({
        "leafCount": n,
        "peakHeights": peak_heights(n),
        "peaks": [hx(p) for p in peaks],
        "root": hx(root(n, peaks)),
    })
emit("mmr_roots.json", {"_spec": "normative.md §5", "chunkPattern": "chunk(i)[b]=(31*i+b)%256", "cases": cases})

# --- append_decomposition.json ----------------------------------------------
# The heart of the update path. For each (prior leaf count n, update size m):
# the expected height sequence from decompose(), the subtree roots a publisher
# would submit, and the resulting peaks/root. Before emitting, we assert that
# applying the batched update to the prior state yields EXACTLY the same peaks
# as building leaf-by-leaf -- i.e. the fast path equals the obviously-correct
# path. Cases cover: appends into an empty MMR, misaligned starts (n = 1, 5,
# 13, 4095), a whole-blob append (4096), and a blob appended after a blob.
cases = []
for (n, m) in [(0, 1), (0, 5), (1, 3), (6, 3), (5, 8), (13, 20), (0, 4096), (4095, 2), (4096, 4096)]:
    heights = decompose(n, m)
    # Recreate the prior on-chain state (peaks at leaf count n).
    peaks_by_h = {}
    cnt = 0
    for i in range(n):
        peaks_by_h, cnt = apply_update(peaks_by_h, cnt, [leaf(chunk(i))], [0])
    # Play the publisher: compute the subtree roots for the new range.
    subtrees, pos = [], n
    for h in heights:
        subtrees.append(subtree_root(pos, h))
        pos += 1 << h
    # Play the contract: merge them in.
    peaks_by_h, cnt = apply_update(peaks_by_h, cnt, subtrees, heights)
    batch_peaks = [peaks_by_h[h] for h in sorted(peaks_by_h, reverse=True)]
    # The two construction orders MUST agree, and the count must add up.
    assert batch_peaks == build(n + m), f"batch != leaf-by-leaf for {(n, m)}"
    assert cnt == n + m
    cases.append({
        "priorLeafCount": n,
        "updateChunks": m,
        "heights": heights,
        "newSubtreePeaks": [hx(p) for p in subtrees],
        "resultPeaks": [hx(p) for p in batch_peaks],
        "resultRoot": hx(root(n + m, batch_peaks)),
    })
emit("append_decomposition.json", {"_spec": "normative.md §6", "cases": cases})

# --- inclusion_proofs.json ---------------------------------------------------
# Proofs at leaf count 13 (peaks of heights 3, 2, 0 -- three peaks of three
# different sizes, so peak-location logic is genuinely exercised). Indices
# chosen to hit: the first leaf (0), interior leaves of the big peak (5, 7),
# the first leaf of the second peak (8), an interior leaf of it (11), and the
# lone height-0 peak (12), whose proof is the empty path. Each proof is checked
# to verify, AND checked to REJECT a wrong chunk -- a verifier that accepts
# everything would otherwise pass.
cases = []
n = 13
peaks = build(n)
for i in [0, 5, 7, 8, 11, 12]:
    k, path = prove(i, n)
    assert verify(chunk(i), i, path, n, peaks)
    assert not verify(chunk(i + 1), i, path, n, peaks), "verifier accepted wrong chunk"
    cases.append({
        "leafCount": n,
        "index": i,
        "chunk": hx(chunk(i)),
        "peakIndex": k,
        "path": [hx(p) for p in path],
    })
emit("inclusion_proofs.json", {"_spec": "normative.md §7.2",
                               "peaks_for_n13": [hx(p) for p in peaks], "cases": cases})

# --- fs_z.json ---------------------------------------------------------------
# One full Fiat-Shamir example (spec section 8): a declaration appending 3
# chunks to a 5-leaf MMR on a made-up instance address, with one made-up blob
# versioned hash (3 chunks fit in one blob). The file includes the complete
# preimage bytes -- so an implementation that gets a different z can diff its
# preimage against ours and see exactly which field it serialized differently
# -- plus the final z after reduction into the BLS scalar field.
instance = bytes.fromhex("00112233445566778899aabbccddeeff00112233")
n0, m = 5, 3
n1 = n0 + m
prior_peaks = build(n0)
heights = decompose(n0, m)
subtrees, pos = [], n0
for h in heights:
    subtrees.append(subtree_root(pos, h))
    pos += 1 << h
# A fake-but-shaped versioned hash: EIP-4844 versioned hashes start with the
# version byte 0x01 followed by 31 bytes of (here, arbitrary) hash material.
vh = [b"\x01" + keccak256(b"vector blob " + u64be(j))[1:] for j in range(1)]
preimage = (b"\x03" + instance + b"".join(vh) + b"".join(prior_peaks)
            + b"".join(subtrees) + u64be(n0) + u64be(n1))
z = int.from_bytes(keccak256(preimage), "big") % R_BLS
emit("fs_z.json", {
    "_spec": "normative.md §8",
    "instance": hx(instance),
    "blobVersionedHashes": [hx(v) for v in vh],
    "priorLeafCount": n0,
    "priorPeaks": [hx(p) for p in prior_peaks],
    "newLeafCount": n1,
    "newSubtreePeaks": [hx(p) for p in subtrees],
    "preimage": hx(preimage),
    "z": hex(z),
})

# --- custody_indices.json ----------------------------------------------------
# The custody sampling derivation (spec section 9): from (instance, period
# seed, providerId, sample ordinal j) to a chunk index. The first 16 indices
# are emitted; j = 0..31 is also exactly what the escape hatch reveals. The
# leaf count is deliberately NOT a power of two, so an implementation that
# reduces modulo a rounded value, or reads the hash little-endian, will
# disagree immediately.
seed = keccak256(b"vector seed")
provider_id = 7
leaf_count = 1_000_003
idxs = []
for j in range(16):
    h = keccak256(b"\x04" + instance + seed + u64be(provider_id) + u64be(j))
    idxs.append(int.from_bytes(h, "big") % leaf_count)
emit("custody_indices.json", {
    "_spec": "normative.md §9",
    "instance": hx(instance),
    "seed": hx(seed),
    "providerId": provider_id,
    "leafCount": leaf_count,
    "indices_j0_to_j15": idxs,
})

print("all internal assertions passed")
