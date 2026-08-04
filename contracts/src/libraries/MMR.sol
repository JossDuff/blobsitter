// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Merkle Mountain Range primitives — normative §5 (hashing, peaks, bagged root) and
/// §6 (update decomposition and peak-merge). Every hash carries its §2 domain tag.
///
/// Peaks are always handled in canonical order: descending height, i.e. the peak covering
/// the oldest leaves first (§5.2). At leaf count n the peak heights are exactly the set
/// bits of n, which is why presence-by-height can be tracked with n's bits during a merge.
library MMR {
    /// §5.1: Leaf(c) = H(0x00 ‖ c), c a 31-byte chunk (33-byte preimage).
    function leafHash(bytes31 chunk) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x00), chunk));
    }

    /// §5.1: Node(a, b) = H(0x01 ‖ a ‖ b); `a` is the LEFT child (lower leaf indices).
    function nodeHash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), a, b));
    }

    /// §5.3: Root(n, peaks) = H(0x02 ‖ u64be(n) ‖ peaks…), canonical order.
    /// Defined for the empty MMR too (n = 0, no peaks).
    function bagRoot(uint64 n, bytes32[] memory peaks) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x02), n, peaks));
    }

    /// popcount(n) — the canonical peak-list length at leaf count n (§5.2).
    function peakCount(uint64 n) internal pure returns (uint256 count) {
        uint256 x = n;
        while (x != 0) {
            x &= x - 1;
            unchecked {
                ++count;
            }
        }
    }

    /// §6.1: split an update of m ≥ 1 leaves appended after leaf count n into the height
    /// sequence of maximal aligned perfect subtrees. Deterministic in (n, m); heights are
    /// never transmitted — the contract recomputes them. Length ≤ 2·⌈log2(m+1)⌉ + 1 ≤ 129.
    function decompose(uint64 n, uint64 m) internal pure returns (uint8[] memory heights) {
        uint8[129] memory tmp;
        uint256 len = 0;
        uint64 pos = n;
        uint64 remaining = m;
        while (remaining > 0) {
            uint8 hAlign = pos == 0 ? 63 : _ctz(pos);
            uint8 hSize = _log2(remaining);
            uint8 h = hAlign < hSize ? hAlign : hSize;
            tmp[len] = h;
            unchecked {
                ++len;
                pos += uint64(1) << h;
                remaining -= uint64(1) << h;
            }
        }
        heights = new uint8[](len);
        for (uint256 i = 0; i < len; ++i) {
            heights[i] = tmp[i];
        }
    }

    /// §6.2: merge the submitted subtree roots into the stored peaks, binary-counter
    /// style. `peaks` is the canonical list at leaf count n; `heights` MUST be
    /// decompose(n, m) with `subtreePeaks.length == heights.length` (the caller enforces
    /// this — it is a normative check with its own error). Returns the new canonical peak
    /// list and leaf count.
    function applyUpdate(
        bytes32[] memory peaks,
        uint64 n,
        bytes32[] memory subtreePeaks,
        uint8[] memory heights
    ) internal pure returns (bytes32[] memory newPeaks, uint64 newCount) {
        // Scatter the canonical list into a by-height table; presence at height h is
        // tracked by bit h of the running leaf count (the binary-counter invariant).
        bytes32[64] memory byHeight;
        {
            uint256 idx = 0;
            for (uint256 h = 64; h > 0;) {
                unchecked {
                    --h;
                }
                if ((n >> h) & 1 == 1) {
                    byHeight[h] = peaks[idx];
                    unchecked {
                        ++idx;
                    }
                }
            }
        }
        uint64 cnt = n;
        for (uint256 k = 0; k < heights.length; ++k) {
            uint8 h = heights[k];
            bytes32 p = subtreePeaks[k];
            // Carry chain: an existing peak covers older leaves, so it is the LEFT child.
            while ((cnt >> h) & 1 == 1) {
                p = nodeHash(byHeight[h], p);
                unchecked {
                    ++h;
                }
            }
            byHeight[h] = p;
            unchecked {
                cnt += uint64(1) << heights[k];
            }
        }
        // Gather back to canonical (descending-height) order.
        newPeaks = new bytes32[](peakCount(cnt));
        uint256 out = 0;
        for (uint256 h = 64; h > 0;) {
            unchecked {
                --h;
            }
            if ((cnt >> h) & 1 == 1) {
                newPeaks[out] = byHeight[h];
                unchecked {
                    ++out;
                }
            }
        }
        newCount = cnt;
    }

    /// §7.1: locate the peak whose perfect subtree covers leaf `i` at leaf count `n`.
    /// Returns (peak index in canonical order, subtree's first leaf index, peak height).
    /// Callers MUST ensure `i < n` (the §7.2 wrapper checks it).
    function locate(uint64 i, uint64 n) internal pure returns (uint256 k, uint64 start, uint8 h) {
        for (uint256 height = 64; height > 0;) {
            unchecked {
                --height;
            }
            if ((n >> height) & 1 == 0) continue;
            uint64 size = uint64(1) << height;
            if (i < start + size) return (k, start, uint8(height));
            unchecked {
                start += size;
                ++k;
            }
        }
        assert(false); // unreachable while i < n: the peaks cover all n leaves
    }

    /// §7.2: inclusion-proof verification against stored peaks — the exact check the
    /// contract runs for challenge responses (and the custody escape hatch in M3). The
    /// possession-evidencing element is the raw chunk: it is hashed before the climb.
    /// SNARK-free by construction and MUST remain so (CLAUDE.md invariant 4).
    function verify(
        bytes31 chunk,
        uint64 i,
        bytes32[] memory path,
        uint64 n,
        bytes32[] memory peaks
    ) internal pure returns (bool) {
        if (i >= n || peaks.length != peakCount(n)) return false;
        (uint256 k, uint64 start, uint8 h) = locate(i, n);
        if (path.length != h) return false;
        uint64 off = i - start;
        bytes32 acc = leafHash(chunk);
        for (uint256 lvl = 0; lvl < h; ++lvl) {
            acc = (off >> lvl) & 1 == 0 ? nodeHash(acc, path[lvl]) : nodeHash(path[lvl], acc);
        }
        return acc == peaks[k];
    }

    /// count_trailing_zero_bits for x != 0.
    function _ctz(uint64 x) private pure returns (uint8 c) {
        while (x & 1 == 0) {
            x >>= 1;
            unchecked {
                ++c;
            }
        }
    }

    /// floor(log2(x)) for x != 0.
    function _log2(uint64 x) private pure returns (uint8 l) {
        while (x > 1) {
            x >>= 1;
            unchecked {
                ++l;
            }
        }
    }
}
