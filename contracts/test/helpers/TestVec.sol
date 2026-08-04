// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MMR} from "src/libraries/MMR.sol";

/// Publisher-side test-data synthesis, mirroring `reference::testvec` and the vector
/// generator: the deterministic chunk pattern (normative §10) and perfect-subtree roots.
/// Test code only — never part of the template.
library TestVec {
    /// §10: chunk(i)[b] = (31·i + b) mod 256.
    function chunk(uint64 i) internal pure returns (bytes31 c) {
        bytes memory buf = new bytes(31);
        for (uint256 b = 0; b < 31; ++b) {
            buf[b] = bytes1(uint8((31 * (uint256(i) % 256) + b) % 256));
        }
        assembly ("memory-safe") {
            c := mload(add(buf, 32))
        }
    }

    /// Root of the perfect subtree of height h over global leaves [start, start + 2^h).
    function subtreeRoot(uint64 start, uint8 h) internal pure returns (bytes32) {
        if (h == 0) {
            return MMR.leafHash(chunk(start));
        }
        uint64 half = uint64(1) << (h - 1);
        return MMR.nodeHash(subtreeRoot(start, h - 1), subtreeRoot(start + half, h - 1));
    }

    /// The §6.1 subtree peaks a publisher would submit for an update of m chunks after
    /// leaf count n, built from the pattern chunks.
    function subtreePeaks(uint64 n, uint64 m) internal pure returns (bytes32[] memory out) {
        uint8[] memory heights = MMR.decompose(n, m);
        out = new bytes32[](heights.length);
        uint64 pos = n;
        for (uint256 k = 0; k < heights.length; ++k) {
            out[k] = subtreeRoot(pos, heights[k]);
            pos += uint64(1) << heights[k];
        }
    }

    /// Inclusion proof for pattern leaf `i` at leaf count `n` (§7): the sibling hash at
    /// every level from the leaf up to its covering peak, bottom level first. Mirrors
    /// `reference::testvec::prove`.
    function prove(uint64 i, uint64 n) internal pure returns (uint256 k, bytes32[] memory path) {
        uint64 start;
        uint8 h;
        (k, start, h) = MMR.locate(i, n);
        uint64 off = i - start;
        path = new bytes32[](h);
        for (uint8 lvl = 0; lvl < h; ++lvl) {
            uint64 width = uint64(1) << lvl;
            uint64 sibOff = (off >> lvl) ^ 1;
            path[lvl] = subtreeRoot(start + sibOff * width, lvl);
        }
    }

    /// Canonical peaks over the first n pattern chunks, built leaf by leaf — the slow,
    /// obviously-correct construction batched updates are checked against.
    function buildPeaks(uint64 n) internal pure returns (bytes32[] memory peaks, uint64 cnt) {
        peaks = new bytes32[](0);
        bytes32[] memory single = new bytes32[](1);
        uint8[] memory h0 = new uint8[](1);
        for (uint64 i = 0; i < n; ++i) {
            single[0] = MMR.leafHash(chunk(i));
            (peaks, cnt) = MMR.applyUpdate(peaks, cnt, single, h0);
        }
    }
}
