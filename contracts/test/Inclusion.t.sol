// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {MMR} from "src/libraries/MMR.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// vectors/inclusion_proofs.json conformance — the exact peak-based verification the
/// challenge-response path runs — plus the negative "verifier that accepts everything"
/// traps: a verifier must reject wrong chunks, wrong indices, and wrong-length paths,
/// or every positive assertion above it is worthless.
contract InclusionTest is Test {
    using stdJson for string;

    function test_vectors_inclusionProofs() public view {
        string memory json = vm.readFile("../vectors/inclusion_proofs.json");
        (bytes32[] memory peaks,) = TestVec.buildPeaks(13);
        assertEq(peaks, json.readBytes32Array(".peaks_for_n13"), "peaks");

        uint256 i;
        while (vm.keyExistsJson(json, string.concat(".cases[", vm.toString(i), "]"))) {
            string memory key = string.concat(".cases[", vm.toString(i), "]");
            uint64 n = uint64(json.readUint(string.concat(key, ".leafCount")));
            uint64 idx = uint64(json.readUint(string.concat(key, ".index")));
            bytes memory chunkBytes = json.readBytes(string.concat(key, ".chunk"));
            assertEq(chunkBytes.length, 31, "chunk length");
            bytes31 chunk = bytes31(chunkBytes);
            assertEq(chunk, TestVec.chunk(idx), "chunk pattern");

            // Prover side must reproduce the vector's path and covering-peak index.
            (uint256 k, bytes32[] memory path) = TestVec.prove(idx, n);
            assertEq(k, json.readUint(string.concat(key, ".peakIndex")), "peak index");
            assertEq(path, json.readBytes32Array(string.concat(key, ".path")), "path");

            // Verifier side: accept the truth, reject each perturbation.
            assertTrue(MMR.verify(chunk, idx, path, n, peaks), "valid proof rejected");
            assertFalse(
                MMR.verify(TestVec.chunk(idx + 1), idx, path, n, peaks), "wrong chunk accepted"
            );
            if (idx + 1 < n) {
                assertFalse(MMR.verify(chunk, idx + 1, path, n, peaks), "wrong index accepted");
            }
            bytes32[] memory padded = new bytes32[](path.length + 1);
            for (uint256 l = 0; l < path.length; ++l) {
                padded[l] = path[l];
            }
            assertFalse(MMR.verify(chunk, idx, padded, n, peaks), "wrong path length accepted");
            // NB: verify() alone cannot reject every wrong n — (n, peaks) are jointly
            // authenticated upstream by re-bagging against the pinned root commitment, so
            // the structural check here is only the peak-count/geometry one:
            assertFalse(MMR.verify(chunk, idx, path, 15, peaks), "peak-count mismatch accepted");
            ++i;
        }
        assertGt(i, 0, "no cases");
    }

    /// Out-of-range index and empty MMR are rejected, not out-of-bounds.
    function test_inclusion_outOfRange() public pure {
        (bytes32[] memory peaks,) = TestVec.buildPeaks(13);
        (, bytes32[] memory path) = TestVec.prove(0, 13);
        assertFalse(MMR.verify(TestVec.chunk(13), 13, path, 13, peaks), "i == n accepted");
        assertFalse(
            MMR.verify(TestVec.chunk(0), 0, new bytes32[](0), 0, new bytes32[](0)),
            "empty MMR accepted"
        );
    }

    /// Differential check on a larger, irregular shape: every leaf of a 3-peak MMR
    /// proves and verifies; cross-peak boundaries included (n = 22 = 0b10110).
    function test_inclusion_allLeaves_n22() public pure {
        uint64 n = 22;
        (bytes32[] memory peaks,) = TestVec.buildPeaks(n);
        for (uint64 i = 0; i < n; ++i) {
            (, bytes32[] memory path) = TestVec.prove(i, n);
            assertTrue(MMR.verify(TestVec.chunk(i), i, path, n, peaks), "leaf failed");
            assertFalse(MMR.verify(TestVec.chunk(i + 1), i, path, n, peaks), "forgery passed");
        }
    }
}
