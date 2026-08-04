// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {MMR} from "src/libraries/MMR.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// Golden-vector conformance: Solidity vs `vectors/*.json`, value for value. A failure
/// means this code and the vector generator disagree about the normative spec —
/// investigate which is wrong; never "fix" a vector.
contract VectorsTest is Test {
    using stdJson for string;

    function _load(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat("../vectors/", name));
    }

    function _caseKey(uint256 i) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "]");
    }

    function _caseCount(string memory json) internal view returns (uint256 n) {
        while (vm.keyExistsJson(json, _caseKey(n))) {
            ++n;
        }
        require(n > 0, "empty vector file");
    }

    /// Hash-primitive anchor: the protocol's hash is Ethereum's Keccak-256, and this
    /// guards against the classic NIST-SHA-3-instead-of-Keccak mixup.
    function test_vectors_keccakSanity() public view {
        string memory json = _load("keccak_sanity.json");
        assertEq(keccak256(""), json.readBytes32(".keccak256_empty"), "empty keccak anchor");
        assertEq(keccak256("abc"), json.readBytes32(".keccak256_abc"), "abc keccak anchor");
        bytes memory chunk0 = json.readBytes(".chunk_0");
        assertEq(chunk0.length, 31, "chunk length");
        assertEq(bytes31(chunk0), TestVec.chunk(0), "chunk pattern");
        assertEq(MMR.leafHash(TestVec.chunk(0)), json.readBytes32(".leaf_of_chunk_0"), "leaf hash");
    }

    /// MMR shape: peaks and bagged root for a spread of leaf counts, built leaf by leaf.
    function test_vectors_mmrRoots() public view {
        string memory json = _load("mmr_roots.json");
        uint256 cases = _caseCount(json);
        for (uint256 i = 0; i < cases; ++i) {
            string memory key = _caseKey(i);
            uint64 n = uint64(json.readUint(string.concat(key, ".leafCount")));
            uint256[] memory heights = json.readUintArray(string.concat(key, ".peakHeights"));
            // Peak heights are the set bits of n, tallest first.
            assertEq(heights.length, MMR.peakCount(n), "peak count");
            for (uint256 k = 0; k < heights.length; ++k) {
                assertEq((n >> heights[k]) & 1, 1, "height not a set bit");
                if (k > 0) assertLt(heights[k], heights[k - 1], "not descending");
            }
            (bytes32[] memory peaks, uint64 cnt) = TestVec.buildPeaks(n);
            assertEq(cnt, n, "leaf count");
            assertEq(peaks, json.readBytes32Array(string.concat(key, ".peaks")), "peaks");
            assertEq(MMR.bagRoot(n, peaks), json.readBytes32(string.concat(key, ".root")), "root");
        }
    }

    /// Append decomposition: the height sequence an update splits into, the publisher-side
    /// subtree roots, and the peak merge — the exact algorithm declareFor executes.
    function test_vectors_appendDecomposition() public view {
        string memory json = _load("append_decomposition.json");
        uint256 cases = _caseCount(json);
        for (uint256 i = 0; i < cases; ++i) {
            string memory key = _caseKey(i);
            uint64 n = uint64(json.readUint(string.concat(key, ".priorLeafCount")));
            uint64 m = uint64(json.readUint(string.concat(key, ".updateChunks")));

            uint8[] memory heights = MMR.decompose(n, m);
            uint256[] memory wantHeights = json.readUintArray(string.concat(key, ".heights"));
            assertEq(heights.length, wantHeights.length, "decompose length");
            for (uint256 k = 0; k < heights.length; ++k) {
                assertEq(heights[k], wantHeights[k], "decompose height");
            }

            // Publisher side: recompute the submitted subtree roots from the pattern.
            bytes32[] memory subtrees = TestVec.subtreePeaks(n, m);
            assertEq(
                subtrees, json.readBytes32Array(string.concat(key, ".newSubtreePeaks")), "subtrees"
            );

            // Contract side: merge into the prior state (built as one batched update
            // from empty — cheap for large n; small cases below cross-check leaf-by-leaf).
            (bytes32[] memory prior, uint64 cnt) = _batchedBuild(n);
            (bytes32[] memory result, uint64 newCnt) =
                MMR.applyUpdate(prior, cnt, subtrees, heights);
            assertEq(newCnt, n + m, "result leaf count");
            assertEq(
                result, json.readBytes32Array(string.concat(key, ".resultPeaks")), "result peaks"
            );
            assertEq(
                MMR.bagRoot(newCnt, result),
                json.readBytes32(string.concat(key, ".resultRoot")),
                "result root"
            );

            // Batched path == the obviously-correct leaf-by-leaf path (small cases).
            if (n + m <= 64) {
                (bytes32[] memory leafwise,) = TestVec.buildPeaks(n + m);
                assertEq(result, leafwise, "batch != leaf-by-leaf");
            }
        }
    }

    /// The Fiat–Shamir evaluation point z. Its derivation hashes in the instance's own
    /// address, so the instance is deployed at the vector's dummy address.
    function test_vectors_fsZ() public {
        string memory json = _load("fs_z.json");
        address at = json.readAddress(".instance");
        BlobsitterInstance.Params memory p;
        p.publisher = address(0xbeef); // z touches no parameter
        deployCodeTo("BlobsitterInstance.sol:BlobsitterInstance", abi.encode(p), at);

        uint64 n0 = uint64(json.readUint(".priorLeafCount"));
        bytes32[] memory priorPeaks = json.readBytes32Array(".priorPeaks");
        // The vector's inputs must themselves be coherent with the pattern build.
        (bytes32[] memory built,) = TestVec.buildPeaks(n0);
        assertEq(built, priorPeaks, "prior peaks");

        bytes32 z = BlobsitterInstance(at)
            .fiatShamirZ(
                json.readBytes32Array(".blobVersionedHashes"),
                priorPeaks,
                json.readBytes32Array(".newSubtreePeaks"),
                n0,
                uint64(json.readUint(".newLeafCount"))
            );
        assertEq(uint256(z), json.readUint(".z"), "z");
    }

    /// Peaks at leaf count n via a single batched update from the empty MMR.
    function _batchedBuild(uint64 n) internal pure returns (bytes32[] memory, uint64) {
        bytes32[] memory empty = new bytes32[](0);
        if (n == 0) return (empty, 0);
        return MMR.applyUpdate(empty, 0, TestVec.subtreePeaks(0, n), MMR.decompose(0, n));
    }
}
