// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// declareFor: happy paths through the real point-evaluation precompile (see
/// InstanceTestBase for the zero-blob-opening strategy) and selector-matched negatives
/// for every declaration error the instance defines.
contract DeclareTest is InstanceTestBase {
    function test_declareFor() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(5, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Declared(
            0, 5, d.blobVersionedHashes, d.newSubtreePeaks, bytes32(0), address(this)
        );
        instance.declareFor(d, _sign(instance.declarationDigest(d)), o, goodProof);

        assertEq(instance.leafCount(), 5, "leaf count");
        assertEq(instance.declarationNonce(), 1, "nonce advanced");
        (bytes32[] memory want,) = TestVec.buildPeaks(5);
        assertEq(instance.allPeaks(), want, "peaks");
        assertEq(instance.appPointer(), bytes32(0), "zero appPointer means no update");

        // Second declaration (5 → 8, the fs_z.json shape) with a batch-final
        // appPointer, submitted exactly at its deadline (intent deadlines are
        // inclusive: valid while now <= deadline).
        bytes32 ptr = keccak256("batch-final view CID");
        (d, o) = _makeDeclaration(3, ptr, address(0));
        d.deadline = uint64(block.timestamp);
        vm.blobhashes(d.blobVersionedHashes);
        instance.declareFor(d, _sign(instance.declarationDigest(d)), o, goodProof);

        assertEq(instance.leafCount(), 8, "leaf count 2");
        assertEq(instance.appPointer(), ptr, "appPointer stored");
        (want,) = TestVec.buildPeaks(8);
        assertEq(instance.allPeaks(), want, "peaks 2");
        assertEq(instance.root(), keccak256(abi.encodePacked(bytes1(0x02), uint64(8), want)));
    }

    /// A multi-blob update (m > 4096 ⇒ B = 2) exercises the per-blob loops.
    function test_declareFor_multiBlob() public {
        BlobsitterInstance.Declaration memory d = _declare(5000);
        assertEq(d.blobVersionedHashes.length, 2, "two blobs");
        assertEq(instance.leafCount(), 5000);
        (bytes32[] memory want,) = TestVec.buildPeaks(5000);
        assertEq(instance.allPeaks(), want, "peaks");
    }

    function test_declareFor_designatedCarrier() public {
        // Designated to this test contract: succeeds.
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(this));
        vm.blobhashes(d.blobVersionedHashes);
        instance.declareFor(d, _sign(instance.declarationDigest(d)), o, goodProof);
        assertEq(instance.leafCount(), 2);

        // Designated to someone else: NotDesignatedCarrier(want).
        (d, o) = _makeDeclaration(2, bytes32(0), address(0xDEAD));
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(
                BlobsitterInstance.NotDesignatedCarrier.selector, address(0xDEAD)
            )
        );
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_expired() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        d.deadline = uint64(block.timestamp - 1);
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.IntentExpired.selector, d.deadline)
        );
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_wrongNonce() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        d.nonce = 3;
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.WrongNonce.selector, uint64(0)));
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_badSignature() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        // Tamper with a signed field after signing.
        d.appPointer = keccak256("tampered");
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        instance.declareFor(d, sig, o, goodProof);
    }

    /// EmptyUpdate rejects any declaration with newLeafCount ≤ current leafCount — the
    /// MMR is append-only, so both the equal and the regressing case must revert.
    function test_declareFor_emptyUpdate() public {
        _declare(4);
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(1, bytes32(0), address(0));

        d.newLeafCount = 4;
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(BlobsitterInstance.EmptyUpdate.selector);
        instance.declareFor(d, sig, o, goodProof);

        d.newLeafCount = 3;
        sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(BlobsitterInstance.EmptyUpdate.selector);
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_blobCountMismatch() public {
        // Two signed versioned hashes for a 2-chunk (1-blob) update.
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        bytes32[] memory two = new bytes32[](2);
        (two[0], two[1]) = (zeroBlobVh, zeroBlobVh);
        d.blobVersionedHashes = two;
        vm.blobhashes(two);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.BlobCountMismatch.selector, uint256(1))
        );
        instance.declareFor(d, sig, o, goodProof);

        // Right hashes, wrong openings count.
        (d,) = _makeDeclaration(2, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        sig = _sign(instance.declarationDigest(d));
        BlobsitterInstance.BlobOpening[] memory none = new BlobsitterInstance.BlobOpening[](0);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.BlobCountMismatch.selector, uint256(1))
        );
        instance.declareFor(d, sig, none, goodProof);
    }

    /// The carrying transaction's blobs must be exactly the versioned hashes the
    /// publisher signed — a carrier cannot substitute its own blobs.
    function test_declareFor_blobHashMismatch() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        bytes32[] memory actual = new bytes32[](1);
        actual[0] = _versionedHash(hex"deadbeef");
        vm.blobhashes(actual);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.BlobHashMismatch.selector, uint256(0))
        );
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_unexpectedExtraBlob() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        bytes32[] memory actual = new bytes32[](2);
        (actual[0], actual[1]) = (zeroBlobVh, zeroBlobVh);
        vm.blobhashes(actual);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(BlobsitterInstance.UnexpectedExtraBlob.selector);
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_subtreeCountMismatch() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(4, bytes32(0), address(0)); // decompose(0,4) = [2]: 1 subtree
        bytes32[] memory padded = new bytes32[](2);
        (padded[0], padded[1]) = (d.newSubtreePeaks[0], bytes32(uint256(1)));
        d.newSubtreePeaks = padded;
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.SubtreeCountMismatch.selector, uint256(1))
        );
        instance.declareFor(d, sig, o, goodProof);
    }

    /// A garbage opening must fail the REAL precompile (no mocks on this path).
    function test_declareFor_pointEvaluationFailed() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        o[0].commitment = new bytes(48); // 0x00…00 is not a valid compressed G1 point
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.PointEvaluationFailed.selector, uint256(0))
        );
        instance.declareFor(d, sig, o, goodProof);

        // A claimed y ≠ 0 for the zero blob is equally rejected.
        (d, o) = _makeDeclaration(2, bytes32(0), address(0));
        o[0].y = bytes32(uint256(1));
        vm.blobhashes(d.blobVersionedHashes);
        sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.PointEvaluationFailed.selector, uint256(0))
        );
        instance.declareFor(d, sig, o, goodProof);
    }

    function test_declareFor_invalidEquivalenceProof() public {
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(BlobsitterInstance.InvalidEquivalenceProof.selector);
        instance.declareFor(d, sig, o, hex"bad0bad0");
    }
}

/// Activity-checkpoint advancement (the dormancy clock resets only once enough new
/// chunks have accumulated since the last checkpoint), on an instance sized so the
/// threshold is reachable in-test (dormancyMinChunks = 8).
contract DeclareCheckpointTest is InstanceTestBase {
    function _params() internal view override returns (BlobsitterInstance.Params memory p) {
        p = super._params();
        p.dormancyMinChunks = 8;
    }

    function test_declareFor_activityCheckpoint() public {
        uint64 deployTime = instance.activityCheckpointTime();
        assertEq(instance.activityCheckpointLeafCount(), 0, "starts at (deployTime, 0)");

        _declare(5); // 5 − 0 < 8: no advance
        assertEq(instance.activityCheckpointTime(), deployTime, "below threshold");

        vm.warp(block.timestamp + 1 days);
        _declare(3); // 8 − 0 ≥ 8: advance to (now, 8)
        assertEq(instance.activityCheckpointTime(), uint64(block.timestamp), "advanced");
        assertEq(instance.activityCheckpointLeafCount(), 8, "advanced count");

        vm.warp(block.timestamp + 1 days);
        _declare(7); // 15 − 8 < 8: no advance
        assertEq(instance.activityCheckpointLeafCount(), 8, "unchanged");
        _declare(1); // 16 − 8 ≥ 8: advance
        assertEq(instance.activityCheckpointLeafCount(), 16, "advanced again");
    }
}
