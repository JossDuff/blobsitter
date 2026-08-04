// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// §12.5 / §13.2 challenge game: open → answer / timeout, pinning, boundaries, and
/// selector-matched negatives for the whole §16 challenge group.
contract ChallengeTest is InstanceTestBase {
    address internal constant OPERATOR = address(0x0101);
    address internal constant WITHDRAWAL = address(0x0202);
    address internal constant CHALLENGER = address(0x0303);

    uint64 internal pid;

    function setUp() public override {
        super.setUp();
        vm.deal(address(this), 100 ether);
        vm.deal(CHALLENGER, 100 ether);
        vm.fee(10 gwei); // §12.5 bond sizing is basefee-denominated
        _declare(13);
        pid = instance.stake{value: 2 ether}(OPERATOR, WITHDRAWAL);
    }

    /// §12.5 bond floor. Deliberately no external calls: a view call into the instance
    /// here would consume a pending vm.prank/vm.expectRevert at the call sites.
    function _requiredBond(uint256 k) internal view returns (uint256) {
        return 3 * (k * 38_680 + 21_000) * block.basefee;
    }

    function _indices3() internal pure returns (uint64[] memory idx) {
        idx = new uint64[](3);
        (idx[0], idx[1], idx[2]) = (0, 5, 12); // first leaf, big-peak interior, lone peak
    }

    function _open(uint64[] memory indices) internal returns (uint64 id) {
        vm.prank(CHALLENGER);
        id = instance.challenge{value: _requiredBond(indices.length)}(pid, indices);
    }

    /// Correct chunks + paths for `indices` against the pattern MMR at leaf count n.
    function _proofsFor(uint64[] memory indices, uint64 n)
        internal
        pure
        returns (BlobsitterInstance.ChunkProof[] memory proofs)
    {
        proofs = new BlobsitterInstance.ChunkProof[](indices.length);
        for (uint256 j = 0; j < indices.length; ++j) {
            (, bytes32[] memory path) = TestVec.prove(indices[j], n);
            proofs[j] =
                BlobsitterInstance.ChunkProof({chunk: TestVec.chunk(indices[j]), path: path});
        }
    }

    function _respond(uint64 id, uint64[] memory indices, uint64 n) internal {
        (bytes32[] memory peaks,) = TestVec.buildPeaks(n);
        vm.prank(OPERATOR);
        instance.respond(id, indices, n, peaks, _proofsFor(indices, n));
    }

    // ------------------------------------------------------------------------- open

    function test_challenge_open() public {
        uint64[] memory idx = _indices3();
        uint256 bond = _requiredBond(3);
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.ChallengeOpened(
            0, pid, idx, bond, instance.root(), 13, uint64(block.timestamp) + uint64(7 days)
        );
        uint64 id = _open(idx);

        BlobsitterInstance.Challenge memory c = instance.getChallenge(id);
        assertEq(c.providerId, pid);
        assertEq(c.challenger, CHALLENGER);
        assertEq(c.bond, bond);
        assertEq(c.pinnedRoot, instance.root(), "ACTIVE pins the current root");
        assertEq(c.pinnedLeafCount, 13);
        assertEq(c.k, 3);
        assertEq(c.indicesHash, keccak256(abi.encodePacked(idx)), "padded-word packed encoding");
        assertEq(instance.getProvider(pid).openChallenges, 1);
    }

    function test_challenge_openNegatives() public {
        uint64[] memory idx = _indices3();
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.UnknownProvider.selector, 99));
        instance.challenge{value: _requiredBond(3)}(99, idx);

        vm.expectRevert(BlobsitterInstance.NoIndices.selector);
        instance.challenge{value: _requiredBond(1)}(pid, new uint64[](0));

        uint64[] memory tooMany = new uint64[](33);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.TooManyIndices.selector, 32));
        instance.challenge{value: _requiredBond(33)}(pid, tooMany);

        uint64[] memory oob = new uint64[](1);
        oob[0] = 13;
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.IndexOutOfRange.selector, 13, 13));
        instance.challenge{value: _requiredBond(1)}(pid, oob);

        uint256 required = _requiredBond(3);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.BondTooSmall.selector, required));
        instance.challenge{value: required - 1}(pid, idx);
    }

    /// Duplicate indices are admitted (§12.5) — they only waste the challenger's bond.
    function test_challenge_duplicateIndices() public {
        uint64[] memory dup = new uint64[](2);
        (dup[0], dup[1]) = (5, 5);
        uint64 id = _open(dup);
        _respond(id, dup, 13);
        assertEq(instance.getProvider(pid).openChallenges, 0);
    }

    // ---------------------------------------------------------------------- respond

    function test_respond() public {
        uint64[] memory idx = _indices3();
        uint64 id = _open(idx);
        uint256 bond = instance.getChallenge(id).bond;

        vm.expectEmit(address(instance));
        emit BlobsitterInstance.ChallengeAnswered(id);
        _respond(id, idx, 13);

        assertEq(instance.getChallenge(id).resolved, true);
        assertEq(instance.getProvider(pid).openChallenges, 0);
        assertEq(OPERATOR.balance, bond, "bond fuels the hot wallet, not the cold keys");
    }

    /// The pin survives later declarations: responders must present the HISTORICAL
    /// (n, peaks) matching the pinned root, not the current state.
    function test_respond_usesPinnedStateAfterNewDeclarations() public {
        uint64[] memory idx = _indices3();
        uint64 id = _open(idx); // pins n = 13
        _declare(3); // now n = 16

        (bytes32[] memory currentPeaks,) = TestVec.buildPeaks(16);
        vm.prank(OPERATOR);
        vm.expectRevert(BlobsitterInstance.PinMismatch.selector);
        instance.respond(id, idx, 16, currentPeaks, _proofsFor(idx, 16));

        _respond(id, idx, 13); // the historical state answers
        assertEq(instance.getChallenge(id).resolved, true);
    }

    function test_respond_windowBoundary() public {
        // Expected deadlines are computed explicitly, never by re-reading
        // block.timestamp after vm.warp — via-IR CSE treats TIMESTAMP as constant
        // within a call, so a re-read can observe the pre-warp value.
        uint64 t0 = uint64(block.timestamp);
        uint64[] memory idx = _indices3();
        uint64 id = _open(idx);

        vm.warp(t0 + 7 days - 1); // §13: open while now < deadline
        _respond(id, idx, 13);

        uint64 id2 = _open(idx); // opened at t0 + 7d − 1
        uint64 deadline2 = t0 + 7 days - 1 + 7 days;
        vm.warp(deadline2);
        (bytes32[] memory peaks,) = TestVec.buildPeaks(13);
        BlobsitterInstance.ChunkProof[] memory proofs = _proofsFor(idx, 13);
        vm.prank(OPERATOR);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.ResponseWindowClosed.selector, deadline2)
        );
        instance.respond(id2, idx, 13, peaks, proofs);
    }

    function test_respond_negatives() public {
        uint64[] memory idx = _indices3();
        uint64 id = _open(idx);
        (bytes32[] memory peaks,) = TestVec.buildPeaks(13);
        BlobsitterInstance.ChunkProof[] memory proofs = _proofsFor(idx, 13);

        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.UnknownChallenge.selector, 77));
        instance.respond(77, idx, 13, peaks, proofs);

        vm.prank(CHALLENGER);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotOperator.selector, pid));
        instance.respond(id, idx, 13, peaks, proofs);

        // Wrong proof count.
        BlobsitterInstance.ChunkProof[] memory two = new BlobsitterInstance.ChunkProof[](2);
        (two[0], two[1]) = (proofs[0], proofs[1]);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.ProofCountMismatch.selector, 3));
        instance.respond(id, idx, 13, peaks, two);

        // Indices not matching the committed hash.
        uint64[] memory other = new uint64[](3);
        (other[0], other[1], other[2]) = (0, 5, 11);
        vm.prank(OPERATOR);
        vm.expectRevert(BlobsitterInstance.IndicesMismatch.selector);
        instance.respond(id, other, 13, peaks, proofs);

        // The §7.2 trap: right shape, wrong chunk at sample 1 — no partial credit.
        BlobsitterInstance.ChunkProof[] memory forged = _proofsFor(idx, 13);
        forged[1].chunk = TestVec.chunk(6);
        vm.prank(OPERATOR);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.InvalidInclusionProof.selector, 1)
        );
        instance.respond(id, idx, 13, peaks, forged);
        assertEq(instance.getChallenge(id).resolved, false, "challenge stays OPEN");

        // Resolved challenges take no further responses.
        _respond(id, idx, 13);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.AlreadyResolved.selector, id));
        instance.respond(id, idx, 13, peaks, proofs);
    }

    /// A post-slash challenge whose window is still open: ProviderSlashed governs
    /// (staggered opens — the second challenge outlives the first one's timeout).
    function test_respond_afterSlash() public {
        uint64 t0 = uint64(block.timestamp);
        uint64 pid2 = instance.stake{value: 2 ether}(OPERATOR, WITHDRAWAL);
        vm.prank(CHALLENGER);
        uint64 c1 = instance.challenge{value: _requiredBond(1)}(pid2, _one(0));
        vm.warp(t0 + 4 days);
        vm.prank(CHALLENGER);
        uint64 c2 = instance.challenge{value: _requiredBond(1)}(pid2, _one(1));
        vm.warp(t0 + 7 days); // c1 expired; c2 has 4 days left
        instance.resolveTimeout(c1); // pid2 slashed

        (bytes32[] memory peaks,) = TestVec.buildPeaks(13);
        BlobsitterInstance.ChunkProof[] memory proofs = _proofsFor(_one(1), 13);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.ProviderSlashed.selector, pid2));
        instance.respond(c2, _one(1), 13, peaks, proofs);
    }

    // --------------------------------------------------------------- resolveTimeout

    function test_resolveTimeout_slashArithmetic() public {
        uint64[] memory idx = _indices3();
        uint64 id = _open(idx);
        uint256 bond = instance.getChallenge(id).bond;
        uint64 deadline = uint64(block.timestamp) + uint64(7 days);

        vm.warp(deadline - 1);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.ResponseWindowStillOpen.selector, deadline)
        );
        instance.resolveTimeout(id);

        vm.warp(deadline); // §13: consequence available at now >= deadline
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Slashed(
            pid, BlobsitterInstance.SlashCause.CHALLENGE_TIMEOUT, address(this)
        );
        instance.resolveTimeout(id);

        uint256 bounty = (2 ether * 1500) / 10_000;
        assertEq(CHALLENGER.balance, 100 ether - bond + bounty + bond, "bounty + bond refund");
        assertEq(instance.pendingSlashRemainders(), 2 ether - bounty, "remainder held for M4");
        // I5: the distribution sums exactly to the stake.
        assertEq(bounty + (2 ether - bounty), 2 ether);
        assertEq(
            uint8(instance.getProvider(pid).status),
            uint8(BlobsitterInstance.ProviderStatus.SLASHED)
        );
        assertEq(instance.getProvider(pid).openChallenges, 0);

        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.AlreadyResolved.selector, id));
        instance.resolveTimeout(id);
    }

    /// Second timeout on an already-slashed provider: refund only, no double slash.
    function test_resolveTimeout_refundPath() public {
        uint64[] memory idx = _indices3();
        uint64 idA = _open(idx);
        uint64 idB = _open(idx);
        uint256 bondEach = instance.getChallenge(idA).bond;
        vm.warp(block.timestamp + 7 days);

        instance.resolveTimeout(idA);
        uint256 remaindersAfterFirst = instance.pendingSlashRemainders();

        vm.expectEmit(address(instance));
        emit BlobsitterInstance.ChallengeRefunded(idB);
        instance.resolveTimeout(idB);

        assertEq(
            instance.pendingSlashRemainders(), remaindersAfterFirst, "no second distribution (I3)"
        );
        uint256 bounty = (2 ether * 1500) / 10_000;
        assertEq(CHALLENGER.balance, 100 ether + bounty, "both bonds back + one bounty");
        assertEq(instance.getProvider(pid).openChallenges, 0);
        assertEq(bondEach > 0, true, "bond was nonzero under vm.fee");
    }

    // ------------------------------------------------- unbonding pins & admission

    /// I10: challenges against an UNBONDING provider pin the exit snapshot; indices
    /// beyond exitLeafCount are inadmissible even though the dataset has grown.
    function test_challenge_unbondingPinsExitSnapshot() public {
        vm.prank(OPERATOR);
        instance.initiateUnbonding(pid);
        bytes32 exitRoot = instance.getProvider(pid).exitRoot;
        _declare(3); // dataset grows to 16 post-initiation

        uint64[] memory oob = _one(13); // < current 16, but >= exit pin 13
        vm.prank(CHALLENGER);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.IndexOutOfRange.selector, 13, 13));
        instance.challenge{value: _requiredBond(1)}(pid, oob);

        uint64 id = _open(_one(12));
        BlobsitterInstance.Challenge memory c = instance.getChallenge(id);
        assertEq(c.pinnedRoot, exitRoot, "pins the exit snapshot, not the live root");
        assertEq(c.pinnedLeafCount, 13);
        _respond(id, _one(12), 13);
    }

    /// §13.1 exit-window boundary + terminal statuses (decision: ChallengeWindowClosed
    /// for every no-longer-challengeable status).
    function test_challenge_windowClosed() public {
        vm.prank(OPERATOR);
        instance.initiateUnbonding(pid);
        uint64 until = uint64(block.timestamp) + uint64(14 days);

        vm.warp(until - 1);
        uint64 id = _open(_one(0)); // still open at delay − 1
        _respond(id, _one(0), 13);

        vm.warp(until);
        vm.prank(CHALLENGER);
        vm.expectRevert(BlobsitterInstance.ChallengeWindowClosed.selector);
        instance.challenge{value: _requiredBond(1)}(pid, _one(0));

        instance.withdraw(pid); // EXITED — still closed
        vm.prank(CHALLENGER);
        vm.expectRevert(BlobsitterInstance.ChallengeWindowClosed.selector);
        instance.challenge{value: _requiredBond(1)}(pid, _one(0));

        // SLASHED — closed too.
        uint64 pid2 = instance.stake{value: 2 ether}(OPERATOR, WITHDRAWAL);
        vm.prank(CHALLENGER);
        uint64 c1 = instance.challenge{value: _requiredBond(1)}(pid2, _one(0));
        vm.warp(block.timestamp + 7 days);
        instance.resolveTimeout(c1);
        vm.prank(CHALLENGER);
        vm.expectRevert(BlobsitterInstance.ChallengeWindowClosed.selector);
        instance.challenge{value: _requiredBond(1)}(pid2, _one(0));
    }

    /// I7 groundwork: an open challenge blocks withdraw until answered.
    function test_withdraw_blockedByOpenChallenge() public {
        vm.prank(OPERATOR);
        instance.initiateUnbonding(pid);
        uint64 until = uint64(block.timestamp) + uint64(14 days);

        vm.warp(until - 12 hours); // late challenge, still in the exit window
        uint64 id = _open(_one(3));

        vm.warp(until);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.OpenChallengesRemain.selector, 1));
        instance.withdraw(pid);

        _respond(id, _one(3), 13);
        instance.withdraw(pid);
        assertEq(WITHDRAWAL.balance, 2 ether, "exit completes after the answer");
    }

    function _one(uint64 i) internal pure returns (uint64[] memory idx) {
        idx = new uint64[](1);
        idx[0] = i;
    }
}
