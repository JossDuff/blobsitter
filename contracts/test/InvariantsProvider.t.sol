// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CommonBase} from "forge-std/Base.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// Random-walk handler over the whole provider/challenge surface: stakes, declarations,
/// unbonding, valid challenge opens, correct responses, timeouts, withdrawals, time
/// warps, and deliberately-invalid operations (I9). Per-operation assertions enforce
/// I2 (stake sink), I4 (bond destination), I6 (transition subset), I9 (admission), and
/// I10 (exit pinning); the invariant functions below check the global properties.
contract ProviderHandler is CommonBase, StdUtils {
    uint256 internal constant PUBLISHER_PK = 0xA11CE;
    uint256 internal constant STAKE = 2 ether;
    uint64 internal constant LEAF_CAP = 200; // bounds TestVec.prove cost

    BlobsitterInstance public immutable instance;
    bytes internal goodProof;
    bytes32 internal zeroBlobVh;
    bytes internal infinityG1;

    address[3] internal operators = [address(0x1001), address(0x1002), address(0x1003)];
    address[3] internal withdrawals = [address(0x2001), address(0x2002), address(0x2003)];
    address[2] internal challengers = [address(0x3001), address(0x3002)];

    // Ghost state.
    uint64[] public providerIds;
    mapping(uint64 => BlobsitterInstance.ProviderStatus) public lastStatus;
    mapping(uint64 => bool) public stakeDistributed; // I3: withdraw XOR slash, at most once
    mapping(uint64 => uint64[]) internal challengeIndicesOf;
    uint256 public slashCount;
    uint256 public expectedBalance; // I1: exact expected instance balance

    constructor(
        BlobsitterInstance instance_,
        bytes memory goodProof_,
        bytes32 zeroBlobVh_,
        bytes memory infinityG1_
    ) {
        instance = instance_;
        goodProof = goodProof_;
        zeroBlobVh = zeroBlobVh_;
        infinityG1 = infinityG1_;
    }

    // -------------------------------------------------------------------- actions

    function warp(uint256 delta) external {
        vm.warp(block.timestamp + _bound(delta, 1 hours, 8 days));
    }

    function declare(uint64 m) external {
        uint64 n0 = instance.leafCount();
        if (n0 >= LEAF_CAP) return;
        m = uint64(_bound(m, 1, LEAF_CAP - n0));

        BlobsitterInstance.Declaration memory d;
        d.nonce = instance.declarationNonce();
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = new bytes32[](1);
        d.blobVersionedHashes[0] = zeroBlobVh;
        d.newSubtreePeaks = TestVec.subtreePeaks(n0, m);
        d.newLeafCount = n0 + m;
        BlobsitterInstance.BlobOpening[] memory o = new BlobsitterInstance.BlobOpening[](1);
        o[0] = BlobsitterInstance.BlobOpening({
            y: bytes32(0), commitment: infinityG1, kzgProof: infinityG1
        });
        vm.blobhashes(d.blobVersionedHashes);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PUBLISHER_PK, instance.declarationDigest(d));
        instance.declareFor(d, abi.encodePacked(r, s, v), o, goodProof);
    }

    function stakeProvider(uint256 seed) external {
        address op = operators[seed % 3];
        vm.deal(op, op.balance + STAKE);
        vm.prank(op);
        uint64 id = instance.stake{value: STAKE}(op, withdrawals[(seed / 3) % 3]);
        providerIds.push(id);
        lastStatus[id] = BlobsitterInstance.ProviderStatus.ACTIVE;
        expectedBalance += STAKE;
        _observe(id);
    }

    function unbond(uint256 seed) external {
        (uint64 id, BlobsitterInstance.Provider memory p) = _pick(seed);
        if (id == 0 || p.status != BlobsitterInstance.ProviderStatus.ACTIVE) return;
        bytes32 rootNow = instance.root();
        uint64 nNow = instance.leafCount();
        vm.prank(p.operator);
        instance.initiateUnbonding(id);
        // I10 (pin source): the exit snapshot equals the state at initiation.
        BlobsitterInstance.Provider memory after_ = instance.getProvider(id);
        require(after_.exitRoot == rootNow && after_.exitLeafCount == nNow, "I10: bad exit pin");
        _observe(id);
    }

    function openChallenge(uint256 seed, uint256 k) external {
        (uint64 id, BlobsitterInstance.Provider memory p) = _pick(seed);
        if (id == 0) return;
        uint64 pinned;
        if (p.status == BlobsitterInstance.ProviderStatus.ACTIVE) {
            pinned = instance.leafCount();
        } else if (
            p.status == BlobsitterInstance.ProviderStatus.UNBONDING
                && block.timestamp < p.unbondingAt + instance.unbondingDelay()
        ) {
            pinned = p.exitLeafCount;
        } else {
            return;
        }
        if (pinned == 0) return;

        k = _bound(k, 1, 8);
        uint64[] memory idx = new uint64[](k);
        for (uint256 j = 0; j < k; ++j) {
            idx[j] = uint64(uint256(keccak256(abi.encode(seed, j))) % pinned);
        }
        uint256 bond = 3 * (k * 38_680 + 21_000) * block.basefee;
        address challenger = challengers[seed % 2];
        vm.deal(challenger, challenger.balance + bond);
        vm.prank(challenger);
        uint64 cid = instance.challenge{value: bond}(id, idx);
        challengeIndicesOf[cid] = idx;
        expectedBalance += bond;

        // I10 (usage): UNBONDING opens pin the exit snapshot, indices < exitLeafCount.
        BlobsitterInstance.Challenge memory c = instance.getChallenge(cid);
        if (p.status == BlobsitterInstance.ProviderStatus.UNBONDING) {
            require(c.pinnedRoot == p.exitRoot, "I10: pin != exit root");
            require(c.pinnedLeafCount == p.exitLeafCount, "I10: pin != exit count");
        }
        _observe(id);
    }

    function respondChallenge(uint256 seed) external {
        (uint64 cid, BlobsitterInstance.Challenge memory c) = _pickChallenge(seed);
        if (cid == type(uint64).max || c.resolved) return;
        if (block.timestamp >= c.openedAt + instance.responseWindow()) return;
        BlobsitterInstance.Provider memory p = instance.getProvider(c.providerId);
        if (p.status == BlobsitterInstance.ProviderStatus.SLASHED) return;

        uint64[] memory idx = challengeIndicesOf[cid];
        uint64 n = c.pinnedLeafCount;
        (bytes32[] memory peaks,) = TestVec.buildPeaks(n);
        BlobsitterInstance.ChunkProof[] memory proofs =
            new BlobsitterInstance.ChunkProof[](idx.length);
        for (uint256 j = 0; j < idx.length; ++j) {
            (, bytes32[] memory path) = TestVec.prove(idx[j], n);
            proofs[j] = BlobsitterInstance.ChunkProof({chunk: TestVec.chunk(idx[j]), path: path});
        }

        uint256 operatorBefore = p.operator.balance;
        vm.prank(p.operator);
        instance.respond(cid, idx, n, peaks, proofs);
        // I4: the whole bond, to the operator, exactly once.
        require(p.operator.balance == operatorBefore + c.bond, "I4: bond != operator delta");
        expectedBalance -= c.bond;
        _observe(c.providerId);
    }

    function timeoutChallenge(uint256 seed) external {
        (uint64 cid, BlobsitterInstance.Challenge memory c) = _pickChallenge(seed);
        if (cid == type(uint64).max || c.resolved) return;
        if (block.timestamp < c.openedAt + instance.responseWindow()) return;

        BlobsitterInstance.Provider memory p = instance.getProvider(c.providerId);
        bool firstSlash = p.status != BlobsitterInstance.ProviderStatus.SLASHED;
        uint256 challengerBefore = c.challenger.balance;
        uint256 bounty = (STAKE * instance.bountyBps()) / 10_000;

        instance.resolveTimeout(cid);

        if (firstSlash) {
            // I3: this is the provider's single stake distribution.
            require(!stakeDistributed[c.providerId], "I3: second distribution");
            stakeDistributed[c.providerId] = true;
            slashCount += 1;
            // I2/I5: bounty + bond to the challenger; remainder retained for M4.
            require(
                c.challenger.balance == challengerBefore + bounty + c.bond,
                "I4/I5: challenger delta"
            );
            expectedBalance -= (bounty + c.bond);
        } else {
            require(c.challenger.balance == challengerBefore + c.bond, "I4: refund delta");
            expectedBalance -= c.bond;
        }
        _observe(c.providerId);
    }

    function withdrawProvider(uint256 seed) external {
        (uint64 id, BlobsitterInstance.Provider memory p) = _pick(seed);
        if (id == 0 || p.status != BlobsitterInstance.ProviderStatus.UNBONDING) return;
        if (block.timestamp < p.unbondingAt + instance.unbondingDelay()) return;
        if (p.openChallenges != 0) return;

        require(!stakeDistributed[id], "I3: withdrawing an already-distributed stake");
        uint256 before = p.withdrawal.balance;
        instance.withdraw(id);
        // I2: the full stake, to the withdrawal address, nothing else.
        require(p.withdrawal.balance == before + STAKE, "I2: stake didn't reach withdrawal");
        stakeDistributed[id] = true;
        expectedBalance -= STAKE;
        _observe(id);
    }

    /// I9: challenges must be inadmissible against EXITED/SLASHED providers.
    function attemptInvalidOpen(uint256 seed) external {
        (uint64 id, BlobsitterInstance.Provider memory p) = _pick(seed);
        if (id == 0) return;
        if (
            p.status != BlobsitterInstance.ProviderStatus.EXITED
                && p.status != BlobsitterInstance.ProviderStatus.SLASHED
        ) return;
        uint64[] memory idx = new uint64[](1);
        try instance.challenge{value: 0}(id, idx) returns (uint64) {
            revert("I9 violated: challenge opened against a terminal provider");
        } catch (bytes memory err) {
            require(
                bytes4(err) == BlobsitterInstance.ChallengeWindowClosed.selector,
                "I9: unexpected admission error"
            );
        }
    }

    // -------------------------------------------------------------------- helpers

    /// I6: every observed transition must be in the legal provider-lifecycle subset —
    /// ACTIVE to UNBONDING or SLASHED, UNBONDING to EXITED or SLASHED — and the
    /// terminal statuses (EXITED, SLASHED) never transition again.
    function _observe(uint64 id) internal {
        BlobsitterInstance.ProviderStatus was = lastStatus[id];
        BlobsitterInstance.ProviderStatus now_ = instance.getProvider(id).status;
        if (was != now_) {
            bool ok =
                (was == BlobsitterInstance.ProviderStatus.ACTIVE
                        && (now_ == BlobsitterInstance.ProviderStatus.UNBONDING
                            || now_ == BlobsitterInstance.ProviderStatus.SLASHED))
                    || (was == BlobsitterInstance.ProviderStatus.UNBONDING
                        && (now_ == BlobsitterInstance.ProviderStatus.EXITED
                            || now_ == BlobsitterInstance.ProviderStatus.SLASHED));
            require(ok, "I6: forbidden transition");
            lastStatus[id] = now_;
        }
    }

    function _pick(uint256 seed)
        internal
        view
        returns (uint64 id, BlobsitterInstance.Provider memory p)
    {
        if (providerIds.length == 0) return (0, p);
        id = providerIds[seed % providerIds.length];
        p = instance.getProvider(id);
    }

    function _pickChallenge(uint256 seed)
        internal
        view
        returns (uint64 cid, BlobsitterInstance.Challenge memory c)
    {
        uint64 total = instance.nextChallengeId();
        if (total == 0) return (type(uint64).max, c);
        cid = uint64(seed % total);
        c = instance.getChallenge(cid);
    }

    function providerCount() external view returns (uint256) {
        return providerIds.length;
    }
}

/// Global invariants I1/I3/I5/I8 over the handler's random walks (I2/I4/I6/I9/I10 are
/// asserted per-operation inside the handler; I7's boundary is a targeted fuzz test).
contract InvariantsProviderTest is InstanceTestBase {
    ProviderHandler internal handler;

    function setUp() public override {
        super.setUp();
        vm.fee(10 gwei);
        handler = new ProviderHandler(instance, goodProof, zeroBlobVh, INFINITY_G1);
        targetContract(address(handler));
    }

    /// I1 — solvency, strengthened to exact balance accounting: stakes of live
    /// providers + open bonds + retained slash remainders (all payout recipients in
    /// this suite are EOAs, so nothing sits in the claimable ledger).
    function invariant_I1_solvency() public view {
        uint256 stakesHeld;
        for (uint256 i = 0; i < handler.providerCount(); ++i) {
            BlobsitterInstance.ProviderStatus s =
            instance.getProvider(handler.providerIds(i)).status;
            if (
                s == BlobsitterInstance.ProviderStatus.ACTIVE
                    || s == BlobsitterInstance.ProviderStatus.UNBONDING
            ) stakesHeld += 2 ether;
        }
        uint256 openBonds;
        for (uint64 c = 0; c < instance.nextChallengeId(); ++c) {
            BlobsitterInstance.Challenge memory ch = instance.getChallenge(c);
            if (!ch.resolved) openBonds += ch.bond;
        }
        uint256 expected = stakesHeld + openBonds + instance.pendingSlashRemainders();
        assertEq(address(instance).balance, expected, "I1: balance != stakes+bonds+remainders");
        assertEq(address(instance).balance, handler.expectedBalance(), "I1: ghost drift");
    }

    /// I3 — single distribution: every SLASHED or EXITED provider distributed exactly
    /// once, every live provider not at all (the handler enforces the XOR per-op; this
    /// checks the aggregate view stayed consistent).
    function invariant_I3_singleDistribution() public view {
        for (uint256 i = 0; i < handler.providerCount(); ++i) {
            uint64 id = handler.providerIds(i);
            BlobsitterInstance.ProviderStatus s = instance.getProvider(id).status;
            bool terminal = s == BlobsitterInstance.ProviderStatus.EXITED
                || s == BlobsitterInstance.ProviderStatus.SLASHED;
            assertEq(handler.stakeDistributed(id), terminal, "I3: distribution/status mismatch");
        }
    }

    /// I5 — slash arithmetic: retained remainders are exactly slashCount × (stake −
    /// bounty); with each bounty paid out, distributions sum to whole stakes.
    function invariant_I5_slashArithmetic() public view {
        uint256 bounty = (2 ether * 1500) / 10_000;
        assertEq(
            instance.pendingSlashRemainders(),
            handler.slashCount() * (2 ether - bounty),
            "I5: remainder sum"
        );
    }

    /// I8 — counter integrity: openChallenges equals the unresolved records per
    /// provider across every interleaving.
    function invariant_I8_counterIntegrity() public view {
        for (uint256 i = 0; i < handler.providerCount(); ++i) {
            uint64 id = handler.providerIds(i);
            uint32 open;
            for (uint64 c = 0; c < instance.nextChallengeId(); ++c) {
                BlobsitterInstance.Challenge memory ch = instance.getChallenge(c);
                if (ch.providerId == id && !ch.resolved) open += 1;
            }
            assertEq(instance.getProvider(id).openChallenges, open, "I8: counter drift");
        }
    }

    /// I7 — exit liveness and bound: withdraw impossible before the delay; with no
    /// open challenge it succeeds exactly at the delay; challenge admission ends at
    /// the same instant, so exit is reachable by delay + responseWindow.
    function testFuzz_I7_exitBound(uint64 offset) public {
        _declare(8);
        address op = address(0x1001);
        uint64 id = instance.stake{value: 2 ether}(op, address(0x2001));
        vm.prank(op);
        instance.initiateUnbonding(id);
        uint64 t0 = uint64(block.timestamp);
        uint64 until = t0 + uint64(14 days);

        offset = uint64(bound(offset, 0, 14 days - 1));
        vm.warp(t0 + offset);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.UnbondingDelayActive.selector, until)
        );
        instance.withdraw(id);

        vm.warp(until);
        uint64[] memory idx = new uint64[](1);
        vm.expectRevert(BlobsitterInstance.ChallengeWindowClosed.selector);
        instance.challenge(id, idx); // no new challenge can defer the exit

        instance.withdraw(id); // and the exit itself succeeds at the bound
        assertEq(
            uint8(instance.getProvider(id).status), uint8(BlobsitterInstance.ProviderStatus.EXITED)
        );
    }
}
