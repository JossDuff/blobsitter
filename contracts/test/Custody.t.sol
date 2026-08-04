// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {stdJson} from "forge-std/StdJson.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// The custody commit/prove cycle: seed + snapshot commitment, the succinct-proof
/// path, the keccak-only escape hatch (including the vacuous empty-dataset case),
/// period discipline, and conformance of the on-chain sample-index derivation to the
/// golden vectors.
contract CustodyTest is InstanceTestBase {
    using stdJson for string;

    address internal constant OPERATOR = address(0x0101);
    address internal constant WITHDRAWAL = address(0x0202);
    bytes32 internal constant SEED = keccak256("period seed");

    uint64 internal pid;

    function setUp() public virtual override {
        super.setUp();
        vm.deal(address(this), 10 ether);
        _declare(50);
        pid = instance.stake{value: 2 ether}(OPERATOR, WITHDRAWAL);
        vm.prevrandao(SEED);
    }

    function _begin() internal {
        vm.prank(OPERATOR);
        instance.beginProof(pid);
    }

    /// Correct escape reveals for the committed snapshot: the contract-derived index
    /// for each ordinal, with the pattern chunk and Merkle path at that position.
    function _revealsFor(bytes32 seed, uint64 n)
        internal
        view
        returns (BlobsitterInstance.ChunkProof[] memory reveals)
    {
        reveals = new BlobsitterInstance.ChunkProof[](32);
        for (uint64 j = 0; j < 32; ++j) {
            uint64 idx = instance.custodyIndex(seed, pid, j, n);
            (, bytes32[] memory path) = TestVec.prove(idx, n);
            reveals[j] = BlobsitterInstance.ChunkProof({chunk: TestVec.chunk(idx), path: path});
        }
    }

    // ------------------------------------------------------------------ beginProof

    function test_beginProof() public {
        uint64 t0 = uint64(block.timestamp);
        vm.warp(t0 + 40 days); // period 1
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.CustodyCommitted(pid, 1, SEED, instance.root(), 50);
        _begin();

        BlobsitterInstance.Provider memory p = instance.getProvider(pid);
        assertEq(p.commitPeriodPlusOne, 2, "period 1 committed");
        assertEq(p.commitSeed, SEED);
        assertEq(p.commitRoot, instance.root());
        assertEq(p.commitLeafCount, 50);
    }

    /// The first commit of a period is binding: the seed cannot be re-rolled even
    /// after the chain's randomness changes.
    function test_beginProof_seedBinding() public {
        _begin();
        vm.prevrandao(keccak256("a luckier seed"));
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.AlreadyCommitted.selector, 0));
        instance.beginProof(pid);
        assertEq(instance.getProvider(pid).commitSeed, SEED, "seed not re-rolled");
    }

    /// A commit from an already-missed period is worthless and silently replaced.
    function test_beginProof_staleCommitOverwritten() public {
        uint64 t0 = uint64(block.timestamp);
        _begin(); // period 0
        vm.warp(t0 + 35 days); // period 1
        vm.prevrandao(keccak256("next period seed"));
        _begin();
        BlobsitterInstance.Provider memory p = instance.getProvider(pid);
        assertEq(p.commitPeriodPlusOne, 2, "fresh commit for period 1");
        assertEq(p.commitSeed, keccak256("next period seed"));
    }

    function test_beginProof_negatives() public {
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotOperator.selector, pid));
        instance.beginProof(pid);

        vm.prank(OPERATOR);
        instance.initiateUnbonding(pid);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotActive.selector, pid));
        instance.beginProof(pid);
    }

    // ------------------------------------------------------------------ submitProof

    function test_submitProof() public {
        _begin();
        // The verifier must be called with the custody vkey, the (deliberately
        // still-empty) public values, and the operator's proof bytes — exactly.
        vm.expectCall(
            instance.SP1_VERIFIER(),
            abi.encodeCall(ISP1VerifierLike.verifyProof, (instance.CUSTODY_VKEY(), "", goodProof))
        );
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.CustodyProven(pid, 0, false);
        vm.prank(OPERATOR);
        instance.submitProof(pid, goodProof);

        BlobsitterInstance.Provider memory p = instance.getProvider(pid);
        assertEq(p.lastProvenPlusOne, 1, "period 0 proven");
        assertEq(p.lastDegraded, false);
        assertEq(p.commitPeriodPlusOne, 0, "commit voided");
    }

    function test_submitProof_negatives() public {
        vm.prank(OPERATOR);
        vm.expectRevert(BlobsitterInstance.NoCommit.selector);
        instance.submitProof(pid, goodProof);

        _begin();
        vm.prank(OPERATOR);
        vm.expectRevert(BlobsitterInstance.InvalidCustodyProof.selector);
        instance.submitProof(pid, hex"bad0");

        // A commit does not survive its period: submission next period is rejected
        // and the missed period stays missed.
        vm.warp(block.timestamp + 30 days);
        vm.prank(OPERATOR);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.CommitFromEarlierPeriod.selector, 0, 1)
        );
        instance.submitProof(pid, goodProof);
    }

    // ----------------------------------------------------------------- escape hatch

    function test_submitProofEscape() public {
        _begin();
        BlobsitterInstance.ChunkProof[] memory reveals = _revealsFor(SEED, 50);
        (bytes32[] memory peaks,) = TestVec.buildPeaks(50);

        vm.expectEmit(address(instance));
        emit BlobsitterInstance.CustodyProven(pid, 0, true);
        vm.prank(OPERATOR);
        instance.submitProofEscape(pid, 50, peaks, reveals);

        BlobsitterInstance.Provider memory p = instance.getProvider(pid);
        assertEq(p.lastProvenPlusOne, 1, "period 0 proven");
        assertEq(p.lastDegraded, true, "flagged degraded");
        assertEq(p.commitPeriodPlusOne, 0, "commit voided");
    }

    /// The committed snapshot survives later declarations: reveals verify against the
    /// commit-time state, and the live state is rejected.
    function test_submitProofEscape_pinnedSnapshot() public {
        _begin(); // pins n = 50
        _declare(10); // live n = 60

        (bytes32[] memory livePeaks,) = TestVec.buildPeaks(60);
        BlobsitterInstance.ChunkProof[] memory liveReveals = _revealsFor(SEED, 60);
        vm.prank(OPERATOR);
        vm.expectRevert(BlobsitterInstance.PinMismatch.selector);
        instance.submitProofEscape(pid, 60, livePeaks, liveReveals);

        (bytes32[] memory peaks,) = TestVec.buildPeaks(50);
        // Hoisted before the prank: _revealsFor makes external view calls, and argument
        // evaluation would otherwise consume the prank.
        BlobsitterInstance.ChunkProof[] memory reveals = _revealsFor(SEED, 50);
        vm.prank(OPERATOR);
        instance.submitProofEscape(pid, 50, peaks, reveals);
        assertEq(instance.getProvider(pid).lastDegraded, true);
    }

    function test_submitProofEscape_negatives() public {
        _begin();
        (bytes32[] memory peaks,) = TestVec.buildPeaks(50);

        // Wrong reveal count.
        BlobsitterInstance.ChunkProof[] memory short_ = new BlobsitterInstance.ChunkProof[](31);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.ProofCountMismatch.selector, 32));
        instance.submitProofEscape(pid, 50, peaks, short_);

        // Right shape, one wrong chunk: rejected at that sample, no partial credit.
        BlobsitterInstance.ChunkProof[] memory forged = _revealsFor(SEED, 50);
        forged[7].chunk = TestVec.chunk(uint64(forged.length)); // any wrong preimage
        vm.prank(OPERATOR);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.InvalidInclusionProof.selector, 7)
        );
        instance.submitProofEscape(pid, 50, peaks, forged);
        assertEq(instance.getProvider(pid).lastProvenPlusOne, 0, "nothing proven");
    }

    /// A provider who staked before any declaration proves the empty snapshot
    /// vacuously: zero reveals, pin check still enforced. Nothing can be sampled from
    /// nothing, and the lapse clock stays curable.
    function test_submitProofEscape_emptyDataset() public {
        BlobsitterInstance fresh = new BlobsitterInstance(_params());
        vm.etch(fresh.SP1_VERIFIER(), instance.SP1_VERIFIER().code);
        uint64 id = fresh.stake{value: 2 ether}(OPERATOR, WITHDRAWAL);
        vm.prank(OPERATOR);
        fresh.beginProof(id);

        // 32 reveals against an empty snapshot are malformed…
        BlobsitterInstance.ChunkProof[] memory nonEmpty = new BlobsitterInstance.ChunkProof[](32);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.ProofCountMismatch.selector, 0));
        fresh.submitProofEscape(id, 0, new bytes32[](0), nonEmpty);

        // …zero reveals prove the period.
        vm.prank(OPERATOR);
        fresh.submitProofEscape(id, 0, new bytes32[](0), new BlobsitterInstance.ChunkProof[](0));
        assertEq(fresh.getProvider(id).lastProvenPlusOne, 1, "vacuously proven");
    }

    // ------------------------------------------------------------------------ lapse

    /// The full health timeline of a provider who stops proving after period 0:
    /// CURRENT through the grace of the first miss, STALE after one full missed
    /// period, LAPSE_ELIGIBLE (provider-curable only) once the second miss completes,
    /// LAPSABLE — and slashable by anyone — one grace window later.
    function test_lapse_statusWalkAndBoundaries() public {
        uint64 t0 = uint64(block.timestamp); // == anchor
        _begin();
        vm.prank(OPERATOR);
        instance.submitProof(pid, goodProof); // period 0 proven; q = 0

        // Misses accumulate: eligibility opens when period q+3 starts, i.e. 3 whole
        // periods after anchor; public slashability one grace window later.
        uint64 eligibleAt = t0 + uint64(90 days);
        uint64 lapsableAt = eligibleAt + uint64(7 days);

        vm.warp(t0 + 35 days); // period 1 (unproven, still current: p == q+1)
        assertEq(
            uint8(instance.custodyStatus(pid)), uint8(BlobsitterInstance.CustodyStatus.CURRENT)
        );
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotLapsable.selector, 0));
        instance.lapse(pid);

        vm.warp(t0 + 65 days); // period 2: one full period missed
        assertEq(uint8(instance.custodyStatus(pid)), uint8(BlobsitterInstance.CustodyStatus.STALE));
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotLapsable.selector, 0));
        instance.lapse(pid);

        vm.warp(eligibleAt); // period 3 begins: two consecutive misses complete
        assertEq(
            uint8(instance.custodyStatus(pid)),
            uint8(BlobsitterInstance.CustodyStatus.LAPSE_ELIGIBLE)
        );
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotLapsable.selector, lapsableAt));
        instance.lapse(pid); // grace: only the provider can act

        vm.warp(lapsableAt - 1);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotLapsable.selector, lapsableAt));
        instance.lapse(pid);

        vm.warp(lapsableAt);
        assertEq(
            uint8(instance.custodyStatus(pid)), uint8(BlobsitterInstance.CustodyStatus.LAPSABLE)
        );
        uint256 bounty = (2 ether * 1500) / 10_000;
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Slashed(pid, BlobsitterInstance.SlashCause.LAPSE, address(this));
        instance.lapse(pid);

        assertEq(address(this).balance, 10 ether - 2 ether + bounty, "bounty to the executor");
        assertEq(address(instance.paymaster()).balance, 2 ether - bounty, "remainder absorbed");
        assertEq(
            uint8(instance.getProvider(pid).status),
            uint8(BlobsitterInstance.ProviderStatus.SLASHED)
        );
        assertEq(
            uint8(instance.custodyStatus(pid)),
            uint8(BlobsitterInstance.CustodyStatus.NONE),
            "slashed providers have no custody status"
        );
    }

    /// An accepted proof at any point before lapse() executes resets the clock —
    /// cure always wins if it lands first, even deep into the grace window.
    function test_lapse_cureDuringGraceWins() public {
        uint64 t0 = uint64(block.timestamp);
        // Nothing ever proven: periods 0 and 1 missed at day 60, grace runs to day 67.
        vm.warp(t0 + 62 days); // mid-grace
        assertEq(
            uint8(instance.custodyStatus(pid)),
            uint8(BlobsitterInstance.CustodyStatus.LAPSE_ELIGIBLE)
        );

        _begin(); // cure through the escape hatch, mid-grace
        BlobsitterInstance.ChunkProof[] memory reveals = _revealsFor(SEED, 50);
        (bytes32[] memory peaks,) = TestVec.buildPeaks(50);
        vm.prank(OPERATOR);
        instance.submitProofEscape(pid, 50, peaks, reveals);

        assertEq(
            uint8(instance.custodyStatus(pid)), uint8(BlobsitterInstance.CustodyStatus.CURRENT)
        );
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotLapsable.selector, 0));
        instance.lapse(pid);
    }

    /// Unbonding ends custody obligations; slashed providers cannot be slashed again.
    function test_lapse_immunity() public {
        vm.warp(block.timestamp + 200 days); // long past any grace
        vm.prank(OPERATOR);
        instance.initiateUnbonding(pid);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotActive.selector, pid));
        instance.lapse(pid);
        assertEq(uint8(instance.custodyStatus(pid)), uint8(BlobsitterInstance.CustodyStatus.NONE));

        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.UnknownProvider.selector, 99));
        instance.lapse(99);
    }

    /// receive() so the lapse bounty push succeeds for this test contract.
    receive() external payable {}

    // ------------------------------------------------------------ vector conformance

    /// The on-chain index derivation must reproduce vectors/custody_indices.json
    /// bit-for-bit (the derivation is instance-bound, so the instance is deployed at
    /// the vector's dummy address).
    function test_vectors_custodyIndices() public {
        string memory json = vm.readFile("../vectors/custody_indices.json");
        address at = json.readAddress(".instance");
        BlobsitterInstance.Params memory p = _params();
        deployCodeTo("BlobsitterInstance.sol:BlobsitterInstance", abi.encode(p), at);
        BlobsitterInstance vecInstance = BlobsitterInstance(at);

        bytes32 seed = json.readBytes32(".seed");
        uint64 providerId = uint64(json.readUint(".providerId"));
        uint64 leafCount = uint64(json.readUint(".leafCount"));
        uint256[] memory want = json.readUintArray(".indices_j0_to_j15");
        assertGt(want.length, 0, "no vector cases");
        for (uint64 j = 0; j < want.length; ++j) {
            assertEq(vecInstance.custodyIndex(seed, providerId, j, leafCount), want[j], "index j");
        }
    }
}

/// Minimal mirror of the verifier ABI for vm.expectCall encoding.
interface ISP1VerifierLike {
    function verifyProof(bytes32 vkey, bytes calldata publicValues, bytes calldata proof)
        external
        view;
}
