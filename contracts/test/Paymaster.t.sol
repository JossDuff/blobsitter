// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {BlobsitterPaymaster} from "src/BlobsitterPaymaster.sol";
import {PayoutSink} from "src/PayoutSink.sol";

/// Stands in for the instance: deploys the paymaster from its constructor (so the
/// one-way binding points here) and exposes the activity checkpoint plus forwarding
/// calls for the instance-only entry points.
contract InstanceStub {
    uint64 public activityCheckpointTime;
    BlobsitterPaymaster public immutable paymaster;

    constructor(uint256 ratePerDay, uint256 cap, uint64 window) {
        paymaster = new BlobsitterPaymaster(ratePerDay, cap, window);
        activityCheckpointTime = uint64(block.timestamp);
    }

    function setCheckpoint(uint64 t) external {
        activityCheckpointTime = t;
    }

    function doReimburse(address carrier, uint256 amount, bool isDeclaration) external {
        paymaster.reimburse(carrier, amount, isDeclaration);
    }

    function doAbsorbSlash() external payable {
        paymaster.absorbSlash{value: msg.value}();
    }
}

/// A donor/carrier that can refuse ETH, for the deferral paths.
contract MoodyActor {
    BlobsitterPaymaster internal immutable pm;
    bool public accepting = true;

    constructor(BlobsitterPaymaster pm_) {
        pm = pm_;
    }

    function setAccepting(bool v) external {
        accepting = v;
    }

    function donate() external payable {
        pm.donate{value: msg.value}();
    }

    function reclaim() external {
        pm.reclaim();
    }

    function doClaim() external {
        pm.claim();
    }

    receive() external payable {
        require(accepting, "no");
    }
}

/// Paymaster unit suite: the donation ledger, the token bucket (full start, refill
/// arithmetic, all-or-nothing), slash absorption, the dormancy reclaim with its
/// telescoping sweep, and the instance-only authority boundary.
contract PaymasterTest is Test {
    uint256 internal constant RATE = 0.05 ether; // per day
    uint256 internal constant CAP = 1.5 ether;
    uint64 internal constant WINDOW = 365 days;

    InstanceStub internal stub;
    BlobsitterPaymaster internal pm;

    address internal constant DONOR_A = address(0xD0A);
    address internal constant DONOR_B = address(0xD0B);
    address internal constant CARRIER = address(0xCa1);

    function setUp() public {
        vm.warp(1_700_000_000);
        stub = new InstanceStub(RATE, CAP, WINDOW);
        pm = stub.paymaster();
        vm.deal(DONOR_A, 100 ether);
        vm.deal(DONOR_B, 100 ether);
        vm.deal(address(this), 100 ether);
    }

    function _donate(address donor, uint256 amount) internal {
        vm.prank(donor);
        (bool ok,) = address(pm).call{value: amount}("");
        assertTrue(ok, "donation transfer");
    }

    // ---------------------------------------------------------------------- ledger

    function test_donations_creditLedger() public {
        vm.expectEmit(address(pm));
        emit BlobsitterPaymaster.Donated(DONOR_A, 3 ether);
        _donate(DONOR_A, 3 ether); // plain transfer path

        vm.prank(DONOR_B);
        pm.donate{value: 1 ether}(); // explicit path

        assertEq(pm.contributions(DONOR_A), 3 ether);
        assertEq(pm.contributions(DONOR_B), 1 ether);
        assertEq(pm.outstanding(), 4 ether, "outstanding is the ledger sum");
        assertEq(address(pm).balance, 4 ether);
    }

    /// Slash inflows and forced ETH raise the balance but never the ledger.
    function test_slashAndForcedEth_unattributed() public {
        stub.doAbsorbSlash{value: 1.7 ether}();
        vm.deal(address(pm), address(pm).balance + 0.3 ether); // "forced" ETH
        assertEq(address(pm).balance, 2 ether);
        assertEq(pm.outstanding(), 0, "no reclaim weight created");
    }

    // -------------------------------------------------------------------- authority

    function test_onlyInstance() public {
        vm.expectRevert(BlobsitterPaymaster.OnlyInstance.selector);
        pm.reimburse(CARRIER, 1, false);
        vm.expectRevert(BlobsitterPaymaster.OnlyInstance.selector);
        pm.absorbSlash{value: 1 ether}();
    }

    // ----------------------------------------------------------------------- bucket

    function test_bucket_startsFullAndPays() public {
        _donate(DONOR_A, 10 ether);
        assertEq(pm.bucketLevel(), CAP, "full at deployment");

        vm.expectEmit(address(pm));
        emit BlobsitterPaymaster.Reimbursed(CARRIER, 1 ether, true);
        stub.doReimburse(CARRIER, 1 ether, true);

        assertEq(CARRIER.balance, 1 ether, "paid in full");
        assertEq(pm.bucketLevel(), CAP - 1 ether, "full amount drawn");
    }

    function test_bucket_refillAndClamp() public {
        _donate(DONOR_A, 10 ether);
        stub.doReimburse(CARRIER, 1.5 ether, true); // drain to zero
        assertEq(pm.bucketLevel(), 0);

        vm.warp(block.timestamp + 12 hours);
        assertEq(pm.bucketLevel(), RATE / 2, "half a day refills half the daily rate");

        vm.warp(block.timestamp + 3650 days);
        assertEq(pm.bucketLevel(), CAP, "clamped at the cap");
    }

    /// All-or-nothing, bucket side: a request over the level pays nothing (and the
    /// level is NOT consumed), recorded via the shortfall event.
    function test_bucket_allOrNothing() public {
        _donate(DONOR_A, 10 ether);
        stub.doReimburse(CARRIER, 1.4 ether, true); // level now 0.1
        uint256 level = pm.bucketLevel();

        vm.expectEmit(address(pm));
        emit BlobsitterPaymaster.ReimbursementSkipped(CARRIER, 0.2 ether, level, 8.6 ether);
        stub.doReimburse(CARRIER, 0.2 ether, true);
        assertEq(CARRIER.balance, 1.4 ether, "nothing extra paid");
        assertEq(pm.bucketLevel(), level, "skip does not consume the level");

        stub.doReimburse(CARRIER, 0.1 ether, false); // exactly the level: pays
        assertEq(CARRIER.balance, 1.5 ether);
    }

    /// All-or-nothing, balance side: a funded bucket cannot spend money that isn't
    /// there — and parked claimable ETH is not "there".
    function test_balance_allOrNothing() public {
        _donate(DONOR_A, 0.4 ether);
        stub.doReimburse(CARRIER, 0.5 ether, true); // bucket fine, balance short
        assertEq(CARRIER.balance, 0, "skipped");

        // Park 0.3 of the 0.4 in the claimable ledger via a refusing carrier…
        MoodyActor moody = new MoodyActor(pm);
        moody.setAccepting(false);
        stub.doReimburse(address(moody), 0.3 ether, true);
        assertEq(pm.claimable(address(moody)), 0.3 ether, "deferred");
        assertEq(pm.availableBalance(), 0.1 ether, "parked ETH is spoken for");

        // …and a 0.2 request must now skip even though raw balance is 0.4.
        stub.doReimburse(CARRIER, 0.2 ether, true);
        assertEq(CARRIER.balance, 0, "cannot spend parked funds");

        moody.setAccepting(true);
        moody.doClaim();
        assertEq(address(moody).balance, 0.3 ether, "claim drains the parked amount");
    }

    // ---------------------------------------------------------------------- reclaim

    function test_reclaim_gateBoundary() public {
        _donate(DONOR_A, 1 ether);
        uint64 dormantAt = stub.activityCheckpointTime() + WINDOW;

        vm.warp(dormantAt); // open only while now − t0 > window: still closed at ==
        vm.prank(DONOR_A);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterPaymaster.NotDormant.selector, dormantAt));
        pm.reclaim();

        vm.warp(dormantAt + 1);
        vm.prank(DONOR_A);
        pm.reclaim();
        assertEq(DONOR_A.balance, 100 ether, "made whole");

        // A fresh checkpoint (a declaration burst) closes the gate again.
        _donate(DONOR_A, 1 ether);
        stub.setCheckpoint(uint64(block.timestamp));
        vm.prank(DONOR_A);
        vm.expectRevert(
            abi.encodeWithSelector(
                BlobsitterPaymaster.NotDormant.selector, uint64(block.timestamp) + WINDOW
            )
        );
        pm.reclaim();
    }

    function test_reclaim_negatives() public {
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectRevert(BlobsitterPaymaster.NothingToReclaim.selector);
        pm.reclaim(); // never donated

        _donate(DONOR_A, 1 ether);
        vm.prank(DONOR_A);
        pm.reclaim();
        vm.prank(DONOR_A);
        vm.expectRevert(BlobsitterPaymaster.NothingToReclaim.selector);
        pm.reclaim(); // already reclaimed
    }

    /// Sequential reclaimers each take their pro-rata share of the balance remaining
    /// at their call; with slash and forced inflows included, a full sweep returns
    /// everything (up to one wei of rounding dust per donor).
    function test_reclaim_telescopingFullSweep() public {
        _donate(DONOR_A, 3 ether);
        _donate(DONOR_B, 1 ether);
        stub.doAbsorbSlash{value: 1.7 ether}();
        vm.deal(address(pm), address(pm).balance + 0.3 ether); // forced
        assertEq(address(pm).balance, 6 ether);

        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(DONOR_A);
        pm.reclaim(); // 3/4 of 6 = 4.5
        assertEq(DONOR_A.balance, 100 ether - 3 ether + 4.5 ether, "pro-rata incl. inflows");

        vm.prank(DONOR_B);
        pm.reclaim(); // 1/1 of the remaining 1.5
        assertEq(DONOR_B.balance, 100 ether - 1 ether + 1.5 ether, "telescoped remainder");

        assertLe(address(pm).balance, 2, "swept to dust");
        assertEq(pm.outstanding(), 0);
    }

    /// A reclaimer that refuses the push gets parked, not blocked — and the parked
    /// amount is excluded from later reclaimers' math.
    function test_reclaim_deferredPayout() public {
        MoodyActor moody = new MoodyActor(pm);
        vm.deal(address(this), 100 ether);
        moody.donate{value: 2 ether}();
        _donate(DONOR_A, 2 ether);
        vm.warp(block.timestamp + WINDOW + 1);

        moody.setAccepting(false);
        moody.reclaim(); // 2 ether parked
        assertEq(pm.claimable(address(moody)), 2 ether);

        vm.prank(DONOR_A);
        pm.reclaim(); // gets the OTHER 2 ether, not the parked funds
        assertEq(DONOR_A.balance, 100 ether, "made whole without touching parked ETH");

        moody.setAccepting(true);
        moody.doClaim();
        assertEq(address(moody).balance, 2 ether);
        assertEq(address(pm).balance, 0, "fully drained");
    }
}
