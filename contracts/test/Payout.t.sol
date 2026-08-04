// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";

/// Harness exposing the internal payout push for unit tests (the real callers —
/// withdraw, bond payouts, bounties — are exercised in Provider/Challenge tests).
contract PayoutHarness is BlobsitterInstance {
    constructor(Params memory p) BlobsitterInstance(p) {}

    function pay(address to) external payable {
        _payout(to, msg.value);
    }
}

/// A receiver whose acceptance can be toggled, with a reentrancy probe.
contract MoodyReceiver {
    bool public accepting;
    bool public reenter;
    PayoutHarness public target;

    constructor(PayoutHarness target_) {
        target = target_;
    }

    function setAccepting(bool v) external {
        accepting = v;
    }

    function setReenter(bool v) external {
        reenter = v;
    }

    function doClaim() external {
        target.claim();
    }

    receive() external payable {
        if (reenter) target.claim(); // probe: must find nothing / revert, never double-pay
        require(accepting, "not accepting");
    }
}

/// A receiver that burns unbounded gas — the push stipend must contain it.
contract GasGuzzler {
    receive() external payable {
        uint256 x;
        while (true) {
            x += 1;
        }
    }
}

/// Payout mechanics: push with pull fallback, 50k stipend, claim() retriability, CEI
/// under reentrancy.
contract PayoutTest is Test {
    PayoutHarness internal harness;
    MoodyReceiver internal moody;

    function setUp() public {
        BlobsitterInstance.Params memory p;
        p.publisher = address(0xbeef);
        harness = new PayoutHarness(p);
        moody = new MoodyReceiver(harness);
        vm.deal(address(this), 100 ether);
    }

    function test_payout_pushSucceeds() public {
        address eoa = address(0xE0A);
        harness.pay{value: 1 ether}(eoa);
        assertEq(eoa.balance, 1 ether, "pushed");
        assertEq(harness.claimable(eoa), 0, "no fallback credit");
    }

    function test_payout_fallbackAndClaim() public {
        // Rejecting receiver: push fails, ledger credited, operation not reverted.
        vm.expectEmit(address(harness));
        emit BlobsitterInstance.PayoutDeferred(address(moody), 1 ether);
        harness.pay{value: 1 ether}(address(moody));
        assertEq(harness.claimable(address(moody)), 1 ether, "deferred");

        // Claim while still rejecting: reverts retriably, balance intact.
        vm.expectRevert(BlobsitterInstance.PayoutFailed.selector);
        moody.doClaim();
        assertEq(harness.claimable(address(moody)), 1 ether, "restored after failed claim");

        // A second deferred payout accumulates.
        harness.pay{value: 2 ether}(address(moody));
        assertEq(harness.claimable(address(moody)), 3 ether, "accumulated");

        // Retry after the receiver relents: pays the full accumulated balance.
        moody.setAccepting(true);
        vm.expectEmit(address(harness));
        emit BlobsitterInstance.Claimed(address(moody), 3 ether);
        moody.doClaim();
        assertEq(address(moody).balance, 3 ether, "claimed");
        assertEq(harness.claimable(address(moody)), 0, "drained");
    }

    function test_payout_claimNothing() public {
        vm.expectRevert(BlobsitterInstance.NothingClaimable.selector);
        harness.claim();
    }

    /// The 50k stipend contains a gas-burning receiver: the push fails into the
    /// ledger instead of consuming the transaction's gas.
    function test_payout_gasGuzzlerContained() public {
        GasGuzzler guzzler = new GasGuzzler();
        uint256 gasBefore = gasleft();
        harness.pay{value: 1 ether}(address(guzzler));
        assertLt(gasBefore - gasleft(), 200_000, "stipend contained the burn");
        assertEq(harness.claimable(address(guzzler)), 1 ether, "deferred");
    }

    /// Reentrancy probe: a receiver reentering claim() during the push sees a zeroed
    /// ledger (CEI) — it cannot double-collect; its own revert just defers the payout.
    function test_payout_reentrancyProbe() public {
        moody.setAccepting(true);
        moody.setReenter(true);
        // Reentrant claim() reverts NothingClaimable inside receive(), so the push
        // fails and defers — no double payment, no stuck funds.
        harness.pay{value: 1 ether}(address(moody));
        assertEq(harness.claimable(address(moody)), 1 ether, "deferred, not double-paid");
        assertEq(address(moody).balance, 0, "nothing pushed");

        moody.setReenter(false);
        moody.doClaim();
        assertEq(address(moody).balance, 1 ether, "single payout total");
    }
}
