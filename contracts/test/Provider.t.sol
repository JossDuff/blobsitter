// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";

/// A withdrawal wallet that can refuse ETH — exercises the push-with-pull-fallback
/// payout path on withdraw.
contract PickyWallet {
    bool public accepting;

    function setAccepting(bool v) external {
        accepting = v;
    }

    receive() external payable {
        require(accepting, "no");
    }
}

/// Provider lifecycle and its state-machine boundaries: stake / initiateUnbonding /
/// withdraw / announce / retract, with selector-matched negatives for the staking &
/// exit errors.
contract ProviderTest is InstanceTestBase {
    address internal constant OPERATOR = address(0x0101);
    address internal constant WITHDRAWAL = address(0x0202);

    function setUp() public override {
        super.setUp();
        vm.deal(address(this), 100 ether);
    }

    function _stake() internal returns (uint64 id) {
        id = instance.stake{value: 2 ether}(OPERATOR, WITHDRAWAL);
    }

    // ------------------------------------------------------------------------ stake

    function test_stake() public {
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Staked(1, OPERATOR, WITHDRAWAL);
        uint64 id = _stake();
        assertEq(id, 1, "ids start at 1 (0 means none, sec 9)");

        BlobsitterInstance.Provider memory p = instance.getProvider(id);
        assertEq(uint8(p.status), uint8(BlobsitterInstance.ProviderStatus.ACTIVE), "active");
        assertEq(p.operator, OPERATOR, "operator");
        assertEq(p.withdrawal, WITHDRAWAL, "withdrawal");
        assertEq(p.anchor, uint64(block.timestamp), "anchor");
        assertEq(p.lastProvenPlusOne, 0, "lastProven = -1 at stake");

        assertEq(_stake(), 2, "sequential ids");
        assertEq(address(instance).balance, 4 ether, "stakes held");
    }

    function test_stake_wrongAmount() public {
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.WrongStakeAmount.selector, 2 ether)
        );
        instance.stake{value: 1 ether}(OPERATOR, WITHDRAWAL);
    }

    function test_stake_zeroAddresses() public {
        vm.expectRevert(BlobsitterInstance.ZeroAddress.selector);
        instance.stake{value: 2 ether}(address(0), WITHDRAWAL);
        vm.expectRevert(BlobsitterInstance.ZeroAddress.selector);
        instance.stake{value: 2 ether}(OPERATOR, address(0));
    }

    // ------------------------------------------------------------- initiateUnbonding

    function test_initiateUnbonding_snapshotsExitPin() public {
        _declare(5);
        uint64 id = _stake();
        bytes32 rootAtExit = instance.root();

        vm.expectEmit(address(instance));
        emit BlobsitterInstance.UnbondingInitiated(id, rootAtExit, 5);
        vm.prank(OPERATOR);
        instance.initiateUnbonding(id);

        BlobsitterInstance.Provider memory p = instance.getProvider(id);
        assertEq(uint8(p.status), uint8(BlobsitterInstance.ProviderStatus.UNBONDING));
        assertEq(p.unbondingAt, uint64(block.timestamp), "unbondingAt");
        assertEq(p.exitRoot, rootAtExit, "exit root");
        assertEq(p.exitLeafCount, 5, "exit leaf count");

        // Later declarations must not disturb the snapshot (I10 groundwork).
        _declare(3);
        p = instance.getProvider(id);
        assertEq(p.exitRoot, rootAtExit, "snapshot immutable");
        assertEq(p.exitLeafCount, 5, "snapshot immutable count");
    }

    function test_initiateUnbonding_negatives() public {
        uint64 id = _stake();
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotOperator.selector, id));
        instance.initiateUnbonding(id); // caller is not the operator

        vm.prank(OPERATOR);
        instance.initiateUnbonding(id);
        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotActive.selector, id));
        instance.initiateUnbonding(id); // already unbonding

        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.UnknownProvider.selector, 99));
        instance.initiateUnbonding(99);
    }

    // --------------------------------------------------------------------- withdraw

    function test_withdraw_boundaryAndDestination() public {
        uint64 id = _stake();
        vm.prank(OPERATOR);
        instance.initiateUnbonding(id);
        uint64 until = uint64(block.timestamp) + uint64(14 days);

        // Half-open window: withdrawal becomes available exactly at the deadline,
        // never a second before.
        vm.warp(until - 1);
        vm.expectRevert(
            abi.encodeWithSelector(BlobsitterInstance.UnbondingDelayActive.selector, until)
        );
        instance.withdraw(id);

        vm.warp(until);
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Withdrawn(id);
        instance.withdraw(id); // anyone may call
        assertEq(WITHDRAWAL.balance, 2 ether, "full stake to the withdrawal address only");
        assertEq(
            uint8(instance.getProvider(id).status),
            uint8(BlobsitterInstance.ProviderStatus.EXITED),
            "exited"
        );

        // EXITED is terminal: a second withdraw fails, and re-staking is a fresh id.
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotUnbonding.selector, id));
        instance.withdraw(id);
        assertEq(_stake(), 2, "re-stake gets a NEW providerId");
    }

    function test_withdraw_notUnbonding() public {
        uint64 id = _stake();
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.NotUnbonding.selector, id));
        instance.withdraw(id);
    }

    /// A refusing withdrawal wallet defers the stake into the claimable ledger — the
    /// withdraw operation itself never reverts on a failed push.
    function test_withdraw_pullFallback() public {
        PickyWallet wallet_ = new PickyWallet();
        uint64 id = instance.stake{value: 2 ether}(OPERATOR, address(wallet_));
        vm.prank(OPERATOR);
        instance.initiateUnbonding(id);
        vm.warp(block.timestamp + 14 days);

        instance.withdraw(id);
        assertEq(instance.claimable(address(wallet_)), 2 ether, "deferred");

        wallet_.setAccepting(true);
        vm.prank(address(wallet_));
        instance.claim();
        assertEq(address(wallet_).balance, 2 ether, "claimed");
    }

    // ----------------------------------------------------------------- mirror tier

    function test_announceRetract_eventsOnly() public {
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Announced("https://mirror.example/dataset");
        instance.announce("https://mirror.example/dataset");
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.Retracted();
        instance.retract();
        assertEq(instance.nextProviderId(), 1, "no provider state touched");
        assertEq(address(instance).balance, 0, "no ETH involved");
    }
}
