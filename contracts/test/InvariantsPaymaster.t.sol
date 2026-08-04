// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CommonBase} from "forge-std/Base.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {BlobsitterPaymaster} from "src/BlobsitterPaymaster.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// Random walks over the donor-facing paymaster surface: donations, time, dormancy
/// reclaims, gate-closing declarations, and unauthorized-caller probes. Runs against a
/// short-dormancy instance so the gate genuinely opens and closes within a run.
contract PaymasterDonorHandler is CommonBase, StdUtils {
    uint256 internal constant PUBLISHER_PK = 0xA11CE;
    uint64 internal constant LEAF_CAP = 200;

    BlobsitterInstance public immutable instance;
    BlobsitterPaymaster public immutable pm;
    bytes internal goodProof;
    bytes32 internal zeroBlobVh;
    bytes internal infinityG1;

    address[3] public donors = [address(0x4001), address(0x4002), address(0x4003)];

    // Ghosts.
    mapping(address => uint256) public contributionGhost;
    uint256 public outstandingGhost;

    constructor(
        BlobsitterInstance instance_,
        bytes memory goodProof_,
        bytes32 zeroBlobVh_,
        bytes memory infinityG1_
    ) {
        instance = instance_;
        pm = instance_.paymaster();
        goodProof = goodProof_;
        zeroBlobVh = zeroBlobVh_;
        infinityG1 = infinityG1_;
    }

    receive() external payable {} // carrier reimbursements from declare()

    function warp(uint256 delta) external {
        vm.warp(block.timestamp + _bound(delta, 1 days, 40 days));
    }

    function donate(uint256 seed, uint256 amount) external {
        address donor = donors[seed % 3];
        amount = _bound(amount, 0.1 ether, 5 ether);
        vm.deal(donor, donor.balance + amount);
        vm.prank(donor);
        // Alternate between the explicit and plain-transfer paths.
        if (seed % 2 == 0) {
            pm.donate{value: amount}();
        } else {
            (bool ok,) = address(pm).call{value: amount}("");
            require(ok, "plain donation failed");
        }
        contributionGhost[donor] += amount;
        outstandingGhost += amount;
    }

    /// A checkpoint-advancing declaration burst: closes the dormancy gate.
    function declareActivity() external {
        uint64 n0 = instance.leafCount();
        if (n0 + 10 > LEAF_CAP) return;
        BlobsitterInstance.Declaration memory d;
        d.nonce = instance.declarationNonce();
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = new bytes32[](1);
        d.blobVersionedHashes[0] = zeroBlobVh;
        d.newSubtreePeaks = TestVec.subtreePeaks(n0, 10);
        d.newLeafCount = n0 + 10;
        BlobsitterInstance.BlobOpening[] memory o = new BlobsitterInstance.BlobOpening[](1);
        o[0] = BlobsitterInstance.BlobOpening({
            y: bytes32(0), commitment: infinityG1, kzgProof: infinityG1
        });
        vm.blobhashes(d.blobVersionedHashes);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PUBLISHER_PK, instance.declarationDigest(d));
        instance.declareFor(d, abi.encodePacked(r, s, v), o, goodProof);
    }

    /// Reclaim with the gate and ledger asserted in BOTH directions (I18 per-op).
    function reclaimOp(uint256 seed) external {
        address donor = donors[seed % 3];
        uint64 dormantAt = instance.activityCheckpointTime() + instance.dormancyWindow();
        uint256 weight = contributionGhost[donor];

        if (block.timestamp <= dormantAt) {
            vm.prank(donor);
            try pm.reclaim() {
                revert("I18: reclaim through a closed gate");
            } catch (bytes memory err) {
                require(bytes4(err) == BlobsitterPaymaster.NotDormant.selector, "wrong gate error");
            }
            return;
        }
        if (weight == 0) {
            vm.prank(donor);
            try pm.reclaim() {
                revert("I18: reclaimed with no contribution");
            } catch (bytes memory err) {
                require(
                    bytes4(err) == BlobsitterPaymaster.NothingToReclaim.selector,
                    "wrong empty error"
                );
            }
            return;
        }

        uint256 available = pm.availableBalance();
        uint256 expected = (available * weight) / outstandingGhost;
        uint256 before = donor.balance;
        vm.prank(donor);
        pm.reclaim();
        require(donor.balance == before + expected, "I18: pro-rata payout mismatch");
        require(expected <= available, "I18: paid more than available");
        outstandingGhost -= weight;
        contributionGhost[donor] = 0;
    }

    /// I19: nothing but the instance can move reimbursements or absorb slashes.
    function attemptUnauthorized(uint256 seed) external {
        address caller = donors[seed % 3];
        vm.deal(caller, caller.balance + 1 ether);
        vm.prank(caller);
        try pm.reimburse(caller, 1, false) {
            revert("I19: unauthorized reimburse");
        } catch (bytes memory err) {
            require(bytes4(err) == BlobsitterPaymaster.OnlyInstance.selector, "wrong error");
        }
        vm.prank(caller);
        try pm.absorbSlash{value: 1 ether}() {
            revert("I19: unauthorized absorbSlash");
        } catch (bytes memory err) {
            require(bytes4(err) == BlobsitterPaymaster.OnlyInstance.selector, "wrong error");
        }
    }
}

/// Ledger and authority invariants over the donor walks.
contract InvariantsPaymasterTest is InstanceTestBase {
    PaymasterDonorHandler internal handler;

    /// Short dormancy so the gate opens (and re-closes via declarations) inside runs.
    function _params() internal view override returns (BlobsitterInstance.Params memory p) {
        p = super._params();
        p.dormancyWindow = 30 days;
        p.dormancyMinChunks = 8;
    }

    function setUp() public override {
        super.setUp();
        handler = new PaymasterDonorHandler(instance, goodProof, zeroBlobVh, INFINITY_G1);
        targetContract(address(handler));
    }

    /// I18 — ledger integrity: outstanding equals the sum of contributions, mirrored
    /// per donor (the pro-rata payout and gate checks are per-op in the handler).
    function invariant_I18_ledgerIntegrity() public view {
        assertEq(
            instance.paymaster().outstanding(), handler.outstandingGhost(), "outstanding drift"
        );
        uint256 sum;
        for (uint256 i = 0; i < 3; ++i) {
            address donor = handler.donors(i);
            assertEq(
                instance.paymaster().contributions(donor),
                handler.contributionGhost(donor),
                "per-donor drift"
            );
            sum += handler.contributionGhost(donor);
        }
        assertEq(sum, handler.outstandingGhost(), "sum != outstanding");
    }

    /// I19 — authority: the one-way instance binding never changes (the unauthorized-
    /// caller probes are per-op in the handler).
    function invariant_I19_authority() public view {
        assertEq(instance.paymaster().instance(), address(instance), "binding drift");
    }
}
