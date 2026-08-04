// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {BlobsitterPaymaster} from "src/BlobsitterPaymaster.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";

/// A carrier that, while receiving its reimbursement push, tries to reenter a
/// publication entrypoint with a pre-loaded VALID signed intent. The guard must make
/// that inner call revert, which merely defers the carrier's own payout.
contract ReentrantCarrier {
    BlobsitterInstance internal immutable instance;
    bool public armed;
    uint64 internal nonce;
    uint64 internal deadline;
    bytes32 internal pointer;
    bytes internal sig;

    constructor(BlobsitterInstance instance_) {
        instance = instance_;
    }

    function arm(uint64 nonce_, uint64 deadline_, bytes32 pointer_, bytes calldata sig_) external {
        (armed, nonce, deadline, pointer, sig) = (true, nonce_, deadline_, pointer_, sig_);
    }

    function submit(
        BlobsitterInstance.Declaration calldata d,
        bytes calldata publisherSig,
        BlobsitterInstance.BlobOpening[] calldata o,
        bytes calldata proof
    ) external {
        instance.declareFor(d, publisherSig, o, proof);
    }

    /// The failed push rolls back the whole receive frame — including the disarm —
    /// so the test disarms explicitly before claiming.
    function disarm() external {
        armed = false;
    }

    function doClaim() external {
        instance.paymaster().claim();
    }

    receive() external payable {
        if (armed) {
            armed = false;
            instance.setAppPointer(nonce, deadline, pointer, sig); // must revert Reentered
        }
    }
}

/// End-to-end reimbursement through declareFor/setAppPointer: the fee formula's
/// components isolated (zero-fee runs make the tip/subsidy and blob terms exact),
/// skip-when-unfunded, and the reentrancy guard.
contract ReimbursementTest is InstanceTestBase {
    BlobsitterPaymaster internal pm;

    function setUp() public virtual override {
        super.setUp();
        pm = instance.paymaster();
        vm.deal(address(this), 100 ether);
        pm.donate{value: 20 ether}();
    }

    /// The blob-fee component at the LIVE blob basefee: the cheatcode's argument is
    /// not adopted verbatim (the EVM derives the fee), so expectations read the real
    /// value back rather than assuming it.
    function _blobFee(uint256 numBlobs) internal view returns (uint256) {
        return numBlobs * 131_072 * block.blobbasefee;
    }

    /// This test contract is the carrier in _declare flows; pushes must land.
    receive() external payable {}

    /// With both fees zero, the formula collapses to the flat components: declarations
    /// pay tip + proving subsidy, pointer updates pay the tip alone.
    function test_reimburse_tipAndSubsidyExact() public {
        uint256 before = address(this).balance;
        _declare(5);
        assertEq(
            address(this).balance - before,
            0.0002 ether + 0.0005 ether + _blobFee(1),
            "tip + subsidy (+ minimum blob fee)"
        );

        before = address(this).balance;
        bytes32 ptr = keccak256("ptr");
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _sign(instance.setAppPointerDigest(0, deadline, ptr));
        instance.setAppPointer(0, deadline, ptr, sig);
        assertEq(address(this).balance - before, 0.0002 ether, "tip only, no subsidy");
    }

    /// Blob fee isolated: with basefee still zero, a nonzero blob basefee adds exactly
    /// blobs x 131072 x blobbasefee.
    function test_reimburse_blobComponentExact() public {
        vm.blobBaseFee(100); // adopted indirectly; expectations read the live value
        uint256 bbfComponent = _blobFee(1);
        assertGt(bbfComponent, 0, "nonzero blob fee in effect");

        uint256 before = address(this).balance;
        _declare(5); // one blob
        assertEq(
            address(this).balance - before,
            bbfComponent + 0.0007 ether,
            "one blob at the blob basefee + flat components"
        );

        before = address(this).balance;
        _declare(5000); // two blobs: the component doubles exactly
        assertEq(address(this).balance - before, 2 * bbfComponent + 0.0007 ether, "two blobs");
    }

    /// With a real basefee the execution component joins; the carrier receives exactly
    /// the event-recorded amount and the amount sits within computable bounds.
    function test_reimburse_withBasefee() public {
        vm.fee(10 gwei);
        vm.blobBaseFee(100);
        uint256 before = address(this).balance;
        vm.recordLogs();
        _declare(7);
        uint256 amount = _lastReimbursedAmount();

        assertEq(address(this).balance - before, amount, "paid exactly the recorded amount");
        uint256 blobAndFlat = _blobFee(1) + 0.0007 ether;
        // Lower bound: intrinsic + tail alone; upper: generous execution allowance.
        assertGt(amount, blobAndFlat + (21_000 + 25_000) * uint256(10 gwei), "floor");
        assertLt(amount, blobAndFlat + uint256(3_000_000) * 10 gwei, "ceiling");
    }

    /// An unfunded paymaster skips silently: publication succeeds, carrier unpaid.
    function test_reimburse_unfundedSkips() public {
        BlobsitterInstance fresh = new BlobsitterInstance(_params());
        vm.etch(fresh.SP1_VERIFIER(), instance.SP1_VERIFIER().code);
        uint256 before = address(this).balance;
        _declareOn(fresh, 4);
        assertEq(fresh.leafCount(), 4, "publication unaffected");
        assertEq(address(this).balance, before, "nothing paid");
    }

    /// The transient guard: a carrier reentering setAppPointer with a VALID signed
    /// intent from inside its reimbursement push gets Reentered; its push defers into
    /// the claimable ledger and the outer declaration completes untouched.
    function test_reimburse_reentrancyGuardDefersPush() public {
        ReentrantCarrier carrier = new ReentrantCarrier(instance);
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 ptr = keccak256("smuggled pointer");
        carrier.arm(0, deadline, ptr, _sign(instance.setAppPointerDigest(0, deadline, ptr)));

        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(3, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        carrier.submit(d, _sign(instance.declarationDigest(d)), o, goodProof);

        assertEq(instance.leafCount(), 3, "outer declaration completed");
        assertEq(instance.appPointer(), bytes32(0), "reentrant intent did not apply");
        uint256 parked = pm.claimable(address(carrier));
        assertEq(parked, 0.0007 ether + _blobFee(1), "push deferred in full");

        carrier.disarm(); // the reverted push frame rolled the auto-disarm back too
        carrier.doClaim();
        assertEq(address(carrier).balance, parked, "collected after the fact");
        // The signed intent itself is still valid and usable outside the push.
        instance.setAppPointer(
            0, deadline, ptr, _sign(instance.setAppPointerDigest(0, deadline, ptr))
        );
        assertEq(instance.appPointer(), ptr);
    }

    function _lastReimbursedAmount() internal returns (uint256 amount) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == BlobsitterPaymaster.Reimbursed.selector) {
                (amount,) = abi.decode(logs[i].data, (uint256, bool));
            }
        }
        require(amount != 0, "no Reimbursed event");
    }
}

/// Calibration aid for the provisional TAIL constant (pre-audit freeze item): with
/// basefee = 1 wei and zero tips, the reimbursed amount numerically equals the gas
/// expression, so the bracketed measurement can be extracted and compared against the
/// gas this test observes around the call. The difference approximates the true tail.
contract ReimbursementCalibrationTest is InstanceTestBase {
    function _params() internal view override returns (BlobsitterInstance.Params memory p) {
        p = super._params();
        p.carrierTipWei = 0;
        p.provingSubsidyWei = 0;
    }

    receive() external payable {}

    function test_gasCalibration_tailEstimate() public {
        instance.paymaster().donate{value: 1 ether}();
        vm.fee(1);

        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(5, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        bytes memory payload = abi.encodeCall(BlobsitterInstance.declareFor, (d, sig, o, goodProof));

        vm.recordLogs();
        uint256 g0 = gasleft();
        (bool ok,) = address(instance).call(payload);
        uint256 used = g0 - gasleft();
        assertTrue(ok, "declaration succeeded");

        uint256 amount;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == BlobsitterPaymaster.Reimbursed.selector) {
                (amount,) = abi.decode(logs[i].data, (uint256, bool));
            }
        }
        // amount (in wei at basefee 1) == blobFee + measured + 21000 + 16*len + TAIL.
        uint256 measured =
            amount - (131_072 * block.blobbasefee) - 21_000 - 16 * payload.length - 25_000;
        uint256 tailActual = used - measured; // call dispatch + paymaster + push + return
        emit log_named_uint("bracketed gas (contract-measured)", measured);
        emit log_named_uint("observed gas around the call", used);
        emit log_named_uint("tail estimate (freeze TAIL near this)", tailActual);
        assertLt(tailActual, 150_000, "tail estimate sane");
    }
}
