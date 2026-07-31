// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {ERC1271Wallet} from "test/mocks/ERC1271Wallet.sol";

/// setAppPointer / setSuccessor (§12.3): happy paths, the intent-deadline boundary
/// (valid at now == deadline, expired after — §11.2), and selector-matched negatives
/// for every §16 error these paths can raise.
contract IntentsTest is Test {
    uint256 internal constant PUBLISHER_PK = 0xA11CE;
    address internal publisherOwner;
    ERC1271Wallet internal wallet;
    BlobsitterInstance internal instance;

    function setUp() public {
        publisherOwner = vm.addr(PUBLISHER_PK);
        wallet = new ERC1271Wallet(publisherOwner);
        BlobsitterInstance.Params memory p;
        p.publisher = address(wallet);
        instance = new BlobsitterInstance(p);
        vm.warp(1_700_000_000);
    }

    function _sign(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PUBLISHER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _deadline() internal view returns (uint64) {
        return uint64(block.timestamp + 1 hours);
    }

    // ------------------------------------------------------------------ setAppPointer

    function test_setAppPointer() public {
        bytes32 pointer = keccak256("pointer");
        uint64 deadline = _deadline();
        bytes memory sig = _sign(instance.setAppPointerDigest(0, deadline, pointer));
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.AppPointerSet(0, pointer);
        instance.setAppPointer(0, deadline, pointer, sig);
        assertEq(instance.appPointer(), pointer, "stored");
        assertEq(instance.appPointerNonce(), 1, "nonce advanced");
        // Zero is a legal pointer value in the standalone intent (only Declaration
        // gives zero the "no update" meaning) — it clears the stored pointer.
        sig = _sign(instance.setAppPointerDigest(1, deadline, bytes32(0)));
        instance.setAppPointer(1, deadline, bytes32(0), sig);
        assertEq(instance.appPointer(), bytes32(0), "cleared");
    }

    /// §11.2: submittable while block.timestamp <= deadline — valid at the boundary.
    function test_setAppPointer_deadlineBoundary() public {
        bytes32 pointer = keccak256("pointer");
        uint64 deadline = uint64(block.timestamp);
        bytes memory sig = _sign(instance.setAppPointerDigest(0, deadline, pointer));
        instance.setAppPointer(0, deadline, pointer, sig);

        sig = _sign(instance.setAppPointerDigest(1, deadline, pointer));
        vm.warp(block.timestamp + 1);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.IntentExpired.selector, deadline));
        instance.setAppPointer(1, deadline, pointer, sig);
    }

    function test_setAppPointer_wrongNonce() public {
        uint64 deadline = _deadline();
        bytes memory sig = _sign(instance.setAppPointerDigest(5, deadline, bytes32(0)));
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.WrongNonce.selector, uint64(0)));
        instance.setAppPointer(5, deadline, bytes32(0), sig);
    }

    function test_setAppPointer_badSignature() public {
        bytes32 pointer = keccak256("pointer");
        uint64 deadline = _deadline();

        // Signature over a different struct's digest.
        bytes memory sig = _sign(instance.setAppPointerDigest(0, deadline, keccak256("other")));
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        instance.setAppPointer(0, deadline, pointer, sig);

        // Right digest, wrong key.
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(0xB0B, instance.setAppPointerDigest(0, deadline, pointer));
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        instance.setAppPointer(0, deadline, pointer, abi.encodePacked(r, s, v));

        // Malformed signature (wallet returns its failure value, not the magic).
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        instance.setAppPointer(0, deadline, pointer, hex"deadbeef");
    }

    /// A publisher with no code (EOA or undeployed) can never authorize anything.
    function test_badSignature_publisherWithoutCode() public {
        BlobsitterInstance.Params memory p;
        p.publisher = address(0x1234); // no code
        BlobsitterInstance bare = new BlobsitterInstance(p);
        uint64 deadline = _deadline();
        bytes memory sig = _sign(bare.setAppPointerDigest(0, deadline, bytes32(0)));
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        bare.setAppPointer(0, deadline, bytes32(0), sig);
    }

    // ------------------------------------------------------------------ setSuccessor

    function test_setSuccessor() public {
        address target = address(0x5AFE);
        uint64 deadline = _deadline();
        bytes memory sig = _sign(instance.setSuccessorDigest(0, deadline, target));
        vm.expectEmit(address(instance));
        emit BlobsitterInstance.SuccessorSet(target);
        instance.setSuccessor(0, deadline, target, sig);
        assertEq(instance.successor(), target, "stored");
        assertEq(instance.successorNonce(), 1, "nonce advanced");
    }

    /// §12.3: successor is write-once.
    function test_setSuccessor_alreadySet() public {
        test_setSuccessor();
        uint64 deadline = _deadline();
        bytes memory sig = _sign(instance.setSuccessorDigest(1, deadline, address(0xD00D)));
        vm.expectRevert(BlobsitterInstance.SuccessorAlreadySet.selector);
        instance.setSuccessor(1, deadline, address(0xD00D), sig);
    }

    /// §12.3: target ≠ 0.
    function test_setSuccessor_zeroAddress() public {
        uint64 deadline = _deadline();
        bytes memory sig = _sign(instance.setSuccessorDigest(0, deadline, address(0)));
        vm.expectRevert(BlobsitterInstance.ZeroAddress.selector);
        instance.setSuccessor(0, deadline, address(0), sig);
    }

    function test_setSuccessor_expired() public {
        uint64 deadline = uint64(block.timestamp - 1);
        bytes memory sig = _sign(instance.setSuccessorDigest(0, deadline, address(0x5AFE)));
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.IntentExpired.selector, deadline));
        instance.setSuccessor(0, deadline, address(0x5AFE), sig);
    }

    function test_setSuccessor_wrongNonce() public {
        uint64 deadline = _deadline();
        bytes memory sig = _sign(instance.setSuccessorDigest(1, deadline, address(0x5AFE)));
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.WrongNonce.selector, uint64(0)));
        instance.setSuccessor(1, deadline, address(0x5AFE), sig);
    }

    /// The two intent nonce spaces are independent of each other (§11.2): consuming
    /// appPointer nonces never advances the successor space.
    function test_nonceSpacesIndependent() public {
        test_setAppPointer(); // appPointerNonce -> 2
        assertEq(instance.successorNonce(), 0);
        assertEq(instance.declarationNonce(), 0);
        test_setSuccessor(); // successorNonce -> 1
        assertEq(instance.appPointerNonce(), 2);
        assertEq(instance.declarationNonce(), 0);
    }
}
