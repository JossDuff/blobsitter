// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

interface ISafeSetup {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address paymentReceiver
    ) external;
}

interface ISafeMessageHash {
    function getMessageHash(bytes memory message) external view returns (bytes32);
}

/// Test-plan Layer 4: the real publisher flow — a real deployed Safe (1.4.1 canonical
/// mainnet contracts, from fork state) as the ERC-1271 publisher, signing through the
/// SafeMessage EIP-712 envelope (§11.3 non-normative tooling note). The instance-side
/// check is untouched: it still just calls isValidSignature(digest, sig).
///
/// Secret-gated like PointEvalForkTest.
contract SafeErc1271ForkTest is InstanceTestBase {
    // Canonical Safe 1.4.1 mainnet deployments.
    address internal constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    address internal constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address internal constant COMPAT_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;

    uint256 internal constant SAFE_OWNER_PK = 0x5AFE0;

    address internal safe;
    BlobsitterInstance internal safeInstance;

    function setUp() public override {
        string memory url = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        super.setUp();

        // A 1-of-1 Safe owned by a test key, with the canonical fallback handler
        // (which is what implements isValidSignature for off-chain messages).
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(SAFE_OWNER_PK);
        bytes memory initializer = abi.encodeCall(
            ISafeSetup.setup,
            (owners, 1, address(0), "", COMPAT_FALLBACK_HANDLER, address(0), 0, address(0))
        );
        safe = ISafeProxyFactory(SAFE_PROXY_FACTORY)
            .createProxyWithNonce(SAFE_SINGLETON, initializer, 0xB10B);

        BlobsitterInstance.Params memory p = _params();
        p.publisher = safe;
        safeInstance = new BlobsitterInstance(p);
    }

    /// The SafeMessage nesting the publisher toolchain must implement: the wallet
    /// co-signs keccak(0x1901 ‖ safeDomain ‖ SafeMessage(abi.encode(digest))), not the
    /// raw instance digest.
    function _safeSign(bytes32 digest) internal view returns (bytes memory) {
        bytes32 safeMessageHash = ISafeMessageHash(safe).getMessageHash(abi.encode(digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SAFE_OWNER_PK, safeMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_fork_safePublisher_setAppPointer() public {
        bytes32 pointer = keccak256("safe-published pointer");
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _safeSign(safeInstance.setAppPointerDigest(0, deadline, pointer));
        safeInstance.setAppPointer(0, deadline, pointer, sig);
        assertEq(safeInstance.appPointer(), pointer, "Safe-authorized intent applied");

        // A signature by a non-owner over the correct SafeMessage hash is rejected.
        bytes32 digest2 = safeInstance.setAppPointerDigest(1, deadline, pointer);
        bytes32 msgHash = ISafeMessageHash(safe).getMessageHash(abi.encode(digest2));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, msgHash);
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        safeInstance.setAppPointer(1, deadline, pointer, abi.encodePacked(r, s, v));

        // The raw (un-nested) digest signature must also fail: the Safe only accepts
        // the SafeMessage envelope.
        (v, r, s) = vm.sign(SAFE_OWNER_PK, digest2);
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        safeInstance.setAppPointer(1, deadline, pointer, abi.encodePacked(r, s, v));
    }

    function test_fork_safePublisher_declareFor() public {
        uint64 m = 5;
        BlobsitterInstance.Declaration memory d;
        d.nonce = 0;
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = new bytes32[](1);
        d.blobVersionedHashes[0] = zeroBlobVh;
        d.newSubtreePeaks = TestVec.subtreePeaks(0, m);
        d.newLeafCount = m;
        BlobsitterInstance.BlobOpening[] memory o = new BlobsitterInstance.BlobOpening[](1);
        o[0] = BlobsitterInstance.BlobOpening({
            y: bytes32(0), commitment: INFINITY_G1, kzgProof: INFINITY_G1
        });
        vm.blobhashes(d.blobVersionedHashes);
        safeInstance.declareFor(d, _safeSign(safeInstance.declarationDigest(d)), o, goodProof);
        assertEq(safeInstance.leafCount(), m, "Safe-authorized declaration applied");
    }
}
