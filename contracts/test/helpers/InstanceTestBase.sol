// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {ERC1271Wallet} from "test/mocks/ERC1271Wallet.sol";
import {MockSP1Verifier} from "test/mocks/MockSP1Verifier.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// Shared fixture for declaration-path tests: an instance with the §12.1 reference
/// parameters, an ECDSA-backed ERC-1271 publisher wallet, the mock SP1 verifier etched
/// at the template's constant address, and helpers to build/sign/submit declarations.
///
/// KZG STRATEGY (milestone 1): forge's EVM implements the real point-evaluation
/// precompile (0x0A), and these tests feed it the *zero-blob opening* — commitment and
/// proof both the compressed G1 point at infinity, y = 0 — which is a genuinely valid
/// KZG opening of the all-zero blob at ANY evaluation point z. Nothing on-chain checks
/// blob *content* in this milestone (that is exactly the equivalence proof's job, and
/// the proof is mocked until §14), so the happy path exercises the real precompile with
/// zero c-kzg tooling. Milestone 2 (test-plan Layer 4) adds real c-kzg pattern-blob
/// fixtures on a mainnet fork.
abstract contract InstanceTestBase is Test {
    uint256 internal constant PUBLISHER_PK = 0xA11CE;

    /// Compressed BLS12-381 G1 point at infinity (0xc0 ‖ 47 zero bytes).
    bytes internal constant INFINITY_G1 =
        hex"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    ERC1271Wallet internal wallet;
    BlobsitterInstance internal instance;
    bytes internal goodProof;
    bytes32 internal zeroBlobVh;

    function setUp() public virtual {
        wallet = new ERC1271Wallet(vm.addr(PUBLISHER_PK));
        instance = new BlobsitterInstance(_params());

        MockSP1Verifier mock = new MockSP1Verifier();
        vm.etch(instance.SP1_VERIFIER(), address(mock).code);
        goodProof = abi.encodePacked(mock.VALID_PROOF_SENTINEL());

        // EIP-4844 versioned hash of the zero-blob commitment: 0x01 ‖ sha256(C)[1:].
        zeroBlobVh = _versionedHash(INFINITY_G1);
        vm.warp(1_700_000_000);
    }

    /// §12.1 reference sizing.
    function _params() internal view virtual returns (BlobsitterInstance.Params memory p) {
        p.publisher = address(wallet);
        p.stakeWei = 2 ether;
        p.responseWindow = 7 days;
        p.unbondingDelay = 14 days;
        p.custodyPeriod = 30 days;
        p.lapseGrace = 7 days;
        p.custodyK = 16_384;
        p.maxSample = 32;
        p.bountyBps = 1500;
        p.carrierTipWei = 0.0002 ether;
        p.provingSubsidyWei = 0.0005 ether;
        p.bucketRateWeiPerDay = 0.05 ether;
        p.bucketCapWei = 1.5 ether;
        p.dormancyWindow = 365 days;
        p.dormancyMinChunks = 32_768;
    }

    function _versionedHash(bytes memory commitment) internal pure returns (bytes32) {
        bytes32 h = sha256(commitment);
        return bytes32((uint256(h) & ((1 << 248) - 1)) | (1 << 248));
    }

    function _sign(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PUBLISHER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// A fully-formed declaration of m pattern chunks on top of the current state,
    /// carried by anyone, with matching zero-blob openings.
    function _makeDeclaration(uint64 m, bytes32 appPtr, address carrier)
        internal
        view
        returns (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o)
    {
        uint64 n0 = instance.leafCount();
        uint256 blobCount = (uint256(m) + 4095) / 4096;
        d.nonce = instance.declarationNonce();
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = new bytes32[](blobCount);
        o = new BlobsitterInstance.BlobOpening[](blobCount);
        for (uint256 j = 0; j < blobCount; ++j) {
            d.blobVersionedHashes[j] = zeroBlobVh;
            o[j] = BlobsitterInstance.BlobOpening({
                y: bytes32(0), commitment: INFINITY_G1, kzgProof: INFINITY_G1
            });
        }
        d.newSubtreePeaks = TestVec.subtreePeaks(n0, m);
        d.newLeafCount = n0 + m;
        d.designatedCarrier = carrier;
        d.appPointer = appPtr;
    }

    /// Sign and submit a well-formed declaration of m chunks; returns the declaration.
    function _declare(uint64 m) internal returns (BlobsitterInstance.Declaration memory d) {
        BlobsitterInstance.BlobOpening[] memory o;
        (d, o) = _makeDeclaration(m, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        instance.declareFor(d, _sign(instance.declarationDigest(d)), o, goodProof);
    }
}
