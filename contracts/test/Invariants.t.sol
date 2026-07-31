// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CommonBase} from "forge-std/Base.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {MMR} from "src/libraries/MMR.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";
import {TestVec} from "test/helpers/TestVec.sol";

/// Handler for the I11 invariant run: performs random full declareFor calls — real
/// EIP-712 signatures through the ERC-1271 wallet, vm.blobhashes, zero-blob openings,
/// mock equivalence proof — and tracks the total declared chunk count.
contract DeclareHandler is CommonBase, StdUtils {
    uint256 internal constant PUBLISHER_PK = 0xA11CE;

    BlobsitterInstance public immutable instance;
    bytes internal goodProof;
    bytes32 internal zeroBlobVh;
    bytes internal infinityG1;

    uint256 public totalDeclared;
    uint256 public declarationCount;

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

    function declare(uint64 m) external {
        m = uint64(_bound(m, 1, 300));
        uint64 n0 = instance.leafCount();

        BlobsitterInstance.Declaration memory d;
        d.nonce = instance.declarationNonce();
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = new bytes32[](1); // m <= 300 => always one blob
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

        // I11 (per-call half): leafCount grew by exactly the declared m >= 1.
        require(instance.leafCount() == n0 + m, "I11: leafCount growth != m");
        totalDeclared += m;
        declarationCount += 1;
    }
}

/// Commitment-state invariants I11–I13 from spec/test-plan.md.
contract InvariantsTest is InstanceTestBase {
    DeclareHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new DeclareHandler(instance, goodProof, zeroBlobVh, INFINITY_G1);
        targetContract(address(handler));
    }

    /// I11 — structure: after every declaration sequence, len(peaks) == popcount(leafCount)
    /// and leafCount equals the sum of declared update sizes (each grew by exactly m,
    /// checked per call in the handler).
    function invariant_I11_structure() public view {
        uint64 n = instance.leafCount();
        assertEq(instance.allPeaks().length, MMR.peakCount(n), "len(peaks) != popcount(n)");
        assertEq(n, handler.totalDeclared(), "leafCount != sum of declared m");
    }

    /// I12 — differential root: random append sequences driven through the contract must
    /// leave exactly the peaks and bagged root the Rust reference computes for the same
    /// leaf count (vm.ffi -> reference/src/bin/mmr_oracle.rs; vectors cover fixed cases,
    /// this covers random ones).
    function testFuzz_I12_differentialRoot(uint256 seed) public {
        uint256 updates = 1 + (seed % 5);
        for (uint256 i = 0; i < updates; ++i) {
            uint64 m = uint64(1 + (uint256(keccak256(abi.encode(seed, i))) % 200));
            _declare(m);
        }

        string[] memory cmd = new string[](2);
        cmd[0] = "../target/debug/mmr_oracle";
        cmd[1] = vm.toString(instance.leafCount());
        (bytes32[] memory wantPeaks, bytes32 wantRoot) =
            abi.decode(vm.ffi(cmd), (bytes32[], bytes32));

        assertEq(instance.allPeaks(), wantPeaks, "peaks != Rust reference");
        assertEq(instance.root(), wantRoot, "root != Rust reference");
    }

    /// I13 — intent replay: a signed struct applies at most once.
    function test_I13_replayReverts() public {
        BlobsitterInstance.Declaration memory d = _declare(3);
        bytes memory sig = _sign(instance.declarationDigest(d));
        (, BlobsitterInstance.BlobOpening[] memory o) = _makeDeclaration(3, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.WrongNonce.selector, uint64(1)));
        instance.declareFor(d, sig, o, goodProof);
    }

    /// I13 — nonces per space are strictly sequential (declaration space; the intent
    /// spaces are covered in Intents.t.sol).
    function test_I13_noncesStrictlySequential() public {
        assertEq(instance.declarationNonce(), 0);
        _declare(2);
        assertEq(instance.declarationNonce(), 1);
        _declare(2);
        assertEq(instance.declarationNonce(), 2);

        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        d.nonce = 3; // skip ahead
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(abi.encodeWithSelector(BlobsitterInstance.WrongNonce.selector, uint64(2)));
        instance.declareFor(d, sig, o, goodProof);
    }

    /// I13 — a digest valid on one instance reverts on another (the domain separator's
    /// verifyingContract binding).
    function test_I13_crossInstanceRejected() public {
        BlobsitterInstance other = new BlobsitterInstance(_params());
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        // Signed for `instance`, submitted to `other` — both empty, so the struct
        // itself is valid on either; only the domain differs.
        bytes memory sig = _sign(instance.declarationDigest(d));
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        other.declareFor(d, sig, o, goodProof);
        // The same bytes succeed where they were meant to.
        instance.declareFor(d, sig, o, goodProof);
    }

    /// I13 — a digest valid on one chain reverts on another (the domain separator's
    /// chainId binding; computed per call, so a fork is picked up immediately).
    /// (No chainId save/restore here: via-IR rematerializes a cached block.chainid
    /// local as a fresh CHAINID read, silently undoing the "restore".)
    function test_I13_crossChainRejected() public {
        // Sanity: the same signing scheme succeeds on the home chain.
        _declare(2);
        // A fresh intent signed for the home chain…
        (BlobsitterInstance.Declaration memory d, BlobsitterInstance.BlobOpening[] memory o) =
            _makeDeclaration(2, bytes32(0), address(0));
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(instance.declarationDigest(d));
        // …is rejected once the executing chain id differs.
        vm.chainId(block.chainid + 1);
        vm.expectRevert(BlobsitterInstance.BadSignature.selector);
        instance.declareFor(d, sig, o, goodProof);
    }
}
