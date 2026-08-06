// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {stdJson} from "forge-std/StdJson.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";
import {InstanceTestBase} from "test/helpers/InstanceTestBase.sol";

/// The full-stack test: a REAL network-generated proof through the REAL deployed SP1
/// verifier via the instance's actual entry points, on a mainnet fork — with the real
/// point-evaluation precompile in the same transaction. No mocks anywhere.
///
/// Flow: fresh instance at the pinned fixture address → declareFor with the genesis
/// KZG fixture + the real equivalence proof → stake → beginProof at the fixture's
/// custody seed → submitProof with the real custody proof → CustodyProven.
///
/// Gated twice: skips without ETH_RPC_URL (like every fork test), and skips when a
/// committed proof fixture's embedded vkey no longer matches the current guest
/// (regenerate with `prove <circuit> <mode> --fixture` in circuits/script).
/// The instance pins the PLONK gateway (wrap mode decided 2026-08-06), so the full
/// loop runs the plonk fixtures; REAL_PROOF_MODE exists only for re-measurement and
/// any non-plonk mode reverts at declareFor. Groth16 fixtures remain consumed by the
/// raw both-modes gas comparison below.
contract RealProofForkTest is InstanceTestBase {
    using stdJson for string;

    string internal mode;
    string internal genesisJson;
    string internal eqProof;
    string internal cuProof;
    BlobsitterInstance internal fx;

    function setUp() public override {
        string memory url = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        mode = vm.envOr("REAL_PROOF_MODE", string("plonk"));
        string memory eqPath = string.concat("test/fixtures/proofs/equivalence_", mode, ".json");
        string memory cuPath = string.concat("test/fixtures/proofs/custody_", mode, ".json");
        if (!vm.exists(eqPath) || !vm.exists(cuPath)) {
            emit log_string("proof fixtures missing - generate with `prove <circuit> <mode> --fixture`");
            vm.skip(true);
            return;
        }
        eqProof = vm.readFile(eqPath);
        cuProof = vm.readFile(cuPath);

        vm.createSelectFork(url);
        // Capture the LIVE gateway bytecode before the base fixture etches its mock
        // over that address, then restore it: this test wants no mocks anywhere.
        // Must match the instance's pinned SP1_VERIFIER (the PLONK gateway).
        address gateway = 0x3B6041173B80E77f038f3F2C0f9744f04837185e;
        bytes memory realGateway = gateway.code;
        require(realGateway.length > 0, "no verifier code on fork at the pinned address");
        super.setUp();
        vm.etch(gateway, realGateway);

        genesisJson = vm.readFile("test/fixtures/kzg_opening_genesis.json");
        address at = genesisJson.readAddress(".instance");
        BlobsitterInstance.Params memory p = _params();
        deployCodeTo("BlobsitterInstance.sol:BlobsitterInstance", abi.encode(p), at);
        fx = BlobsitterInstance(at);

        // Staleness guard: the committed proofs must match the CURRENT vkeys.
        if (
            eqProof.readBytes32(".vkey") != fx.EQUIVALENCE_VKEY()
                || cuProof.readBytes32(".vkey") != fx.CUSTODY_VKEY()
        ) {
            emit log_string("proof fixtures stale (vkey mismatch) - regenerate");
            vm.skip(true);
        }
    }

    function test_fork_realProof_fullLoop() public {
        // Genesis declaration: real KZG opening + real network proof, real precompile
        // + real verifier in one transaction.
        BlobsitterInstance.Declaration memory d;
        d.nonce = 0;
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = genesisJson.readBytes32Array(".blobVersionedHashes");
        d.newSubtreePeaks = genesisJson.readBytes32Array(".newSubtreePeaks");
        d.newLeafCount = uint64(genesisJson.readUint(".newLeafCount"));
        BlobsitterInstance.BlobOpening[] memory o = new BlobsitterInstance.BlobOpening[](1);
        o[0] = BlobsitterInstance.BlobOpening({
            y: genesisJson.readBytes32(".y"),
            commitment: genesisJson.readBytes(".commitment"),
            kzgProof: genesisJson.readBytes(".kzgProof")
        });
        vm.blobhashes(d.blobVersionedHashes);

        uint256 g0 = gasleft();
        fx.declareFor(d, _sign(fx.declarationDigest(d)), o, eqProof.readBytes(".proofBytes"));
        emit log_named_uint(
            string.concat("declareFor gas (real ", mode, " proof + real precompile)"),
            g0 - gasleft()
        );
        assertEq(fx.leafCount(), d.newLeafCount, "genesis declared");

        // Custody: replay the fixture's seed, then the real proof.
        uint64 pid = fx.stake{value: 2 ether}(address(this), address(0x0202));
        vm.prevrandao(keccak256("fork custody seed"));
        fx.beginProof(pid);

        g0 = gasleft();
        fx.submitProof(pid, cuProof.readBytes(".proofBytes"));
        emit log_named_uint(
            string.concat("submitProof gas (real ", mode, " proof)"), g0 - gasleft()
        );
        assertEq(fx.getProvider(pid).lastProvenPlusOne, 1, "custody proven for real");
    }

    /// Raw verify-gas comparison across BOTH wrap modes, calling the live gateways
    /// directly (spike finding: SP1 deploys SEPARATE gateways per wrap mode). The
    /// instance pins the PLONK gateway; Groth16 stays measured here for the record
    /// of what the Ignition-provenance preference costs.
    function test_fork_rawVerifierGasBothModes() public {
        address groth16Gateway = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
        address plonkGateway = 0x3B6041173B80E77f038f3F2C0f9744f04837185e;

        string[2] memory modes = ["groth16", "plonk"];
        address[2] memory gateways = [groth16Gateway, plonkGateway];
        for (uint256 i = 0; i < 2; ++i) {
            string memory path =
                string.concat("test/fixtures/proofs/equivalence_", modes[i], ".json");
            if (!vm.exists(path)) continue;
            string memory fixt = vm.readFile(path);
            bytes memory callData = abi.encodeWithSignature(
                "verifyProof(bytes32,bytes,bytes)",
                fixt.readBytes32(".vkey"),
                fixt.readBytes(".publicValues"),
                fixt.readBytes(".proofBytes")
            );
            uint256 g0 = gasleft();
            (bool ok,) = gateways[i].staticcall(callData);
            uint256 used = g0 - gasleft();
            assertTrue(ok, string.concat(modes[i], " raw verify failed"));
            emit log_named_uint(string.concat("raw verifyProof gas, ", modes[i]), used);
        }
    }

    /// One flipped byte anywhere in the proof must be rejected by the real verifier.
    function test_fork_realProof_tamperedRejected() public {
        BlobsitterInstance.Declaration memory d;
        d.nonce = 0;
        d.deadline = uint64(block.timestamp + 1 hours);
        d.blobVersionedHashes = genesisJson.readBytes32Array(".blobVersionedHashes");
        d.newSubtreePeaks = genesisJson.readBytes32Array(".newSubtreePeaks");
        d.newLeafCount = uint64(genesisJson.readUint(".newLeafCount"));
        BlobsitterInstance.BlobOpening[] memory o = new BlobsitterInstance.BlobOpening[](1);
        o[0] = BlobsitterInstance.BlobOpening({
            y: genesisJson.readBytes32(".y"),
            commitment: genesisJson.readBytes(".commitment"),
            kzgProof: genesisJson.readBytes(".kzgProof")
        });
        vm.blobhashes(d.blobVersionedHashes);
        bytes memory sig = _sign(fx.declarationDigest(d));

        bytes memory tampered = eqProof.readBytes(".proofBytes");
        tampered[tampered.length / 2] ^= 0x01;
        vm.expectRevert(BlobsitterInstance.InvalidEquivalenceProof.selector);
        fx.declareFor(d, sig, o, tampered);
    }

    receive() external payable {}
}
