// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BlobsitterInstance} from "src/BlobsitterInstance.sol";

/// vectors/eip712.json conformance (§11): the instance's digests must equal the golden
/// vectors bit-for-bit — a disagreement means signatures made by the publisher toolchain
/// (or the Rust reference) would be rejected on-chain. The vector domain is chainId
/// 31337 + a fixed dummy address, so the instance is deployed at exactly that address.
contract Eip712VectorsTest is Test {
    using stdJson for string;

    string json;
    BlobsitterInstance instance;

    function setUp() public {
        json = vm.readFile("../vectors/eip712.json");
        vm.chainId(json.readUint(".domain.chainId"));
        address at = json.readAddress(".domain.verifyingContract");
        BlobsitterInstance.Params memory p; // digest computation touches no parameter
        p.publisher = address(0xbeef);
        deployCodeTo("BlobsitterInstance.sol:BlobsitterInstance", abi.encode(p), at);
        instance = BlobsitterInstance(at);
    }

    /// The generator's typehash strings must hash to its recorded typehashes (the
    /// contract's own constants are checked implicitly through every digest below).
    function test_vectors_eip712_typehashes() public view {
        assertEq(
            keccak256(bytes(json.readString(".domain.typehashString"))),
            json.readBytes32(".domain.typehash"),
            "domain typehash"
        );
        string[3] memory keys = ["declaration", "setAppPointer", "setSuccessor"];
        for (uint256 i = 0; i < keys.length; ++i) {
            assertEq(
                keccak256(
                    bytes(json.readString(string.concat(".typehashes.", keys[i], ".string")))
                ),
                json.readBytes32(string.concat(".typehashes.", keys[i], ".hash")),
                keys[i]
            );
        }
    }

    function test_vectors_eip712_domainSeparator() public view {
        assertEq(json.readString(".domain.name"), "blobsitter", "domain name");
        assertEq(json.readString(".domain.version"), "1", "domain version");
        assertEq(instance.domainSeparator(), json.readBytes32(".domain.separator"), "separator");
    }

    function test_vectors_eip712_declarationDigests() public view {
        uint256 i;
        while (vm.keyExistsJson(json, string.concat(".declarations[", vm.toString(i), "]"))) {
            string memory key = string.concat(".declarations[", vm.toString(i), "]");
            BlobsitterInstance.Declaration memory d = BlobsitterInstance.Declaration({
                nonce: uint64(json.readUint(string.concat(key, ".nonce"))),
                deadline: uint64(json.readUint(string.concat(key, ".deadline"))),
                blobVersionedHashes: json.readBytes32Array(
                    string.concat(key, ".blobVersionedHashes")
                ),
                newSubtreePeaks: json.readBytes32Array(string.concat(key, ".newSubtreePeaks")),
                newLeafCount: uint64(json.readUint(string.concat(key, ".newLeafCount"))),
                designatedCarrier: json.readAddress(string.concat(key, ".designatedCarrier")),
                appPointer: json.readBytes32(string.concat(key, ".appPointer"))
            });
            assertEq(
                instance.declarationDigest(d),
                json.readBytes32(string.concat(key, ".digest")),
                string.concat("declaration digest ", vm.toString(i))
            );
            ++i;
        }
        assertGt(i, 0, "no declaration cases");
    }

    function test_vectors_eip712_intentDigests() public view {
        assertEq(
            instance.setAppPointerDigest(
                uint64(json.readUint(".setAppPointer.nonce")),
                uint64(json.readUint(".setAppPointer.deadline")),
                json.readBytes32(".setAppPointer.appPointer")
            ),
            json.readBytes32(".setAppPointer.digest"),
            "setAppPointer digest"
        );
        assertEq(
            instance.setSuccessorDigest(
                uint64(json.readUint(".setSuccessor.nonce")),
                uint64(json.readUint(".setSuccessor.deadline")),
                json.readAddress(".setSuccessor.successor")
            ),
            json.readBytes32(".setSuccessor.digest"),
            "setSuccessor digest"
        );
    }
}
