// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISP1Verifier} from "src/interfaces/ISP1Verifier.sol";

/// Mock SP1 verifier standing in until the real circuits exist. Interface-exact —
/// verifyProof(vkey, publicValues, proof), the same signature and call shapes the
/// instance already uses — so swapping in the real SP1VerifierGateway changes no call
/// sites. Tests etch this contract's runtime code at the template's SP1_VERIFIER
/// constant address.
///
/// Accepts exactly one 32-byte sentinel as the proof; everything else reverts, like
/// the real gateway. publicValues is deliberately not inspected: its layout belongs
/// to the still-reserved circuit part of the spec, and the instance passes empty
/// bytes until that part is written.
contract MockSP1Verifier is ISP1Verifier {
    bytes32 public constant VALID_PROOF_SENTINEL = keccak256("blobsitter.test.valid-proof");

    error MockProofRejected();

    function verifyProof(bytes32, bytes calldata, bytes calldata proofBytes) external pure {
        if (proofBytes.length != 32 || bytes32(proofBytes[0:32]) != VALID_PROOF_SENTINEL) {
            revert MockProofRejected();
        }
    }
}
