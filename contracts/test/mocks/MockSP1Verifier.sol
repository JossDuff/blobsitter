// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISP1Verifier} from "src/interfaces/ISP1Verifier.sol";

/// Mock SP1 verifier for the pre-§14 milestones. Interface-exact per the §14
/// reservation note — (vkey, publicValues, proof) with the §12 call shapes — so
/// swapping in the real SP1VerifierGateway changes no call sites. Tests etch this
/// contract's runtime code at the template's SP1_VERIFIER constant address.
///
/// Accepts exactly one 32-byte sentinel as the proof; everything else reverts, like
/// the real gateway. publicValues is deliberately not inspected: its layout is the
/// reserved §14, and the instance passes empty bytes until that section is written.
contract MockSP1Verifier is ISP1Verifier {
    bytes32 public constant VALID_PROOF_SENTINEL = keccak256("blobsitter.test.valid-proof");

    error MockProofRejected();

    function verifyProof(bytes32, bytes calldata, bytes calldata proofBytes) external pure {
        if (proofBytes.length != 32 || bytes32(proofBytes[0:32]) != VALID_PROOF_SENTINEL) {
            revert MockProofRejected();
        }
    }
}
