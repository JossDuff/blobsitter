// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// The SP1 verifier interface (the deployed SP1VerifierGateway's ABI). Reverts on an
/// invalid proof; returns nothing on success.
///
/// The circuits (and their public-input layouts) are not yet specified, so a mock stands
/// in until they exist. The mock MUST take exactly (vkey, publicValues, proof) with the
/// same call shapes the instance uses, so swapping in the real verifier changes no call
/// sites.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
