// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// The SP1 verifier interface (the deployed SP1VerifierGateway's ABI). Reverts on an
/// invalid proof; returns nothing on success.
///
/// §14 reservation note: the mock used before the circuits exist MUST take exactly
/// (vkey, publicValues, proof) with the §12 call shapes, so swapping in the real
/// verifier changes no call sites.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
