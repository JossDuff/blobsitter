// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Minimal ECDSA-backed ERC-1271 wallet for tests: valid iff the 65-byte (r ‖ s ‖ v)
/// signature over the raw digest recovers to `owner`. The real publisher wallet is a
/// Safe with its SafeMessage envelope — exercised against a real deployed Safe in the
/// mainnet-fork tests; the instance-side check is identical either way: one ERC-1271
/// isValidSignature staticcall on the EIP-712 digest, accepting only the magic value.
contract ERC1271Wallet {
    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (signature.length != 65) return 0xffffffff;
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        address recovered = ecrecover(digest, v, r, s);
        if (recovered != address(0) && recovered == owner) return 0x1626ba7e;
        return 0xffffffff;
    }
}
