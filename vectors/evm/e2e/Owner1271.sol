// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal ERC-1271 owner-check fixture for siwx e2e tests.
contract Owner1271 {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        returns (bytes4)
    {
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        if (v < 27) {
            v += 27;
        }
        if (ecrecover(hash, v, r, s) == owner) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }

    function _split(bytes memory signature)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(signature.length == 65, "bad length");
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
    }
}
