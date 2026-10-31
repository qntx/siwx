// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Owner1271.sol";

/// CREATE2 deployer for the counterfactual ERC-6492 path.
contract Factory {
    function deploy(address owner, bytes32 salt) external returns (address) {
        return address(new Owner1271{salt: salt}(owner));
    }

    function addressOf(address owner, bytes32 salt) external view returns (address) {
        bytes32 initHash = keccak256(
            abi.encodePacked(type(Owner1271).creationCode, abi.encode(owner))
        );
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xff),
                                address(this),
                                salt,
                                initHash
                            )
                        )
                    )
                )
            );
    }
}
