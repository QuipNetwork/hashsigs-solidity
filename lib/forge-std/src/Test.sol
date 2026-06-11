// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface Vm {
    function readFile(string calldata path) external returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function pauseGasMetering() external;
    function resumeGasMetering() external;
}

abstract contract Test {
    address internal constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm internal constant vm = Vm(VM_ADDRESS);

    function assertTrue(bool condition, string memory err) internal pure {
        if (!condition) {
            revert(err);
        }
    }

    function assertEq(bool left, bool right, string memory err) internal pure {
        if (left != right) {
            revert(err);
        }
    }

    function assertEq(bytes32 left, bytes32 right) internal pure {
        if (left != right) {
            revert("assertEq(bytes32) failed");
        }
    }
}
