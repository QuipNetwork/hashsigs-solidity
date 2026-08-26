// Copyright (C) 2026 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WOTSPlus} from "../contracts/WOTSPlus.sol";

/// @notice Pins that secret-bearing legacy helpers are absent from the
/// production WOTSPlus library artifact.
contract Issue13SecretHelpersTest is Test {
    function testSecretHelperSelectorsAreNotDeployable() public pure {
        bytes memory runtime = type(WOTSPlus).runtimeCode;
        assertTrue(
            _contains(
                runtime,
                bytes4(keccak256("generateRandomizationElements(bytes32)"))
            ),
            "selector scan must find a retained public function"
        );
        assertFalse(
            _contains(runtime, bytes4(keccak256("sign(bytes32,(bytes32))"))),
            "production runtime must not expose sign"
        );
        assertFalse(
            _contains(
                runtime, bytes4(keccak256("generateKeyPair(bytes32)"))
            ),
            "production runtime must not expose generateKeyPair"
        );
    }

    function _contains(bytes memory code, bytes4 selector)
        private
        pure
        returns (bool)
    {
        if (code.length < 4) return false;
        for (uint256 i = 0; i <= code.length - 4; ++i) {
            bytes4 candidate;
            assembly ("memory-safe") {
                candidate := mload(add(add(code, 32), i))
            }
            if (candidate == selector) return true;
        }
        return false;
    }
}
