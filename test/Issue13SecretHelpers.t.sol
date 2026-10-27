// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
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
