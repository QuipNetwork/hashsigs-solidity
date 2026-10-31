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

import {Test} from "../lib/forge-std/src/Test.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {UXMSS} from "../contracts/UXMSS.sol";

/// @title SHRINCSSignatureTwinDriftTest
/// @notice Pins that SHRINCS.Signature and UXMSS.Signature stay identical
/// twins. SHRINCS._toUxmss re-tags a SHRINCS.Signature memory pointer as a
/// UXMSS.Signature without copying; that is memory-safe only while the two
/// declarations share an identical layout. This test builds one signature's
/// values into both structs and asserts abi.encode byte equality, so any
/// future field reorder/type change in one struct that is not mirrored in the
/// other fails closed here.
/// @dev Coverage limit: abi.encode equality cannot detect a same-word
/// numeric widening (e.g. one struct's `counter` widened uint32 -> uint64):
/// both pad to the same 32-byte word for every value <= uint32.max, so the
/// boundary case below cannot flag it either. That residual drift is guarded
/// by the mirrored struct-field comments and review; the boundary case pins
/// the narrowing/reorder half that encode equality DOES catch.
contract SHRINCSSignatureTwinDriftTest is Test {
    function testTwinLayoutEquality() public pure {
        bytes32[] memory chains = new bytes32[](3);
        chains[0] = bytes32(uint256(0x11));
        chains[1] = bytes32(uint256(0x22));
        chains[2] = bytes32(uint256(0x33));

        bytes32[] memory authPath = new bytes32[](2);
        authPath[0] = bytes32(uint256(0x44));
        authPath[1] = bytes32(uint256(0x55));

        SHRINCS.Signature memory shrincsSignature = SHRINCS.Signature({
            randomizer: bytes32(uint256(0xabc)),
            counter: 7,
            chains: chains,
            authPath: authPath
        });
        UXMSS.Signature memory uxmssSignature = UXMSS.Signature({
            randomizer: bytes32(uint256(0xabc)),
            counter: 7,
            chains: chains,
            authPath: authPath
        });

        assertEq(
            keccak256(abi.encode(shrincsSignature)),
            keccak256(abi.encode(uxmssSignature)),
            "SHRINCS.Signature and UXMSS.Signature layouts diverged"
        );
    }

    // Boundary fixture: max-width counter and all-ones words. This does not
    // close the widening blind spot documented in the contract header, but a
    // field narrowed below uint32 would fail to compile the max counter here,
    // and a reorder still fails the byte-equality assertion.
    function testTwinLayoutEqualityAtBoundaries() public pure {
        bytes32[] memory chains = new bytes32[](3);
        chains[0] = bytes32(type(uint256).max);
        chains[1] = bytes32(uint256(0));
        chains[2] = bytes32(type(uint256).max);

        bytes32[] memory authPath = new bytes32[](2);
        authPath[0] = bytes32(type(uint256).max);
        authPath[1] = bytes32(uint256(0));

        SHRINCS.Signature memory shrincsSignature = SHRINCS.Signature({
            randomizer: bytes32(type(uint256).max),
            counter: type(uint32).max,
            chains: chains,
            authPath: authPath
        });
        UXMSS.Signature memory uxmssSignature = UXMSS.Signature({
            randomizer: bytes32(type(uint256).max),
            counter: type(uint32).max,
            chains: chains,
            authPath: authPath
        });

        assertEq(
            keccak256(abi.encode(shrincsSignature)),
            keccak256(abi.encode(uxmssSignature)),
            "SHRINCS.Signature and UXMSS.Signature layouts diverged at bounds"
        );
    }
}
