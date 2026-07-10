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

import {ShrincsUtils} from "../../contracts/ShrincsUtils.sol";

/// @title ShrincsSymbolic
/// @notice hevm symbolic-execution properties for the pure bit-arithmetic
/// helpers (security-testing plan Task 6, advisory). These are the same
/// bounds the forge fuzz suite ShrincsArithmeticFuzz checks over concrete
/// inputs; hevm proves them over fully symbolic inputs.
/// @dev hevm 0.58 runs `prove_`-prefixed functions symbolically
/// (`hevm test --root . --match prove_`). Properties are loop-free so no
/// symbolic trip counts fork: readBits32/64 and baseWDigit are branch-light
/// pure arithmetic. Plain `assert` marks the property; `require` constrains
/// the symbolic inputs to each reader's documented contract. Fallback if
/// hevm rots: keep the forge fuzz mirror as the source of truth.
contract ShrincsSymbolic {
    // A base-16 digit read from any 32-byte word at any valid index is in
    // [0, 15], so the WOTS-C chain-step count (15 - digit) never underflows.
    function prove_baseW16DigitBounded(bytes32 word, uint256 index)
        external
        pure
    {
        require(index < 64, "index in range");
        bytes memory digest = abi.encodePacked(word);
        uint32 digit = ShrincsUtils.baseWDigit(16, digest, index);
        assert(digit < 16);
    }

    // readBits32 of a fixed 14-bit window (the FORS tree height) at any valid
    // start bit yields a value that fits in 14 bits.
    function prove_readBits32ForsHeightBounded(
        bytes32 hi,
        bytes32 lo,
        uint256 startBit
    ) external pure {
        // Keep the 14-bit window inside the two data words.
        require(startBit <= 512 - 14, "window in buffer");
        bytes memory buffer = _twoWordBuffer(hi, lo);
        uint32 value = ShrincsUtils.readBits32(buffer, startBit, 14);
        assert(value < (uint32(1) << 14));
    }

    // readBits64 of a fixed 48-bit window (a hypertree tree-index slice) at
    // any valid start bit yields a value that fits in 48 bits.
    function prove_readBits64TreeIndexBounded(
        bytes32 hi,
        bytes32 lo,
        uint256 startBit
    ) external pure {
        require(startBit <= 512 - 48, "window in buffer");
        bytes memory buffer = _twoWordBuffer(hi, lo);
        uint64 value = ShrincsUtils.readBits64(buffer, startBit, 48);
        assert(value < (uint64(1) << 48));
    }

    // _twoWordBuffer: two data words plus 32 bytes of readable slack so any
    // window inside the first 512 bits satisfies the reader's slack contract.
    function _twoWordBuffer(bytes32 hi, bytes32 lo)
        internal
        pure
        returns (bytes memory buffer)
    {
        buffer = new bytes(96);
        assembly {
            mstore(add(buffer, 32), hi)
            mstore(add(buffer, 64), lo)
        }
    }
}
