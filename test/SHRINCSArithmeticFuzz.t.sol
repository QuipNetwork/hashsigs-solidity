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
import {SHRINCSHash} from "../contracts/SHRINCSHash.sol";

/// @title SHRINCSArithmeticFuzzTest
/// @notice Differential and bounds fuzz for the pure bit-arithmetic helpers
/// (security-testing plan P5, P8). readBits32/64 are checked against an
/// independent shift-free reference reader; base-w digits are checked to stay
/// in range so the (w-1) - digit chain-step count never underflows.
/// @dev The reference readers walk bits one at a time so they share no code
/// with the production assembly. The buffers carry the 32-byte read slack
/// SHRINCSHash.readBits32/64 document, so the fuzz respects the caller
/// contract (F-07). The same properties are proved symbolically by Task 6's
/// hevm job over SHRINCSSymbolic.
contract SHRINCSArithmeticFuzzTest is Test {
    // WOTS `w` for the 256s/128s profiles is 16 (base-16 digits). Named for
    // the bound the digits must respect.
    uint16 internal constant CHAIN_BASE_16 = 16;
    uint16 internal constant CHAIN_BASE_256 = 256;

    // readBits reads a 32-byte word at the start byte, so a buffer needs 32
    // bytes of readable slack past the last logical byte.
    uint256 internal constant READ_SLACK_BYTES = 32;

    // readBits32 matches the reference over any in-buffer window, and its
    // result never exceeds bitLen bits.
    function testFuzz_readBits32(
        bytes32 hi,
        bytes32 lo,
        uint256 startBitSeed,
        uint256 bitLenSeed
    ) public pure {
        uint32 bitLen = uint32(bound(bitLenSeed, 1, 32));
        // Two data words give 512 readable bits; keep the window inside them.
        uint256 startBit = bound(startBitSeed, 0, 512 - bitLen);
        bytes memory buffer = _twoWordBuffer(hi, lo);

        uint32 got = SHRINCSHash.readBits32(buffer, startBit, bitLen);
        uint256 want = _referenceBits(buffer, startBit, bitLen);
        assertEq(uint256(got), want, "readBits32 != reference");

        uint256 ceiling =
            bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        assertLe(uint256(got), ceiling, "readBits32 over bitLen");
    }

    // readBits64 matches the reference (used for the hypertree tree index).
    function testFuzz_readBits64(
        bytes32 hi,
        bytes32 lo,
        uint256 startBitSeed,
        uint256 bitLenSeed
    ) public pure {
        uint32 bitLen = uint32(bound(bitLenSeed, 1, 64));
        uint256 startBit = bound(startBitSeed, 0, 512 - bitLen);
        bytes memory buffer = _twoWordBuffer(hi, lo);

        uint64 got = SHRINCSHash.readBits64(buffer, startBit, bitLen);
        uint256 want = _referenceBits(buffer, startBit, bitLen);
        assertEq(uint256(got), want, "readBits64 != reference");

        uint256 ceiling =
            bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        assertLe(uint256(got), ceiling, "readBits64 over bitLen");
    }

    // The result depends only on the bytes the window covers, never on
    // trailing slack (the F-07 slack contract).
    function testFuzz_readBits32IgnoresSlack(
        bytes32 hi,
        uint256 startBitSeed,
        uint256 bitLenSeed,
        bytes32 slackNoise
    ) public pure {
        uint32 bitLen = uint32(bound(bitLenSeed, 1, 32));
        // Only the first word holds window data; the second word is pure
        // slack, so perturbing it must not change the result.
        uint256 startBit = bound(startBitSeed, 0, 256 - bitLen);
        bytes memory clean = _twoWordBuffer(hi, bytes32(0));
        bytes memory noisy = _twoWordBuffer(hi, slackNoise);

        uint32 fromClean = SHRINCSHash.readBits32(clean, startBit, bitLen);
        uint32 fromNoisy = SHRINCSHash.readBits32(noisy, startBit, bitLen);
        assertEq(fromClean, fromNoisy, "slack changed readBits32");
    }

    // Every base-16 digit is in [0, 15], so the chain-step count
    // (w-1) - digit never underflows.
    function testFuzz_baseW16DigitBounded(bytes32 word, uint256 indexSeed)
        public
        pure
    {
        uint256 index = bound(indexSeed, 0, 63);
        bytes memory digest = abi.encodePacked(word);
        uint32 digit = SHRINCSHash.baseWDigit(CHAIN_BASE_16, digest, index);
        assertLe(uint256(digit), CHAIN_BASE_16 - 1, "base16 digit range");
        // Underflow guard: (w-1) - digit stays inside [0, w-1].
        uint256 stepsLeft = uint256(CHAIN_BASE_16 - 1) - uint256(digit);
        assertLe(stepsLeft, CHAIN_BASE_16 - 1, "steps underflow");
    }

    // A byte-wide (base-256) digit is always one byte.
    function testFuzz_baseW256DigitBounded(bytes32 word, uint256 indexSeed)
        public
        pure
    {
        uint256 index = bound(indexSeed, 0, 31);
        bytes memory digest = abi.encodePacked(word);
        uint32 digit = SHRINCSHash.baseWDigit(CHAIN_BASE_256, digest, index);
        assertLe(uint256(digit), CHAIN_BASE_256 - 1, "base256 digit range");
    }

    // _twoWordBuffer: two data words plus 32 bytes of readable slack, so any
    // readBits window inside the first 512 bits satisfies the reader's slack
    // contract.
    function _twoWordBuffer(bytes32 hi, bytes32 lo)
        internal
        pure
        returns (bytes memory buffer)
    {
        buffer = new bytes(64 + READ_SLACK_BYTES);
        assembly {
            mstore(add(buffer, 32), hi)
            mstore(add(buffer, 64), lo)
        }
    }

    // _referenceBits: MSB-first bit reader that walks one bit at a time and
    // shares no code with the production assembly reader.
    function _referenceBits(
        bytes memory buffer,
        uint256 startBit,
        uint256 bitLen
    ) internal pure returns (uint256 value) {
        for (uint256 i = 0; i < bitLen; i++) {
            uint256 position = startBit + i;
            uint256 byteIndex = position >> 3;
            uint256 bitInByte = 7 - (position & 7);
            uint256 bit = (uint8(buffer[byteIndex]) >> bitInByte) & 1;
            value = (value << 1) | bit;
        }
    }
}
