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

import {WOTSPlus} from "../../contracts/WOTSPlus.sol";

/// @dev Test-only legacy WOTS+ key generation and signing. Secret-bearing
/// helpers must not be included in deployable production artifacts.
library WOTSPlusTestSigner {
    // NUM_SIGNATURE_CHUNKS: aliases WOTSPlus.NumSignatureChunks
    // [WOTSPLUS §3]: len_1 + len_2
    // -> NumMessageChunks + NumChecksumChunks = 64 + 3 = 67
    // Python: 64 + 3
    // solc 5462: a foreign library constant is not a valid fixed-array
    // length, so this file keeps a local literal of the same value.
    uint8 private constant NUM_SIGNATURE_CHUNKS = 67;

    function sign(
        bytes32 privateKey,
        WOTSPlus.WinternitzMessage memory message
    )
        internal
        pure
        returns (bytes32[NUM_SIGNATURE_CHUNKS] memory signature)
    {
        bytes32 publicSeed = _prf(privateKey, 0);
        WOTSPlus.WinternitzElements memory randomizationElements =
            WOTSPlus.generateRandomizationElements(publicSeed);
        bytes32 functionKey = randomizationElements.elements[0];
        uint8[] memory chainSegments = _chainIndexes(message.messageHash);

        for (uint8 i = 0; i < chainSegments.length; ++i) {
            bytes32 secretKeySegment = keccak256(
                abi.encodePacked(functionKey, _prf(privateKey, i + 1))
            );
            signature[i] = WOTSPlus.chain(
                secretKeySegment, randomizationElements, 0, chainSegments[i]
            );
        }
    }

    function generateKeyPair(bytes32 privateSeed)
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress memory publicKey,
            bytes32 privateKey
        )
    {
        privateKey = _prf(privateSeed, 0);
        bytes32 publicSeed = _prf(privateKey, 0);
        WOTSPlus.WinternitzElements memory randomizationElements =
            WOTSPlus.generateRandomizationElements(publicSeed);
        bytes32 functionKey = randomizationElements.elements[0];
        bytes memory publicKeySegments = new bytes(WOTSPlus.SignatureSize);

        for (uint8 i = 0; i < WOTSPlus.NumSignatureChunks; ++i) {
            bytes32 secretKeySegment = keccak256(
                abi.encodePacked(functionKey, _prf(privateKey, i + 1))
            );
            bytes32 segment = WOTSPlus.chain(
                secretKeySegment,
                randomizationElements,
                0,
                WOTSPlus.ChainLen - 1
            );
            assembly ("memory-safe") {
                mstore(add(add(publicKeySegments, 32), mul(i, 32)), segment)
            }
        }

        publicKey = WOTSPlus.WinternitzAddress({
            publicKeyHash: keccak256(publicKeySegments),
            publicSeed: publicSeed
        });
    }

    function _prf(bytes32 seed, uint16 index)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(bytes1(0x03), seed, index));
    }

    function _chainIndexes(bytes32 messageHash)
        private
        pure
        returns (uint8[] memory indexes)
    {
        indexes = new uint8[](WOTSPlus.NumSignatureChunks);
        bytes memory message = abi.encodePacked(messageHash);
        _toBaseW(message, WOTSPlus.NumMessageChunks, indexes, 0);

        uint16 sum;
        for (uint8 i = 0; i < WOTSPlus.NumMessageChunks; ++i) {
            sum += WOTSPlus.ChainLen - 1 - indexes[i];
        }
        sum <<= 4;
        bytes memory checksum = abi.encodePacked(sum);
        _toBaseW(
            checksum,
            WOTSPlus.NumChecksumChunks,
            indexes,
            WOTSPlus.NumMessageChunks
        );
    }

    function _toBaseW(
        bytes memory input,
        uint8 count,
        uint8[] memory output,
        uint8 offset
    ) private pure {
        uint8 inputIndex;
        uint8 value;
        uint8 bits;
        for (uint8 i = 0; i < count; ++i) {
            if (bits == 0) {
                value = uint8(input[inputIndex]);
                ++inputIndex;
                bits = 8;
            }
            bits -= WOTSPlus.LgChainLen;
            output[offset + i] = (value >> bits) & (WOTSPlus.ChainLen - 1);
        }
    }
}
