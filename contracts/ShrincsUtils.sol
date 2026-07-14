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

import {ShrincsTypes} from "./ShrincsTypes.sol";

library ShrincsUtils {
    // validActionContext: Perform lightweight structural checks for canonical action contexts.
    // 1. Require a nonzero domain separator.
    // 2. Require a nonzero action type.
    // 3. Require a nonzero payload hash.
    function validActionContext(ShrincsTypes.ActionContext memory context) internal pure returns (bool) {
        // Domain separation must be explicit.
        if (context.domainSeparator == bytes32(0)) return false;
        // The action type must not be left unspecified.
        if (context.actionType == bytes32(0)) return false;
        // The payload must commit to some nonzero value.
        return context.payloadHash != bytes32(0);
    }

    // validRotationContext: Perform lightweight structural checks for canonical rotation contexts.
    // 1. Require a nonzero domain separator.
    function validRotationContext(ShrincsTypes.RotationContext memory context) internal pure returns (bool) {
        return context.domainSeparator != bytes32(0);
    }

    // matchesExpectedStatelessKey: Check that a bundled public key matches installed pkSeed/root storage.
    // 1. Require nonzero installed public key words.
    // 2. Require fixed-width public-key fields.
    // 3. Load pkSeed/root from calldata and compare directly to storage words.
    function matchesExpectedStatelessKey(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot
    ) internal pure returns (bool) {
        // Missing installed key material is always invalid.
        if (expectedPkSeed == bytes32(0)) return false;
        if (expectedHypertreeRoot == bytes32(0)) return false;
        if (!validPublicKey(publicKey)) return false;
        bytes calldata encodedPkSeed = publicKey.pkSeed;
        bytes calldata encodedHypertreeRoot = publicKey.hypertreeRoot;
        bytes32 actualPkSeed;
        bytes32 actualHypertreeRoot;
        assembly {
            // Load the two public key words directly from calldata.
            actualPkSeed := calldataload(encodedPkSeed.offset)
            actualHypertreeRoot := calldataload(encodedHypertreeRoot.offset)
        }
        return actualPkSeed == expectedPkSeed && actualHypertreeRoot == expectedHypertreeRoot;
    }

    // validPublicKey: Validate public-key byte lengths.
    // 1. Check the public-seed and hypertree-root lengths.
    function validPublicKey(ShrincsTypes.PublicKey calldata publicKey) internal pure returns (bool) {
        // The stateless public seed is always one hash output wide.
        if (publicKey.pkSeed.length != 32) return false;
        // The hypertree root is always one hash output wide.
        return publicKey.hypertreeRoot.length == 32;
    }

    // addressWord32: Pack the SPHINCS/XMSS-style address components into one 32-byte word.
    // 1. Shift each address component into its reserved bit range.
    // 2. OR the shifted components together into one packed value.
    // 3. Return the packed 32-byte address word.
    function addressWord32(uint32 layer, uint64 tree, uint32 addressType, uint32 keypair, uint32 chain, uint32 step)
        internal
        pure
        returns (bytes32)
    {
        // Place the layer identifier in the top address bits.
        uint256 shiftedLayer = uint256(layer) << 224;
        // Place the subtree index below the layer field.
        uint256 shiftedTree = uint256(tree) << 128;
        // Place the address-domain selector below the tree field.
        uint256 shiftedAddressType = uint256(addressType) << 96;
        // Place the keypair identifier below the address-type field.
        uint256 shiftedKeypair = uint256(keypair) << 64;
        // Place the chain index below the keypair field.
        uint256 shiftedChain = uint256(chain) << 32;
        // Place the per-chain step index in the low 32 bits.
        uint256 shiftedStep = uint256(step);

        uint256 addressValue = shiftedLayer;
        addressValue |= shiftedTree;
        addressValue |= shiftedAddressType;
        addressValue |= shiftedKeypair;
        addressValue |= shiftedChain;
        addressValue |= shiftedStep;

        return bytes32(addressValue);
    }

    // baseWDigit: Read one base-w digit from a digest, supporting both byte-wide and base-16 forms.
    // 1. Return one whole byte when w = 256.
    // 2. Otherwise select the byte that contains the requested base-16 digit.
    // 3. Return the high nibble for even indices.
    // 4. Return the low nibble for odd indices.
    function baseWDigit(uint16 w, bytes memory digest, uint256 index) internal pure returns (uint32) {
        // Byte-wide base-w uses one full digest byte per digit.
        if (w == 256) return uint8(digest[index]);
        // Base-16 uses two digits per digest byte.
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? b >> 4 : b & 0x0f;
    }

    // setHashChunk: Copy up to one 32-byte hash chunk into a mutable output buffer.
    // 1. Walk over the requested chunk length one byte at a time.
    // 2. Copy each byte from the hash block into the requested output offset.
    function setHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) internal pure {
        for (uint256 i = 0; i < chunk;) {
            // Copy one byte from the block hash into the requested output position.
            out[offset + i] = blockHash[i];
            unchecked {
                ++i;
            }
        }
    }

    // readBits32: Extract up to 32 bits starting at an arbitrary bit offset.
    // 1. Locate the starting byte and bit offset.
    // 2. Load the surrounding 32-byte word from memory.
    // 3. Shift the requested bit range down to the low bits.
    // 4. Mask off any higher bits and return the 32-bit result.
    function readBits32(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint32) {
        // Convert the starting bit offset into a byte offset.
        uint256 byteOffset = startBit >> 3;
        // Keep only the bit offset within that byte.
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            // Load the 32-byte word starting at the requested byte offset.
            word := mload(add(add(input, 32), byteOffset))
        }
        // Shift the requested bit range down to the low bits of the loaded word.
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        // Build a bit mask of exactly bitLen low bits.
        uint256 mask = bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        // casting to 'uint32' is safe because the mask bounds the result to at most 32 bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(shifted & mask);
    }

    // readBits64: Extract up to 64 bits starting at an arbitrary bit offset.
    // 1. Locate the starting byte and bit offset.
    // 2. Load the surrounding 32-byte word from memory.
    // 3. Shift the requested bit range down to the low bits.
    // 4. Mask off any higher bits and return the 64-bit result.
    function readBits64(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint64) {
        // Convert the starting bit offset into a byte offset.
        uint256 byteOffset = startBit >> 3;
        // Keep only the bit offset within that byte.
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            // Load the 32-byte word starting at the requested byte offset.
            word := mload(add(add(input, 32), byteOffset))
        }
        // Shift the requested bit range down to the low bits of the loaded word.
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        // Build a bit mask of exactly bitLen low bits.
        uint256 mask = bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        // casting to 'uint64' is safe because the mask bounds the result to at most 64 bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(shifted & mask);
    }
}
