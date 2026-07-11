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

/// @title SHRINCSHash
/// @notice Profile-independent hash and bit primitives shared by every
/// SHRINCS module: address-word packing, hash-output masking, base-w digit
/// extraction, and the memory-safe bit readers.
/// @dev This library is the compile-time hash-suite seam. The current suite
/// is keccak-256; a future SHA-256 suite plugs in here via remapping without
/// touching the verifier logic that calls these helpers.
library SHRINCSHash {
    // addressWord32: Pack the SPHINCS/XMSS-style address components into one
    // 32-byte word.
    // 1. Shift each address component into its reserved bit range.
    // 2. OR the shifted components together into one packed value.
    // 3. Return the packed 32-byte address word.
    function addressWord32(
        uint32 layer,
        uint64 tree,
        uint32 addressType,
        uint32 keypair,
        uint32 chain,
        uint32 step
    ) internal pure returns (bytes32) {
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

    // maskHash: Truncate a freshly produced 32-byte hash to the active
    // profile's HASH_LEN, keeping the high HASH_LEN bytes and zeroing
    // the low (32 - HASH_LEN) ([DESIGN §2(b)/§3.3]). Applied at every
    // hash-*producing* site so a truncated profile emits high-aligned,
    // zero-padded node values in a bytes32 slot; the exact bytes hashed
    // downstream stay 32-byte-slot sized. No masking is done on *load*,
    // so a mutated low half fails a downstream comparison rather than
    // opening a second accepted encoding (canonicality, [DESIGN §2(b)]).
    // For the 256s profile HASH_MASK is all-ones, so this folds to a
    // no-op under via-ir.
    function maskHash(bytes32 hashValue) internal pure returns (bytes32) {
        return hashValue & ShrincsTypes.HASH_MASK;
    }

    // baseWDigit: Read one base-w digit from a digest, supporting both
    // byte-wide and base-16 forms.
    // chainBase: the WOTSPLUS `w` (Winternitz) parameter [WOTSPLUS §3]
    // — the base of the digit representation.
    // 1. Return one whole byte when chainBase = 256.
    // 2. Otherwise select the byte that contains the requested base-16 digit.
    // 3. Return the high nibble for even indices.
    // 4. Return the low nibble for odd indices.
    function baseWDigit(uint16 chainBase, bytes memory digest, uint256 index)
        internal
        pure
        returns (uint32)
    {
        // Byte-wide base-w uses one full digest byte per digit.
        if (chainBase == 256) return uint8(digest[index]);
        // Base-16 uses two digits per digest byte.
        uint8 packedByte = uint8(digest[index >> 1]);
        return index & 1 == 0 ? packedByte >> 4 : packedByte & 0x0f;
    }

    // setHashChunk: Copy up to one 32-byte hash chunk into a mutable output
    // buffer.
    // 1. Walk over the requested chunk length one byte at a time.
    // 2. Copy each byte from the hash block into the requested output offset.
    function setHashChunk(
        bytes memory out,
        bytes32 blockHash,
        uint256 offset,
        uint256 chunk
    ) internal pure {
        for (uint256 i = 0; i < chunk;) {
            // Copy one byte from the block hash into the requested output
            // position.
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
    // Caller contract: mload reads a full 32-byte word at the byte offset,
    // touching up to 31 bytes past input's logical length. The caller MUST
    // keep startBit + bitLen <= 8 * input.length and provide at least 32
    // bytes of readable slack beyond input's data, or the load reads
    // adjacent heap. forsDigestBytes over-allocates digestBytes + 32 to
    // satisfy this.
    function readBits32(bytes memory input, uint256 startBit, uint32 bitLen)
        internal
        pure
        returns (uint32)
    {
        // Convert the starting bit offset into a byte offset.
        uint256 byteOffset = startBit >> 3;
        // Keep only the bit offset within that byte.
        uint256 bitOffset = startBit & 7;
        uint256 word;
        // Memory-safe: reads one 32-byte word from within input's allocated
        // buffer (the caller guarantees 32 bytes of readable slack, above);
        // no memory is written.
        assembly ("memory-safe") {
            // Load the 32-byte word starting at the requested byte offset.
            word := mload(add(add(input, 32), byteOffset))
        }
        // Shift the requested bit range down to the low bits of the loaded
        // word.
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        // Build a bit mask of exactly bitLen low bits.
        uint256 mask =
            bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        // casting to 'uint32' is safe because the mask bounds the result to
        // at most 32 bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(shifted & mask);
    }

    // readBits64: Extract up to 64 bits starting at an arbitrary bit offset.
    // 1. Locate the starting byte and bit offset.
    // 2. Load the surrounding 32-byte word from memory.
    // 3. Shift the requested bit range down to the low bits.
    // 4. Mask off any higher bits and return the 64-bit result.
    // Caller contract: mload reads a full 32-byte word at the byte offset,
    // touching up to 31 bytes past input's logical length. The caller MUST
    // keep startBit + bitLen <= 8 * input.length and provide at least 32
    // bytes of readable slack beyond input's data, or the load reads
    // adjacent heap. forsDigestBytes over-allocates digestBytes + 32 to
    // satisfy this.
    function readBits64(bytes memory input, uint256 startBit, uint32 bitLen)
        internal
        pure
        returns (uint64)
    {
        // Convert the starting bit offset into a byte offset.
        uint256 byteOffset = startBit >> 3;
        // Keep only the bit offset within that byte.
        uint256 bitOffset = startBit & 7;
        uint256 word;
        // Memory-safe: reads one 32-byte word from within input's allocated
        // buffer (the caller guarantees 32 bytes of readable slack, above);
        // no memory is written.
        assembly ("memory-safe") {
            // Load the 32-byte word starting at the requested byte offset.
            word := mload(add(add(input, 32), byteOffset))
        }
        // Shift the requested bit range down to the low bits of the loaded
        // word.
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        // Build a bit mask of exactly bitLen low bits.
        uint256 mask =
            bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        // casting to 'uint64' is safe because the mask bounds the result to
        // at most 64 bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(shifted & mask);
    }
}
