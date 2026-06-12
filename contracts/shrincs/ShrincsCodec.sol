// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";

// Low-level encoding primitives shared by every SHRINCS verification path:
// address-word packing, packed-bitstring readers, output-buffer writers,
// base-W digit extraction, and the two public-key byte decoders.
//
// These helpers carry no cryptographic meaning on their own; they exist so the
// same assembly bit-twiddling is written once and reused by the WOTS-C, FORS,
// hypertree, and stateful modules.
library ShrincsCodec {
    // Pack the compact 32-byte address word used by the stateful and stateless
    // Keccak-based hash domains in this verifier.
    function addressWord32(uint32 layer, uint64 tree, uint32 addressType, uint32 keypair, uint32 chain, uint32 step)
        internal
        pure
        returns (bytes32)
    {
        return bytes32(
            (uint256(layer) << 224) | (uint256(tree) << 128) | (uint256(addressType) << 96) | (uint256(keypair) << 64)
                | (uint256(chain) << 32) | uint256(step)
        );
    }

    // Read up to 32 bits from a packed big-endian bitstring without branching over
    // byte boundaries.
    function readBits32(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint32) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        return uint32(shifted & mask);
    }

    // Read up to 64 bits from a packed big-endian bitstring without materializing
    // intermediate slices.
    function readBits64(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint64) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        return uint64(shifted & mask);
    }

    // Copy a partial 32-byte hash block into an output byte string at the requested
    // offset.
    function writeHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) internal pure {
        for (uint256 i = 0; i < chunk;) {
            out[offset + i] = blockHash[i];
            unchecked {
                ++i;
            }
        }
    }

    // Store one 32-byte segment into a byte buffer at a fixed offset.
    function writeSegment32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    // Extract one base-W digit from the packed digest bytes used by stateless WOTS-C.
    function baseWDigit(uint16 w, bytes memory digest, uint256 index) internal pure returns (uint32) {
        if (w == 256) return uint8(digest[index]);
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? b >> 4 : b & 0x0f;
    }

    // Extract one base-16 digit from the packed stateful WOTS digest.
    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32 digit) {
        assembly {
            let b := byte(shr(1, index), digest)
            digit := and(b, 0x0f)
            if iszero(and(index, 1)) { digit := shr(4, b) }
        }
    }

    // Load the single 32-byte composite public-key word, or zero if malformed.
    function compositePublicKeyWord(bytes calldata compositePublicKey) internal pure returns (bytes32 word) {
        if (compositePublicKey.length != 32) return bytes32(0);
        assembly {
            word := calldataload(compositePublicKey.offset)
        }
    }

    // Decode the packed stateful public key bytes into the typed `pkSeed`, `root`,
    // and `maxSignatures` fields expected by the stateful verifier path.
    function decodeStatefulPublicKey(bytes calldata encoded)
        internal
        pure
        returns (ShrincsType.StatefulPublicKey memory publicKey, bool ok)
    {
        if (encoded.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES) return (publicKey, false);
        assembly {
            publicKey := mload(0x40)
            mstore(publicKey, calldataload(encoded.offset))
            mstore(add(publicKey, 0x20), calldataload(add(encoded.offset, 32)))
            mstore(add(publicKey, 0x40), shr(224, calldataload(add(encoded.offset, 64))))
            mstore(0x40, add(publicKey, 0x60))
        }
        return (publicKey, true);
    }
}
