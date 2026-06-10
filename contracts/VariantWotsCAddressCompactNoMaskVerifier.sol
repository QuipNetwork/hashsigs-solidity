// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WotsTypes } from "../WotsTypes.sol";
import { WotsBaseW } from "../WotsBaseW.sol";
import { Hashing } from "../Hashing.sol";

contract VariantWotsCAddressCompactNoMaskVerifier {
    uint8 internal constant WOTSC_LEN = 64; // = N*8/log2(W)
    uint8 internal constant N = 32; // hash output length in bytes
    uint8 internal constant W = 16; // Winternitz parameter, chain length is W-1
    uint16 internal constant WOTSC_TARGET_SUM = 480; // (w-1)/2 * wotscLen = 15 * 64
    uint32 internal constant WOTS_HASH_TYPE = 0;

    function verify(
        WotsTypes.AddressContext calldata context,
        WotsTypes.WotsCPublicKey calldata publicKey,
        bytes calldata message,
        WotsTypes.WotsCSignature calldata signature
    ) external pure returns (bool) {
        // Bind the digest to the public seed, public key hash, randomizer, counter, and message.
        bytes32 digest = hashSeeded(
            "wots-c-msg", publicKey.pkSeed, abi.encodePacked(publicKey.pkHash, signature.randomizer, signature.counter, message)
        );
        uint8[] memory digits = new uint8[](WOTSC_LEN);
        WotsBaseW.toBaseW16(digest, WOTSC_LEN, digits, 0);
        uint16 digitSum = 0;
        bytes memory segments = new bytes(uint16(WOTSC_LEN) * uint16(N));

        for (uint8 i = 0; i < WOTSC_LEN; i++) {
            uint8 digit = digits[i]; // get the i-th base-W digit of the digest
            digitSum += digit;
            bytes32 segment = chain(context, publicKey.pkSeed, i, signature.chains[i], digit);
            setSlice32(segments, segment, uint16(i) * uint16(N));
        }

        if (digitSum != WOTSC_TARGET_SUM) return false;
        return hashSeeded("wots-c-pk", publicKey.pkSeed, segments) == publicKey.pkHash;
    }

    // Finish one WOTS-C chain with address binding and no mask.
    function chain(WotsTypes.AddressContext calldata context, bytes32 pkSeed, uint32 chainIdx, bytes32 value, uint8 digit)
        internal
        pure
        returns (bytes32)
    {
        bytes32 segment = value;
        uint256 addressBase = wotsAddressBase(context, chainIdx);
        for (uint8 j = 0; j < W - 1 - digit; j++) {
            uint32 step = uint32(digit + j);
            bytes32 addressWord = bytes32(addressBase | uint256(step));
            segment = hashSeeded("wots-c-chain", pkSeed, abi.encodePacked(addressWord, segment));
        }
        return segment;
    }

    // Compact WOTS address construction, adapted from the SPHINCS+/FIPS 205 address layout:
    // [0..4]   layer: u32
    // [4..16]  tree: bytes12 in this implementation
    // [16..20] type: u32, where 0 means WOTS hash
    // [20..24] keypair: u32
    // [24..28] chain: u32
    // [28..32] step: u32, filled inside chain()
    function wotsAddressBase(WotsTypes.AddressContext calldata context, uint32 chainIdx) internal pure returns (uint256) {
        return (uint256(context.layer) << 224) | (uint256(uint96(context.tree)) << 128) | (uint256(WOTS_HASH_TYPE) << 96)
            | (uint256(context.keypair) << 64) | (uint256(chainIdx) << 32);
    }

    function hashSeeded(bytes memory domain, bytes32 seed, bytes memory data) internal pure returns (bytes32) {
        return Hashing.hash(abi.encodePacked(domain, seed, data));
    }

    function setSlice32(bytes memory dst, bytes32 src, uint16 offset) internal pure {
        assembly {
            // add (dst,32) because the first 32 bytes of a bytes array in memory is the length, so the actual data starts at dst+32
            // add offset to get the correct position for the i-th segment, then store the 32-byte src into the dst array at that position
            mstore(add(add(dst, 32), offset), src) // into the dst array at the specified offset, store the 32-byte src
        }
    }
}
