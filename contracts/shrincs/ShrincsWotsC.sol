// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";

// Stateless WOTS-C: rebuild a layer's public-key hash from its signature chains
// and the message-derived base-W digits, enforcing the fixed target digit sum.
library ShrincsWotsC {
    // Rebuild the WOTS-C public-key hash for one hypertree layer and compare it to
    // the expected leaf commitment carried in the layer signature.
    function verifyWotsC32(
        ShrincsType.ParamsView memory params,
        bytes calldata pkSeedBytes,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes calldata expectedPkHashBytes,
        bytes32 message,
        ShrincsType.WotsCSignature calldata signature
    ) internal pure returns (bool) {
        uint256 chainCount = uint256(params.l);
        if (
            signature.randomizer.length != 32 || signature.chains.length != chainCount
                || expectedPkHashBytes.length != 32
        ) {
            return false;
        }

        bytes calldata randomizerBytes = signature.randomizer;
        bytes32 pkSeed;
        bytes32 expectedPkHash;
        bytes32 randomizer;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            expectedPkHash := calldataload(expectedPkHashBytes.offset)
            randomizer := calldataload(randomizerBytes.offset)
        }

        bytes memory digest =
            _wotsDigest32(pkSeed, expectedPkHash, randomizer, signature.counter, message, _wotsDigestBytes(params));
        uint256 pkInputLen = 41 + chainCount * 32;
        uint256 pkInput;
        assembly {
            pkInput := mload(0x40)
            mstore(pkInput, "wots-c-pk")
            mstore(add(pkInput, 9), pkSeed)
            mstore(0x40, add(pkInput, and(add(pkInputLen, 31), not(31))))
        }

        uint256 addressBase = (uint256(layer) << 224) | (uint256(tree) << 128) | (uint256(keypair) << 64);
        uint32 digitSum;
        for (uint256 i = 0; i < chainCount;) {
            bytes calldata chain = signature.chains[i];
            if (chain.length != 32) return false;
            uint32 digit = ShrincsCodec.baseWDigit(params.w, digest, i);
            digitSum += digit;
            bytes32 segment = _wotsChain32NoMaskBase(params.w, pkSeed, addressBase, uint32(i), chain, digit);
            assembly {
                mstore(add(add(pkInput, 41), mul(i, 32)), segment)
            }
            unchecked {
                ++i;
            }
        }
        if (digitSum != params.wotsTargetSum) return false;

        bytes32 computedPkHash;
        assembly {
            computedPkHash := keccak256(pkInput, pkInputLen)
        }
        return computedPkHash == expectedPkHash;
    }

    // Derive the WOTS-C message digest bytes from the public seed, randomizer,
    // counter, expected public-key hash, and message.
    function _wotsDigest32(
        bytes32 pkSeed,
        bytes32 expectedPkHash,
        bytes32 randomizer,
        uint32 counter,
        bytes32 message,
        uint256 outLen
    ) private pure returns (bytes memory out) {
        out = new bytes(outLen);
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "wots-c-msg")
            mstore(add(ptr, 10), pkSeed)
            mstore(add(ptr, 42), expectedPkHash)
            mstore(add(ptr, 74), randomizer)
            mstore(add(ptr, 106), shl(224, counter))
            mstore(add(ptr, 110), message)
            let digestWord := keccak256(ptr, 142)
            mstore(add(out, 32), digestWord)
            mstore(0x40, add(ptr, 160))
        }
    }

    // Finish a stateless WOTS-C chain from the received signature element to its
    // terminal value using compact per-step addressing.
    function _wotsChain32NoMaskBase(
        uint16 w,
        bytes32 pkSeed,
        uint256 addressBase,
        uint32 chainIdx,
        bytes calldata value,
        uint32 digit
    ) private pure returns (bytes32 out) {
        assembly {
            out := calldataload(value.offset)
        }
        uint256 steps = uint256(w - 1) - digit;
        for (uint256 j = 0; j < steps;) {
            out = _hashStatelessWotsCChainNoMask32(
                pkSeed, bytes32(addressBase | (uint256(chainIdx) << 32) | (uint256(digit) + j)), out
            );
            unchecked {
                ++j;
            }
        }
    }

    // Finish a stateless WOTS-C chain using the structured WOTS context variant.
    // This helper remains available for paths that use full address composition.
    function _wotsChain32NoMask(
        ShrincsType.WotsContext memory ctx,
        bytes calldata pkSeedBytes,
        uint32 chainIdx,
        bytes calldata value,
        uint32 digit
    ) private pure returns (bytes32 out) {
        bytes32 pkSeed;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            out := calldataload(value.offset)
        }
        uint32 steps = uint32(ctx.w - 1) - digit;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord = ShrincsCodec.addressWord32(
                ctx.layer, ctx.tree, ShrincsType.WOTS_HASH_TYPE, ctx.keypair, chainIdx, digit + j
            );
            out = _hashStatelessWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    // Hash one stateless WOTS-C chain step under the chain domain separator and
    // encoded address word.
    function _hashStatelessWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "wots-c-chain")
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), segment)
            out := keccak256(ptr, 108)
        }
    }

    // Return the number of digest bytes needed to encode all base-W WOTS digits for
    // the current stateless parameter set.
    function _wotsDigestBytes(ShrincsType.ParamsView memory params) private pure returns (uint256) {
        uint256 bitsPerDigit = params.w == 256 ? 8 : 4;
        return (uint256(params.l) * bitsPerDigit + 7) / 8;
    }
}
