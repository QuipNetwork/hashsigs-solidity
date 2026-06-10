// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessTypes } from './ShrincsStatelessTypes.sol';

abstract contract ShrincsStatelessWotsC is ShrincsStatelessTypes {
    struct WotsContext {
        uint16 w;
        uint32 layer;
        uint64 tree;
        uint32 keypair;
        bool useMask;
    }

    function verifyWotsC(
        ParamsView memory params,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes calldata expectedPkHash,
        bytes memory message,
        WotsCSignature calldata signature
    ) internal pure returns (bool) {
        if (signature.randomizer.length != 32 || signature.chains.length != params.l) return false;

        bytes memory digest = domainKeccakBytes(
            'wots-c-msg',
            pkSeed,
            abi.encodePacked(expectedPkHash, signature.randomizer, signature.counter, message),
            wotsDigestBytes(params)
        );
        WotsContext memory ctx = WotsContext({ w: params.w, layer: layer, tree: tree, keypair: keypair, useMask: params.wotsMask });
        (bytes memory segments, uint32 digitSum) = wotsSegmentsAndSum(params.l, pkSeed, ctx, digest, signature);
        if (segments.length == 0 || digitSum != params.wotsTargetSum) return false;
        return eq(domainKeccakBytes('wots-c-pk', pkSeed, segments, params.nBytes), expectedPkHash);
    }

    function verifyWotsC32(
        ParamsView memory params,
        bytes calldata pkSeedBytes,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes calldata expectedPkHashBytes,
        bytes32 message,
        WotsCSignature calldata signature
    ) internal pure returns (bool) {
        uint256 chainCount = uint256(params.l);
        if (signature.randomizer.length != 32 || signature.chains.length != chainCount || expectedPkHashBytes.length != 32) return false;

        bytes calldata randomizerBytes = signature.randomizer;
        bytes32 pkSeed;
        bytes32 expectedPkHash;
        bytes32 randomizer;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            expectedPkHash := calldataload(expectedPkHashBytes.offset)
            randomizer := calldataload(randomizerBytes.offset)
        }

        bytes memory digest = wotsDigest32(pkSeed, expectedPkHash, randomizer, signature.counter, message, wotsDigestBytes(params));
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
            uint32 digit = baseWDigit(params.w, digest, i);
            digitSum += digit;
            bytes32 segment = params.wotsMask
                ? wotsChain32MaskedBase(params.w, pkSeed, addressBase, uint32(i), chain, digit)
                : wotsChain32NoMaskBase(params.w, pkSeed, addressBase, uint32(i), chain, digit);
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

    function wotsDigest32(
        bytes32 pkSeed,
        bytes32 expectedPkHash,
        bytes32 randomizer,
        uint32 counter,
        bytes32 message,
        uint256 outLen
    ) internal pure returns (bytes memory out) {
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

    function wotsChain32NoMaskBase(uint16 w, bytes32 pkSeed, uint256 addressBase, uint32 chainIdx, bytes calldata value, uint32 digit)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            out := calldataload(value.offset)
        }
        uint256 steps = uint256(w - 1) - digit;
        for (uint256 j = 0; j < steps;) {
            out = hashWotsCChainNoMask32(pkSeed, bytes32(addressBase | (uint256(chainIdx) << 32) | (uint256(digit) + j)), out);
            unchecked {
                ++j;
            }
        }
    }

    function wotsChain32MaskedBase(uint16 w, bytes32 pkSeed, uint256 addressBase, uint32 chainIdx, bytes calldata value, uint32 digit)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            out := calldataload(value.offset)
        }
        uint256 steps = uint256(w - 1) - digit;
        for (uint256 j = 0; j < steps;) {
            out = hashWotsCChainMasked32(pkSeed, bytes32(addressBase | (uint256(chainIdx) << 32) | (uint256(digit) + j)), out);
            unchecked {
                ++j;
            }
        }
    }

    function wotsSegmentsAndSum(
        uint16 chainCount,
        bytes calldata pkSeed,
        WotsContext memory ctx,
        bytes memory digest,
        WotsCSignature calldata signature
    ) internal pure returns (bytes memory segments, uint32 digitSum) {
        // returns WOTS-C advanced values for all chains, and the sum of the base-w digits
        segments = new bytes(uint256(chainCount) * 32);
        for (uint256 i = 0; i < chainCount; ) {
            if (signature.chains[i].length != 32) return ('', 0);
            uint32 digit = baseWDigit(ctx.w, digest, i);
            digitSum += digit;
            bytes32 segment;
            if (ctx.useMask) {
                segment = wotsChain32Masked(ctx, pkSeed, uint32(i), signature.chains[i], digit);
            } else {
                segment = wotsChain32NoMask(ctx, pkSeed, uint32(i), signature.chains[i], digit);
            }
            setSlice32(segments, segment, i * 32);
            unchecked {
                ++i;
            }
        }
    }

    function wotsChain32NoMask(WotsContext memory ctx, bytes calldata pkSeedBytes, uint32 chainIdx, bytes calldata value, uint32 digit) internal pure returns (bytes32) {
        bytes32 pkSeed;
        bytes32 out;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset) // calldataload(p) loads 32 bytes from calldata at position p
            out := calldataload(value.offset)
        }

        uint32 steps = uint32(ctx.w - 1) - digit;
        for (uint32 j = 0; j < steps; ) {
            bytes32 addressWord = addressWord32(ctx.layer, ctx.tree, WOTS_HASH_TYPE, ctx.keypair, chainIdx, digit + j);
            out = hashWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
        return out;
    }

    function wotsChain32Masked(WotsContext memory ctx, bytes calldata pkSeedBytes, uint32 chainIdx, bytes calldata value, uint32 digit) internal pure returns (bytes32) {
        bytes32 pkSeed;
        bytes32 out;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            out := calldataload(value.offset)
        }

        uint32 steps = uint32(ctx.w - 1) - digit;
        for (uint32 j = 0; j < steps; ) {
            bytes32 addressWord = addressWord32(ctx.layer, ctx.tree, WOTS_HASH_TYPE, ctx.keypair, chainIdx, digit + j);
            out = hashWotsCChainMasked32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
        return out;
    }

    function hashWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment) internal pure returns (bytes32 out) {
        assembly {
            // keccak256("wots-c-chain" || pkSeed || addressWord || segment)
            let ptr := mload(0x40)
            mstore(ptr, 'wots-c-chain')
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), segment)
            out := keccak256(ptr, 108)
        }
    }

    function hashWotsCChainMasked32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment) internal pure returns (bytes32 out) {
        bytes32 mask;
        assembly {
            //keccak256("wots-c-mask" || pkSeed || addressWord) gives the mask for the current step
            let ptr := mload(0x40)
            mstore(ptr, 'wots-c-mask')
            mstore(add(ptr, 11), pkSeed)
            mstore(add(ptr, 43), addressWord)
            mask := keccak256(ptr, 75)

            //keccak256("wots-c-chain" || pkSeed || addressWord || (segment XOR mask)) gives the next chain value
            mstore(ptr, 'wots-c-chain')
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), xor(segment, mask))
            out := keccak256(ptr, 108)
        }
    }

    function wotsDigestBytes(ParamsView memory params) internal pure returns (uint256) {
        uint256 bitsPerDigit = params.w == 256 ? 8 : 4; // if w=256, each base-w digit is log_2 (256) = 8 bits, else for w=16, each digit is log_2(16) = 4 bits
        return (uint256(params.l) * bitsPerDigit + 7) / 8; // params.l is number of chains/digits, so total bits is l*bitsPerDigit, convert to bytes with +7/8 rounding up
    }
}
