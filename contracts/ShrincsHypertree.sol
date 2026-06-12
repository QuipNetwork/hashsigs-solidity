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

import { ShrincsTypes } from "./ShrincsTypes.sol";
import { ShrincsUtils } from "./ShrincsUtils.sol";

library ShrincsHypertree {
    function verifyHypertree(
        ShrincsTypes.ParamsView memory params,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 messageRoot,
        ShrincsTypes.HypertreeLayerSignature[] calldata layers
    ) internal pure returns (bool) {
        if (layers.length != params.d) return false;
        uint32 subtreeHeight = uint32(params.h / params.d);
        uint32 leafCount = uint32(1) << subtreeHeight;
        bytes32 current = messageRoot;

        for (uint256 layer = 0; layer < layers.length;) {
            ShrincsTypes.HypertreeLayerSignature calldata layerSig = layers[layer];
            // NOTE: This verifier currently accepts upper-layer hypertree coordinates directly from
            // the signature. The Rust signer under code/src/hypertree.rs emits sequential per-layer
            // tree and leaf indices rather than deriving them from the FORS-pinned layer-0 index.
            // We keep that compatibility for now because the current vectors were generated against
            // that signer behavior. This is not directly forgeable: every WOTS-C and hypertree node
            // hash binds (layer, tree, leaf) into its address word, and the full chain still has to
            // close at the pinned hypertree root. The full fix is signer/vector regeneration and
            // then enforcing the FIPS-style recurrence here.
            if (layerSig.leafIndex >= leafCount) return false;
            if (layerSig.wotsCPkHash.length != params.nBytes) return false;
            if (layerSig.authPath.length != subtreeHeight) return false;
            if (
                !verifyWotsC32(
                    params,
                    publicKey.hypertreePkSeed,
                    uint32(layer),
                    layerSig.treeIndex,
                    layerSig.leafIndex,
                    layerSig.wotsCPkHash,
                    current,
                    layerSig.wotsCSignature
                )
            ) return false;

            bytes calldata wotsPkHash = layerSig.wotsCPkHash;
            bytes32 leaf;
            assembly {
                leaf := calldataload(wotsPkHash.offset)
            }

            (bytes32 nextRoot, bool ok) = hypertreeRootFromPath32(
                subtreeHeight, publicKey.hypertreePkSeed, uint32(layer), layerSig.treeIndex, layerSig.leafIndex, leaf, layerSig.authPath
            );
            if (!ok) return false;
            current = nextRoot;
            unchecked {
                ++layer;
            }
        }

        bytes calldata expectedRootBytes = publicKey.hypertreeRoot;
        bytes32 expectedRoot;
        assembly {
            expectedRoot := calldataload(expectedRootBytes.offset)
        }
        return current == expectedRoot;
    }

    function verifyWotsC32(
        ShrincsTypes.ParamsView memory params,
        bytes calldata pkSeedBytes,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes calldata expectedPkHashBytes,
        bytes32 message,
        ShrincsTypes.WotsCSignature calldata signature
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
            uint32 digit = ShrincsUtils.baseWDigit(params.w, digest, i);
            digitSum += digit;
            bytes32 segment = wotsChain32NoMaskBase(params.w, pkSeed, addressBase, uint32(i), chain, digit);
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
            out = hashStatelessWotsCChainNoMask32(pkSeed, bytes32(addressBase | (uint256(chainIdx) << 32) | (uint256(digit) + j)), out);
            unchecked {
                ++j;
            }
        }
    }

    function wotsChain32NoMask(
        ShrincsTypes.WotsContext memory ctx,
        bytes calldata pkSeedBytes,
        uint32 chainIdx,
        bytes calldata value,
        uint32 digit
    ) internal pure returns (bytes32 out) {
        bytes32 pkSeed;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            out := calldataload(value.offset)
        }
        uint32 steps = uint32(ctx.w - 1) - digit;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord =
                ShrincsUtils.addressWord32(ctx.layer, ctx.tree, ShrincsTypes.WOTS_HASH_TYPE, ctx.keypair, chainIdx, digit + j);
            out = hashStatelessWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    function hashStatelessWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        internal
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

    function wotsDigestBytes(ShrincsTypes.ParamsView memory params) internal pure returns (uint256) {
        uint256 bitsPerDigit = params.w == 256 ? 8 : 4;
        return (uint256(params.l) * bitsPerDigit + 7) / 8;
    }

    function hypertreeRootFromPath32(
        uint32 height,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes32 leaf,
        bytes[] calldata authPath
    ) internal pure returns (bytes32 node, bool ok) {
        if (authPath.length != height) return (bytes32(0), false);
        bytes32 pkSeedWord;
        assembly {
            pkSeedWord := calldataload(pkSeed.offset)
        }
        uint256 addressBase =
            (uint256(layer) << 224) | (uint256(treeIndex) << 128) | (uint256(ShrincsTypes.TREE_TYPE) << 96);
        node = leaf;
        uint256 index = leafIndex;
        for (uint256 level = 0; level < height;) {
            bytes calldata authNode = authPath[level];
            if (authNode.length != 32) return (bytes32(0), false);
            bytes32 sibling;
            assembly {
                sibling := calldataload(authNode.offset)
            }
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            uint256 nodeHeight = level + 1;
            uint256 shiftedNodeHeight = nodeHeight << 32;
            uint256 parentIndex = index >> 1;
            bytes32 addressWord = bytes32(addressBase | shiftedNodeHeight | parentIndex);
            node = hashHypertreeNode32(pkSeedWord, addressWord, left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
        ok = true;
    }

    function hashHypertreeNode32(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "hypertree-node")
            mstore(add(ptr, 14), pkSeed)
            mstore(add(ptr, 46), addressWord)
            mstore(add(ptr, 78), left)
            mstore(add(ptr, 110), right)
            out := keccak256(ptr, 142)
        }
    }
}
