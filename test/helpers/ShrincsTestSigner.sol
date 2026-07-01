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

import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {ShrincsTypes} from "../../contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "../../contracts/ShrincsUtils.sol";

/// @notice TEST-ONLY Solidity signer helpers that mirror the Rust signer for stateful flows.
/// @dev This library is kept under `test/helpers` so it does not become part of the
/// production Solidity surface. It is used for deterministic keygen and stateful-signing tests.
library ShrincsTestSigner {
    uint32 internal constant INITIAL_STATEFUL_LEAF_INDEX = 0;
    uint32 internal constant MAX_STATEFUL_SIGNATURES_LIMIT = ShrincsTypes.STATEFUL_Q_MAX;
    uint32 internal constant FORS_C_MAX_GRIND_COUNTER = 1 << 24;
    uint8 internal constant NUM_HYPERTREE_LAYERS = 8;

    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        internal
        pure
        returns (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok)
    {
        if (maxStatefulSignatures == 0) return (signingKey, publicKey, false);
        if (maxStatefulSignatures > MAX_STATEFUL_SIGNATURES_LIMIT) return (signingKey, publicKey, false);

        bytes32 statefulSkSeed = derive32("shrincs-stateful-sk-seed", seedMaterial, "");
        bytes32 statefulPrfSeed = derive32("shrincs-stateful-prf-seed", seedMaterial, "");
        bytes32 statefulPkSeed = derive32("shrincs-stateful-pk-seed", seedMaterial, "");
        bytes32 statefulRoot = statefulSubtreeRoot(statefulSkSeed, statefulPkSeed);
        bytes32 statelessSkSeed = derive32("shrincs-stateless-sk-seed", seedMaterial, "");
        bytes32 statelessPrfSeed = derive32("shrincs-stateless-prf-seed", seedMaterial, "");
        bytes32 pkSeed = derive32("shrincs-pk-seed", seedMaterial, "");
        bytes32 hypertreeRoot = hypertreePublicRoot(statelessSkSeed, pkSeed);

        signingKey = ShrincsTypes.SigningKey({
            statefulSkSeed: statefulSkSeed,
            statefulPrfSeed: statefulPrfSeed,
            statefulPkSeed: statefulPkSeed,
            statefulRoot: statefulRoot,
            maxStatefulSignatures: maxStatefulSignatures,
            nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
            statelessSkSeed: statelessSkSeed,
            statelessPrfSeed: statelessPrfSeed,
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });

        bytes memory statefulPublicKey = encodeStatefulPublicKey(statefulPkSeed, statefulRoot, maxStatefulSignatures);
        bytes32 publicKeyCommitment = ShrincsUtils.publicKeyCommitmentFromParts(
            statefulPublicKey, abi.encodePacked(pkSeed), abi.encodePacked(hypertreeRoot)
        );
        publicKey = ShrincsTypes.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(publicKeyCommitment),
            pkSeed: abi.encodePacked(pkSeed),
            hypertreeRoot: abi.encodePacked(hypertreeRoot)
        });
        return (signingKey, publicKey, true);
    }

    function signStatefulRaw(ShrincsTypes.SigningKey memory signingKey, bytes memory message)
        internal
        pure
        returns (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.StatefulSignature memory signature,
            bool ok
        )
    {
        uint32 leafIndex = signingKey.nextStatefulLeafIndex;
        if (leafIndex >= signingKey.maxStatefulSignatures) return (nextSigningKey, signature, false);

        (signature, ok) = signStatefulRawAtLeaf(signingKey, leafIndex, message);
        if (!ok) return (nextSigningKey, signature, false);

        nextSigningKey = signingKey;
        nextSigningKey.nextStatefulLeafIndex = leafIndex + 1;
        return (nextSigningKey, signature, true);
    }

    function signStatefulAction(
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.ActionContext memory context
    )
        internal
        pure
        returns (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.StatefulSignature memory signature,
            bool ok
        )
    {
        if (publicKey.publicKeyCommitment.length != 32) return (nextSigningKey, signature, false);
        bytes32 expectedPublicKeyCommitment;
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(expectedPublicKeyCommitment, context));
        return signStatefulRaw(signingKey, message);
    }

    function derive32(bytes memory domain, bytes memory seed, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, seed, data));
    }

    function signStatefulRawAtLeaf(ShrincsTypes.SigningKey memory signingKey, uint32 leafIndex, bytes memory message)
        internal
        pure
        returns (ShrincsTypes.StatefulSignature memory signature, bool ok)
    {
        if (leafIndex >= signingKey.maxStatefulSignatures) return (signature, false);
        if (leafIndex >= ShrincsTypes.STATEFUL_Q_MAX) return (signature, false);

        uint8 q = uint8(leafIndex);
        (signature, ok) = signCompactForsC(
            signingKey.statefulSkSeed,
            signingKey.statefulPrfSeed,
            signingKey.statefulPkSeed,
            signingKey.statefulRoot,
            q,
            message
        );
        if (!ok) return (signature, false);
        signature.authPath = statefulAuthPath(signingKey.statefulSkSeed, signingKey.statefulPkSeed, q);
        return (signature, true);
    }

    function encodeStatefulPublicKey(bytes32 pkSeed, bytes32 root, uint32 maxSignatures)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(pkSeed, root, maxSignatures);
    }

    function statefulSubtreeRoot(bytes32 skSeed, bytes32 subPkSeed) internal pure returns (bytes32 root) {
        return statefulMerkleNode(skSeed, subPkSeed, ShrincsTypes.STATEFUL_MERKLE_HEIGHT, 0);
    }

    function statefulMerkleNode(bytes32 skSeed, bytes32 subPkSeed, uint32 height, uint32 index)
        internal
        pure
        returns (bytes32)
    {
        if (height == 0) {
            return compactForsCPublicKey(skSeed, subPkSeed, uint8(index));
        }
        bytes32 left = statefulMerkleNode(skSeed, subPkSeed, height - 1, index << 1);
        bytes32 right = statefulMerkleNode(skSeed, subPkSeed, height - 1, (index << 1) | 1);
        uint32 level = uint32(ShrincsTypes.STATEFUL_MERKLE_HEIGHT) - height;
        return jardinMerkleParentHash(subPkSeed, level, index, left, right);
    }

    function signCompactForsC(
        bytes32 skSeed,
        bytes32 skPrf,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        uint8 q,
        bytes memory message
    ) internal pure returns (ShrincsTypes.StatefulSignature memory signature, bool ok) {
        for (uint32 counter = 0; counter < FORS_C_MAX_GRIND_COUNTER;) {
            bytes memory mStar = abi.encodePacked("JARDIN/TYPE2/v1", subPkSeed, subPkRoot, q, message);
            bytes32 randomizer = compactRandomizer(skPrf, bytes32(0), counter, mStar);
            bytes memory digest = compactDigest(subPkSeed, subPkRoot, q, randomizer, counter, message);
            uint256 a = uint256(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
            uint256 kOpen = uint256(ShrincsTypes.STATEFUL_FORS_K_OPEN);
            if (ShrincsUtils.readBits32(digest, kOpen * a, ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) == 0) {
                ShrincsTypes.ForsEntry[] memory entries = new ShrincsTypes.ForsEntry[](kOpen);
                for (uint256 tree = 0; tree < kOpen;) {
                    uint32 leaf = ShrincsUtils.readBits32(digest, tree * a, ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
                    (, bytes[] memory authPath) =
                        compactForsTreeRootAndAuthPath(skSeed, subPkSeed, q, uint32(tree), leaf);
                    entries[tree] = ShrincsTypes.ForsEntry({
                        secretLeaf: abi.encodePacked(
                            compactForsLeafSecret(skSeed, subPkSeed, q, compactForsTreeLowLeafIndex(uint32(tree), leaf))
                        ),
                        authPath: authPath
                    });
                    unchecked {
                        ++tree;
                    }
                }
                signature = ShrincsTypes.StatefulSignature({
                    q: q, randomizer: randomizer, counter: counter, forsEntries: entries, authPath: new bytes32[](0)
                });
                return (signature, true);
            }
            unchecked {
                ++counter;
            }
        }
    }

    function compactForsCPublicKey(bytes32 skSeed, bytes32 subPkSeed, uint8 q) internal pure returns (bytes32) {
        bytes memory roots = new bytes(uint256(ShrincsTypes.STATEFUL_FORS_K_OPEN) * 32);
        for (uint32 tree = 0; tree < ShrincsTypes.STATEFUL_FORS_K_OPEN;) {
            bytes32 root = compactForsTreeRoot(skSeed, subPkSeed, q, tree);
            setSlice32(roots, root, uint256(tree) * 32);
            unchecked {
                ++tree;
            }
        }
        return keccak256(
            abi.encodePacked(
                "JARDIN/T_k", subPkSeed, jardinAddressWord(ShrincsTypes.AddressTypeForsRoots, q, 0, 0), roots
            )
        );
    }

    function compactForsTreeRoot(bytes32 skSeed, bytes32 subPkSeed, uint8 q, uint32 forsTree)
        internal
        pure
        returns (bytes32)
    {
        return compactForsTreeNode(skSeed, subPkSeed, q, forsTree, ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT, 0);
    }

    function compactForsTreeNode(
        bytes32 skSeed,
        bytes32 subPkSeed,
        uint8 q,
        uint32 forsTree,
        uint32 height,
        uint32 index
    ) internal pure returns (bytes32) {
        if (height == 0) {
            return compactForsLeafHash(skSeed, subPkSeed, q, compactForsTreeLowLeafIndex(forsTree, index));
        }
        bytes32 left = compactForsTreeNode(skSeed, subPkSeed, q, forsTree, height - 1, index << 1);
        bytes32 right = compactForsTreeNode(skSeed, subPkSeed, q, forsTree, height - 1, (index << 1) | 1);
        uint32 nodeHeight = uint32(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) - height + 1;
        uint64 shiftedTree = uint64(forsTree) << (uint32(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) - nodeHeight);
        uint64 parentLowIndex = shiftedTree + uint64(index);
        return compactForsNodeHash(subPkSeed, q, nodeHeight, parentLowIndex, left, right);
    }

    function compactForsTreeRootAndAuthPath(bytes32 skSeed, bytes32 subPkSeed, uint8 q, uint32 forsTree, uint32 leaf)
        internal
        pure
        returns (bytes32 root, bytes[] memory authPath)
    {
        uint32 height = uint32(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
        bytes32[] memory levelNodes = new bytes32[](uint256(1) << height);
        for (uint256 i = 0; i < levelNodes.length;) {
            levelNodes[i] = compactForsLeafHash(skSeed, subPkSeed, q, compactForsTreeLowLeafIndex(forsTree, uint32(i)));
            unchecked {
                ++i;
            }
        }
        uint256 index = leaf;
        authPath = new bytes[](height);
        for (uint32 nodeHeight = 1; nodeHeight <= height;) {
            authPath[nodeHeight - 1] = abi.encodePacked(levelNodes[index ^ 1]);
            bytes32[] memory parents = new bytes32[](levelNodes.length / 2);
            for (uint256 parent = 0; parent < parents.length;) {
                uint64 shiftedTree = uint64(forsTree) << (height - nodeHeight);
                uint64 parentLowIndex = shiftedTree + uint64(parent);
                parents[parent] = compactForsNodeHash(
                    subPkSeed, q, nodeHeight, parentLowIndex, levelNodes[parent * 2], levelNodes[parent * 2 + 1]
                );
                unchecked {
                    ++parent;
                }
            }
            levelNodes = parents;
            index >>= 1;
            unchecked {
                ++nodeHeight;
            }
        }
        root = levelNodes[0];
    }

    function statefulAuthPath(bytes32 skSeed, bytes32 subPkSeed, uint8 q)
        internal
        pure
        returns (bytes32[] memory path)
    {
        path = new bytes32[](ShrincsTypes.STATEFUL_MERKLE_HEIGHT);
        uint32 index = uint32(q);
        for (uint32 j = 0; j < ShrincsTypes.STATEFUL_MERKLE_HEIGHT;) {
            uint32 siblingIndex = (index >> j) ^ 1;
            path[j] = statefulMerkleNode(skSeed, subPkSeed, j, siblingIndex);
            unchecked {
                ++j;
            }
        }
    }

    function compactRandomizer(bytes32 skPrf, bytes32 optRand, uint32 counter, bytes memory mStar)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("JARDIN/PRF_msg/v1", skPrf, optRand, counter, mStar));
    }

    function compactDigest(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        uint8 q,
        bytes32 randomizer,
        uint32 counter,
        bytes memory message
    ) internal pure returns (bytes memory out) {
        uint256 digestBits = uint256(ShrincsTypes.STATEFUL_FORS_K_TOTAL)
            * uint256(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
        uint256 digestBytes = (digestBits + 7) / 8;
        bytes memory mStar = abi.encodePacked("JARDIN/TYPE2/v1", subPkSeed, subPkRoot, q, message);
        bytes memory base = abi.encodePacked("JARDIN/H_msg/v1", randomizer, subPkSeed, subPkRoot, counter, mStar);
        out = new bytes(digestBytes);
        if (digestBytes <= 32) {
            setHashChunk(out, keccak256(base), 0, digestBytes);
            return out;
        }
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            setHashChunk(out, keccak256(abi.encodePacked(base, blockCounter)), offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
    }

    function compactForsLeafSecret(bytes32 skSeed, bytes32 subPkSeed, uint8 q, uint64 treeIndex)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "JARDIN/FORS_PRF",
                skSeed,
                subPkSeed,
                jardinAddressWord(ShrincsTypes.AddressTypeForsPrf, q, 0, treeIndex)
            )
        );
    }

    function compactForsLeafHash(bytes32 skSeed, bytes32 subPkSeed, uint8 q, uint64 treeIndex)
        internal
        pure
        returns (bytes32)
    {
        bytes32 secret = compactForsLeafSecret(skSeed, subPkSeed, q, treeIndex);
        return keccak256(
            abi.encodePacked(
                "JARDIN/F", subPkSeed, jardinAddressWord(ShrincsTypes.AddressTypeForsTree, q, 0, treeIndex), secret
            )
        );
    }

    function compactForsNodeHash(
        bytes32 subPkSeed,
        uint8 q,
        uint32 nodeHeight,
        uint64 treeIndex,
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "JARDIN/H",
                subPkSeed,
                jardinAddressWord(ShrincsTypes.AddressTypeForsTree, q, nodeHeight, treeIndex),
                left,
                right
            )
        );
    }

    function jardinMerkleParentHash(bytes32 subPkSeed, uint32 level, uint32 nodeIndex, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(abi.encodePacked("JARDIN/H", subPkSeed, jardinMerkleAddressWord(level, nodeIndex), left, right));
    }

    function compactForsTreeLowLeafIndex(uint32 forsTree, uint32 leaf) internal pure returns (uint64) {
        return (uint64(forsTree) << ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) | uint64(leaf);
    }

    function jardinAddressWord(uint32 addressType, uint8 q, uint32 x, uint64 y) internal pure returns (bytes32) {
        uint256 value = uint256(addressType) << 128;
        value |= uint256(uint32(q) + 1) << 64;
        value |= uint256(x) << 32;
        value |= uint256(y);
        return bytes32(value);
    }

    function jardinMerkleAddressWord(uint32 level, uint32 nodeIndex) internal pure returns (bytes32) {
        uint256 value = uint256(ShrincsTypes.AddressTypeJardinMerkle) << 128;
        value |= uint256(level) << 32;
        value |= uint256(nodeIndex);
        return bytes32(value);
    }

    function setHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) internal pure {
        for (uint256 i = 0; i < chunk;) {
            out[offset + i] = blockHash[i];
            unchecked {
                ++i;
            }
        }
    }

    function hypertreePublicRoot(bytes32 statelessSkSeed, bytes32 pkSeed) internal pure returns (bytes32) {
        bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds = hypertreeLayerSeeds(statelessSkSeed);
        uint32 topLayer = NUM_HYPERTREE_LAYERS - 1;
        uint32 subtreeHeight = uint32(ShrincsTypes.HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
        return hypertreeVirtualNode(pkSeed, layerSeeds[topLayer], topLayer, 0, subtreeHeight, 0);
    }

    function hypertreeLayerSeeds(bytes32 statelessSkSeed)
        internal
        pure
        returns (bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds)
    {
        for (uint8 layer = 0; layer < NUM_HYPERTREE_LAYERS;) {
            layerSeeds[layer] = keccak256(abi.encodePacked("hypertree-layer-seed", statelessSkSeed, bytes1(layer)));
            unchecked {
                ++layer;
            }
        }
    }

    function hypertreeVirtualNode(
        bytes32 pkSeed,
        bytes32 layerSeed,
        uint32 layer,
        uint64 tree,
        uint32 height,
        uint32 index
    ) internal pure returns (bytes32) {
        if (height == 0) {
            return hypertreeLeaf(pkSeed, layerSeed, layer, tree, index);
        }
        bytes32 left = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, height - 1, index << 1);
        uint32 rightIndex = (index << 1) | 1;
        bytes32 right = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, height - 1, rightIndex);
        bytes32 addressWord = hypertreeAddressWord(layer, tree, height, index);
        return keccak256(abi.encodePacked("hypertree-node", pkSeed, addressWord, left, right));
    }

    function hypertreeLeaf(bytes32 pkSeed, bytes32 layerSeed, uint32 layer, uint64 tree, uint32 leaf)
        internal
        pure
        returns (bytes32)
    {
        bytes32 leafSeed = keccak256(abi.encodePacked("hypertree-leaf-seed", layerSeed, tree, leaf));
        bytes32 skSeed = keccak256(abi.encodePacked("hypertree-wots-sk-seed", leafSeed));
        return statelessWotsCPublicKey(pkSeed, skSeed, layer, tree, leaf);
    }

    function statelessWotsCPublicKey(bytes32 pkSeed, bytes32 skSeed, uint32 layer, uint64 tree, uint32 keypair)
        internal
        pure
        returns (bytes32)
    {
        bytes memory endpoints = new bytes(uint256(ShrincsTypes.NUM_WOTS_CHAINS) * 32);
        for (uint32 chain = 0; chain < ShrincsTypes.NUM_WOTS_CHAINS;) {
            bytes32 secret = statelessWotsCSecret(skSeed, chain);
            bytes32 endpoint =
                statelessWotsCChain(pkSeed, layer, tree, keypair, chain, secret, 0, ShrincsTypes.WOTS_CHAIN_LEN - 1);
            setSlice32(endpoints, endpoint, uint256(chain) * 32);
            unchecked {
                ++chain;
            }
        }
        return keccak256(abi.encodePacked("wots-c-pk", pkSeed, endpoints));
    }

    function statelessWotsCSecret(bytes32 skSeed, uint32 chain) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("wots-c-secret", skSeed, chain));
    }

    function statelessWotsCChain(
        bytes32 pkSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        uint32 chain,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        out = value;
        for (uint32 step = start; step < start + steps;) {
            bytes32 addressWord =
                ShrincsUtils.addressWord32(layer, tree, ShrincsTypes.AddressTypeWotsHash, keypair, chain, step);
            out = keccak256(abi.encodePacked("wots-c-chain", pkSeed, addressWord, out));
            unchecked {
                ++step;
            }
        }
    }

    function hypertreeAddressWord(uint32 layer, uint64 treeIndex, uint32 nodeHeight, uint32 parentIndex)
        internal
        pure
        returns (bytes32)
    {
        bytes32 out;
        assembly {
            out := or(shl(224, layer), shl(128, treeIndex))
            out := or(out, shl(96, 2))
            out := or(out, or(shl(32, nodeHeight), parentIndex))
        }
        return out;
    }

    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32 digit) {
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? uint32(b >> 4) : uint32(b & 0x0f);
    }
}
