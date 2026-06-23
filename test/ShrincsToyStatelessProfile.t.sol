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

library ShrincsToyStatelessProfile {
    uint32 internal constant HYPERTREE_HEIGHT = 4;
    uint32 internal constant NUM_HYPERTREE_LAYERS = 2;
    uint32 internal constant SUBTREE_HEIGHT = 2;
    uint32 internal constant FORS_TREE_HEIGHT = 3;
    uint32 internal constant NUM_FORS_TREES = 4;
    uint32 internal constant SIGNED_FORS_TREES = 3;
    uint32 internal constant NUM_WOTS_CHAINS = 8;
    uint32 internal constant WOTS_CHAIN_LEN = 16;
    uint32 internal constant WOTS_TARGET_SUM = 60;
    uint32 internal constant MAX_GRIND_COUNTER = 1 << 16;

    struct PublicKey {
        bytes32 pkSeed;
        bytes32 hypertreeRoot;
    }

    struct SigningKey {
        bytes32 statelessSkSeed;
        bytes32 statelessPrfSeed;
        bytes32 pkSeed;
        bytes32 hypertreeRoot;
    }

    struct ForsEntry {
        bytes32 secretLeaf;
        bytes32[] authPath;
    }

    struct ForsSignature {
        bytes32 randomizer;
        uint32 counter;
        ForsEntry[] entries;
    }

    struct WotsSignature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[] chains;
    }

    struct HypertreeLayerSignature {
        uint64 treeIndex;
        uint32 leafIndex;
        bytes32 wotsPkHash;
        WotsSignature wotsSignature;
        bytes32[] authPath;
    }

    struct StatelessSignature {
        ForsSignature fors;
        HypertreeLayerSignature[] hypertree;
    }

    function keygen(bytes memory seedMaterial) internal pure returns (SigningKey memory signingKey, PublicKey memory publicKey) {
        bytes32 statelessSkSeed = derive32("toy-stateless-sk-seed", seedMaterial, "");
        bytes32 statelessPrfSeed = derive32("toy-stateless-prf-seed", seedMaterial, "");
        bytes32 pkSeed = derive32("toy-pk-seed", seedMaterial, "");
        bytes32 hypertreeRoot = hypertreePublicRoot(statelessSkSeed, pkSeed);

        signingKey = SigningKey({
            statelessSkSeed: statelessSkSeed,
            statelessPrfSeed: statelessPrfSeed,
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
        publicKey = PublicKey({pkSeed: pkSeed, hypertreeRoot: hypertreeRoot});
    }

    function sign(SigningKey memory signingKey, bytes memory message)
        internal
        pure
        returns (StatelessSignature memory signature, bool ok)
    {
        bytes32 forsRoot;
        ForsSignature memory forsSignature;
        uint64 treeIndex;
        uint32 leafIndex;
        (forsRoot, forsSignature, treeIndex, leafIndex, ok) = signFors(signingKey, message);
        if (!ok) return (signature, false);

        HypertreeLayerSignature[] memory layers;
        (layers, ok) = signHypertree(signingKey, forsRoot, treeIndex, leafIndex);
        if (!ok) return (signature, false);

        signature = StatelessSignature({fors: forsSignature, hypertree: layers});
        return (signature, true);
    }

    function verify(PublicKey memory publicKey, bytes memory message, StatelessSignature memory signature)
        internal
        pure
        returns (bool)
    {
        bytes32 forsRoot;
        uint64 treeIndex;
        uint32 leafIndex;
        bool ok;
        (forsRoot, treeIndex, leafIndex, ok) = verifyFors(publicKey, message, signature.fors);
        if (!ok) return false;
        return verifyHypertree(publicKey, forsRoot, treeIndex, leafIndex, signature.hypertree);
    }

    function signFors(SigningKey memory signingKey, bytes memory message)
        internal
        pure
        returns (bytes32 forsRoot, ForsSignature memory signature, uint64 treeIndex, uint32 leafIndex, bool ok)
    {
        bytes32 randomizer = keccak256(abi.encodePacked("toy-fors-randomizer", signingKey.statelessPrfSeed, message));
        for (uint32 counter = 0; counter < MAX_GRIND_COUNTER;) {
            bytes memory digest;
            uint64 digestTreeIndex;
            uint32 digestLeafIndex;
            (digest, digestTreeIndex, digestLeafIndex) =
                forsDigest(signingKey.pkSeed, signingKey.hypertreeRoot, message, randomizer, counter);
            if (readBits32(digest, SIGNED_FORS_TREES * FORS_TREE_HEIGHT, FORS_TREE_HEIGHT) != 0) {
                unchecked {
                    ++counter;
                }
                continue;
            }

            bytes memory roots = new bytes(SIGNED_FORS_TREES * 32);
            ForsEntry[] memory entries = new ForsEntry[](SIGNED_FORS_TREES);
            for (uint32 forsTree = 0; forsTree < SIGNED_FORS_TREES;) {
                uint32 leaf = readBits32(digest, uint256(forsTree) * FORS_TREE_HEIGHT, FORS_TREE_HEIGHT);
                (bytes32 root, bytes32[] memory authPath) =
                    forsTreeRootAndAuthPath(signingKey.pkSeed, signingKey.statelessSkSeed, digestTreeIndex, digestLeafIndex, forsTree, leaf);
                setSlice32(roots, root, uint256(forsTree) * 32);
                entries[forsTree] = ForsEntry({
                    secretLeaf: forsLeafSecret(
                        signingKey.pkSeed, signingKey.statelessSkSeed, digestTreeIndex, digestLeafIndex, forsTree, leaf
                    ),
                    authPath: authPath
                });
                unchecked {
                    ++forsTree;
                }
            }

            signature = ForsSignature({randomizer: randomizer, counter: counter, entries: entries});
            forsRoot = keccak256(abi.encodePacked("toy-fors-pk", signingKey.pkSeed, roots));
            return (forsRoot, signature, digestTreeIndex, digestLeafIndex, true);
        }
        return (forsRoot, signature, 0, 0, false);
    }

    function verifyFors(PublicKey memory publicKey, bytes memory message, ForsSignature memory signature)
        internal
        pure
        returns (bytes32 forsRoot, uint64 treeIndex, uint32 leafIndex, bool ok)
    {
        if (signature.entries.length != SIGNED_FORS_TREES) return (forsRoot, treeIndex, leafIndex, false);
        bytes memory digest;
        (digest, treeIndex, leafIndex) =
            forsDigest(publicKey.pkSeed, publicKey.hypertreeRoot, message, signature.randomizer, signature.counter);
        if (readBits32(digest, SIGNED_FORS_TREES * FORS_TREE_HEIGHT, FORS_TREE_HEIGHT) != 0) {
            return (forsRoot, treeIndex, leafIndex, false);
        }

        bytes memory roots = new bytes(SIGNED_FORS_TREES * 32);
        for (uint32 forsTree = 0; forsTree < SIGNED_FORS_TREES;) {
            uint32 entryLeaf = readBits32(digest, uint256(forsTree) * FORS_TREE_HEIGHT, FORS_TREE_HEIGHT);
            bytes32 root = forsEntryRoot(publicKey.pkSeed, treeIndex, leafIndex, forsTree, entryLeaf, signature.entries[forsTree]);
            setSlice32(roots, root, uint256(forsTree) * 32);
            unchecked {
                ++forsTree;
            }
        }
        forsRoot = keccak256(abi.encodePacked("toy-fors-pk", publicKey.pkSeed, roots));
        return (forsRoot, treeIndex, leafIndex, true);
    }

    function signHypertree(SigningKey memory signingKey, bytes32 forsRoot, uint64 bottomTree, uint32 bottomLeaf)
        internal
        pure
        returns (HypertreeLayerSignature[] memory layers, bool ok)
    {
        bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds = hypertreeLayerSeeds(signingKey.statelessSkSeed);
        layers = new HypertreeLayerSignature[](NUM_HYPERTREE_LAYERS);
        bytes32 current = forsRoot;
        uint64 tree = bottomTree;
        uint32 leaf = bottomLeaf;
        uint64 leafMask = uint64((uint256(1) << SUBTREE_HEIGHT) - 1);

        for (uint32 layer = 0; layer < NUM_HYPERTREE_LAYERS;) {
            bytes32 leafSeed = keccak256(abi.encodePacked("toy-hypertree-leaf-seed", layerSeeds[layer], tree, leaf));
            bytes32 skSeed = keccak256(abi.encodePacked("toy-hypertree-wots-sk-seed", leafSeed));
            bytes32 pkHash = wotsPublicKey(signingKey.pkSeed, skSeed, layer, tree, leaf);
            WotsSignature memory wotsSignature;
            (wotsSignature, ok) =
                signWots(signingKey.pkSeed, skSeed, signingKey.statelessPrfSeed, pkHash, layer, tree, leaf, current);
            if (!ok) return (layers, false);
            bytes32[] memory authPath = hypertreeAuthPath(signingKey.pkSeed, layerSeeds[layer], layer, tree, leaf);
            layers[layer] = HypertreeLayerSignature({
                treeIndex: tree,
                leafIndex: leaf,
                wotsPkHash: pkHash,
                wotsSignature: wotsSignature,
                authPath: authPath
            });
            current = hypertreeVirtualNode(signingKey.pkSeed, layerSeeds[layer], layer, tree, SUBTREE_HEIGHT, 0);
            leaf = uint32(tree & leafMask);
            tree >>= SUBTREE_HEIGHT;
            unchecked {
                ++layer;
            }
        }
        return (layers, true);
    }

    function verifyHypertree(
        PublicKey memory publicKey,
        bytes32 forsRoot,
        uint64 treeIndex,
        uint32 leafIndex,
        HypertreeLayerSignature[] memory layers
    ) internal pure returns (bool) {
        if (layers.length != NUM_HYPERTREE_LAYERS) return false;
        bytes32 current = forsRoot;
        uint64 expectedTreeIndex = treeIndex;
        uint32 expectedLeafIndex = leafIndex;
        uint64 leafMask = uint64((uint256(1) << SUBTREE_HEIGHT) - 1);

        for (uint32 layer = 0; layer < NUM_HYPERTREE_LAYERS;) {
            HypertreeLayerSignature memory layerSig = layers[layer];
            if (layerSig.treeIndex != expectedTreeIndex) return false;
            if (layerSig.leafIndex != expectedLeafIndex) return false;
            if (!verifyWots(publicKey.pkSeed, layer, layerSig.treeIndex, layerSig.leafIndex, layerSig.wotsPkHash, current, layerSig.wotsSignature)) {
                return false;
            }
            bytes32 root = hypertreeRootFromPath(publicKey.pkSeed, layer, layerSig.treeIndex, layerSig.leafIndex, layerSig.wotsPkHash, layerSig.authPath);
            current = root;
            expectedLeafIndex = uint32(expectedTreeIndex & leafMask);
            expectedTreeIndex >>= SUBTREE_HEIGHT;
            unchecked {
                ++layer;
            }
        }
        return current == publicKey.hypertreeRoot;
    }

    function signWots(
        bytes32 pkSeed,
        bytes32 skSeed,
        bytes32 prfSeed,
        bytes32 pkHash,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes32 message
    ) internal pure returns (WotsSignature memory signature, bool ok) {
        bytes32 randomizer = keccak256(abi.encodePacked("toy-wots-randomizer", prfSeed, message));
        for (uint32 counter = 0; counter < MAX_GRIND_COUNTER;) {
            bytes32 fullDigest = keccak256(abi.encodePacked("toy-wots-msg", pkSeed, pkHash, randomizer, counter, message));
            (bytes32[] memory chains, uint32 digitSum) =
                buildSignedWotsChains(pkSeed, skSeed, layer, tree, keypair, fullDigest);
            if (digitSum == WOTS_TARGET_SUM) {
                signature = WotsSignature({randomizer: randomizer, counter: counter, chains: chains});
                return (signature, true);
            }
            unchecked {
                ++counter;
            }
        }
        return (signature, false);
    }

    function buildSignedWotsChains(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes32 digest
    ) internal pure returns (bytes32[] memory chains, uint32 digitSum) {
        chains = new bytes32[](NUM_WOTS_CHAINS);
        for (uint32 chain = 0; chain < NUM_WOTS_CHAINS;) {
            uint32 digit = baseW16Digit(digest, chain);
            digitSum += digit;
            bytes32 secret = wotsSecret(skSeed, chain);
            chains[chain] = wotsChain(pkSeed, layer, tree, keypair, chain, secret, 0, digit);
            unchecked {
                ++chain;
            }
        }
    }

    function verifyWots(
        bytes32 pkSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes32 expectedPkHash,
        bytes32 message,
        WotsSignature memory signature
    ) internal pure returns (bool) {
        if (signature.chains.length != NUM_WOTS_CHAINS) return false;
        bytes32 digest = keccak256(abi.encodePacked("toy-wots-msg", pkSeed, expectedPkHash, signature.randomizer, signature.counter, message));
        bytes memory endpoints = new bytes(NUM_WOTS_CHAINS * 32);
        uint32 digitSum;
        for (uint32 chain = 0; chain < NUM_WOTS_CHAINS;) {
            uint32 digit = baseW16Digit(digest, chain);
            digitSum += digit;
            bytes32 endpoint = wotsChain(pkSeed, layer, tree, keypair, chain, signature.chains[chain], digit, WOTS_CHAIN_LEN - 1 - digit);
            setSlice32(endpoints, endpoint, uint256(chain) * 32);
            unchecked {
                ++chain;
            }
        }
        if (digitSum != WOTS_TARGET_SUM) return false;
        return keccak256(abi.encodePacked("toy-wots-pk", pkSeed, endpoints)) == expectedPkHash;
    }

    function forsDigest(bytes32 pkSeed, bytes32 hypertreeRoot, bytes memory message, bytes32 randomizer, uint32 counter)
        internal
        pure
        returns (bytes memory digest, uint64 treeIndex, uint32 leafIndex)
    {
        uint32 indexBits = NUM_FORS_TREES * FORS_TREE_HEIGHT;
        uint32 treeBits = HYPERTREE_HEIGHT - SUBTREE_HEIGHT;
        uint256 digestBytes = (uint256(indexBits) + uint256(HYPERTREE_HEIGHT) + 7) / 8;
        digest = new bytes(digestBytes);
        bytes32 digestWord = keccak256(abi.encodePacked("toy-fors-digest", pkSeed, hypertreeRoot, randomizer, counter, message));
        setHashChunk(digest, digestWord, 0, digestBytes);
        treeIndex = readBits64(digest, indexBits, treeBits);
        leafIndex = readBits32(digest, indexBits + treeBits, SUBTREE_HEIGHT);
    }

    function forsTreeRootAndAuthPath(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTree,
        uint32 leaf
    ) internal pure returns (bytes32 root, bytes32[] memory authPath) {
        uint32 leafCount = uint32(1) << FORS_TREE_HEIGHT;
        bytes32[] memory levelNodes = new bytes32[](leafCount);
        for (uint32 i = 0; i < leafCount;) {
            levelNodes[i] = forsLeafHash(pkSeed, skSeed, treeIndex, leafIndex, forsTree, i);
            unchecked {
                ++i;
            }
        }
        authPath = new bytes32[](FORS_TREE_HEIGHT);
        uint256 index = leaf;
        for (uint32 level = 0; level < FORS_TREE_HEIGHT;) {
            authPath[level] = levelNodes[index ^ 1];
            bytes32[] memory parents = new bytes32[](levelNodes.length / 2);
            for (uint256 parentIndex = 0; parentIndex < parents.length;) {
                uint64 shiftedTree = uint64(forsTree) << (FORS_TREE_HEIGHT - level - 1);
                uint64 parentLowIndex = shiftedTree + uint64(parentIndex);
                bytes32 addressWord = forsAddressWord(treeIndex, leafIndex, level + 1, parentLowIndex);
                parents[parentIndex] = keccak256(
                    abi.encodePacked(
                        "toy-fors-node",
                        pkSeed,
                        addressWord,
                        levelNodes[parentIndex * 2],
                        levelNodes[parentIndex * 2 + 1]
                    )
                );
                unchecked {
                    ++parentIndex;
                }
            }
            levelNodes = parents;
            index >>= 1;
            unchecked {
                ++level;
            }
        }
        root = levelNodes[0];
    }

    function forsEntryRoot(
        bytes32 pkSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTree,
        uint32 entryLeaf,
        ForsEntry memory entry
    ) internal pure returns (bytes32 node) {
        bytes32 addressWord = forsAddressWord(
            treeIndex, leafIndex, 0, (uint64(forsTree) << FORS_TREE_HEIGHT) + uint64(entryLeaf)
        );
        node = keccak256(abi.encodePacked("toy-fors-leaf", pkSeed, addressWord, entry.secretLeaf));
        uint256 index = entryLeaf;
        for (uint32 level = 0; level < FORS_TREE_HEIGHT;) {
            bytes32 sibling = entry.authPath[level];
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            uint64 shiftedTree = uint64(forsTree) << (FORS_TREE_HEIGHT - level - 1);
            uint64 parentLowIndex = shiftedTree + uint64(index >> 1);
            bytes32 parentWord = forsAddressWord(treeIndex, leafIndex, level + 1, parentLowIndex);
            node = keccak256(abi.encodePacked("toy-fors-node", pkSeed, parentWord, left, right));
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    function hypertreePublicRoot(bytes32 statelessSkSeed, bytes32 pkSeed) internal pure returns (bytes32) {
        bytes32[2] memory layerSeeds = hypertreeLayerSeeds(statelessSkSeed);
        return hypertreeVirtualNode(pkSeed, layerSeeds[1], 1, 0, SUBTREE_HEIGHT, 0);
    }

    function hypertreeLayerSeeds(bytes32 statelessSkSeed)
        internal
        pure
        returns (bytes32[2] memory layerSeeds)
    {
        for (uint32 layer = 0; layer < NUM_HYPERTREE_LAYERS;) {
            layerSeeds[layer] =
                keccak256(abi.encodePacked("toy-hypertree-layer-seed", statelessSkSeed, bytes1(uint8(layer))));
            unchecked {
                ++layer;
            }
        }
    }

    function hypertreeVirtualNode(bytes32 pkSeed, bytes32 layerSeed, uint32 layer, uint64 tree, uint32 height, uint32 index)
        internal
        pure
        returns (bytes32)
    {
        if (height == 0) {
            return hypertreeLeaf(pkSeed, layerSeed, layer, tree, index);
        }
        bytes32 left = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, height - 1, index << 1);
        bytes32 right = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, height - 1, (index << 1) | 1);
        return keccak256(abi.encodePacked("toy-hypertree-node", pkSeed, hypertreeAddressWord(layer, tree, height, index), left, right));
    }

    function hypertreeLeaf(bytes32 pkSeed, bytes32 layerSeed, uint32 layer, uint64 tree, uint32 leaf)
        internal
        pure
        returns (bytes32)
    {
        bytes32 leafSeed = keccak256(abi.encodePacked("toy-hypertree-leaf-seed", layerSeed, tree, leaf));
        bytes32 skSeed = keccak256(abi.encodePacked("toy-hypertree-wots-sk-seed", leafSeed));
        return wotsPublicKey(pkSeed, skSeed, layer, tree, leaf);
    }

    function hypertreeAuthPath(bytes32 pkSeed, bytes32 layerSeed, uint32 layer, uint64 tree, uint32 leaf)
        internal
        pure
        returns (bytes32[] memory path)
    {
        path = new bytes32[](SUBTREE_HEIGHT);
        for (uint32 level = 0; level < SUBTREE_HEIGHT;) {
            uint32 sibling = (leaf >> level) ^ 1;
            path[level] = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, level, sibling);
            unchecked {
                ++level;
            }
        }
    }

    function hypertreeRootFromPath(
        bytes32 pkSeed,
        uint32 layer,
        uint64 tree,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] memory authPath
    ) internal pure returns (bytes32 node) {
        node = leaf;
        uint256 index = leafIndex;
        for (uint32 height = 1; height <= SUBTREE_HEIGHT;) {
            bytes32 sibling = authPath[height - 1];
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            node = keccak256(
                abi.encodePacked("toy-hypertree-node", pkSeed, hypertreeAddressWord(layer, tree, height, uint32(index >> 1)), left, right)
            );
            index >>= 1;
            unchecked {
                ++height;
            }
        }
    }

    function wotsPublicKey(bytes32 pkSeed, bytes32 skSeed, uint32 layer, uint64 tree, uint32 keypair)
        internal
        pure
        returns (bytes32)
    {
        bytes memory endpoints = new bytes(NUM_WOTS_CHAINS * 32);
        for (uint32 chain = 0; chain < NUM_WOTS_CHAINS;) {
            bytes32 secret = wotsSecret(skSeed, chain);
            bytes32 endpoint = wotsChain(pkSeed, layer, tree, keypair, chain, secret, 0, WOTS_CHAIN_LEN - 1);
            setSlice32(endpoints, endpoint, uint256(chain) * 32);
            unchecked {
                ++chain;
            }
        }
        return keccak256(abi.encodePacked("toy-wots-pk", pkSeed, endpoints));
    }

    function wotsSecret(bytes32 skSeed, uint32 chain) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("toy-wots-secret", skSeed, chain));
    }

    function wotsChain(bytes32 pkSeed, uint32 layer, uint64 tree, uint32 keypair, uint32 chain, bytes32 value, uint32 start, uint32 steps)
        internal
        pure
        returns (bytes32 out)
    {
        out = value;
        for (uint32 step = start; step < start + steps;) {
            out = keccak256(abi.encodePacked("toy-wots-chain", pkSeed, wotsAddressWord(layer, tree, keypair, chain, step), out));
            unchecked {
                ++step;
            }
        }
    }

    function forsLeafSecret(bytes32 pkSeed, bytes32 skSeed, uint64 treeIndex, uint32 leafIndex, uint32 forsTree, uint32 leaf)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "toy-fors-sk",
                skSeed,
                pkSeed,
                forsAddressWord(treeIndex, leafIndex, 0, (uint64(forsTree) << FORS_TREE_HEIGHT) + uint64(leaf))
            )
        );
    }

    function forsLeafHash(bytes32 pkSeed, bytes32 skSeed, uint64 treeIndex, uint32 leafIndex, uint32 forsTree, uint32 leaf)
        internal
        pure
        returns (bytes32)
    {
        bytes32 secret = forsLeafSecret(pkSeed, skSeed, treeIndex, leafIndex, forsTree, leaf);
        bytes32 addressWord =
            forsAddressWord(treeIndex, leafIndex, 0, (uint64(forsTree) << FORS_TREE_HEIGHT) + uint64(leaf));
        return keccak256(abi.encodePacked("toy-fors-leaf", pkSeed, addressWord, secret));
    }

    function derive32(bytes memory domain, bytes memory seed, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, seed, data));
    }

    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32) {
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? uint32(b >> 4) : uint32(b & 0x0f);
    }

    function setHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) internal pure {
        for (uint256 i = 0; i < chunk;) {
            out[offset + i] = blockHash[i];
            unchecked {
                ++i;
            }
        }
    }

    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    function readBits32(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint32) {
        return uint32(readBits64(input, startBit, bitLen));
    }

    function readBits64(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint64 out) {
        for (uint256 bit = 0; bit < bitLen;) {
            uint256 absolute = startBit + bit;
            uint8 byteValue = uint8(input[absolute >> 3]);
            uint256 bitInByte = 7 - (absolute & 7);
            out = (out << 1) | uint64((byteValue >> bitInByte) & 1);
            unchecked {
                ++bit;
            }
        }
    }

    function forsAddressWord(uint64 treeIndex, uint32 leafIndex, uint32 nodeHeight, uint64 lowIndex)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            out := shl(128, treeIndex)
            out := or(out, shl(96, 3))
            out := or(out, shl(64, leafIndex))
            out := or(out, or(shl(32, nodeHeight), lowIndex))
        }
    }

    function hypertreeAddressWord(uint32 layer, uint64 treeIndex, uint32 nodeHeight, uint32 parentIndex)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            out := or(shl(224, layer), shl(128, treeIndex))
            out := or(out, shl(96, 2))
            out := or(out, or(shl(32, nodeHeight), parentIndex))
        }
    }

    function wotsAddressWord(uint32 layer, uint64 tree, uint32 keypair, uint32 chain, uint32 step)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            out := or(shl(224, layer), shl(128, tree))
            out := or(out, shl(64, keypair))
            out := or(out, shl(32, chain))
            out := or(out, step)
        }
    }
}

contract ShrincsToyStatelessHarness {
    function keygen(bytes memory seedMaterial)
        external
        pure
        returns (ShrincsToyStatelessProfile.SigningKey memory, ShrincsToyStatelessProfile.PublicKey memory)
    {
        return ShrincsToyStatelessProfile.keygen(seedMaterial);
    }

    function sign(ShrincsToyStatelessProfile.SigningKey memory signingKey, bytes memory message)
        external
        pure
        returns (ShrincsToyStatelessProfile.StatelessSignature memory, bool)
    {
        return ShrincsToyStatelessProfile.sign(signingKey, message);
    }

    function verify(
        ShrincsToyStatelessProfile.PublicKey memory publicKey,
        bytes memory message,
        ShrincsToyStatelessProfile.StatelessSignature memory signature
    ) external pure returns (bool) {
        return ShrincsToyStatelessProfile.verify(publicKey, message, signature);
    }
}

contract ShrincsToyStatelessProfileTest is Test {
    ShrincsToyStatelessHarness internal harness;

    function setUp() public {
        harness = new ShrincsToyStatelessHarness();
    }

    function testToyProfileStatelessSignAndVerify() public view {
        (
            ShrincsToyStatelessProfile.SigningKey memory signingKey,
            ShrincsToyStatelessProfile.PublicKey memory publicKey
        ) = harness.keygen(bytes("toy stateless seed"));

        bytes memory message = abi.encodePacked(keccak256("toy stateless message"));
        (ShrincsToyStatelessProfile.StatelessSignature memory signature, bool ok) = harness.sign(signingKey, message);

        assertTrue(ok, "toy stateless signing must succeed");
        assertEq(
            signature.fors.entries.length,
            ShrincsToyStatelessProfile.SIGNED_FORS_TREES,
            "toy FORS-C must omit the final tree"
        );
        assertEq(
            signature.hypertree.length,
            ShrincsToyStatelessProfile.NUM_HYPERTREE_LAYERS,
            "toy hypertree must include all layers"
        );
        assertTrue(harness.verify(publicKey, message, signature), "toy stateless signature must verify");
    }

    function testToyProfileStatelessSignIsDeterministic() public view {
        (ShrincsToyStatelessProfile.SigningKey memory signingKey,) = harness.keygen(bytes("toy deterministic seed"));

        bytes memory message = abi.encodePacked(keccak256("toy deterministic message"));
        (ShrincsToyStatelessProfile.StatelessSignature memory signatureA, bool okA) = harness.sign(signingKey, message);
        (ShrincsToyStatelessProfile.StatelessSignature memory signatureB, bool okB) = harness.sign(signingKey, message);

        assertTrue(okA && okB, "toy stateless signing must succeed");
        assertEq(keccak256(abi.encode(signatureA)), keccak256(abi.encode(signatureB)), "toy stateless signature must be deterministic");
    }
}
