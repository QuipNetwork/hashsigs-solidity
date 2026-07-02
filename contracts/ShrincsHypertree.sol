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
import {ShrincsUtils} from "./ShrincsUtils.sol";

library ShrincsHypertree {
    // verifyHypertree: Verify every SHRINCS hypertree layer from the FORS root to the public root.
    // 1. Check that the signature provides exactly one layer signature per hypertree layer.
    // 2. Initialize the expected subtree coordinates from the bottom FORS digest output.
    // 3. Verify each layer's WOTS-C signature against the running message/root value.
    // 4. Rebuild the XMSS-style subtree root from the revealed auth path.
    // 5. Derive the next layer's expected coordinates from the current tree index.
    // 6. Accept only if the final reconstructed root matches the installed hypertree root.
    function verifyHypertree(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 forsRoot,
        ShrincsTypes.HypertreeLayerSignature[] calldata layers
    ) internal pure returns (bool) {
        // Every hypertree layer must be present exactly once.
        if (layers.length != ShrincsTypes.NUM_HYPERTREE_LAYERS) return false;
        // The hypertree cannot be empty.
        if (layers.length == 0) return false;
        // Each subtree has height h / d in the supported balanced hypertree layout.
        uint32 subtreeHeight = uint32(ShrincsTypes.HYPERTREE_HEIGHT / ShrincsTypes.NUM_HYPERTREE_LAYERS);
        // Bound the leaf index range accepted inside each subtree.
        uint32 leafCount = uint32(1) << subtreeHeight;
        // Mask off one subtree-height slice of tree-index bits at a time.
        uint64 leafMask = uint64((uint256(1) << subtreeHeight) - 1);
        // Layer 0 must start from the coordinates chosen by the FORS digest.
        uint64 expectedTreeIndex = layers[0].treeIndex;
        uint32 expectedLeafIndex = layers[0].leafIndex;
        // Carry the FORS root upward as the running message/root value.
        bytes32 current = forsRoot;

        for (uint256 layer = 0; layer < layers.length;) {
            ShrincsTypes.HypertreeLayerSignature calldata layerSig = layers[layer];
            // Layer 0 starts from the FORS-derived coordinate. Each upper layer's
            // coordinate is then derived from the lower layer's tree index, so the
            // signature cannot freely choose independent upper-layer addresses.
            // Enforce the expected subtree coordinate for this layer.
            if (layerSig.treeIndex != expectedTreeIndex) return false;
            if (layerSig.leafIndex != expectedLeafIndex) return false;
            // Reject leaf indices that fall outside the subtree width.
            if (layerSig.leafIndex >= leafCount) return false;
            // The compressed WOTS-C public-key hash is always one hash output.
            if (layerSig.wotsCPkHash.length != ShrincsTypes.HASH_LEN) return false;
            // Every subtree auth path must contain one node per subtree level.
            if (layerSig.authPath.length != subtreeHeight) return false;
            // Verify the WOTS-C layer signature against the current carried value.
            if (!verifyWotsC32(
                    publicKey.pkSeed,
                    // casting to 'uint32' is safe because layer is bounded by the fixed 8-layer hypertree
                    // forge-lint: disable-next-line(unsafe-typecast)
                    uint32(layer),
                    layerSig.treeIndex,
                    layerSig.leafIndex,
                    layerSig.wotsCPkHash,
                    current,
                    layerSig.wotsCSignature
                )) return false;

            bytes calldata wotsPkHash = layerSig.wotsCPkHash;
            bytes32 leaf;
            assembly {
                // Load the 32-byte WOTS-C public-key hash that becomes the subtree leaf value.
                leaf := calldataload(wotsPkHash.offset)
            }

            // casting to 'uint32' is safe because layer is bounded by the fixed 8-layer hypertree
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 layerIndex = uint32(layer);
            // Rebuild the subtree root above this WOTS-C leaf.
            (bytes32 nextRoot, bool ok) = hypertreeRootFromPath32(
                subtreeHeight,
                publicKey.pkSeed,
                layerIndex,
                layerSig.treeIndex,
                layerSig.leafIndex,
                leaf,
                layerSig.authPath
            );
            if (!ok) return false;
            // Carry the reconstructed subtree root into the next layer.
            current = nextRoot;

            // casting to 'uint32' is safe because leafMask keeps only subtreeHeight bits,
            // and leafCount above bounds each fixed subtree to 256 leaves
            // forge-lint: disable-next-line(unsafe-typecast)
            // The next layer's leaf index comes from the low subtree-height bits of the current tree index.
            expectedLeafIndex = uint32(expectedTreeIndex & leafMask);
            // Shift away this layer's subtree bits to get the next layer's tree index.
            expectedTreeIndex >>= subtreeHeight;
            unchecked {
                ++layer;
            }
        }

        bytes calldata expectedRootBytes = publicKey.hypertreeRoot;
        bytes32 expectedRoot;
        assembly {
            // Load the installed 32-byte hypertree root from calldata.
            expectedRoot := calldataload(expectedRootBytes.offset)
        }
        // All tree-index bits must be consumed exactly by the time the top layer is reached.
        if (expectedTreeIndex != 0) return false;
        return current == expectedRoot;
    }

    // verifyWotsC32: Verify one compressed stateless WOTS-C signature inside a hypertree layer.
    // 1. Check the compact WOTS-C signature shape and digest width assumptions.
    // 2. Load the public seed, expected public-key hash, and signature randomizer.
    // 3. Recompute the WOTS-C message digest that selects one base-w digit per chain.
    // 4. Advance each revealed chain value to its endpoint to reconstruct the compressed public key.
    // 5. Enforce the fixed WOTS-C digit-sum constraint used instead of an explicit checksum suffix.
    // 6. Hash the reconstructed segments and compare them to the expected public-key hash.
    function verifyWotsC32(
        bytes calldata pkSeedBytes,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes calldata expectedPkHashBytes,
        bytes32 message,
        ShrincsTypes.WotsCSignature calldata signature
    ) internal pure returns (bool) {
        uint256 chainCount = uint256(ShrincsTypes.NUM_WOTS_CHAINS);
        // The WOTS-C randomizer is always one hash output wide.
        if (signature.randomizer.length != 32) return false;
        // One revealed chain value is required per WOTS-C chain.
        if (signature.chains.length != chainCount) return false;
        // The compressed WOTS-C public-key hash is always one hash output.
        if (expectedPkHashBytes.length != 32) return false;
        // This implementation supports only 32-byte WOTS digest expansion.
        if (wotsDigestBytes() != 32) return false;

        bytes calldata randomizerBytes = signature.randomizer;
        bytes32 pkSeed;
        bytes32 expectedPkHash;
        bytes32 randomizer;
        assembly {
            // Load the 32-byte public seed from calldata.
            pkSeed := calldataload(pkSeedBytes.offset)
            // Load the expected compressed WOTS-C public-key hash from calldata.
            expectedPkHash := calldataload(expectedPkHashBytes.offset)
            // Load the 32-byte per-signature randomizer from calldata.
            randomizer := calldataload(randomizerBytes.offset)
        }

        // Recompute the digest whose base-w digits determine chain stopping points.
        bytes32 digest = wotsDigest32(pkSeed, expectedPkHash, randomizer, signature.counter, message);
        // "wots-c-pk" || pkSeed || segment_0 || ... || segment_{len-1}
        uint256 pkInputLen = 41 + chainCount * 32;
        uint256 pkInput;
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            pkInput := mload(0x40)
            // Write the domain tag prefix for compressed WOTS-C public-key hashing.
            mstore(pkInput, "wots-c-pk")
            // Write the public seed immediately after the 9-byte tag.
            mstore(add(pkInput, 9), pkSeed)
            // Bump the free-memory pointer to the next 32-byte aligned slot after this buffer.
            mstore(0x40, add(pkInput, and(add(pkInputLen, 31), not(31))))
        }

        // Encode the layer, tree, and keypair location shared by all chains in this WOTS key.
        uint256 shiftedLayer = uint256(layer) << 224;
        uint256 shiftedTree = uint256(tree) << 128;
        uint256 shiftedKeypair = uint256(keypair) << 64;
        uint256 addressBase = shiftedLayer;
        addressBase |= shiftedTree;
        addressBase |= shiftedKeypair;
        uint32 digitSum;
        for (uint256 i = 0; i < chainCount;) {
            // Read the revealed starting value for this chain.
            bytes calldata chain = signature.chains[i];
            if (chain.length != 32) return false;
            // Read the digest-selected base-w digit for this chain.
            uint32 digit = baseW16Digit32(digest, i);
            // Accumulate the fixed WOTS-C target-sum check.
            digitSum += digit;
            // casting to 'uint32' is safe because i ranges over the fixed 64 WOTS chains
            // forge-lint: disable-next-line(unsafe-typecast)
            // Complete the chain from the revealed value to its endpoint.
            bytes32 segment =
                wotsChain32NoMaskBase(ShrincsTypes.WOTS_CHAIN_LEN, pkSeed, addressBase, uint32(i), chain, digit);
            assembly {
                // Write this reconstructed chain endpoint after the fixed tag-and-seed prefix.
                mstore(add(add(pkInput, 41), mul(i, 32)), segment)
            }
            unchecked {
                ++i;
            }
        }
        // WOTS-C does not carry an explicit checksum chain suffix. Instead the message expansion
        // is accepted only when the reconstructed base-w digits add up to the fixed target sum.
        if (digitSum != ShrincsTypes.WOTS_TARGET_SUM_STATEFUL) return false;

        bytes32 computedPkHash;
        assembly {
            // Hash the reconstructed chain endpoints into the compressed WOTS-C public-key hash.
            computedPkHash := keccak256(pkInput, pkInputLen)
        }
        return computedPkHash == expectedPkHash;
    }

    // wotsDigest32: Derive the WOTS-C message digest that determines chain positions.
    // 1. Domain-separate the digest input as a WOTS-C message computation.
    // 2. Bind the public seed, expected public-key hash, and signature randomizer.
    // 3. Bind the grind counter and signed message value.
    // 4. Return the single 32-byte digest block used for base-w digit extraction.
    function wotsDigest32(bytes32 pkSeed, bytes32 expectedPkHash, bytes32 randomizer, uint32 counter, bytes32 message)
        internal
        pure
        returns (bytes32 out)

    {
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the digest domain tag prefix.
            mstore(ptr, "wots-c-msg")
            // Write the 32-byte public seed after the 10-byte tag.
            mstore(add(ptr, 10), pkSeed)
            // Write the expected compressed public-key hash after the seed.
            mstore(add(ptr, 42), expectedPkHash)
            // Write the 32-byte randomizer after the expected public-key hash.
            mstore(add(ptr, 74), randomizer)
            // Write the 4-byte grind counter after the randomizer.
            mstore(add(ptr, 106), shl(224, counter))
            // Write the 32-byte message after the counter.
            mstore(add(ptr, 110), message)
            // Hash the full WOTS-C message preimage.
            out := keccak256(ptr, 142)
            // Bump the free-memory pointer to the next 32-byte aligned slot.
            mstore(0x40, add(ptr, 160))
        }
    }
    // baseW16Digit32: Read one base-16 digit from a fixed 32-byte WOTS digest.
    function baseW16Digit32(bytes32 digest, uint256 index) internal pure returns (uint32) {
        uint256 shift = 252 - ((index & 63) << 2);
        return uint32((uint256(digest) >> shift) & 0x0f);
    }
    // wotsChain32NoMaskBase: Advance one stateless WOTS-C chain from the revealed value to its endpoint.
    // 1. Load the revealed chain value from calldata.
    // 2. Compute how many steps remain until the end of the chain.
    // 3. Rebuild the per-step chain address from the shared key location and chain index.
    // 4. Apply one unmasked chain hash per remaining step.
    // 5. Return the reconstructed endpoint for this chain.
    function wotsChain32NoMaskBase(
        uint16 w,
        bytes32 pkSeed,
        uint256 addressBase,
        uint32 chainIdx,
        bytes calldata value,
        uint32 digit
    ) internal pure returns (bytes32 out) {
        assembly {
            // Load the revealed 32-byte chain value directly from calldata.
            out := calldataload(value.offset)
        }
        // The chain must continue from the revealed digit position up to w - 1.
        uint256 steps = uint256(w - 1) - digit;
        for (uint256 j = 0; j < steps;) {
            // Encode which chain inside the WOTS key this step belongs to.
            uint256 shiftedChain = uint256(chainIdx) << 32;
            // Encode the current position within that chain.
            uint256 chainStep = uint256(digit) + j;
            uint256 addressValue = addressBase;
            addressValue |= shiftedChain;
            addressValue |= chainStep;
            // Hash one step forward using the chain-specific address.
            out = hashStatelessWotsCChainNoMask32(pkSeed, bytes32(addressValue), out);
            unchecked {
                ++j;
            }
        }
    }

    // hashStatelessWotsCChainNoMask32: Execute one unmasked stateless WOTS-C chain-hash step.
    // 1. Domain-separate the hash as a WOTS-C chain computation.
    // 2. Bind the public seed and chain-step address.
    // 3. Mix in the current chain segment value.
    // 4. Return the next chain value.
    function hashStatelessWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for WOTS-C chain hashing.
            mstore(ptr, "wots-c-chain")
            // Write the 32-byte public seed after the 12-byte tag.
            mstore(add(ptr, 12), pkSeed)
            // Write the 32-byte address word after the seed.
            mstore(add(ptr, 44), addressWord)
            // Write the current chain segment after the address.
            mstore(add(ptr, 76), segment)
            // Hash the complete WOTS-C chain-step preimage.
            out := keccak256(ptr, 108)
        }
    }

    // wotsDigestBytes: Return the number of bytes needed to encode all WOTS-C digits.
    // 1. Choose the number of bits per base-w digit from the chain length.
    // 2. Multiply by the number of WOTS chains.
    // 3. Round up to a whole number of bytes.
    function wotsDigestBytes() internal pure returns (uint256) {
        uint256 bitsPerDigit = ShrincsTypes.WOTS_CHAIN_LEN == 256 ? 8 : 4;
        return (uint256(ShrincsTypes.NUM_WOTS_CHAINS) * bitsPerDigit + 7) / 8;
    }

    // hypertreeRootFromPath32: Rebuild one XMSS-style subtree root from a leaf value and auth path.
    // 1. Check that the auth path has exactly one node per subtree level.
    // 2. Construct the shared tree-hash address prefix for this layer and tree.
    // 3. Walk upward from the supplied leaf one level at a time.
    // 4. Rebuild each parent node with the correct left/right ordering and address.
    // 5. Return the reconstructed subtree root and success flag.
    function hypertreeRootFromPath32(
        uint32 height,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes32 leaf,
        bytes[] calldata authPath
    ) internal pure returns (bytes32 node, bool ok) {
        // Every subtree auth path must contain one node per subtree level.
        if (authPath.length != height) return (bytes32(0), false);
        bytes32 pkSeedWord;
        assembly {
            // Load the 32-byte public seed from calldata once for repeated subtree hashing.
            pkSeedWord := calldataload(pkSeed.offset)
        }
        // Encode the hypertree layer in the shared address prefix.
        uint256 shiftedLayer = uint256(layer) << 224;
        // Encode the hypertree tree index in the shared address prefix.
        uint256 shiftedTree = uint256(treeIndex) << 128;
        // Mark these addresses as belonging to the tree-hash domain.
        uint256 shiftedAddressType = uint256(ShrincsTypes.AddressTypeTree) << 96;
        uint256 addressBase = shiftedLayer;
        addressBase |= shiftedTree;
        addressBase |= shiftedAddressType;
        // Start the upward walk from the supplied leaf value.
        node = leaf;
        uint256 index = leafIndex;
        for (uint256 level = 0; level < height;) {
            // Read the sibling node supplied for this subtree level.
            bytes calldata authNode = authPath[level];
            if (authNode.length != 32) return (bytes32(0), false);
            bytes32 sibling;
            assembly {
                // Load the 32-byte sibling node directly from calldata.
                sibling := calldataload(authNode.offset)
            }
            // Place the current node and sibling in canonical left/right order for this level.
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            // Parent nodes live one level higher than their children.
            uint256 nodeHeight = level + 1;
            uint256 shiftedNodeHeight = nodeHeight << 32;
            // Collapse the current leaf/node index to its parent index.
            uint256 parentIndex = index >> 1;
            // Start from the shared address prefix and then fill in height and parent index.
            uint256 addressValue = addressBase;
            addressValue |= shiftedNodeHeight;
            addressValue |= parentIndex;
            bytes32 addressWord = bytes32(addressValue);
            // Hash the two children into their parent node using the parent address.
            node = hashHypertreeNode32(pkSeedWord, addressWord, left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
        ok = true;
    }

    // hashHypertreeNode32: Hash one internal hypertree node at a specific layer/tree location.
    // 1. Domain-separate the hash as a hypertree internal-node computation.
    // 2. Bind the public seed and parent-node address.
    // 3. Mix in the left and right child node values in canonical order.
    // 4. Return the parent node value.
    function hashHypertreeNode32(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for hypertree internal-node hashing.
            mstore(ptr, "hypertree-node")
            // Write the 32-byte public seed after the 14-byte tag.
            mstore(add(ptr, 14), pkSeed)
            // Write the 32-byte address word after the seed.
            mstore(add(ptr, 46), addressWord)
            // Write the left child after the address.
            mstore(add(ptr, 78), left)
            // Write the right child after the left child.
            mstore(add(ptr, 110), right)
            // Hash the complete hypertree internal-node preimage.
            out := keccak256(ptr, 142)
        }
    }
}
