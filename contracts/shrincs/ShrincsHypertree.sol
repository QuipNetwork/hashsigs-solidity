// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsWotsC} from "./ShrincsWotsC.sol";

// Hypertree verification: walk each XMSS layer in sequence, carrying the
// reconstructed root from one layer into the next until the public hypertree root
// is reached. Each layer's leaf commitment is checked via stateless WOTS-C.
library ShrincsHypertree {
    // Verify each hypertree XMSS layer in sequence, carrying the reconstructed root
    // from one layer into the next until the public hypertree root is reached.
    function verifyHypertree(
        ShrincsType.ParamsView memory params,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory messageRoot,
        ShrincsType.HypertreeLayerSignature[] calldata layers
    ) internal pure returns (bool) {
        if (layers.length != params.d) return false;
        uint32 subtreeHeight = uint32(params.h / params.d);
        uint32 leafCount = uint32(1) << subtreeHeight;

        bytes32 current;
        assembly {
            current := mload(add(messageRoot, 32))
        }

        for (uint256 layer = 0; layer < layers.length;) {
            ShrincsType.HypertreeLayerSignature calldata layerSig = layers[layer];
            if (layerSig.leafIndex >= leafCount || layerSig.wotsCPkHash.length != params.nBytes) return false;
            if (layerSig.authPath.length != subtreeHeight) return false;
            if (!ShrincsWotsC.verifyWotsC32(
                    params,
                    publicKey.hypertreePkSeed,
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
                leaf := calldataload(wotsPkHash.offset)
            }

            (bytes32 nextRoot, bool ok) = _rootFromPath32(
                subtreeHeight,
                publicKey.hypertreePkSeed,
                uint32(layer),
                layerSig.treeIndex,
                layerSig.leafIndex,
                leaf,
                layerSig.authPath
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

    // Rebuild one hypertree XMSS root from a leaf and its authentication path using
    // compact Keccak-based node hashing.
    function _rootFromPath32(
        uint32 height,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes32 leaf,
        bytes[] calldata authPath
    ) private pure returns (bytes32 node, bool ok) {
        if (authPath.length != height) return (bytes32(0), false);
        bytes32 pkSeedWord;
        assembly {
            pkSeedWord := calldataload(pkSeed.offset)
        }
        uint256 addressBase =
            (uint256(layer) << 224) | (uint256(treeIndex) << 128) | (uint256(ShrincsType.TREE_TYPE) << 96);
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
            node =
                _hashHypertreeNode32(pkSeedWord, bytes32(addressBase | (nodeHeight << 32) | (index >> 1)), left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
        ok = true;
    }

    // Hash two hypertree child nodes into their parent under the hypertree node
    // domain separator.
    function _hashHypertreeNode32(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        private
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
