// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessTypes } from './ShrincsStatelessTypes.sol';

abstract contract ShrincsStatelessMerkle is ShrincsStatelessTypes {
    function merkleRootFromPath(
        uint16 nBytes,
        uint32 height,
        uint32 leafIndex,
        bytes memory leaf,
        bytes[] calldata authPath,
        bytes calldata pkSeed,
        uint8 treeMode,
        uint32 layer,
        uint64 addressTree,
        uint32 keypair,
        uint64 treeIndex
    ) internal pure returns (bytes memory) {
        bytes memory node = leaf;
        uint32 index = leafIndex;
        for (uint32 level = 0; level < height; ) {
            if (authPath[level].length != nBytes) return '';
            bytes memory left;
            bytes memory right;
            if (index & 1 == 0) {
                // even index means current node is left child
                left = node;
                right = authPath[level];
            } else {
                left = authPath[level];
                right = node;
            }
            if (treeMode == MODE_FORS_C) {
                node = domainKeccakBytes(
                    'fors-node',
                    pkSeed,
                    abi.encodePacked(
                        forsAddress(FORS_TREE_TYPE, addressTree, keypair, level + 1, forsTreeIndex(uint32(treeIndex), height, level + 1, index >> 1)), //returns (layer, tree, addressType, keypair, height, index);
                        left,
                        right
                    ),
                    nBytes
                );
            } else {
                // FIPS TREE address: (layer, tree, TREE_TYPE, padding=0, tree height, tree index).
                node = domainKeccakBytes(
                    'hypertree-node',
                    pkSeed,
                    abi.encodePacked(hashTreeAddress(layer, treeIndex, level + 1, index >> 1), left, right), //return addressWord32(layer, tree, TREE_TYPE, 0, height, index);
                    nBytes
                );
            }
            index >>= 1; // divide index by 2 to move up one level
            unchecked {
                ++level;
            }
        }
        return node;
    }

    function hypertreeRootFromPath(
        ParamsView memory params,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes memory leaf,
        bytes[] calldata authPath
    ) internal pure returns (bytes memory) {
        // calculate the expected root of this XMSS subtree from the provided leaf and authentication path
        // `addressTree` and `keypair` are FORS-only fields in `merkleRootFromPath`; hypertree mode uses `layer` and `treeIndex`.
        return merkleRootFromPath(params.nBytes, uint32(params.h / params.d), leafIndex, leaf, authPath, pkSeed, 0, layer, treeIndex, 0, treeIndex);
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
        uint256 addressBase = (uint256(layer) << 224) | (uint256(treeIndex) << 128) | (uint256(TREE_TYPE) << 96);
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
            node = hashHypertreeNode32(pkSeedWord, bytes32(addressBase | (nodeHeight << 32) | (index >> 1)), left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
        ok = true;
    }

    function hashHypertreeNode32(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right) internal pure returns (bytes32 out) {
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
