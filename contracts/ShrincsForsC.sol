// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import { ShrincsTypes } from "./ShrincsTypes.sol";
import { ShrincsUtils } from "./ShrincsUtils.sol";

library ShrincsForsC {
    function verifyForsCAndReturnRoot(
        ShrincsTypes.ParamsView memory params,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.ForsSignature calldata signature,
        uint64 xmssTree,
        uint32 xmssKeypair
    ) internal pure returns (bytes32 messageRoot, bool ok) {
        uint256 signedTrees = uint256(params.k) - 1;
        if (signature.randomizer.length != 32 || signature.entries.length != signedTrees) return (bytes32(0), false);

        ShrincsTypes.ForsDigest memory digest =
            forsDigest(params, publicKey, message, signature.randomizer, signature.counter);
        uint256 a = uint256(params.a);
        if (ShrincsUtils.readBits32Fast(digest.digest, signedTrees * a, params.a) != 0) return (bytes32(0), false);
        if (digest.xmssTree != xmssTree || digest.xmssKeypair != xmssKeypair) return (bytes32(0), false);

        bytes calldata pkSeed = publicKey.messagePkSeed;
        uint256 forsPkInputLen = 39 + signedTrees * 32;
        uint256 forsPkInput;
        assembly {
            forsPkInput := mload(0x40)
            mstore(forsPkInput, "fors-pk")
            calldatacopy(add(forsPkInput, 7), pkSeed.offset, 32)
            mstore(0x40, add(forsPkInput, and(add(forsPkInputLen, 31), not(31))))
        }

        for (uint256 tree = 0; tree < signedTrees;) {
            ShrincsTypes.ForsEntry calldata entry = signature.entries[tree];
            if (entry.sk.length != 32 || entry.auth.length != a) return (bytes32(0), false);
            uint32 leafIndex = ShrincsUtils.readBits32Fast(digest.digest, tree * a, params.a);
            bytes32 root = forsEntryRoot32(uint32(a), pkSeed, xmssTree, xmssKeypair, uint32(tree), leafIndex, entry);
            if (root == bytes32(0)) return (bytes32(0), false);
            assembly {
                mstore(add(add(forsPkInput, 39), mul(tree, 32)), root)
            }
            unchecked {
                ++tree;
            }
        }

        bytes32 computedRoot32;
        assembly {
            computedRoot32 := keccak256(forsPkInput, forsPkInputLen)
        }
        bytes calldata expectedRootBytes = publicKey.messageRoot;
        bytes32 expectedRoot;
        assembly {
            expectedRoot := calldataload(expectedRootBytes.offset)
        }
        return computedRoot32 == expectedRoot ? (computedRoot32, true) : (bytes32(0), false);
    }

    function forsEntryRoot32(
        uint32 height,
        bytes calldata pkSeed,
        uint64 xmssTree,
        uint32 xmssKeypair,
        uint32 tree,
        uint32 leafIndex,
        ShrincsTypes.ForsEntry calldata entry
    ) internal pure returns (bytes32 node) {
        uint256 addressBase = forsAddressBase(xmssTree, xmssKeypair);
        node = hashForsLeaf32(pkSeed, bytes32(addressBase | ((uint256(tree) << height) + uint256(leafIndex))), entry.sk);
        uint256 index = leafIndex;
        for (uint256 level = 0; level < height;) {
            bytes calldata authNode = entry.auth[level];
            if (authNode.length != 32) return bytes32(0);
            bytes32 sibling;
            assembly {
                sibling := calldataload(authNode.offset)
            }
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            uint256 nodeHeight = level + 1;
            uint256 shiftedNodeHeight = nodeHeight << 32;
            uint256 shiftedTree = uint256(tree) << (height - nodeHeight);
            uint256 parentIndex = index >> 1;
            bytes32 addressWord = bytes32(addressBase | shiftedNodeHeight | (shiftedTree + parentIndex));
            node = hashForsNode32(
                pkSeed,
                addressWord,
                left,
                right
            );
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    function forsAddressBase(uint64 xmssTree, uint32 xmssKeypair) internal pure returns (uint256) {
        return (uint256(xmssTree) << 128) | (uint256(ShrincsTypes.FORS_TREE_TYPE) << 96) | (uint256(xmssKeypair) << 64);
    }

    function hashForsLeaf32(bytes calldata pkSeed, bytes32 addressWord, bytes calldata sk)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "fors-leaf")
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            mstore(add(ptr, 41), addressWord)
            calldatacopy(add(ptr, 73), sk.offset, 32)
            out := keccak256(ptr, 105)
            mstore(0x40, add(ptr, 128))
        }
    }

    function hashForsNode32(bytes calldata pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "fors-node")
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            mstore(add(ptr, 41), addressWord)
            mstore(add(ptr, 73), left)
            mstore(add(ptr, 105), right)
            out := keccak256(ptr, 137)
            mstore(0x40, add(ptr, 160))
        }
    }

    function forsDigest(
        ShrincsTypes.ParamsView memory params,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        bytes calldata randomizer,
        uint32 counter
    ) internal pure returns (ShrincsTypes.ForsDigest memory out) {
        uint32 indexBits = uint32(params.k) * uint32(params.a);
        uint32 subtreeHeight = uint32(params.h / params.d);
        uint32 treeBits = uint32(params.h) - subtreeHeight;
        uint256 digestBytes = (uint256(indexBits) + uint256(params.h) + 7) / 8;
        bytes memory digest = forsDigestBytes(publicKey.messagePkSeed, publicKey.hypertreeRoot, randomizer, counter, message, digestBytes);

        uint256 cursor = indexBits;
        out.xmssTree = ShrincsUtils.readBits64Fast(digest, cursor, treeBits);
        cursor += treeBits;
        out.xmssKeypair = ShrincsUtils.readBits32Fast(digest, cursor, subtreeHeight);
        out.digest = digest;
    }

    function forsDigestBytes(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes calldata randomizer,
        uint32 counter,
        bytes memory message,
        uint256 digestBytes
    ) internal pure returns (bytes memory out) {
        out = new bytes(digestBytes);
        uint256 messageLen = message.length;
        uint256 baseLen = 111 + messageLen;
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(ptr, "fors-digest")
            calldatacopy(add(ptr, 11), pkSeed.offset, 32)
            calldatacopy(add(ptr, 43), hypertreeRoot.offset, 32)
            calldatacopy(add(ptr, 75), randomizer.offset, 32)
            mstore(add(ptr, 107), shl(224, counter))
            let src := add(message, 32)
            let dst := add(ptr, 111)
            for { let end := add(src, messageLen) } lt(src, end) { src := add(src, 32) dst := add(dst, 32) } {
                mstore(dst, mload(src))
            }
        }
        if (digestBytes <= 32) {
            bytes32 digestWord;
            assembly {
                digestWord := keccak256(ptr, baseLen)
                mstore(add(out, 32), digestWord)
                mstore(0x40, add(ptr, and(add(baseLen, 31), not(31))))
            }
            return out;
        }
        uint256 totalLen = baseLen + 4;
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            bytes32 digestWord;
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            assembly {
                mstore(add(ptr, baseLen), shl(224, blockCounter))
                digestWord := keccak256(ptr, totalLen)
            }
            ShrincsUtils.setHashChunk(out, digestWord, offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
        assembly {
            mstore(0x40, add(ptr, and(add(totalLen, 31), not(31))))
        }
    }
}
