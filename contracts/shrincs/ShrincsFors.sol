// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";

// FORS-C portion of the stateless signature: reconstruct each FORS tree root from
// the revealed leaves and authentication paths, then return the message root that
// seeds the first hypertree layer.
library ShrincsFors {
    // Verify the FORS-C portion of the stateless signature and return the message
    // root that seeds the first hypertree layer on success.
    function verifyForsCAndReturnRoot(
        ShrincsType.ParamsView memory params,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.ForsSignature calldata signature,
        uint64 xmssTree,
        uint32 xmssKeypair
    ) internal pure returns (bytes memory) {
        uint256 signedTrees = uint256(params.k) - 1;
        if (signature.randomizer.length != 32 || signature.entries.length != signedTrees) return "";

        ShrincsType.ForsDigest memory digest =
            _forsDigest(params, publicKey, message, signature.randomizer, signature.counter);
        uint256 a = uint256(params.a);
        if (ShrincsCodec.readBits32(digest.digest, signedTrees * a, params.a) != 0) return "";
        if (digest.xmssTree != xmssTree || digest.xmssKeypair != xmssKeypair) return "";

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
            ShrincsType.ForsEntry calldata entry = signature.entries[tree];
            if (entry.sk.length != 32 || entry.auth.length != a) return "";
            uint32 leafIndex = ShrincsCodec.readBits32(digest.digest, tree * a, params.a);
            bytes32 root = _forsEntryRoot32(uint32(a), pkSeed, xmssTree, xmssKeypair, uint32(tree), leafIndex, entry);
            if (root == bytes32(0)) return "";
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
        return computedRoot32 == expectedRoot ? abi.encodePacked(computedRoot32) : bytes("");
    }

    // Reconstruct one FORS tree root from the revealed secret leaf and its
    // authentication path.
    function _forsEntryRoot32(
        uint32 height,
        bytes calldata pkSeed,
        uint64 xmssTree,
        uint32 xmssKeypair,
        uint32 tree,
        uint32 leafIndex,
        ShrincsType.ForsEntry calldata entry
    ) private pure returns (bytes32 node) {
        uint256 addressBase = _forsAddressBase(xmssTree, xmssKeypair);
        node =
            _hashForsLeaf32(pkSeed, bytes32(addressBase | ((uint256(tree) << height) + uint256(leafIndex))), entry.sk);
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
            node = _hashForsNode32(
                pkSeed,
                bytes32(addressBase | (nodeHeight << 32) | ((uint256(tree) << (height - nodeHeight)) + (index >> 1))),
                left,
                right
            );
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    // Build the common high bits of a FORS address from the XMSS tree and keypair
    // coordinates.
    function _forsAddressBase(uint64 xmssTree, uint32 xmssKeypair) private pure returns (uint256) {
        return (uint256(xmssTree) << 128) | (uint256(ShrincsType.FORS_TREE_TYPE) << 96) | (uint256(xmssKeypair) << 64);
    }

    // Hash one FORS secret value into its leaf under the FORS leaf domain.
    function _hashForsLeaf32(bytes calldata pkSeed, bytes32 addressWord, bytes calldata sk)
        private
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

    // Hash two FORS child nodes into their parent under the FORS node domain.
    function _hashForsNode32(bytes calldata pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        private
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

    // Derive the FORS message digest and split out the hypertree coordinates used
    // by the first XMSS layer.
    function _forsDigest(
        ShrincsType.ParamsView memory params,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        bytes calldata randomizer,
        uint32 counter
    ) private pure returns (ShrincsType.ForsDigest memory out) {
        uint32 indexBits = uint32(params.k) * uint32(params.a);
        uint32 subtreeHeight = uint32(params.h / params.d);
        uint32 treeBits = uint32(params.h) - subtreeHeight;
        uint256 digestBytes = (uint256(indexBits) + uint256(params.h) + 7) / 8;
        bytes memory digest = _forsDigestBytes(
            publicKey.messagePkSeed, publicKey.hypertreeRoot, randomizer, counter, message, digestBytes
        );

        uint256 cursor = indexBits;
        out.xmssTree = ShrincsCodec.readBits64(digest, cursor, treeBits);
        cursor += treeBits;
        out.xmssKeypair = ShrincsCodec.readBits32(digest, cursor, subtreeHeight);
        out.digest = digest;
    }

    // Hash the message, randomizer, and public context into the variable-length byte
    // string consumed by FORS digit extraction.
    function _forsDigestBytes(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes calldata randomizer,
        uint32 counter,
        bytes memory message,
        uint256 digestBytes
    ) private pure returns (bytes memory out) {
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
            for { let end := add(src, messageLen) } lt(src, end) {
                src := add(src, 32)
                dst := add(dst, 32)
            } {
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
            ShrincsCodec.writeHashChunk(out, digestWord, offset, chunk);
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
