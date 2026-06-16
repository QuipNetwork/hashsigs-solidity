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

library ShrincsForsC {
    // verifyForsCAndReturnRoot: Verify the FORS-C portion of a stateless SHRINCS signature.
    // 1. Check the compact FORS-C signature shape and randomizer length.
    // 2. Recompute the FORS digest bits and expected hypertree coordinates.
    // 3. Enforce the FORS-C convention that the omitted final tree selects leaf 0.
    // 4. Rebuild each signed FORS tree root from its revealed leaf and auth path.
    // 5. Hash those per-tree roots together into the reconstructed FORS root.
    // 6. Return the FORS root for hypertree verification together with a success flag.
    function verifyForsCAndReturnRoot(
        ShrincsTypes.ParamsView memory params,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.ForsSignature calldata signature,
        uint64 treeIndex,
        uint32 leafIndex
    ) internal pure returns (bytes32 forsRoot, bool ok) {
        // FORS-C omits the final FORS tree by forcing its digest-selected leaf index to zero.
        // Verification therefore expects only k - 1 revealed entries and rejects any digest
        // whose omitted final tree would require a nonzero leaf.
        uint256 signedTrees = uint256(params.numForsTrees) - 1;
        // The randomizer is always one hash output wide.
        if (signature.randomizer.length != 32) return (bytes32(0), false);
        // FORS-C reveals only the signedTrees entries, never the omitted final tree.
        if (signature.entries.length != signedTrees) return (bytes32(0), false);

        // Recompute the FORS digest and the hypertree coordinates that the signer committed to.
        ShrincsTypes.ForsDigest memory digest =
            forsDigest(params, publicKey, message, signature.randomizer, signature.counter);
        uint256 a = uint256(params.forsTreeHeight);
        // The omitted final FORS tree must always select leaf 0 in the compressed FORS-C layout.
        if (ShrincsUtils.readBits32(digest.digest, signedTrees * a, params.forsTreeHeight) != 0) {
            return (bytes32(0), false);
        }
        // The stateless signature must verify for the caller-supplied hypertree coordinates.
        if (digest.treeIndex != treeIndex) return (bytes32(0), false);
        if (digest.leafIndex != leafIndex) return (bytes32(0), false);

        bytes calldata pkSeed = publicKey.pkSeed;
        // "fors-pk" || pkSeed || root_0 || ... || root_{k-2}
        uint256 forsPkInputLen = 39 + signedTrees * 32;
        uint256 forsPkInput;
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            forsPkInput := mload(0x40)
            // Write the domain tag prefix at the start of the buffer.
            mstore(forsPkInput, "fors-pk")
            // Copy the 32-byte public seed immediately after the 7-byte tag.
            calldatacopy(add(forsPkInput, 7), pkSeed.offset, 32)
            // Bump the free-memory pointer to the next 32-byte aligned slot after this buffer.
            mstore(0x40, add(forsPkInput, and(add(forsPkInputLen, 31), not(31))))
        }

        for (uint256 tree = 0; tree < signedTrees;) {
            // Read one revealed FORS entry for this tree.
            ShrincsTypes.ForsEntry calldata entry = signature.entries[tree];
            // Every revealed secret leaf is a single 32-byte hash input.
            if (entry.secretLeaf.length != 32) return (bytes32(0), false);
            // Every revealed auth path must have exactly one node per FORS tree level.
            if (entry.authPath.length != a) return (bytes32(0), false);
            // Read the digest-selected leaf for this FORS tree.
            uint32 entryLeafIndex = ShrincsUtils.readBits32(digest.digest, tree * a, params.forsTreeHeight);
            // casting to 'uint32' is safe because the supported FORS tree height is 14 bits
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 treeHeight = uint32(a);
            // casting to 'uint32' is safe because tree ranges over signedTrees, which is 21 in the supported profile
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 forsTreeIndex = uint32(tree);
            // Rebuild this FORS tree root from the revealed leaf and authentication path.
            bytes32 root =
                forsEntryRoot32(treeHeight, pkSeed, treeIndex, leafIndex, forsTreeIndex, entryLeafIndex, entry);
            if (root == bytes32(0)) return (bytes32(0), false);
            // Append each reconstructed root into the final FORS public-key hash input.
            assembly {
                // Write this 32-byte root at slot `tree` after the fixed tag-and-seed prefix.
                mstore(add(add(forsPkInput, 39), mul(tree, 32)), root)
            }
            unchecked {
                ++tree;
            }
        }

        assembly {
            // Hash the per-tree roots into the reconstructed FORS public value.
            forsRoot := keccak256(forsPkInput, forsPkInputLen)
        }
        return (forsRoot, true);
    }

    // forsEntryRoot32: Rebuild one FORS tree root from a revealed secret leaf and auth path.
    // 1. Construct the shared address prefix for this hypertree tree/leaf location.
    // 2. Hash the revealed secret leaf into its public FORS leaf value.
    // 3. Walk upward through the authentication path one level at a time.
    // 4. Rebuild each parent node with the correct left/right ordering and address.
    // 5. Return the reconstructed root for this FORS tree.
    function forsEntryRoot32(
        uint32 height,
        bytes calldata pkSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTreeIndex,
        uint32 entryLeafIndex,
        ShrincsTypes.ForsEntry calldata entry
    ) internal pure returns (bytes32 node) {
        // Build the shared address prefix used by all nodes in this FORS tree location.
        uint256 addressBase = forsAddressBase(treeIndex, leafIndex);
        // Shift this FORS tree into the low-index range reserved for its leaves.
        uint256 shiftedForsTree = uint256(forsTreeIndex) << height;
        // Select the concrete low leaf index inside this FORS tree.
        uint256 leafLowIndex = shiftedForsTree + uint256(entryLeafIndex);
        // Finish the address for the revealed leaf.
        uint256 leafAddressValue = addressBase | leafLowIndex;
        // Hash the revealed secret leaf into the corresponding public FORS leaf value.
        node = hashForsLeaf32(pkSeed, bytes32(leafAddressValue), entry.secretLeaf);
        // Track the current node position as we walk upward through the auth path.
        uint256 index = entryLeafIndex;
        for (uint256 level = 0; level < height;) {
            // Read the sibling node supplied for this level.
            bytes calldata authNode = entry.authPath[level];
            if (authNode.length != 32) return bytes32(0);
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
            // Shift this FORS tree into the low-index range reserved for this parent level.
            uint256 shiftedTree = uint256(forsTreeIndex) << (height - nodeHeight);
            // Collapse the current leaf/node index to its parent index.
            uint256 parentIndex = index >> 1;
            uint256 parentLowIndex = shiftedTree + parentIndex;
            // Start from the shared address prefix and then fill in height and low index.
            uint256 addressValue = addressBase;
            addressValue |= shiftedNodeHeight;
            addressValue |= parentLowIndex;
            bytes32 addressWord = bytes32(addressValue);
            // Hash the two children into their parent node using the parent address.
            node = hashForsNode32(pkSeed, addressWord, left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    // forsAddressBase: Construct the shared address prefix for one FORS tree/leaf location.
    // 1. Encode the hypertree tree index in the high address bits.
    // 2. Encode the FORS address type so hashes stay domain-separated.
    // 3. Encode the hypertree leaf index that owns this FORS instance.
    // 4. Return the shared prefix used by all leaves and nodes in that FORS tree.
    function forsAddressBase(uint64 treeIndex, uint32 leafIndex) internal pure returns (uint256) {
        // Place the hypertree subtree index in the high address region.
        uint256 shiftedTreeIndex = uint256(treeIndex) << 128;
        // Mark this address as belonging to the FORS tree domain.
        uint256 shiftedAddressType = uint256(ShrincsTypes.AddressTypeForsTree) << 96;
        // Bind the FORS instance to the bottom-layer hypertree leaf.
        uint256 shiftedLeafIndex = uint256(leafIndex) << 64;
        uint256 addressBase = shiftedTreeIndex;
        addressBase |= shiftedAddressType;
        addressBase |= shiftedLeafIndex;
        return addressBase;
    }

    // hashForsLeaf32: Hash one revealed FORS secret leaf into its public leaf value.
    // 1. Domain-separate this hash as a FORS leaf computation.
    // 2. Bind the public seed and leaf address.
    // 3. Mix in the revealed secret leaf bytes.
    // 4. Return the public FORS leaf value.
    function hashForsLeaf32(bytes calldata pkSeed, bytes32 addressWord, bytes calldata sk)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for FORS leaf hashing.
            mstore(ptr, "fors-leaf")
            // Copy the 32-byte public seed after the 9-byte tag.
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            // Write the 32-byte address word after the seed.
            mstore(add(ptr, 41), addressWord)
            // Copy the 32-byte secret leaf after the address.
            calldatacopy(add(ptr, 73), sk.offset, 32)
            // Hash the complete FORS leaf preimage.
            out := keccak256(ptr, 105)
            // Bump the free-memory pointer to the next 32-byte aligned slot.
            mstore(0x40, add(ptr, 128))
        }
    }

    // hashForsNode32: Hash one internal FORS node from its left and right children.
    // 1. Domain-separate this hash as an internal FORS node computation.
    // 2. Bind the public seed and parent-node address.
    // 3. Mix in the left and right child values in canonical order.
    // 4. Return the parent node value.
    function hashForsNode32(bytes calldata pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for FORS internal-node hashing.
            mstore(ptr, "fors-node")
            // Copy the 32-byte public seed after the 9-byte tag.
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            // Write the 32-byte parent-node address after the seed.
            mstore(add(ptr, 41), addressWord)
            // Write the left child after the address.
            mstore(add(ptr, 73), left)
            // Write the right child after the left child.
            mstore(add(ptr, 105), right)
            // Hash the complete FORS internal-node preimage.
            out := keccak256(ptr, 137)
            // Bump the free-memory pointer to the next 32-byte aligned slot.
            mstore(0x40, add(ptr, 160))
        }
    }

    // forsDigest: Derive the FORS digest bits and selected hypertree coordinates.
    // 1. Compute how many bits are needed for FORS choices and hypertree coordinates.
    // 2. Expand the digest stream from the message, public key, randomizer, and counter.
    // 3. Read the hypertree tree index from the digest stream.
    // 4. Read the hypertree leaf index from the remaining digest bits.
    // 5. Return both coordinates together with the digest bytes used for FORS leaf selection.
    function forsDigest(
        ShrincsTypes.ParamsView memory params,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        bytes calldata randomizer,
        uint32 counter
    ) internal pure returns (ShrincsTypes.ForsDigest memory out) {
        // Reserve bits for all signed FORS tree leaf choices.
        uint32 indexBits = uint32(params.numForsTrees) * uint32(params.forsTreeHeight);
        // Each hypertree layer shares this many leaf-index bits.
        uint32 subtreeHeight = uint32(params.hypertreeHeight / params.numHypertreeLayers);
        // The remaining hypertree bits identify the subtree itself.
        uint32 treeBits = uint32(params.hypertreeHeight) - subtreeHeight;
        // Expand enough bytes to cover FORS choices plus hypertree coordinates.
        uint256 digestBytes = (uint256(indexBits) + uint256(params.hypertreeHeight) + 7) / 8;
        // Derive the digest stream from the public seed/root, signature randomizer, counter, and message.
        bytes memory digest =
            forsDigestBytes(publicKey.pkSeed, publicKey.hypertreeRoot, randomizer, counter, message, digestBytes);

        // Start reading coordinates immediately after the FORS choice bits.
        uint256 cursor = indexBits;
        // Read the hypertree tree index immediately after the FORS choice bits.
        out.treeIndex = ShrincsUtils.readBits64(digest, cursor, treeBits);
        cursor += treeBits;
        // Read the bottom-layer leaf index from the remaining subtree-height bits.
        out.leafIndex = ShrincsUtils.readBits32(digest, cursor, subtreeHeight);
        out.digest = digest;
    }

    // forsDigestBytes: Expand the digest stream used by FORS-C and the hypertree.
    // 1. Domain-separate the digest input as a FORS digest computation.
    // 2. Bind the public seed, public root, randomizer, and grind counter.
    // 3. Mix in the signed message bytes.
    // 4. Produce either one digest block or as many blocks as needed.
    // 5. Return exactly the requested number of digest bytes.
    function forsDigestBytes(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes calldata randomizer,
        uint32 counter,
        bytes memory message,
        uint256 digestBytes
    ) internal pure returns (bytes memory out) {
        // Allocate output plus one spare block so partial chunk writes stay simple.
        out = new bytes(digestBytes + 32);
        uint256 messageLen = message.length;
        // "fors-digest" || pkSeed || hypertreeRoot || randomizer || counter || message
        uint256 baseLen = 111 + messageLen;
        uint256 ptr;
        assembly {
            // Set the visible bytes length of the output buffer.
            mstore(out, digestBytes)
            // Allocate a scratch buffer starting at the free-memory pointer.
            ptr := mload(0x40)
            // Write the digest domain tag prefix.
            mstore(ptr, "fors-digest")
            // Copy the 32-byte public seed after the 11-byte tag.
            calldatacopy(add(ptr, 11), pkSeed.offset, 32)
            // Copy the 32-byte hypertree root after the seed.
            calldatacopy(add(ptr, 43), hypertreeRoot.offset, 32)
            // Copy the 32-byte per-signature randomizer after the root.
            calldatacopy(add(ptr, 75), randomizer.offset, 32)
            // Write the 4-byte grind counter after the randomizer.
            mstore(add(ptr, 107), shl(224, counter))
            let src := add(message, 32)
            let dst := add(ptr, 111)
            let end := add(src, messageLen)
            // Copy the variable-length message body into the digest preimage.
            for {} lt(src, end) {} {
                // Copy one 32-byte chunk of the message into the scratch buffer.
                mstore(dst, mload(src))
                // Advance to the next source chunk.
                src := add(src, 32)
                // Advance to the next destination chunk.
                dst := add(dst, 32)
            }
        }
        if (digestBytes <= 32) {
            bytes32 digestWord;
            assembly {
                // One digest block is enough for the whole FORS and hypertree coordinate stream.
                digestWord := keccak256(ptr, baseLen)
                // Store that single digest block into the output bytes payload.
                mstore(add(out, 32), digestWord)
                // Bump the free-memory pointer past the scratch buffer.
                mstore(0x40, add(ptr, and(add(baseLen, 31), not(31))))
            }
            return out;
        }
        // Add a 4-byte block counter suffix for multi-block expansion.
        uint256 totalLen = baseLen + 4;
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            bytes32 digestWord;
            // Emit only as many bytes as remain needed from this block.
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            assembly {
                // Append a block counter when more than one digest block is needed.
                mstore(add(ptr, baseLen), shl(224, blockCounter))
                // Hash the base preimage plus the 4-byte block counter suffix.
                digestWord := keccak256(ptr, totalLen)
            }
            // Copy only as many bytes as are still required from this digest block.
            ShrincsUtils.setHashChunk(out, digestWord, offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
        assembly {
            // Bump the free-memory pointer past the scratch buffer with counter suffix space.
            mstore(0x40, add(ptr, and(add(totalLen, 31), not(31))))
        }
    }
}
