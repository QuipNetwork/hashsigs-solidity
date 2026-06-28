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

library ShrincsStateful {
    // verifyStatefulUncheckedMessage: Verify a JARDIN compact-path stateful signature against an exact caller-supplied message.
    // 1. Check that the public key uses the compiled fixed layout.
    // 2. Check the installed public-key commitment and the public-key encoding.
    // 3. Decode the compact stateful public key embedded inside the SHRINCS public bundle.
    // 4. Validate the explicit compact-path slot q and the FORS+C signature shape.
    // 5. Reconstruct the compact FORS+C public key from the opened body and message.
    // 6. Rebuild the balanced h=7 JARDIN compact-path root from q and the Merkle auth path.
    // 7. Accept only if the reconstructed root matches the decoded stateful public root.
    function verifyStatefulUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed composite public-key fields before touching stateful internals.
        if (!ShrincsUtils.validPublicKey(publicKey)) return false;
        // Ensure the caller supplied the currently installed SHRINCS public-key commitment.
        if (!ShrincsUtils.matchesExpectedPublicKeyCommitment(publicKey, expectedPublicKeyCommitment)) return false;

        // Decode the packed stateful subkey: subPkSeed || subPkRoot || maxSignatures.
        (ShrincsTypes.StatefulPublicKey memory statefulKey, bool ok) =
            ShrincsUtils.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        // The signature carries the consumed compact-path slot explicitly as q.
        uint32 q = uint32(signature.q);
        // The embedded usage budget must be nonzero and cannot exceed the committed Q_MAX tree size.
        if (statefulKey.maxSignatures == 0 || statefulKey.maxSignatures > ShrincsTypes.STATEFUL_Q_MAX) return false;
        // Reject signatures for slots outside this key's allowed usage budget.
        if (q >= statefulKey.maxSignatures) return false;
        // Compact path opens k_open FORS trees and omits the final constrained tree.
        if (signature.forsEntries.length != ShrincsTypes.STATEFUL_FORS_K_OPEN) return false;
        // The compact-path Merkle proof is over the balanced Q_MAX tree, so it has fixed height h.
        if (signature.authPath.length != ShrincsTypes.STATEFUL_MERKLE_HEIGHT) return false;

        // Reconstruct the FORS+C public key committed as the selected balanced-tree leaf.
        (bytes32 forsPk, bool validFors) =
            verifyCompactForsCAndReturnPk(statefulKey.pkSeed, statefulKey.root, signature.q, message, signature);
        if (!validFors) return false;

        // Climb from the reconstructed FORS+C public key to the candidate compact-path root.
        (bytes32 root, bool validPath) =
            rootFromJardinMerklePath(statefulKey.pkSeed, signature.q, forsPk, signature.authPath);
        if (!validPath) return false;
        // Accept only the root committed in the decoded stateful public key.
        return root == statefulKey.root;
    }

    // verifyCompactForsCAndReturnPk: Reconstruct the compact FORS+C public key.
    // 1. Derive the 260-bit digest from `M*` and the signature randomizer/counter.
    // 2. Enforce the compact-path opening rule: the hidden k_total-k_open tree must select leaf 0.
    // 3. Recompute each opened FORS tree root from its secret leaf and auth path.
    // 4. Hash the ordered opened roots with the JARDIN FORS-roots address to obtain `forsPk`.
    function verifyCompactForsCAndReturnPk(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        uint8 q,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bytes32 forsPk, bool ok) {
        bytes memory digest = compactDigest(subPkSeed, subPkRoot, q, signature.randomizer, signature.counter, message);
        // `a` is the per-FORS-tree leaf-index bit width.
        uint256 a = uint256(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
        // `kOpen` is the number of explicit FORS openings carried in the signature.
        uint256 kOpen = uint256(ShrincsTypes.STATEFUL_FORS_K_OPEN);
        // The final digest slice corresponds to the omitted tree; compact path fixes it to leaf 0.
        if (ShrincsUtils.readBits32(digest, kOpen * a, ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) != 0) {
            return (bytes32(0), false);
        }

        // Store the opened roots contiguously so `T_k` hashes exactly the JARDIN roots byte string.
        uint256 rootsLen = kOpen * 32;
        bytes memory roots = new bytes(rootsLen);
        for (uint256 tree = 0; tree < kOpen;) {
            // Each `a`-bit digest slice selects the opened leaf for this FORS tree.
            uint32 entryLeafIndex = ShrincsUtils.readBits32(digest, tree * a, ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
            // Reconstruct the root that this FORS opening commits to.
            bytes32 root = compactForsEntryRoot(subPkSeed, q, uint32(tree), entryLeafIndex, signature.forsEntries[tree]);
            if (root == bytes32(0)) return (bytes32(0), false);
            // Append the root in tree order before computing the aggregate FORS+C public key.
            setSlice32(roots, root, tree * 32);
            unchecked {
                ++tree;
            }
        }
        return (
            keccak256(
                abi.encodePacked(
                    "JARDIN/T_k", subPkSeed, jardinAddressWord(ShrincsTypes.AddressTypeForsRoots, q, 0, 0), roots
                )
            ),
            true
        );
    }

    // compactForsEntryRoot: Rebuild one opened FORS tree root.
    // 1. Validate the opened secret leaf and its a-level authentication path.
    // 2. Hash the secret leaf into the selected FORS leaf address.
    // 3. Walk upward, ordering each sibling by the current low bit.
    // 4. Return the root for this FORS tree.
    function compactForsEntryRoot(
        bytes32 subPkSeed,
        uint8 q,
        uint32 forsTree,
        uint32 leaf,
        ShrincsTypes.ForsEntry calldata entry
    ) internal pure returns (bytes32 node) {
        if (entry.secretLeaf.length != 32) return bytes32(0);
        if (entry.authPath.length != ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) return bytes32(0);

        // Leaf hash `F` binds the revealed secret to the FORS tree and leaf address.
        node = keccak256(
            abi.encodePacked(
                "JARDIN/F",
                subPkSeed,
                jardinAddressWord(ShrincsTypes.AddressTypeForsTree, q, 0, compactForsTreeLowLeafIndex(forsTree, leaf)),
                entry.secretLeaf
            )
        );

        // `index` tracks the node's position within the current level while climbing to the root.
        uint256 index = leaf;
        // `height` is `a`, the fixed compact FORS tree height.
        uint32 height = uint32(ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT);
        for (uint32 level = 0; level < height;) {
            // Every auth node is one 32-byte sibling hash.
            bytes calldata authNode = entry.authPath[level];
            if (authNode.length != 32) return bytes32(0);
            bytes32 sibling;
            assembly {
                sibling := calldataload(authNode.offset)
            }
            // Even indices are left children; odd indices are right children.
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            // JARDIN stores parent height as one-based FORS height in the address `x` field.
            uint32 nodeHeight = level + 1;
            // Fold the FORS tree number and parent position into the low-leaf-index address field.
            uint64 shiftedTree = uint64(forsTree) << (height - nodeHeight);
            uint64 parentLowIndex = shiftedTree + uint64(index >> 1);
            // Parent hash `H` binds the ordered children to the parent address.
            node = keccak256(
                abi.encodePacked(
                    "JARDIN/H",
                    subPkSeed,
                    jardinAddressWord(ShrincsTypes.AddressTypeForsTree, q, nodeHeight, parentLowIndex),
                    left,
                    right
                )
            );
            // Move to the parent index for the next level.
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    // rootFromJardinMerklePath: Climb the balanced Q_MAX-slot compact-path tree.
    // 1. Start from the FORS+C public key for slot q.
    // 2. At each level, order the sibling by the corresponding q bit.
    // 3. Hash with the JARDIN Merkle address for that parent.
    // 4. Return the reconstructed `subPkRoot`.
    function rootFromJardinMerklePath(bytes32 subPkSeed, uint8 q, bytes32 leaf, bytes32[] calldata authPath)
        internal
        pure
        returns (bytes32 node, bool ok)
    {
        if (authPath.length != ShrincsTypes.STATEFUL_MERKLE_HEIGHT) return (bytes32(0), false);
        // The first node is the opened slot commitment, i.e. the FORS+C public key.
        node = leaf;
        // Keep q as a word so bit tests and shifts are explicit.
        uint32 qValue = uint32(q);
        for (uint32 j = 0; j < ShrincsTypes.STATEFUL_MERKLE_HEIGHT;) {
            // Auth paths are stored bottom-up; JARDIN address levels count top-down here.
            uint32 level = uint32(ShrincsTypes.STATEFUL_MERKLE_HEIGHT) - 1 - j;
            // Parent index is q with the consumed child bits removed.
            uint32 parentIndex = qValue >> (j + 1);
            // The j-th q bit selects whether the current node is left or right.
            (bytes32 left, bytes32 right) = ((qValue >> j) & 1) == 0 ? (node, authPath[j]) : (authPath[j], node);
            // Hash the ordered pair at the exact balanced-tree parent address.
            node = keccak256(
                abi.encodePacked("JARDIN/H", subPkSeed, jardinMerkleAddressWord(level, parentIndex), left, right)
            );
            unchecked {
                ++j;
            }
        }
        ok = true;
    }

    // compactDigest: Build the JARDIN compact FORS+C digest.
    // 1. Compute k_total*a bits; with current params this is 52*5 = 260 bits.
    // 2. Build `M* = tag || subPkSeed || subPkRoot || q || message`.
    // 3. Domain-separate H_msg with the signature randomizer and grind counter.
    // 4. Expand Keccak blocks until enough digest bytes are available.
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
        // Round up to whole bytes because the 260-bit digest occupies 33 bytes.
        uint256 digestBytes = (digestBits + 7) / 8;
        // `M*` binds the message to this compact subkey and the exact slot q.
        bytes memory mStar = abi.encodePacked("JARDIN/TYPE2/v1", subPkSeed, subPkRoot, q, message);
        // The H_msg base includes both anti-replay key material and the grind counter.
        bytes memory base = abi.encodePacked("JARDIN/H_msg/v1", randomizer, subPkSeed, subPkRoot, counter, mStar);
        // Allocate the exact digest byte length that bit extraction will read from.
        out = new bytes(digestBytes);
        if (digestBytes <= 32) {
            // One Keccak word is enough for parameter sets up to 256 digest bits.
            setHashChunk(out, keccak256(base), 0, digestBytes);
            return out;
        }

        // For 260 bits, append counter-suffixed Keccak words and truncate the final chunk.
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            // Copy a full word except for the final partial chunk.
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            setHashChunk(out, keccak256(abi.encodePacked(base, blockCounter)), offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
    }

    // compactForsTreeLowLeafIndex: Pack a FORS tree id and leaf id into JARDIN's low-index field.
    function compactForsTreeLowLeafIndex(uint32 forsTree, uint32 leaf) internal pure returns (uint64) {
        return (uint64(forsTree) << ShrincsTypes.STATEFUL_FORS_TREE_HEIGHT) | uint64(leaf);
    }

    // jardinAddressWord: Pack the JARDIN FORS+C address word.
    // 1. Put the address type in the high type field.
    // 2. Encode JARDIN ci as q+1 because q is zero-indexed in the signature.
    // 3. Store x and y in the low address fields used for node height and low index.
    function jardinAddressWord(uint32 addressType, uint8 q, uint32 x, uint64 y) internal pure returns (bytes32) {
        // Place the JARDIN address type in the address word.
        uint256 value = uint256(addressType) << 128;
        // JARDIN ci is one-indexed, so the zero-indexed signature slot q becomes q + 1.
        value |= uint256(uint32(q) + 1) << 64;
        // Pack the x field, used here for FORS node height.
        value |= uint256(x) << 32;
        // Pack the y field, used here for the FORS low leaf/node index.
        value |= uint256(y);
        return bytes32(value);
    }

    // jardinMerkleAddressWord: Pack the balanced compact-path Merkle address word.
    // 1. Use the dedicated JARDIN Merkle address type.
    // 2. Store the current Merkle level.
    // 3. Store the parent node index at that level.
    function jardinMerkleAddressWord(uint32 level, uint32 nodeIndex) internal pure returns (bytes32) {
        // Place the dedicated balanced-Merkle address type in the address word.
        uint256 value = uint256(ShrincsTypes.AddressTypeJardinMerkle) << 128;
        // Pack the Merkle level into the x-style low address field.
        value |= uint256(level) << 32;
        // Pack the parent node index at that level.
        value |= uint256(nodeIndex);
        return bytes32(value);
    }

    // setHashChunk: Copy `chunk` bytes from one Keccak word into a digest byte array.
    function setHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) internal pure {
        for (uint256 i = 0; i < chunk;) {
            // Copy byte i from the hash word into the requested output offset.
            out[offset + i] = blockHash[i];
            unchecked {
                // The loop bound guarantees i cannot overflow before exiting.
                ++i;
            }
        }
    }

    // setSlice32: Write one 32-byte segment into a packed byte buffer.
    // 1. Skip the bytes-array length prefix.
    // 2. Advance to the requested byte offset.
    // 3. Store the 32-byte segment in place.
    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            // Skip the bytes length word to reach the payload start.
            let dataPtr := add(dst, 32)
            // Advance to the caller-requested byte offset inside the payload.
            let writePtr := add(dataPtr, offset)
            // Store the 32-byte segment at that payload location.
            mstore(writePtr, src)
        }
    }
}
