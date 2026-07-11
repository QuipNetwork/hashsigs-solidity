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
    // verifyStatefulUncheckedMessage: Verify a stateful signature against an exact caller-supplied message.
    // 1. Check that the public key uses the compiled fixed layout.
    // 2. Check the installed public-key commitment and the public-key encoding.
    // 3. Decode the compact stateful public key embedded inside the SHRINCS public bundle.
    // 4. Recover and validate the consumed stateful leaf index from the auth path length.
    // 5. Reconstruct the compact WOTS-C public-key hash from the signature and message.
    // 6. Rebuild the unbalanced stateful tree root from that leaf and auth path.
    // 7. Accept only if the reconstructed root matches the decoded stateful public root.
    function verifyStatefulUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // The public key must satisfy the compiled fixed key shape.
        if (!ShrincsUtils.validPublicKey(publicKey)) return false;
        // The bundled public key must match the installed public-key commitment.
        if (!ShrincsUtils.matchesExpectedPublicKeyCommitment(publicKey, expectedPublicKeyCommitment)) return false;
        // Decode the compact stateful public key fields from the public bundle.
        (ShrincsTypes.StatefulPublicKey memory statefulKey, bool ok) =
            ShrincsUtils.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        // In this unbalanced stateful tree, the leaf index is encoded by auth-path length.
        uint32 leafIndex = uint32(signature.authPath.length);
        // Leaf 0 is reserved and never used for valid stateful signatures.
        if (leafIndex == 0) return false;
        // Reject signatures that claim a leaf beyond the configured stateful budget.
        if (leafIndex > statefulKey.maxSignatures) return false;
        // Stateful WOTS-C always reveals a fixed number of chains.
        if (signature.chains.length != ShrincsTypes.WOTS_CHAINS_STATEFUL) return false;

        // Reconstruct the compact WOTS-C public-key hash from the signature and message.
        (bytes32 pkHash, bool validWots) =
            compactStatefulWotsPublicKeyFromSignature(statefulKey.pkSeed, leafIndex, message, signature);
        if (!validWots) return false;

        // Rebuild the unbalanced stateful tree root above that WOTS-derived leaf.
        (bytes32 root, bool validPath) =
            rootFromUnbalancedPath(statefulKey.pkSeed, leafIndex, pkHash, signature.authPath);
        if (!validPath) return false;
        return statefulKey.root == root;
    }

    // compactStatefulWotsPublicKeyFromSignature: Reconstruct the compact stateful WOTS-C public-key hash.
    // 1. Derive the stateful WOTS-C digest from the public seed, leaf index, randomizer, counter, and message.
    // 2. Read one base-16 digit per WOTS chain from that digest.
    // 3. Advance each revealed chain value to its endpoint.
    // 4. Enforce the fixed target-sum constraint used instead of an explicit checksum suffix.
    // 5. Hash the reconstructed chain endpoints into the compact WOTS-C public-key hash.
    function compactStatefulWotsPublicKeyFromSignature(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bytes32 pkHash, bool ok) {
        // Bind the stateful WOTS-C digest to the seed, leaf, randomizer, counter, and signed message.
        bytes32 digest = keccak256(
            abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, signature.randomizer, signature.counter, message)
        );

        uint32 digitSum;
        // Reserve one 32-byte slot per reconstructed WOTS chain endpoint.
        bytes memory segments = new bytes(ShrincsTypes.WOTS_CHAINS_STATEFUL * 32);
        for (uint256 i = 0; i < ShrincsTypes.WOTS_CHAINS_STATEFUL;) {
            // Read the base-16 digit that chooses where this chain stopped during signing.
            uint32 digit = baseW16Digit(digest, i);
            // Accumulate the fixed target-sum check used by this compact WOTS-C variant.
            digitSum += digit;
            // casting to 'uint32' is safe because i ranges over 64 stateful WOTS chains
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 chainIndex = uint32(i);
            // Complete the revealed chain from its signing position to the chain endpoint.
            bytes32 segment = statefulChainNoMask(
                pkSeed, leafIndex, chainIndex, signature.chains[i], digit, ShrincsTypes.WOTS_BASE_STATEFUL - 1 - digit
            );
            // Store the reconstructed endpoint into the packed segment buffer.
            setSlice32(segments, segment, i * 32);
            unchecked {
                ++i;
            }
        }

        // Reject messages whose reconstructed digit sum does not hit the fixed target.
        if (digitSum != ShrincsTypes.WOTS_TARGET_SUM_STATEFUL) return (bytes32(0), false);
        // Hash the reconstructed endpoints into the compact stateful WOTS public-key hash.
        return (keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, segments)), true);
    }

    // rootFromUnbalancedPath: Rebuild the root of the custom unbalanced stateful tree from one leaf and path.
    // 1. Check that the auth path length matches the encoded leaf index.
    // 2. Hash the leaf together with the first auth node to form the first parent.
    // 3. Walk upward through the remaining auth path nodes in the tree's unbalanced order.
    // 4. Return the reconstructed root and success flag.
    function rootFromUnbalancedPath(bytes32 pkSeed, uint32 leafIndex, bytes32 leaf, bytes32[] calldata authPath)
        internal
        pure
        returns (bytes32 root, bool ok)
    {
        // This unbalanced tree encodes the leaf index as the auth-path length.
        if (authPath.length != leafIndex) return (bytes32(0), false);
        // Leaf 0 is invalid, so a valid auth path is never empty.
        if (authPath.length == 0) return (bytes32(0), false);
        // The first parent hashes the leaf with the first auth-path node on its right.
        root = statefulParentHash(pkSeed, leafIndex, leaf, authPath[0]);
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            // casting to 'uint32' is safe because offset is bounded by authPath.length - 1, and authPath.length == leafIndex
            // forge-lint: disable-next-line(unsafe-typecast)
            // Higher parents hash the next auth node on the left with the running root on the right.
            root = statefulParentHash(pkSeed, leafIndex - uint32(offset) - 1, authPath[offset + 1], root);
            unchecked {
                ++offset;
            }
        }
        ok = true;
    }

    // statefulParentHash: Hash one parent node in the stateful unbalanced tree.
    // 1. Domain-separate the hash as an unbalanced XMSS-style node computation.
    // 2. Bind the public seed and left-leaf index that identify this parent location.
    // 3. Mix in the left and right child values in tree order.
    // 4. Return the parent node value.
    function statefulParentHash(bytes32 pkSeed, uint32 leftLeafIndex, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for unbalanced stateful parent hashing.
            mstore(ptr, "uxmss-node")
            // Write the 32-byte public seed after the 10-byte tag.
            mstore(add(ptr, 10), pkSeed)
            // Write the 4-byte left-leaf index after the seed.
            mstore(add(ptr, 42), shl(224, leftLeafIndex))
            // Write the left child after the leaf index.
            mstore(add(ptr, 46), left)
            // Write the right child after the left child.
            mstore(add(ptr, 78), right)
            // Hash the complete parent-node preimage.
            out := keccak256(ptr, 110)
            // Reserve the rounded-up scratch region used by this preimage.
            mstore(0x40, add(ptr, 128))
        }
    }

    // statefulChainNoMask: Advance one stateful WOTS-C chain for a chosen number of steps.
    // 1. Start from the revealed chain value.
    // 2. Rebuild the address word for each remaining chain position.
    // 3. Apply one unmasked WOTS-C chain hash per remaining step.
    // 4. Return the reconstructed chain endpoint.
    function statefulChainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIdx,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        // Start from the revealed chain value carried in the signature.
        out = value;
        for (uint32 j = 0; j < steps;) {
            // Rebuild the WOTS chain-step address for this leaf, chain, and step index.
            bytes32 addressWord =
                ShrincsUtils.addressWord32(0, 0, ShrincsTypes.AddressTypeWotsHash, leafIndex, chainIdx, start + j);
            // Hash one step forward along the chain.
            out = hashStatefulWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    // hashStatefulWotsCChainNoMask32: Execute one unmasked stateful WOTS-C chain-hash step.
    // 1. Domain-separate the hash as a WOTS-C chain computation.
    // 2. Bind the public seed and chain-step address.
    // 3. Mix in the current chain segment value.
    // 4. Return the next chain value.
    function hashStatefulWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
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
            // Reserve the rounded-up scratch region used by this preimage.
            mstore(0x40, add(ptr, 128))
        }
    }

    // baseW16Digit: Read one base-16 digit from a 32-byte digest.
    // 1. Select the byte containing the requested high or low nibble.
    // 2. Return the high nibble for even indices.
    // 3. Return the low nibble for odd indices.
    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32 digit) {
        // Each byte of the digest carries two base-16 digits.
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? uint32(b >> 4) : uint32(b & 0x0f);
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
