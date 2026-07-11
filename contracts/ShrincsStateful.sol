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

import {SHRINCS} from "./SHRINCS.sol";
import {ShrincsParams} from "shrincs-profile/ShrincsParams.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";
import {SHRINCSHash} from "./SHRINCSHash.sol";
import {WOTSPlusC} from "./WOTSPlusC.sol";

library ShrincsStateful {
    // Address-type words for the SPHINCS-style keyed hash inputs. These
    // are the ADRS type constants [FIPS205 §4.2]: WOTS+ hash (0), tree
    // (2), and FORS tree (3).
    uint32 internal constant AddressTypeWotsHash = 0;

    struct StatefulPublicKey {
        // Public seed for stateful WOTS-C and tree hashing.
        bytes32 pkSeed;
        // Root of the custom stateful tree.
        bytes32 root;
        // Maximum number of stateful leaves/signatures under this key.
        uint32 maxSignatures;
    }

    struct StatefulSignature {
        // Per-signature randomizer committed into the stateful message
        // digest.
        bytes32 randomizer;
        // Grinding counter used to satisfy the WOTS-C target-sum rule.
        uint32 counter;
        // Revealed WOTS-C chain values.
        bytes32[] chains;
        // Unbalanced authentication path proving the selected stateful leaf.
        bytes32[] authPath;
    }

    // verifyStatefulUncheckedMessage: Verify a stateful signature against an
    // exact caller-supplied message.
    // 1. Check that the public key uses the compiled fixed layout.
    // 2. Check the installed public-key commitment and the public-key
    // encoding.
    // 3. Decode the compact stateful public key embedded inside the SHRINCS
    // public bundle.
    // 4. Recover and validate the consumed stateful leaf index from the auth
    // path length.
    // 5. Reconstruct the compact WOTS-C public-key hash from the signature
    // and message.
    // 6. Rebuild the unbalanced stateful tree root from that leaf and auth
    // path.
    // 7. Accept only if the reconstructed root matches the decoded stateful
    // public root.
    function verifyStatefulUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsStateful.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // The public key must satisfy the compiled fixed key shape.
        if (!ShrincsCodec.validPublicKey(publicKey)) return false;
        // The bundled public key must match the installed public-key
        // commitment.
        if (!ShrincsCodec.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return false;
        // Decode the compact stateful public key fields from the public
        // bundle.
        (ShrincsStateful.StatefulPublicKey memory statefulKey, bool ok) =
            ShrincsCodec.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        // In this unbalanced stateful tree, the leaf index is encoded by
        // auth-path length.
        uint32 leafIndex = uint32(signature.authPath.length);
        // Leaf 0 is reserved and never used for valid stateful signatures.
        if (leafIndex == 0) return false;
        // Reject signatures that claim a leaf beyond the configured stateful
        // budget.
        if (leafIndex > statefulKey.maxSignatures) return false;
        // Stateful WOTS-C always reveals a fixed number of chains.
        if (signature.chains.length != ShrincsParams.WOTS_CHAINS_STATEFUL) {
            return false;
        }

        // Reconstruct the compact WOTS-C public-key hash from the signature
        // and message.
        // line-length: allow — fmt canonical tuple head exceeds cap
        (bytes32 pkHash, bool validWots) = compactStatefulWotsPublicKeyFromSignature(
            statefulKey.pkSeed, leafIndex, message, signature
        );
        if (!validWots) return false;

        // Rebuild the unbalanced stateful tree root above that WOTS-derived
        // leaf.
        (bytes32 root, bool validPath) = rootFromUnbalancedPath(
            statefulKey.pkSeed, leafIndex, pkHash, signature.authPath
        );
        if (!validPath) return false;
        return statefulKey.root == root;
    }

    // compactStatefulWotsPublicKeyFromSignature: Reconstruct the compact
    // stateful WOTS-C public-key hash.
    // WOTS-C (WOTS+C in [SPHINCSPLUSC §3]): a fixed target-sum check
    // stands in for the WOTS checksum chains. Construction: [SHRINCS §5].
    // 1. Derive the stateful WOTS-C digest from the public seed, leaf index,
    // randomizer, counter, and message.
    // 2. Read one base-16 digit per WOTS chain from that digest.
    // 3. Advance each revealed chain value to its endpoint.
    // 4. Enforce the fixed target-sum constraint used instead of an explicit
    // checksum suffix.
    // 5. Hash the reconstructed chain endpoints into the compact WOTS-C
    // public-key hash.
    function compactStatefulWotsPublicKeyFromSignature(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory message,
        ShrincsStateful.StatefulSignature calldata signature
    ) internal pure returns (bytes32 pkHash, bool ok) {
        // Bind the stateful WOTS-C digest to the seed, leaf, randomizer,
        // counter, and signed message.
        bytes32 digest = keccak256(
            abi.encodePacked(
                "uxmss-wots-digits",
                pkSeed,
                leafIndex,
                signature.randomizer,
                signature.counter,
                message
            )
        );

        // Zero-initialized accumulator: summed over every WOTS-C chain in
        // the loop below before the target-sum check; the default-zero
        // start is intended, not an uninitialized read.
        // slither-disable-next-line uninitialized-local
        uint32 digitSum;
        // Reserve one 32-byte slot per reconstructed WOTS chain endpoint.
        bytes memory segments =
            new bytes(ShrincsParams.WOTS_CHAINS_STATEFUL * 32);
        // Shared WOTS-C key address base for this stateful leaf: the WOTS-
        // hash address type (0) in bits 96..127 and the leaf index in bits
        // 64..95; layer and tree are 0 for the stateful subtree. The
        // per-step chain index and step are folded in by the shared walk
        // (WOTSPlusC.wotsChainNoMaskBase), reproducing the address word this
        // path previously built via SHRINCSHash.addressWord32.
        uint256 addressBase = (uint256(AddressTypeWotsHash) << 96)
            | (uint256(leafIndex) << 64);
        for (uint256 i = 0; i < ShrincsParams.WOTS_CHAINS_STATEFUL;) {
            // Read the base-16 digit that chooses where this chain stopped
            // during signing.
            uint32 digit = WOTSPlusC.baseW16Digit32(digest, i);
            // Accumulate the fixed target-sum check used by this compact
            // WOTS-C variant.
            digitSum += digit;
            // casting to 'uint32' is safe because i ranges over 64 stateful
            // WOTS chains
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 chainIndex = uint32(i);
            // T6/F-08: to unconditionally separate the stateful chain
            // domain, pass the tag "uxmss-wots-chain" / 16 here instead of
            // the shared WOTS_C_CHAIN_TAG (see
            // WOTSPlusC.hashWotsCChainNoMask32).
            // Complete the revealed chain from its signing position to the
            // chain endpoint.
            bytes32 segment = WOTSPlusC.wotsChainNoMaskBase(
                WOTSPlusC.WOTS_C_CHAIN_TAG,
                WOTSPlusC.WOTS_C_CHAIN_TAG_LEN,
                ShrincsParams.WOTS_BASE_STATEFUL,
                pkSeed,
                addressBase,
                chainIndex,
                signature.chains[i],
                digit
            );
            // Store the reconstructed endpoint into the packed segment
            // buffer.
            setSlice32(segments, segment, i * 32);
            unchecked {
                ++i;
            }
        }

        // Reject messages whose reconstructed digit sum does not hit the
        // fixed target.
        if (digitSum != ShrincsParams.WOTS_TARGET_SUM_STATEFUL) {
            return (bytes32(0), false);
        }
        // Hash the reconstructed endpoints into the compact stateful WOTS
        // public-key hash. Output truncated to HASH_LEN bytes, high-
        // aligned (maskHash); for 256s this folds to a no-op.
        return (
            SHRINCSHash.maskHash(
                keccak256(
                    abi.encodePacked(
                        "uxmss-wots-pk", pkSeed, leafIndex, segments
                    )
                )
            ),
            true
        );
    }

    // rootFromUnbalancedPath: Rebuild the root of the custom unbalanced
    // stateful tree from one leaf and path.
    // Unbalanced XMSS-style tree per [SHRINCS App. B.3].
    // 1. Check that the auth path length matches the encoded leaf index.
    // 2. Hash the leaf together with the first auth node to form the first
    // parent.
    // 3. Walk upward through the remaining auth path nodes in the tree's
    // unbalanced order.
    // 4. Return the reconstructed root and success flag.
    function rootFromUnbalancedPath(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] calldata authPath
    ) internal pure returns (bytes32 root, bool ok) {
        // This unbalanced tree encodes the leaf index as the auth-path
        // length.
        if (authPath.length != leafIndex) return (bytes32(0), false);
        // Leaf 0 is invalid, so a valid auth path is never empty.
        if (authPath.length == 0) return (bytes32(0), false);
        // The first parent hashes the leaf with the first auth-path node on
        // its right.
        root = statefulParentHash(pkSeed, leafIndex, leaf, authPath[0]);
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            // Higher parents hash the next auth node on the left with the
            // running root on the right.
            root = statefulParentHash(
                pkSeed,
                // casting to 'uint32' is safe because offset is bounded by
                // authPath.length - 1, and authPath.length == leafIndex
                // forge-lint: disable-next-line(unsafe-typecast)
                leafIndex - uint32(offset) - 1,
                authPath[offset + 1],
                root
            );
            unchecked {
                ++offset;
            }
        }
        ok = true;
    }

    // statefulParentHash: Hash one parent node in the stateful unbalanced
    // tree.
    // 1. Domain-separate the hash as an unbalanced XMSS-style node
    // computation.
    // 2. Bind the public seed and left-leaf index that identify this parent
    // location.
    // 3. Mix in the left and right child values in tree order.
    // 4. Return the parent node value.
    function statefulParentHash(
        bytes32 pkSeed,
        uint32 leftLeafIndex,
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32 out) {
        // keccak256 input ("uxmss-node" tag [§1 tags], 110 bytes):
        //   [0..10)   "uxmss-node"
        //   [10..42)  pkSeed
        //   [42..46)  leftLeafIndex (big-endian uint32)
        //   [46..78)  left child
        //   [78..110) right child
        // Output truncated to HASH_LEN bytes, high-aligned (maskHash
        // below); for 256s this folds to a no-op.
        // Memory-safe: uses scratch at the free-memory pointer without
        // advancing it and without relying on prior contents.
        assembly ("memory-safe") {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for unbalanced stateful parent
            // hashing.
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
        }
        out = SHRINCSHash.maskHash(out);
    }

    // setSlice32: Write one 32-byte segment into a packed byte buffer.
    // 1. Skip the bytes-array length prefix.
    // 2. Advance to the requested byte offset.
    // 3. Store the 32-byte segment in place.
    function setSlice32(bytes memory dst, bytes32 src, uint256 offset)
        internal
        pure
    {
        // Memory-safe: writes one 32-byte word into the dst buffer's
        // payload at the caller-checked offset; no scratch or FMP change.
        assembly ("memory-safe") {
            // Skip the bytes length word to reach the payload start.
            let dataPtr := add(dst, 32)
            // Advance to the caller-requested byte offset inside the payload.
            let writePtr := add(dataPtr, offset)
            // Store the 32-byte segment at that payload location.
            mstore(writePtr, src)
        }
    }
}
