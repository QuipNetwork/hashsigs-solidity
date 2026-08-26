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

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {WOTSPlusC} from "./WOTSPlusC.sol";

/// @title UXMSS
/// @notice Unbalanced-XMSS stateful component ([SHRINCS App. B.3]): compact
/// WOTS-C digit reconstruction and unbalanced authentication-path
/// verification. Uses the `uxmss-*` keyed-hash tag family.
library UXMSS {
    // AddressTypeWotsHash: the WOTS+ hash ADRS type constant
    // [FIPS205 §4.2] (value 0) for the SPHINCS-style keyed hash inputs.
    uint32 internal constant AddressTypeWotsHash = 0;

    // Stateful WOTS-C chain-step domain tag and its byte length. F-08
    // split: the stateful (UXMSS) walk uses "uxmss-wots-chain" (16 bytes)
    // to unconditionally separate its chain domain from the stateless
    // hypertree walk (which keeps WOTSPlusC.WOTS_C_CHAIN_TAG,
    // "wots-c-chain"). The chain-step preimage is [tag | pkSeed |
    // addressWord | segment], so its length here is
    // UXMSS_WOTS_CHAIN_TAG_LEN + 96 = 112 bytes. Profile-agnostic: one
    // string across all keccak profiles.
    bytes32 internal constant UXMSS_WOTS_CHAIN_TAG = "uxmss-wots-chain";
    uint256 internal constant UXMSS_WOTS_CHAIN_TAG_LEN = 16;

    struct StatefulPublicKey {
        // Public seed for stateful WOTS-C and tree hashing.
        bytes32 pkSeed;
        // Root of the custom stateful tree.
        bytes32 root;
        // Maximum number of stateful leaves/signatures under this key.
        uint32 maxSignatures;
    }

    // TWIN of SHRINCS.Signature: the field list here and in SHRINCS.Signature
    // must stay identical. SHRINCS re-tags a SHRINCS.Signature pointer to
    // this type at its single call boundary (SHRINCS._toUxmss) rather than
    // copying; the twin-drift test asserts abi.encode equality so any layout
    // change here that is not mirrored in SHRINCS.Signature fails closed.
    struct Signature {
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

    // verify: Verify a stateful signature against an exact caller-supplied
    // message using the decoded stateful key fields.
    // 1. Recover and validate the consumed stateful leaf index from the auth
    // path length.
    // 2. Reconstruct the compact WOTS-C public-key hash from the signature
    // and message.
    // 3. Rebuild the unbalanced stateful tree root from that leaf and auth
    // path.
    // 4. Accept only if the reconstructed root matches the decoded stateful
    // public root.
    function verify(
        bytes32 pkSeed,
        bytes32 root,
        uint32 maxSignatures,
        bytes memory message,
        UXMSS.Signature calldata signature
    ) internal view returns (bool) {
        // In this unbalanced stateful tree, the leaf index is encoded by
        // auth-path length.
        uint32 leafIndex = uint32(signature.authPath.length);
        // Leaf zero is reserved and has no authentication path. Reject it
        // explicitly before WOTS reconstruction so invalid signatures return
        // false rather than relying on a downstream empty-array failure.
        // Also reject leaves beyond the configured stateful budget.
        if (leafIndex == 0 || leafIndex > maxSignatures) return false;

        // Reconstruct the compact WOTS-C public-key hash from the signature
        // and message.
        // line-length: allow — fmt canonical tuple head exceeds cap
        (bytes32 pkHash, bool validWots) = compactStatefulWotsPublicKeyFromSignature(
            pkSeed, leafIndex, message, signature
        );
        if (!validWots) return false;

        // Rebuild the unbalanced stateful tree root above that WOTS-derived
        // leaf.
        (bytes32 reconstructedRoot, bool validPath) = rootFromUnbalancedPath(
            pkSeed, leafIndex, pkHash, signature.authPath
        );
        if (!validPath) return false;
        return root == reconstructedRoot;
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
        UXMSS.Signature calldata signature
    ) internal view returns (bytes32 pkHash, bool ok) {
        // Bind the stateful WOTS-C digest to the seed, leaf, randomizer,
        // counter, and signed message.
        bytes32 digest = HashSuite.uxmssWotsDigits32(
            pkSeed,
            leafIndex,
            signature.randomizer,
            signature.counter,
            message
        );

        // Zero-initialized accumulator: summed over every WOTS-C chain in
        // the loop below before the target-sum check; the default-zero
        // start is intended, not an uninitialized read.
        // slither-disable-next-line uninitialized-local
        uint32 digitSum;
        // Reserve one 32-byte slot per reconstructed WOTS chain endpoint.
        bytes memory segments =
            new bytes(SHRINCSParams.WOTS_CHAINS_STATEFUL * 32);
        // Shared WOTS-C key address base for this stateful leaf: the WOTS-
        // hash address type (0) in bits 96..127 and the leaf index in bits
        // 64..95; layer and tree are 0 for the stateful subtree. The
        // per-step chain index and step are folded in by the shared walk
        // (WOTSPlusC.wotsChainNoMaskBase), reproducing the address word this
        // path previously built via the now-test-only address-word oracle.
        uint256 addressBase = (uint256(AddressTypeWotsHash) << 96)
            | (uint256(leafIndex) << 64);
        // Hoist the calldata array reference so the loop reads element data
        // from a fixed base pointer instead of re-resolving the struct member
        // offset on every iteration.
        bytes32[] calldata chains = signature.chains;
        for (uint256 i = 0; i < SHRINCSParams.WOTS_CHAINS_STATEFUL;) {
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
            // F-08: the stateful chain domain is separated from the
            // stateless hypertree walk by its own tag "uxmss-wots-chain"
            // / 16 (112-byte preimage), not the shared WOTS_C_CHAIN_TAG
            // (see HashSuite.hashWotsCChainNoMask32).
            // Complete the revealed chain from its signing position to the
            // chain endpoint.
            bytes32 segment = WOTSPlusC.wotsChainNoMaskBase(
                UXMSS_WOTS_CHAIN_TAG,
                UXMSS_WOTS_CHAIN_TAG_LEN,
                SHRINCSParams.WOTS_BASE_STATEFUL,
                pkSeed,
                addressBase,
                chainIndex,
                chains[i],
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
        if (digitSum != SHRINCSParams.WOTS_TARGET_SUM_STATEFUL) {
            return (bytes32(0), false);
        }
        // Hash the reconstructed endpoints into the compact stateful WOTS
        // public-key hash. Output truncated to HASH_LEN bytes, high-
        // aligned (maskHash inside the suite helper); 256s no-op.
        return (HashSuite.uxmssWotsPk32(pkSeed, leafIndex, segments), true);
    }

    // rootFromUnbalancedPath: Rebuild the root of the custom unbalanced
    // stateful tree from one leaf and path.
    // Unbalanced XMSS-style tree per [SHRINCS App. B.3].
    // 1. Hash the leaf together with the first auth node to form the first
    // parent.
    // 2. Walk upward through the remaining auth path nodes in the tree's
    // unbalanced order.
    // 3. Return false for an empty path; otherwise return the reconstructed
    // root and success.
    function rootFromUnbalancedPath(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] calldata authPath
    ) internal view returns (bytes32 root, bool ok) {
        if (authPath.length == 0) return (bytes32(0), false);

        // The first parent hashes the leaf with the first auth-path node on
        // its right.
        root = HashSuite.statefulParentHash32(
            pkSeed, leafIndex, leaf, authPath[0]
        );
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            // Higher parents hash the next auth node on the left with the
            // running root on the right.
            root = HashSuite.statefulParentHash32(
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
