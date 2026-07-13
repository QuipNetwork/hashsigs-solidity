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

import {Hash} from "../../Hash.sol";

/// @title HashSuite (SHA-256)
/// @notice The SHA-256 hash-suite seam: the sibling of the keccak HashSuite,
/// selected by remapping `shrincs-hash/` to contracts/hash/sha2/. Each helper
/// hashes a preimage byte-identical to the keccak suite's (tag strings
/// and field layouts are shared across suites); only the hash primitive
/// differs. Cross-suite domain separation therefore comes from the hash
/// function itself plus HASH_SUITE_ID and the suite-qualified profile id, not
/// from distinct tags.
/// @dev Groups 1-2 compute SHA-256 through the 0x02 precompile via
/// `staticcall`, so every such helper is `view` (staticcall reads the call
/// environment); the shared verifier stack is `view` for the same reason. The
/// call is fail-closed: an out-of-gas inner call returns 0 and counts as a
/// verify failure (`revert`). Output comes from the reserved scratch word at
/// 0x00, so no per-call return memory is allocated. Group-3 helpers use the
/// `sha256()` builtin (a `pure` intrinsic over an abi.encodePacked buffer).
/// EVM-domain hashes (operation tags, bundle commitments, identity constants)
/// stay keccak under every suite and are NOT routed here.
library HashSuite {
    // Hash-suite identifier bound into the canonical SHRINCS action and
    // rotation message hashes. The keccak suite file exports 1.
    uint32 internal constant HASH_SUITE_ID = 2;

    // hashWotsCChainNoMask32: Execute one unmasked WOTS-C chain-hash step
    // under a caller-supplied domain tag.
    // 1. Domain-separate the hash as a WOTS-C chain computation.
    // 2. Bind the public seed and chain-step address.
    // 3. Mix in the current chain segment value.
    // 4. Return the next chain value.
    // Domain separation: both the hypertree (stateless) and stateful WOTS-C
    // walks feed this one tag-parameterized step, but pass distinct tags.
    // The stateless hypertree walk passes "wots-c-chain"
    // (WOTSPlusC.WOTS_C_CHAIN_TAG, 12 bytes) with a 108-byte preimage; the
    // stateful (UXMSS) walk passes "uxmss-wots-chain"
    // (UXMSS.UXMSS_WOTS_CHAIN_TAG, 16 bytes) with a 112-byte preimage
    // (F-08 split). The dedicated stateful tag separates the two chain
    // domains unconditionally, so a stateless and a stateful chain step can
    // never share a preimage regardless of how the two pkSeeds relate.
    function hashWotsCChainNoMask32(
        bytes32 tag,
        uint256 tagLen,
        bytes32 pkSeed,
        bytes32 addressWord,
        bytes32 segment
    ) internal view returns (bytes32 out) {
        // sha256 input (tag [§1 tags], tagLen + 96 bytes; for the shared
        // WOTS_C_CHAIN_TAG this is "wots-c-chain" and 108 bytes):
        //   [0..tagLen)          tag
        //   [tagLen..tagLen+32)  pkSeed
        //   [tagLen+32..+64)     addressWord
        //   [tagLen+64..+96)     chain segment
        // Output truncated to HASH_LEN bytes, high-aligned (maskHash
        // below); for 256s this folds to a no-op.
        // Memory-safe: input scratch at the free-memory pointer (not
        // advanced); output written to the reserved scratch word at 0x00.
        assembly ("memory-safe") {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for WOTS-C chain hashing.
            mstore(ptr, tag)
            // Write the 32-byte public seed after the tag.
            mstore(add(ptr, tagLen), pkSeed)
            // Write the 32-byte address word after the seed.
            mstore(add(ptr, add(tagLen, 32)), addressWord)
            // Write the current chain segment after the address.
            mstore(add(ptr, add(tagLen, 64)), segment)
            // Hash the complete WOTS-C chain-step preimage; fail closed.
            if iszero(staticcall(gas(), 2, ptr, add(tagLen, 96), 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // hashForsLeaf32: Hash one revealed FORS secret leaf into its public leaf
    // value.
    // 1. Domain-separate this hash as a FORS leaf computation.
    // 2. Bind the public seed and leaf address.
    // 3. Mix in the revealed secret leaf bytes.
    // 4. Return the public FORS leaf value.
    /// @dev Precondition: pkSeed is exactly 32 bytes, validPublicKey-checked
    /// or a 32-byte key slice, as the fixed calldata read below assumes.
    function hashForsLeaf32(
        bytes calldata pkSeed,
        bytes32 addressWord,
        bytes calldata sk
    ) internal view returns (bytes32 out) {
        // sha256 input ("fors-leaf" tag [§1 tags], 105 bytes):
        //   [0..9)    "fors-leaf"
        //   [9..41)   pkSeed
        //   [41..73)  addressWord
        //   [73..105) secret leaf
        // Output truncated to HASH_LEN bytes, high-aligned (maskHash
        // below); for 256s this folds to a no-op.
        // Memory-safe: input scratch at the free-memory pointer (not
        // advanced); output written to the reserved scratch word at 0x00.
        assembly ("memory-safe") {
            // Use the current free-memory pointer as scratch without
            // advancing it.
            let ptr := mload(0x40)
            // Write the domain tag prefix for FORS leaf hashing.
            mstore(ptr, "fors-leaf")
            // Copy the 32-byte public seed after the 9-byte tag.
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            // Write the 32-byte address word after the seed.
            mstore(add(ptr, 41), addressWord)
            // Copy the 32-byte secret leaf after the address.
            calldatacopy(add(ptr, 73), sk.offset, 32)
            // Hash the complete FORS leaf preimage; fail closed.
            if iszero(staticcall(gas(), 2, ptr, 105, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // hashForsNode32: Hash one internal FORS node from its left and right
    // children.
    // 1. Domain-separate this hash as an internal FORS node computation.
    // 2. Bind the public seed and parent-node address.
    // 3. Mix in the left and right child values in canonical order.
    // 4. Return the parent node value.
    /// @dev Precondition: pkSeed is exactly 32 bytes, validPublicKey-checked
    /// or a 32-byte key slice, as the fixed calldata read below assumes.
    function hashForsNode32(
        bytes calldata pkSeed,
        bytes32 addressWord,
        bytes32 left,
        bytes32 right
    ) internal view returns (bytes32 out) {
        // sha256 input ("fors-node" tag [§1 tags], 137 bytes):
        //   [0..9)     "fors-node"
        //   [9..41)    pkSeed
        //   [41..73)   addressWord
        //   [73..105)  left child
        //   [105..137) right child
        // Output truncated to HASH_LEN bytes, high-aligned (maskHash
        // below); for 256s this folds to a no-op.
        // Memory-safe: input scratch at the free-memory pointer (not
        // advanced); output written to the reserved scratch word at 0x00.
        assembly ("memory-safe") {
            // Use the current free-memory pointer as scratch without
            // advancing it.
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
            // Hash the complete FORS internal-node preimage; fail closed.
            if iszero(staticcall(gas(), 2, ptr, 137, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // wotsDigest32: Derive the WOTS-C message digest that determines chain
    // positions.
    // 1. Domain-separate the digest input as a WOTS-C message computation.
    // 2. Bind the public seed, expected public-key hash, and signature
    // randomizer.
    // 3. Bind the grind counter and signed message value.
    // 4. Return the single 32-byte digest block used for base-w digit
    // extraction.
    function wotsDigest32(
        bytes32 pkSeed,
        bytes32 expectedPkHash,
        bytes32 randomizer,
        uint32 counter,
        bytes32 message
    ) internal view returns (bytes32 out) {
        // sha256 input ("wots-c-msg" tag [§1 tags], 142 bytes):
        //   [0..10)    "wots-c-msg"
        //   [10..42)   pkSeed
        //   [42..74)   expectedPkHash
        //   [74..106)  randomizer
        //   [106..110) grind counter (big-endian uint32)
        //   [110..142) message
        // Memory-safe: input scratch at the free-memory pointer (not
        // advanced); output written to the reserved scratch word at 0x00.
        assembly ("memory-safe") {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the digest domain tag prefix.
            mstore(ptr, "wots-c-msg")
            // Write the 32-byte public seed after the 10-byte tag.
            mstore(add(ptr, 10), pkSeed)
            // Write the expected compressed public-key hash after the seed.
            mstore(add(ptr, 42), expectedPkHash)
            // Write the 32-byte randomizer after the expected public-key
            // hash.
            mstore(add(ptr, 74), randomizer)
            // Write the 4-byte grind counter after the randomizer.
            mstore(add(ptr, 106), shl(224, counter))
            // Write the 32-byte message after the counter.
            mstore(add(ptr, 110), message)
            // Hash the full WOTS-C message preimage; fail closed.
            if iszero(staticcall(gas(), 2, ptr, 142, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
    }

    // hashHypertreeNode32: Hash one internal hypertree node at a specific
    // layer/tree location.
    // 1. Domain-separate the hash as a hypertree internal-node computation.
    // 2. Bind the public seed and parent-node address.
    // 3. Mix in the left and right child node values in canonical order.
    // 4. Return the parent node value.
    function hashHypertreeNode32(
        bytes32 pkSeed,
        bytes32 addressWord,
        bytes32 left,
        bytes32 right
    ) internal view returns (bytes32 out) {
        // sha256 input ("hypertree-node" tag [§1 tags], 142 bytes):
        //   [0..14)    "hypertree-node"
        //   [14..46)   pkSeed
        //   [46..78)   addressWord
        //   [78..110)  left child
        //   [110..142) right child
        // Output truncated to HASH_LEN bytes, high-aligned (maskHash
        // below); for 256s this folds to a no-op.
        // Memory-safe: input scratch at the free-memory pointer (not
        // advanced); output written to the reserved scratch word at 0x00.
        assembly ("memory-safe") {
            // Allocate a scratch buffer starting at the free-memory pointer.
            let ptr := mload(0x40)
            // Write the domain tag prefix for hypertree internal-node
            // hashing.
            mstore(ptr, "hypertree-node")
            // Write the 32-byte public seed after the 14-byte tag.
            mstore(add(ptr, 14), pkSeed)
            // Write the 32-byte address word after the seed.
            mstore(add(ptr, 46), addressWord)
            // Write the left child after the address.
            mstore(add(ptr, 78), left)
            // Write the right child after the left child.
            mstore(add(ptr, 110), right)
            // Hash the hypertree internal-node preimage; fail closed.
            if iszero(staticcall(gas(), 2, ptr, 142, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // statefulParentHash32: Hash one parent node in the stateful unbalanced
    // tree.
    // 1. Domain-separate the hash as an unbalanced XMSS-style node
    // computation.
    // 2. Bind the public seed and left-leaf index that identify this parent
    // location.
    // 3. Mix in the left and right child values in tree order.
    // 4. Return the parent node value.
    function statefulParentHash32(
        bytes32 pkSeed,
        uint32 leftLeafIndex,
        bytes32 left,
        bytes32 right
    ) internal view returns (bytes32 out) {
        // sha256 input ("uxmss-node" tag [§1 tags], 110 bytes):
        //   [0..10)   "uxmss-node"
        //   [10..42)  pkSeed
        //   [42..46)  leftLeafIndex (big-endian uint32)
        //   [46..78)  left child
        //   [78..110) right child
        // Output truncated to HASH_LEN bytes, high-aligned (maskHash
        // below); for 256s this folds to a no-op.
        // Memory-safe: input scratch at the free-memory pointer (not
        // advanced); output written to the reserved scratch word at 0x00.
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
            // Hash the complete parent-node preimage; fail closed.
            if iszero(staticcall(gas(), 2, ptr, 110, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // hashForsPk32: Finalizer over the caller-built "fors-pk" buffer.
    // FORSMinusC.verifyForsCAndReturnRoot fills [tag | pkSeed | roots] into a
    // memory-safe scratch region and passes its (ptr, len); this hashes it
    // and truncates to HASH_LEN. The buffer construction is suite-
    // independent and stays in the caller.
    function hashForsPk32(uint256 ptr, uint256 len)
        internal
        view
        returns (bytes32 out)
    {
        // Memory-safe: hashes an already-built buffer; output written to the
        // reserved scratch word at 0x00. Fail closed on an inner-call
        // failure.
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 2, ptr, len, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // hashWotsCPk32: Finalizer over the caller-built "wots-c-pk" buffer.
    // Hypertree.verifyWotsC32 fills [tag | pkSeed | segments] into a
    // memory-safe scratch region and passes its (ptr, len); this hashes it
    // and truncates to HASH_LEN. The buffer construction is suite-
    // independent and stays in the caller.
    function hashWotsCPk32(uint256 ptr, uint256 len)
        internal
        view
        returns (bytes32 out)
    {
        // Memory-safe: hashes an already-built buffer; output written to the
        // reserved scratch word at 0x00. Fail closed on an inner-call
        // failure.
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 2, ptr, len, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
        out = Hash.maskHash(out);
    }

    // hashForsDigestBlock32: Finalizer over the caller-built "fors-digest"
    // buffer. FORSMinusC.forsDigestBytes fills [tag | pkSeed | hypertreeRoot
    // | randomizer | counter | message] (plus an optional 4-byte block
    // counter) and passes its (ptr, len); this returns the RAW digest block
    // with NO masking, because the caller reads a bit stream out of it via
    // Hash.readBits*, so the low bytes must survive.
    function hashForsDigestBlock32(uint256 ptr, uint256 len)
        internal
        view
        returns (bytes32 out)
    {
        // Memory-safe: hashes an already-built buffer; output written to the
        // reserved scratch word at 0x00. Fail closed on an inner-call
        // failure.
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 2, ptr, len, 0, 32)) {
                revert(0, 0)
            }
            out := mload(0)
        }
    }

    // uxmssWotsDigits32: Derive the stateful WOTS-C message digest.
    // Binds the public seed, leaf index, randomizer, grind counter, and
    // signed message. Returns the RAW digest word (no masking): the caller
    // reads base-16 digits out of the full 32-byte value.
    function uxmssWotsDigits32(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 randomizer,
        uint32 counter,
        bytes memory message
    ) internal pure returns (bytes32) {
        // sha256 input ("uxmss-wots-digits" tag, 89 + message bytes):
        //   tag | pkSeed | leafIndex(4) | randomizer | counter(4) | message
        return sha256(
            abi.encodePacked(
                "uxmss-wots-digits",
                pkSeed,
                leafIndex,
                randomizer,
                counter,
                message
            )
        );
    }

    // uxmssWotsPk32: Hash the reconstructed stateful WOTS-C chain endpoints
    // into the compact public-key hash, truncated to HASH_LEN.
    function uxmssWotsPk32(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory segments
    ) internal pure returns (bytes32) {
        // sha256 input ("uxmss-wots-pk" tag, 49 + segments bytes):
        //   tag | pkSeed | leafIndex(4) | segments
        return Hash.maskHash(
            sha256(
                abi.encodePacked(
                    "uxmss-wots-pk", pkSeed, leafIndex, segments
                )
            )
        );
    }
}
