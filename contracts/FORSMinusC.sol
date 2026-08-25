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
import {Hash} from "./Hash.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";

library FORSMinusC {
    // AddressTypeForsTree: the FORS-tree ADRS type constant
    // [FIPS205 §4.2] (value 3) for the SPHINCS-style keyed hash inputs.
    uint32 internal constant AddressTypeForsTree = 3;

    struct ForsDigest {
        // Hypertree subtree selected for this stateless signature.
        uint64 treeIndex;
        // Leaf inside that subtree.
        uint32 leafIndex;
        // Message-derived FORS digest bits used to choose revealed leaves.
        bytes digest;
    }

    struct ForsEntry {
        // Revealed secret leaf for one FORS tree.
        bytes secretLeaf;
        // Authentication path from that leaf to the tree root.
        bytes[] authPath;
    }

    struct ForsSignature {
        // Per-signature randomizer used in FORS message hashing.
        bytes randomizer;
        // Grinding counter for the FORS-C constrained digest.
        uint32 counter;
        // Revealed FORS leaves and authentication paths.
        ForsEntry[] entries;
    }

    // verifyForsCAndReturnRoot: Verify the FORS-C portion of a stateless
    // SHRINCS signature.
    // FORS-C (FORS+C in [SPHINCSPLUSC §4]): the omitted final tree is
    // forced to select leaf 0 by grinding the digest so its last a
    // bits (a = FORS_TREE_HEIGHT) are zero. Construction: [SHRINCS §9.2].
    // 1. Check the compact FORS-C signature shape and randomizer length.
    // 2. Recompute the FORS digest bits and the hypertree coordinates the
    // signer committed to.
    // 3. Enforce the FORS-C convention that the omitted final tree selects
    // leaf 0.
    // 4. Rebuild each signed FORS tree root from its revealed leaf and auth
    // path.
    // 5. Hash those per-tree roots together into the reconstructed FORS root.
    // 6. Return the FORS root plus the digest-derived hypertree coordinates
    // (the seed for hypertree verification) together with a success flag.
    /// @dev T6 wire change: the hypertree coordinates are no longer carried
    /// in the signature. This returns the digest-derived coordinates for the
    /// caller to seed Hypertree.verifyHypertree; they are a pure function of
    /// the public key, message, and signature (randomizer, counter), never
    /// attacker-chosen.
    /// @dev Precondition: pkSeed is exactly 32 bytes, validPublicKey-checked
    /// or a 32-byte key slice, as the fixed calldata read below assumes.
    function verifyForsCAndReturnRoot(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes memory message,
        FORSMinusC.ForsSignature calldata signature
    )
        internal
        view
        returns (
            bytes32 forsRoot,
            uint64 treeIndex,
            uint32 leafIndex,
            bool ok
        )
    {
        // FORS-C omits the final FORS tree by forcing its digest-selected
        // leaf index to zero. Verification therefore expects only k - 1
        // revealed entries and rejects any digest whose omitted final tree
        // would require a nonzero leaf.
        uint256 signedTrees = uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
        // Reject malformed dynamic fields before fixed-count iteration or
        // fixed-width calldata reads. This prevents short arrays from
        // panicking and prevents trailing entries or randomizer bytes from
        // becoming ignored encoding malleability.
        if (
            signature.entries.length != signedTrees
                || signature.randomizer.length != 32
        ) return (bytes32(0), 0, 0, false);

        // Recompute the FORS digest and the hypertree coordinates that the
        // signer committed to. These digest-derived coordinates are the sole
        // source of the layer-0 hypertree address (T6: no longer carried in
        // the signature); they are returned to seed hypertree verification.
        FORSMinusC.ForsDigest memory digest = forsDigest(
            pkSeed,
            hypertreeRoot,
            message,
            signature.randomizer,
            signature.counter
        );
        treeIndex = digest.treeIndex;
        leafIndex = digest.leafIndex;
        // forsHeight: the SPHINCSPLUS `a` parameter [SPHINCSPLUS §5.5]
        // — FORS tree height.
        uint256 forsHeight = uint256(SHRINCSParams.FORS_TREE_HEIGHT);
        // The omitted final FORS tree must always select leaf 0 in the
        // compressed FORS-C layout.
        if (
            Hash.readBits32(
                    digest.digest,
                    signedTrees * forsHeight,
                    SHRINCSParams.FORS_TREE_HEIGHT
                ) != 0
        ) {
            return (bytes32(0), 0, 0, false);
        }

        // "fors-pk" || pkSeed || root_0 || ... || root_{k-2}
        uint256 forsPkInputLen = 39 + signedTrees * 32;
        uint256 forsPkInput;
        // keccak256 input ("fors-pk" tag [§1 tags], forsPkInputLen bytes):
        //   [0..7)         "fors-pk"
        //   [7..39)        pkSeed
        //   [39..39+32*t)  reconstructed per-tree roots (t = signedTrees)
        // forsPkInputLen = 39 + signedTrees * 32.
        // Memory-safe: allocates roundup32(forsPkInputLen) bytes at the
        // free-memory pointer and advances the pointer past them; the loop
        // below fills the per-tree roots and the final hash reads exactly
        // forsPkInputLen bytes.
        assembly ("memory-safe") {
            // Allocate a scratch buffer starting at the free-memory pointer.
            forsPkInput := mload(0x40)
            // Write the domain tag prefix at the start of the buffer.
            mstore(forsPkInput, "fors-pk")
            // Copy the 32-byte public seed immediately after the 7-byte tag.
            calldatacopy(add(forsPkInput, 7), pkSeed.offset, 32)
            // Bump the free-memory pointer to the next 32-byte aligned slot
            // after this buffer.
            mstore(
                0x40,
                add(forsPkInput, and(add(forsPkInputLen, 31), not(31)))
            )
        }

        for (uint256 tree = 0; tree < signedTrees;) {
            // Read one revealed FORS entry for this tree.
            FORSMinusC.ForsEntry calldata entry = signature.entries[tree];
            // Read the digest-selected leaf for this FORS tree.
            uint32 entryLeafIndex = Hash.readBits32(
                digest.digest,
                tree * forsHeight,
                SHRINCSParams.FORS_TREE_HEIGHT
            );
            // casting to 'uint32' is safe because the supported FORS tree
            // height is 14 bits
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 treeHeight = uint32(forsHeight);
            // casting to 'uint32' is safe because tree ranges over the fixed
            // 21 signed FORS trees
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 forsTreeIndex = uint32(tree);
            // Rebuild this FORS tree root from the revealed leaf and
            // authentication path.
            bytes32 root = forsEntryRoot32(
                treeHeight,
                pkSeed,
                treeIndex,
                leafIndex,
                forsTreeIndex,
                entryLeafIndex,
                entry
            );
            // Append each reconstructed root into the final FORS public-key
            // hash input.
            // Memory-safe: writes one 32-byte root into the forsPkInput
            // buffer allocated above (slot 39 + tree*32).
            assembly ("memory-safe") {
                // Write this 32-byte root at slot `tree` after the fixed
                // tag-and-seed prefix.
                mstore(add(add(forsPkInput, 39), mul(tree, 32)), root)
            }
            unchecked {
                ++tree;
            }
        }

        // Hash the per-tree roots into the reconstructed FORS public value.
        // The buffer above is suite-independent; only this finalizer swaps
        // per suite. Output truncated to HASH_LEN bytes, high-aligned
        // (maskHash inside the suite helper); for 256s this folds to a no-op.
        return (
            HashSuite.hashForsPk32(forsPkInput, forsPkInputLen),
            treeIndex,
            leafIndex,
            true
        );
    }

    // forsEntryRoot32: Rebuild one FORS tree root from a revealed secret leaf
    // and auth path.
    // 1. Construct the shared address prefix for this hypertree tree/leaf
    // location.
    // 2. Hash the revealed secret leaf into its public FORS leaf value.
    // 3. Walk upward through the authentication path one level at a time.
    // 4. Rebuild each parent node with the correct left/right ordering and
    // address.
    // 5. Return the reconstructed root for this FORS tree.
    function forsEntryRoot32(
        uint32 height,
        bytes calldata pkSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTreeIndex,
        uint32 entryLeafIndex,
        FORSMinusC.ForsEntry calldata entry
    ) internal view returns (bytes32 node) {
        // Build the shared address prefix used by all nodes in this FORS tree
        // location.
        uint256 addressBase = forsAddressBase(treeIndex, leafIndex);
        // Shift this FORS tree into the low-index range reserved for its
        // leaves.
        uint256 shiftedForsTree = uint256(forsTreeIndex) << height;
        // Select the concrete low leaf index inside this FORS tree.
        uint256 leafLowIndex = shiftedForsTree + uint256(entryLeafIndex);
        // Finish the address for the revealed leaf.
        uint256 leafAddressValue = addressBase | leafLowIndex;
        // Hash the revealed secret leaf into the corresponding public FORS
        // leaf value.
        node = HashSuite.hashForsLeaf32(
            pkSeed, bytes32(leafAddressValue), entry.secretLeaf
        );
        // Track the current node position as we walk upward through the auth
        // path.
        uint256 index = entryLeafIndex;
        // Hoist the calldata array reference so the loop reads element data
        // from a fixed base pointer instead of re-resolving the struct member
        // offset on every iteration.
        bytes[] calldata authPath = entry.authPath;
        for (uint256 level = 0; level < height;) {
            // Read the sibling node supplied for this level.
            bytes calldata authNode = authPath[level];
            bytes32 sibling;
            // Memory-safe: reads one calldata word into a stack variable;
            // no memory is written.
            assembly ("memory-safe") {
                // Load the 32-byte sibling node directly from calldata.
                sibling := calldataload(authNode.offset)
            }
            // Place the current node and sibling in canonical left/right
            // order for this level.
            (bytes32 left, bytes32 right) =
                index & 1 == 0 ? (node, sibling) : (sibling, node);
            // Parent nodes live one level higher than their children.
            uint256 nodeHeight = level + 1;
            uint256 shiftedNodeHeight = nodeHeight << 32;
            // Shift this FORS tree into the low-index range reserved for this
            // parent level.
            uint256 shiftedTree =
                uint256(forsTreeIndex) << (height - nodeHeight);
            // Collapse the current leaf/node index to its parent index.
            uint256 parentIndex = index >> 1;
            uint256 parentLowIndex = shiftedTree + parentIndex;
            // Start from the shared address prefix and then fill in height
            // and low index.
            uint256 addressValue = addressBase;
            addressValue |= shiftedNodeHeight;
            addressValue |= parentLowIndex;
            bytes32 addressWord = bytes32(addressValue);
            // Hash the two children into their parent node using the parent
            // address.
            node = HashSuite.hashForsNode32(pkSeed, addressWord, left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    // forsAddressBase: Construct the shared address prefix for one FORS
    // tree/leaf location.
    // 1. Encode the hypertree tree index in the high address bits.
    // 2. Encode the FORS address type so hashes stay domain-separated.
    // 3. Encode the hypertree leaf index that owns this FORS instance.
    // 4. Return the shared prefix used by all leaves and nodes in that FORS
    // tree.
    function forsAddressBase(uint64 treeIndex, uint32 leafIndex)
        internal
        pure
        returns (uint256)
    {
        // Place the hypertree subtree index in the high address region.
        uint256 shiftedTreeIndex = uint256(treeIndex) << 128;
        // Mark this address as belonging to the FORS tree domain.
        uint256 shiftedAddressType =
            uint256(FORSMinusC.AddressTypeForsTree) << 96;
        // Bind the FORS instance to the bottom-layer hypertree leaf.
        uint256 shiftedLeafIndex = uint256(leafIndex) << 64;
        uint256 addressBase = shiftedTreeIndex;
        addressBase |= shiftedAddressType;
        addressBase |= shiftedLeafIndex;
        return addressBase;
    }

    // forsDigest: Derive the FORS digest bits and selected hypertree
    // coordinates.
    // The grind counter drives the FORS-C digest-grinding rule
    // [SHRINCS §9.2]: iterate the counter until the digest forces the
    // omitted final tree to leaf 0.
    // 1. Compute how many bits are needed for FORS choices and hypertree
    // coordinates.
    // 2. Expand the digest stream from the message, public key, randomizer,
    // and counter.
    // 3. Read the hypertree tree index from the digest stream.
    // 4. Read the hypertree leaf index from the remaining digest bits.
    // 5. Return both coordinates together with the digest bytes used for FORS
    // leaf selection.
    function forsDigest(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes memory message,
        bytes calldata randomizer,
        uint32 counter
    ) internal view returns (FORSMinusC.ForsDigest memory out) {
        // Reserve bits for all signed FORS tree leaf choices.
        uint32 indexBits = uint32(SHRINCSParams.NUM_FORS_TREES)
            * uint32(SHRINCSParams.FORS_TREE_HEIGHT);
        // Each hypertree layer shares this many leaf-index bits.
        uint32 subtreeHeight = uint32(
            SHRINCSParams.HYPERTREE_HEIGHT
                / SHRINCSParams.NUM_HYPERTREE_LAYERS
        );
        // The remaining hypertree bits identify the subtree itself.
        uint32 treeBits =
            uint32(SHRINCSParams.HYPERTREE_HEIGHT) - subtreeHeight;
        // Expand enough bytes to cover FORS choices plus hypertree
        // coordinates.
        uint256 digestBytes =
            (uint256(indexBits)
                    + uint256(SHRINCSParams.HYPERTREE_HEIGHT)
                    + 7) / 8;
        // Derive the digest stream from the public seed/root, signature
        // randomizer, counter, and message.
        bytes memory digest = forsDigestBytes(
            pkSeed, hypertreeRoot, randomizer, counter, message, digestBytes
        );

        // Start reading coordinates immediately after the FORS choice bits.
        uint256 cursor = indexBits;
        // Read the hypertree tree index immediately after the FORS choice
        // bits.
        out.treeIndex = Hash.readBits64(digest, cursor, treeBits);
        cursor += treeBits;
        // Read the bottom-layer leaf index from the remaining subtree-height
        // bits.
        out.leafIndex = Hash.readBits32(digest, cursor, subtreeHeight);
        out.digest = digest;
    }

    // forsDigestBytes: Expand the digest stream used by FORS-C and the
    // hypertree.
    // Binds the grind counter that the FORS-C grinding rule iterates
    // [SHRINCS §9.2].
    // 1. Domain-separate the digest input as a FORS digest computation.
    // 2. Bind the public seed, public root, randomizer, and grind counter.
    // 3. Mix in the signed message bytes.
    // 4. Produce either one digest block or as many blocks as needed.
    // 5. Return exactly the requested number of digest bytes.
    /// @dev Precondition: pkSeed is exactly 32 bytes, validPublicKey-checked
    /// or a 32-byte key slice, as the fixed calldata read below assumes.
    function forsDigestBytes(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes calldata randomizer,
        uint32 counter,
        bytes memory message,
        uint256 digestBytes
    ) internal view returns (bytes memory out) {
        // Allocate the requested digest bytes plus one spare 32-byte word.
        // readBits32/64 loads a full 32-byte word at its byte offset, so it
        // may touch up to 31 bytes past the logical end of this buffer; the
        // spare word guarantees that slack is allocated, readable memory.
        out = new bytes(digestBytes + 32);
        uint256 messageLen = message.length;
        bytes32 profileId = SHRINCSParams.PROFILE_ID;
        // "fors-digest" || PROFILE_ID || pkSeed || hypertreeRoot ||
        // randomizer || counter || message. PROFILE_ID separates otherwise
        // identical verification parameter sets such as 128s-q18 and q20.
        uint256 baseLen = 143 + messageLen;
        // Reserve scratch covering roundup32(baseLen) plus one extra
        // word, so the whole-word message copy below (which rounds the
        // message length up to a 32-byte boundary) and the multi-block
        // counter suffix (a full-word mstore at offset baseLen) never
        // write above the free-memory pointer.
        uint256 scratchLen = ((baseLen + 31) & ~uint256(31)) + 32;
        uint256 ptr;
        // keccak256 input ("fors-digest" tag [§1 tags], baseLen bytes; a
        // 4-byte block counter is appended at [baseLen..baseLen+4) in the
        // multi-block path below):
        //   [0..11)      "fors-digest"
        //   [11..43)     PROFILE_ID
        //   [43..75)     pkSeed
        //   [75..107)    hypertreeRoot
        //   [107..139)   randomizer
        //   [139..143)   grind counter (big-endian uint32)
        //   [143..143+m) message (m = messageLen)
        // baseLen = 143 + messageLen; scratchLen bytes are reserved above.
        // Memory-safe: the whole scratch region is allocated by advancing
        // the free-memory pointer before any write, so the whole-word
        // message copy and the multi-block counter suffix stay at or below
        // the pointer.
        assembly ("memory-safe") {
            // Set the visible bytes length of the output buffer.
            mstore(out, digestBytes)
            // Reserve the scratch buffer at the free-memory pointer and
            // advance the pointer past it up front.
            ptr := mload(0x40)
            mstore(0x40, add(ptr, scratchLen))
            // Write the digest domain tag prefix.
            mstore(ptr, "fors-digest")
            // Bind the compiled profile immediately after the domain tag.
            mstore(add(ptr, 11), profileId)
            // Copy the 32-byte public seed after the profile identifier.
            calldatacopy(add(ptr, 43), pkSeed.offset, 32)
            // Copy the 32-byte hypertree root after the seed.
            calldatacopy(add(ptr, 75), hypertreeRoot.offset, 32)
            // Copy the 32-byte per-signature randomizer after the root.
            calldatacopy(add(ptr, 107), randomizer.offset, 32)
            // Write the 4-byte grind counter after the randomizer.
            mstore(add(ptr, 139), shl(224, counter))
            let src := add(message, 32)
            let dst := add(ptr, 143)
            let end := add(src, messageLen)
            // Copy the variable-length message body into the digest preimage.
            for {} lt(src, end) {} {
                // Copy one 32-byte chunk of the message into the scratch
                // buffer.
                mstore(dst, mload(src))
                // Advance to the next source chunk.
                src := add(src, 32)
                // Advance to the next destination chunk.
                dst := add(dst, 32)
            }
        }
        // Single-block fast path. digestBytes = ceil((k*a + h) / 8)
        // [SHRINCS §9.2], k = NUM_FORS_TREES, a = FORS_TREE_HEIGHT,
        // h = HYPERTREE_HEIGHT. 256s: (22*14+64+7)/8 = 47, so this branch
        // is unreachable there; kept as defense-in-depth. 128s-q18 and
        // 128s-q20: (6*24+18+7)/8 = 21, so this branch is the LIVE path
        // for those profiles, exercised by the 128s vector suites.
        // Python: (22*14 + 64 + 7) // 8, (6*24 + 18 + 7) // 8
        if (digestBytes <= 32) {
            // One digest block is enough for the whole FORS and hypertree
            // coordinate stream. The suite helper returns the raw block.
            bytes32 digestWord =
                HashSuite.hashForsDigestBlock32(ptr, baseLen);
            // Memory-safe: writes one word into the out buffer's payload
            // (allocated above).
            assembly ("memory-safe") {
                // Store that single digest block into the output bytes
                // payload.
                mstore(add(out, 32), digestWord)
            }
            return out;
        }
        // Add a 4-byte block counter suffix for multi-block expansion.
        uint256 totalLen = baseLen + 4;
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            // Emit only as many bytes as remain needed from this block.
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            // Memory-safe: writes the 4-byte block counter into the reserved
            // scratch (offset baseLen); scratchLen reserved above covers
            // baseLen + 32 bytes.
            assembly ("memory-safe") {
                // Append a block counter when more than one digest block is
                // needed.
                mstore(add(ptr, baseLen), shl(224, blockCounter))
            }
            // Hash the base preimage plus the 4-byte block counter suffix.
            // The suite helper returns the raw block.
            bytes32 digestWord =
                HashSuite.hashForsDigestBlock32(ptr, totalLen);
            // Copy only as many bytes as are still required from this digest
            // block.
            Hash.setHashChunk(out, digestWord, offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
    }
}
