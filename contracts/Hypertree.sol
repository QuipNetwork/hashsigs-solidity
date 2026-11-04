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
import {StatelessLayout} from "./StatelessLayout.sol";

library Hypertree {
    // AddressTypeWotsPk: the WOTS public-key compression ADRS type constant
    // [FIPS205 §4.2] (value 1).
    uint32 internal constant AddressTypeWotsPk = 1;
    // AddressTypeTree: the tree ADRS type constant [FIPS205 §4.2]
    // (value 2) for the SPHINCS-style keyed hash inputs.
    uint32 internal constant AddressTypeTree = 2;

    // wotsDigestBytes: Return the number of bytes needed to encode all WOTS-C
    // digits.
    // 1. Choose the number of bits per base-w digit from the chain length.
    // 2. Multiply by the number of WOTS chains.
    // 3. Round up to a whole number of bytes.
    function wotsDigestBytes() internal pure returns (uint256) {
        uint256 bitsPerDigit = SHRINCSParams.WOTS_CHAIN_LEN == 256 ? 8 : 4;
        return
            (uint256(SHRINCSParams.NUM_WOTS_CHAINS) * bitsPerDigit + 7) / 8;
    }

    // verifyHypertree: Verify every SHRINCS hypertree layer from the FORS
    // root to the public root. `hypertree` is the fixed-layout hypertree
    // slice of a StatelessLayout payload, layer j at j * LAYER_LEN.
    // 1. Reject any slice whose length is not exactly HYPERTREE_LEN.
    // 2. Seed the expected subtree coordinates from the caller-supplied
    // FORS-derived coordinates (not carried in the signature).
    // 3. Verify each layer's WOTS-C signature against the running
    // message/root value.
    // 4. Rebuild the XMSS-style subtree root from the revealed auth path.
    // 5. Derive the next layer's expected coordinates from the current tree
    // index.
    // 6. Accept only if the final reconstructed root matches the installed
    // hypertree root.
    /// @dev Never reverts on malformed input: the length check is the only
    /// input guard, and it proves every fixed-offset read below in bounds.
    function verifyHypertree(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes32 forsRoot,
        uint64 seedTreeIndex,
        uint32 seedLeafIndex,
        bytes calldata hypertree
    ) internal view returns (bool) {
        // The single input guard: the slice must be exactly
        // NUM_HYPERTREE_LAYERS fixed-width layers. Every field in a layer has
        // one width, so this one check fixes the layer count, chain count
        // and auth-path length at once.
        if (hypertree.length != StatelessLayout.HYPERTREE_LEN) return false;
        // Each subtree has height h / d in the supported balanced hypertree
        // layout.
        // casting to 'uint32' is safe because the subtree height h / d is
        // at most HYPERTREE_HEIGHT, a uint8
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 subtreeHeight = uint32(StatelessLayout.SUBTREE_HEIGHT);
        // Mask off one subtree-height slice of tree-index bits at a time.
        uint64 leafMask = uint64((uint256(1) << subtreeHeight) - 1);
        // The hypertree coordinates are not carried in the layer signature.
        // Layer 0 starts from the FORS-digest-derived coordinates the caller
        // passes in; each upper layer is then derived by the shift/mask
        // recurrence below, so the derived value is the sole coordinate
        // input and a signature cannot verify under any coordinate other
        // than the one the FORS digest dictates.
        uint64 expectedTreeIndex = seedTreeIndex;
        uint32 expectedLeafIndex = seedLeafIndex;
        // Carry the FORS root upward as the running message/root value.
        bytes32 current = forsRoot;

        for (uint256 layer = 0; layer < SHRINCSParams.NUM_HYPERTREE_LAYERS;) {
            // Locate this layer's fixed-width slice: layer j starts at
            // j * LAYER_LEN.
            uint256 start = layer * StatelessLayout.LAYER_LEN;
            bytes calldata layerSig =
                hypertree[start:start + StatelessLayout.LAYER_LEN];
            // casting to 'uint32' is safe because layer is bounded by
            // NUM_HYPERTREE_LAYERS, a uint8
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 layerIndex = uint32(layer);
            // Deviates from [FIPS205 §8.2]: SHRINCS chains the hypertree
            // coordinates sequentially per layer instead of following the
            // FIPS-205 tree/leaf index recurrence. Layer 0 uses the
            // FORS-derived coordinate; each upper layer's coordinate is
            // derived from the lower layer's tree index (see the right-shift
            // below), binding every layer's address to the derived value.
            // Verify the WOTS-C layer signature against the current carried
            // value.
            if (!_verifyWotsC32(
                    pkSeed,
                    layerIndex,
                    expectedTreeIndex,
                    expectedLeafIndex,
                    current,
                    layerSig
                )) return false;

            // The auth path is the layer's tail: h' 32-byte sibling words
            // from LAYER_AUTH_PATH_OFFSET to LAYER_LEN.
            bytes calldata authPath =
                layerSig[StatelessLayout.LAYER_AUTH_PATH_OFFSET:];
            // The 32-byte WOTS-C public-key hash becomes the subtree leaf
            // value.
            bytes32 leaf = StatelessLayout.readWord(
                layerSig, StatelessLayout.LAYER_PK_HASH_OFFSET
            );
            // Rebuild the subtree root above this WOTS-C leaf and carry it
            // into the next layer.
            current = _hypertreeRootFromPath32(
                subtreeHeight,
                pkSeed,
                layerIndex,
                expectedTreeIndex,
                expectedLeafIndex,
                leaf,
                authPath
            );

            // The next layer's leaf index comes from the low subtree-height
            // bits of the current tree index.
            // casting to 'uint32' is safe because leafMask keeps only
            // subtreeHeight bits
            // forge-lint: disable-next-line(unsafe-typecast)
            expectedLeafIndex = uint32(expectedTreeIndex & leafMask);
            // Shift away this layer's subtree bits to get the next layer's
            // tree index.
            expectedTreeIndex >>= subtreeHeight;
            unchecked {
                ++layer;
            }
        }

        // Accept only if the top reconstructed root equals the installed
        // 32-byte hypertree root.
        return current == StatelessLayout.readWord(hypertreeRoot, 0);
    }

    // _verifyWotsC32: Verify one compressed stateless WOTS-C signature inside
    // a hypertree layer.
    // WOTS-C (WOTS+C in [SPHINCSPLUSC §3]): a fixed target-sum check
    // replaces the WOTS checksum chains. Construction: [SHRINCS §5].
    // 1. Check the WOTS-C digest width assumption.
    // 2. Read the public seed, expected public-key hash, randomizer, and
    // counter from the fixed-layout layer slice.
    // 3. Recompute the WOTS-C message digest that selects one base-w digit
    // per chain.
    // 4. Advance each revealed chain value to its endpoint to reconstruct the
    // compressed public key.
    // 5. Enforce the fixed WOTS-C digit-sum constraint used instead of an
    // explicit checksum suffix.
    // 6. Hash the reconstructed segments and compare them to the expected
    // public-key hash.
    /// @dev Private: no length check of its own. Precondition:
    /// layerSig.length == StatelessLayout.LAYER_LEN and pkSeedBytes is a
    /// 32-byte slice, both guaranteed by verifyHypertree, its only caller.
    /// See DECISIONS_REQUIRED.md before making this internal.
    function _verifyWotsC32(
        bytes calldata pkSeedBytes,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes32 message,
        bytes calldata layerSig
    ) private view returns (bool) {
        uint256 chainCount = uint256(SHRINCSParams.NUM_WOTS_CHAINS);
        // The base-w digits are read from the first len/2 bytes of the
        // 32-byte digest word (baseW16Digit32). A profile whose digest
        // needs more than one 32-byte word is unsupported here; the
        // exact per-profile expectation is asserted by the profile-
        // invariants test ([DESIGN §3.3/§3.5]). For every supported
        // profile wotsDigestBytes() <= 32, so this folds to false.
        if (wotsDigestBytes() > 32) return false;

        // Load the 32-byte public seed.
        bytes32 pkSeed = StatelessLayout.readWord(pkSeedBytes, 0);
        // Load the expected compressed WOTS-C public-key hash.
        bytes32 expectedPkHash = StatelessLayout.readWord(
            layerSig, StatelessLayout.LAYER_PK_HASH_OFFSET
        );
        // Recompute the digest whose base-w digits determine chain stopping
        // points, from the 32-byte randomizer and the 4-byte grinding
        // counter read at their fixed layer offsets.
        bytes32 digest = HashSuite.wotsDigest32(
            pkSeed,
            expectedPkHash,
            StatelessLayout.readWord(
                layerSig, StatelessLayout.LAYER_RANDOMIZER_OFFSET
            ),
            StatelessLayout.readUint32(
                layerSig, StatelessLayout.LAYER_COUNTER_OFFSET
            ),
            message
        );
        // "wots-c-pk" || pkSeed || WOTS_PK ADRS || segment_0 || ...
        uint256 pkInputLen = 73 + chainCount * 32;
        uint256 pkInput;
        // keccak256 input ("wots-c-pk" tag [§1 tags], pkInputLen bytes):
        //   [0..9)          "wots-c-pk"
        //   [9..41)         pkSeed
        //   [41..73)        WOTS_PK address (type 1)
        //   [73..73+32*len) reconstructed chain endpoints (len = chainCount)
        // pkInputLen = 73 + chainCount * 32.
        // Memory-safe: allocates roundup32(pkInputLen) bytes at the
        // free-memory pointer and advances the pointer past them; the loop
        // below fills the endpoints and the final hash reads exactly
        // pkInputLen bytes.
        assembly ("memory-safe") {
            // Allocate a scratch buffer starting at the free-memory pointer.
            pkInput := mload(0x40)
            // Write the domain tag prefix for compressed WOTS-C public-key
            // hashing.
            mstore(pkInput, "wots-c-pk")
            // Write the public seed immediately after the 9-byte tag.
            mstore(add(pkInput, 9), pkSeed)
            // Bind the compression to this WOTS key's position. Chain and
            // step fields remain zero for the WOTS_PK address type.
            // ADRS bit layout [FIPS205 §4.2]: layer<<224 | tree<<128 |
            // type<<96 | keypair<<64 | chain<<32 | step
            mstore(
                add(pkInput, 41),
                or(
                    or(shl(224, layer), shl(128, tree)),
                    or(shl(96, AddressTypeWotsPk), shl(64, keypair))
                )
            )
            // Bump the free-memory pointer to the next 32-byte aligned slot
            // after this buffer.
            mstore(0x40, add(pkInput, and(add(pkInputLen, 31), not(31))))
        }

        // Encode the location shared by all chains in this WOTS key:
        //   layer << 224 | tree << 128 | keypair << 64
        // (ADRS layout [FIPS205 §4.2]; chain and step are set per chain).
        uint256 addressBase = (uint256(layer) << 224)
            | (uint256(tree) << 128) | (uint256(keypair) << 64);
        uint32 digitSum;
        for (uint256 i = 0; i < chainCount;) {
            // Read the digest-selected base-w digit for this chain.
            uint32 digit = WOTSPlusC.baseW16Digit32(digest, i);
            // Accumulate the fixed WOTS-C target-sum check.
            digitSum += digit;
            // Complete the chain from the revealed value to its endpoint.
            // The revealed starting value for chain `i` sits at
            // LAYER_CHAINS_OFFSET + i * 32.
            bytes32 segment = WOTSPlusC.wotsChainNoMaskBase(
                WOTSPlusC.WOTS_C_CHAIN_TAG,
                WOTSPlusC.WOTS_C_CHAIN_TAG_LEN,
                SHRINCSParams.WOTS_CHAIN_LEN,
                pkSeed,
                addressBase,
                // casting to 'uint32' is safe because i ranges over the
                // fixed NUM_WOTS_CHAINS chains
                // forge-lint: disable-next-line(unsafe-typecast)
                uint32(i),
                StatelessLayout.readWord(
                    layerSig, StatelessLayout.LAYER_CHAINS_OFFSET + i * 32
                ),
                digit
            );
            // Memory-safe: writes one 32-byte endpoint into the pkInput
            // buffer allocated above (slot 73 + i*32).
            assembly ("memory-safe") {
                // Write this reconstructed chain endpoint after the fixed
                // tag-and-seed prefix.
                mstore(add(add(pkInput, 73), mul(i, 32)), segment)
            }
            unchecked {
                ++i;
            }
        }
        // WOTS-C does not carry an explicit checksum chain suffix. Instead
        // the message expansion is accepted only when the reconstructed
        // base-w digits add up to the fixed target sum ([SHRINCS §5]).
        // This is the stateless hypertree WOTS-C check (chainCount =
        // NUM_WOTS_CHAINS), so it compares against the matching
        // stateless target sum, not the stateful side's constant.
        if (digitSum != SHRINCSParams.WOTS_TARGET_SUM_STATELESS) {
            return false;
        }

        // Hash the reconstructed chain endpoints into the compressed WOTS-C
        // public-key hash. The buffer above is suite-independent; only this
        // finalizer swaps per suite. Output truncated to HASH_LEN bytes,
        // high-aligned (maskHash inside the suite helper); 256s no-op.
        return HashSuite.hashWotsCPk32(pkInput, pkInputLen) == expectedPkHash;
    }

    // _hypertreeRootFromPath32: Rebuild one XMSS-style subtree root from a
    // leaf value and auth path. `authPath` is height consecutive 32-byte
    // sibling words.
    // 1. Construct the shared tree-hash address prefix for this layer and
    // tree.
    // 2. Walk upward from the supplied leaf one level at a time.
    // 3. Rebuild each parent node with the correct left/right ordering and
    // address.
    // 4. Return the reconstructed subtree root.
    /// @dev Private: no length check of its own. Precondition:
    /// authPath.length == height * 32 and pkSeed is a 32-byte slice, both
    /// guaranteed by verifyHypertree, its only caller. See
    /// DECISIONS_REQUIRED.md before making this internal.
    function _hypertreeRootFromPath32(
        uint32 height,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes32 leaf,
        bytes calldata authPath
    ) private view returns (bytes32 node) {
        // Load the 32-byte public seed once for repeated subtree hashing.
        bytes32 pkSeedWord = StatelessLayout.readWord(pkSeed, 0);
        // Shared address prefix for this layer and tree:
        //   layer << 224      (hypertree layer)
        //   treeIndex << 128  (hypertree tree index)
        //   TREE << 96        (tree-hash address type, domain separation)
        uint256 addressBase = (uint256(layer) << 224)
            | (uint256(treeIndex) << 128)
            | (uint256(Hypertree.AddressTypeTree) << 96);
        // Start the upward walk from the supplied leaf value.
        node = leaf;
        uint256 index = leafIndex;
        for (uint256 level = 0; level < height;) {
            // Read the sibling node supplied for this subtree level: auth
            // node `level` sits at level * 32.
            bytes32 sibling = StatelessLayout.readWord(authPath, level * 32);
            // Place the current node and sibling in canonical left/right
            // order for this level.
            (bytes32 left, bytes32 right) =
                index & 1 == 0 ? (node, sibling) : (sibling, node);
            // Parent address:
            //   nodeHeight  = level + 1  (parents sit one level higher)
            //   parentIndex = index >> 1  (collapse to the parent)
            //   address     = addressBase | nodeHeight << 32 | parentIndex
            bytes32 addressWord =
                bytes32(addressBase | ((level + 1) << 32) | (index >> 1));
            // Hash the two children into their parent node using it.
            node = HashSuite.hashHypertreeNode32(
                pkSeedWord, addressWord, left, right
            );
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }
}
