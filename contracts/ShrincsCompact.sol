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

// JARDIN-style raw compact FORS-C verification.
//
// References:
// - JARDIN Section 3.3, Algorithms from forest-FORS to JARDIN:
//   https://notes.ethereum.org/@niard/JARDIN#33-Algorithms-from-forest-FORS-to-JARDIN
// - JARDIN Section 5, FORS+C parameter selection:
//   https://notes.ethereum.org/@niard/JARDIN#5-FORSC-Parameter-Selection
// - FIPS 205 Algorithms 14-17, FORS key generation/signing/verification:
//   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
// - Gas-oriented JARDIN prototype:
//   https://github.com/nconsigny/JARDIN/blob/main/src/JardinForsPlainVerifier.sol
library ShrincsCompact {
    // CompactDigestBytes: ceil(k * a / 8) for k=52 and a=5.
    uint16 internal constant CompactDigestBytes = 33;
    // CompactForsOffset: R(32) || uint32_be(counter).
    uint16 internal constant CompactForsOffset = 36;
    // CompactForsEntryBytes: secret leaf plus a=5 authentication nodes.
    uint16 internal constant CompactForsEntryBytes = 192;
    // CompactQOffset: byte offset of the balanced-tree leaf q.
    uint16 internal constant CompactQOffset = 9828;
    // CompactMerkleAuthOffset: byte offset of the h=7 balanced-tree auth path.
    uint16 internal constant CompactMerkleAuthOffset = 9829;
    // CompactSignatureBytes: 32 + 4 + 51 * (32 + 5 * 32) + 1 + 7 * 32.
    uint16 internal constant CompactSignatureBytes = 10053;
    // ForsPkInputBytes: pkSeed || FORS_ROOTS ADRS || 51 reconstructed roots.
    uint16 internal constant ForsPkInputBytes = 1696;

    // verifyCompactRaw: Verify the raw JARDIN Type 2 compact path.
    // Implements JARDIN Section 3.3 compact verification around FIPS 205 Algorithm 17.
    // The caller handles account context, compact-slot authorization, and nonce freshness.
    function verifyCompactRaw(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        internal
        pure
        returns (bool)
    {
        // Reject any signature that is not the fixed 10,053-byte compact shape.
        if (sig.length != CompactSignatureBytes) return false;

        // Load q, the 0-indexed balanced Merkle leaf and JARDIN ci value.
        uint32 q = sigQ(sig);
        // Reject q values outside the h=7 balanced Merkle tree.
        if (q >= ShrincsTypes.COMPACT_Q_MAX) return false;

        // Recompute JARDIN H_msg for the Type 2 message binding.
        bytes memory md = hMsg(pkSeed, pkRoot, message, sig);
        // FORS+C omits the final tree by forcing its a-bit index to zero.
        if (base2b(md, ShrincsTypes.COMPACT_OPEN_FORS_TREES) != 0) return false;

        // Rebuild the compact FORS+C public key from the 51 opened trees.
        bytes32 forsPk = forsPkFromSig(sig, md, pkSeed, q);
        // Rebuild the balanced 128-leaf Merkle root above that FORS+C key.
        bytes32 root = jardinRootFromAuthPath(sig, pkSeed, q, forsPk);

        // Accept only the compact path rooted at the supplied subPkRoot.
        return root == pkRoot;
    }

    // forsPkFromSig: Rebuild the FORS+C public key.
    // Implements FIPS 205 Algorithm 17, with JARDIN FORS+C opening only k-1 trees.
    function forsPkFromSig(bytes calldata sig, bytes memory md, bytes32 pkSeed, uint32 q)
        internal
        pure
        returns (bytes32 pk)
    {
        // Reserve one packed T_k input: pkSeed || ADRS(FORS_ROOTS) || roots.
        uint256 ptr;
        assembly {
            // Start the packed input at the current free-memory pointer.
            ptr := mload(0x40)
            // Reserve the packed input before helper hashes use free-memory scratch.
            mstore(0x40, add(ptr, and(add(ForsPkInputBytes, 31), not(31))))
            // Write pkSeed as the first T_k input field.
            mstore(ptr, pkSeed)
        }

        // Write ADRS(type=FORS_ROOTS, kp=0, ci=q, x=0, y=0).
        bytes32 rootsAdrs = adrs(ShrincsTypes.AddressTypeForsRoots, 0, q, 0, 0);
        assembly {
            // Store the JARDIN FORS_ROOTS address after pkSeed.
            mstore(add(ptr, 32), rootsAdrs)
        }

        // Reconstruct each opened FORS tree root and append it to the T_k input.
        for (uint32 i = 0; i < ShrincsTypes.COMPACT_OPEN_FORS_TREES;) {
            // FIPS base_2b selects the revealed leaf in this FORS tree.
            uint32 idx = base2b(md, i);
            // Rebuild the root for tree i from its secret leaf and auth path.
            bytes32 root = forsNodeFromSig(sig, pkSeed, q, i, idx);
            assembly {
                // Store the root after pkSeed || ADRS, preserving tree order.
                mstore(add(add(ptr, 64), mul(i, 32)), root)
            }
            unchecked {
                ++i;
            }
        }

        assembly {
            // JARDIN th_multi/T_k: keccak256(pkSeed || ADRS || root_0 || ...).
            pk := keccak256(ptr, ForsPkInputBytes)
        }
    }

    // forsNodeFromSig: Rebuild one opened FORS tree root from the raw signature.
    // Implements FIPS 205 Algorithm 17 lines 3-19, using Algorithm 15 node addresses.
    function forsNodeFromSig(bytes calldata sig, bytes32 pkSeed, uint32 q, uint32 i, uint32 idx)
        internal
        pure
        returns (bytes32 node)
    {
        // Locate the raw opening for FORS tree i.
        uint256 offset = uint256(CompactForsOffset) + uint256(i) * CompactForsEntryBytes;
        // Compute FIPS/JARDIN's continuous FORS leaf treeIndex.
        uint32 treeIndex = (i << ShrincsTypes.COMPACT_FORS_TREE_HEIGHT) + idx;
        // Load the revealed secret leaf directly from calldata.
        bytes32 sk = calldataWord(sig, offset);
        // Hash the revealed secret leaf into its FORS public leaf.
        node = f(pkSeed, adrs(ShrincsTypes.AddressTypeForsTree, 0, q, 0, treeIndex), sk);

        // Walk the a=5 authentication path to the root of this FORS tree.
        for (uint32 j = 0; j < ShrincsTypes.COMPACT_FORS_TREE_HEIGHT;) {
            // Load the sibling for this level directly from calldata.
            bytes32 auth = calldataWord(sig, offset + 32 + uint256(j) * 32);
            // Use the current low bit to choose FIPS left/right child order.
            (bytes32 left, bytes32 right) = idx & 1 == 0 ? (node, auth) : (auth, node);
            // Move one level upward in this FORS tree.
            uint32 height = j + 1;
            // Collapse the selected node index to its parent.
            idx >>= 1;
            // Keep y continuous across all FORS trees, as in FIPS Algorithms 14-17.
            treeIndex = (i << (ShrincsTypes.COMPACT_FORS_TREE_HEIGHT - height)) + idx;
            // Hash this parent under ADRS(type=FORS_TREE, ci=q, x=height, y=treeIndex).
            node = h(pkSeed, adrs(ShrincsTypes.AddressTypeForsTree, 0, q, height, treeIndex), left, right);
            unchecked {
                ++j;
            }
        }
    }

    // jardinRootFromAuthPath: Rebuild the JARDIN balanced Merkle root.
    // Implements the Section 3.3 balanced Merkle path using type=JARDIN_MERKLE.
    function jardinRootFromAuthPath(bytes calldata sig, bytes32 pkSeed, uint32 q, bytes32 forsPk)
        internal
        pure
        returns (bytes32 node)
    {
        // Start at the compact FORS+C public key for lane q.
        node = forsPk;

        // Fold h=7 siblings from the compact lane to subPkRoot.
        for (uint32 j = 0; j < ShrincsTypes.COMPACT_MERKLE_HEIGHT;) {
            // Load this balanced-tree sibling from the raw signature tail.
            bytes32 auth = calldataWord(sig, uint256(CompactMerkleAuthOffset) + uint256(j) * 32);
            // Use q bit j to choose the left/right child order.
            (bytes32 left, bytes32 right) = q & (uint32(1) << j) == 0 ? (node, auth) : (auth, node);
            // JARDIN labels levels from root downward in the compact Merkle ADRS x field.
            uint32 level = uint32(ShrincsTypes.COMPACT_MERKLE_HEIGHT) - 1 - j;
            // The compact Merkle ADRS y field is the parent node index.
            uint32 nodeIndex = q >> (j + 1);
            // Hash this parent under ADRS(type=JARDIN_MERKLE, ci=0, x=level, y=nodeIndex).
            node = h(pkSeed, adrs(ShrincsTypes.AddressTypeJardinMerkle, 0, 0, level, nodeIndex), left, right);
            unchecked {
                ++j;
            }
        }
    }

    // hMsg: Compute the JARDIN Type 2 compact digest stream.
    // Implements H_msg(R, pkSeed, pkRoot, uint32_be(counter) || M*) with Keccak blocks.
    function hMsg(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        internal
        pure
        returns (bytes memory out)
    {
        // Allocate exactly the 33 digest bytes needed for k=52 and a=5.
        out = new bytes(CompactDigestBytes);
        assembly {
            // Allocate scratch after the digest bytes.
            let ptr := mload(0x40)
            // Write the H_msg domain tag.
            mstore(ptr, "JARDIN/H_MSG/v1")
            // Copy R from the raw signature.
            calldatacopy(add(ptr, 15), sig.offset, 32)
            // Bind the compact public seed.
            mstore(add(ptr, 47), pkSeed)
            // Bind the compact public root.
            mstore(add(ptr, 79), pkRoot)
            // Copy uint32_be(counter) from the raw signature.
            calldatacopy(add(ptr, 111), add(sig.offset, 32), 4)
            // Write M*'s Type 2 domain tag.
            mstore(add(ptr, 115), "JARDIN/TYPE2/v1")
            // Bind subPkSeed inside M*.
            mstore(add(ptr, 130), pkSeed)
            // Bind subPkRoot inside M*.
            mstore(add(ptr, 162), pkRoot)
            // Copy q into M*.
            calldatacopy(add(ptr, 194), add(sig.offset, CompactQOffset), 1)
            // Bind the caller-supplied account/action message hash.
            mstore(add(ptr, 195), message)
            // Append uint32_be(0) for digest block 0.
            mstore(add(ptr, 227), 0)
            // Fill the first 32 digest bytes.
            mstore(add(out, 32), keccak256(ptr, 231))
            // Append uint32_be(1) for digest block 1.
            mstore(add(ptr, 227), shl(224, 1))
            // Copy only the one remaining digest byte.
            mstore8(add(out, 64), byte(0, keccak256(ptr, 231)))
            // Bump the free-memory pointer past the whole-word counter write.
            mstore(0x40, add(ptr, 288))
        }
    }

    // base2b: Read one a-bit FORS index from md.
    // Implements FIPS 205 base_2b for this profile's b=a=5.
    function base2b(bytes memory md, uint32 i) internal pure returns (uint32 idx) {
        // Compute the bit position of the i-th 5-bit digit.
        uint256 startBit = uint256(i) * ShrincsTypes.COMPACT_FORS_TREE_HEIGHT;
        // Compute the byte containing that bit.
        uint256 byteOffset = startBit >> 3;
        // Compute the bit position inside that byte.
        uint256 bitOffset = startBit & 7;
        assembly {
            // Load the digest word beginning at byteOffset.
            let word := mload(add(add(md, 32), byteOffset))
            // Align the selected five bits to the low end.
            idx := and(shr(sub(251, bitOffset), word), 31)
        }
    }

    // sigQ: Load q from the raw compact signature.
    function sigQ(bytes calldata sig) internal pure returns (uint32 q) {
        assembly {
            // Extract q as the first byte at CompactQOffset.
            q := byte(0, calldataload(add(sig.offset, CompactQOffset)))
        }
    }

    // calldataWord: Load one aligned 32-byte compact signature word.
    function calldataWord(bytes calldata sig, uint256 offset) internal pure returns (bytes32 word) {
        assembly {
            // Load one 32-byte field from the raw signature.
            word := calldataload(add(sig.offset, offset))
        }
    }

    // adrs: Pack JARDIN's 32-byte ADRS.
    // ADRS = layer:4 || tree:8 || type:4 || kp:4 || ci:4 || x:4 || y:4.
    function adrs(uint32 addressType, uint32 kp, uint32 ci, uint32 x, uint32 y) internal pure returns (bytes32) {
        // Place type below the zero layer/tree prefix.
        uint256 value = uint256(addressType) << 128;
        // Place kp below type.
        value |= uint256(kp) << 96;
        // Place ci below kp.
        value |= uint256(ci) << 64;
        // Place x below ci.
        value |= uint256(x) << 32;
        // Place y in the low word.
        value |= uint256(y);
        // Return the packed address word.
        return bytes32(value);
    }

    // f: JARDIN/FIPS tweakable hash for one FORS leaf input.
    function f(bytes32 pkSeed, bytes32 addressWord, bytes32 input) internal pure returns (bytes32 out) {
        assembly {
            // Use transient free-memory scratch.
            let ptr := mload(0x40)
            // Write pkSeed.
            mstore(ptr, pkSeed)
            // Write ADRS.
            mstore(add(ptr, 32), addressWord)
            // Write the revealed secret leaf.
            mstore(add(ptr, 64), input)
            // th(seed, ADRS, input).
            out := keccak256(ptr, 96)
        }
    }

    // h: JARDIN/FIPS tweakable hash for two child nodes.
    function h(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right) internal pure returns (bytes32 out) {
        assembly {
            // Use transient free-memory scratch.
            let ptr := mload(0x40)
            // Write pkSeed.
            mstore(ptr, pkSeed)
            // Write ADRS.
            mstore(add(ptr, 32), addressWord)
            // Write the left child.
            mstore(add(ptr, 64), left)
            // Write the right child.
            mstore(add(ptr, 96), right)
            // th_pair(seed, ADRS, left, right).
            out := keccak256(ptr, 128)
        }
    }
}
