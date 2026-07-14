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

import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {ShrincsTypes} from "../../contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "../../contracts/ShrincsUtils.sol";

/// @notice TEST-ONLY Solidity signer helpers that mirror the Rust signer for stateless and compact flows.
/// @dev This library is kept under `test/helpers` so it does not become part of the
/// production Solidity surface.
library ShrincsTestSigner {
    uint32 internal constant WOTS_C_MAX_GRIND_COUNTER = 1 << 24;
    // COMPACT_C_MAX_GRIND_COUNTER: Test-only bound for finding the omitted FORS+C tree.
    uint32 internal constant COMPACT_C_MAX_GRIND_COUNTER = 1 << 16;
    // Raw compact signature layout:
    //   R32 || counter4 || openedFORS[51] || q1 || merkleAuth[7].
    // Compact parameters are n=32, k=52, a=5, opened trees=51, and outer Merkle h=7.
    // COMPACT_DIGEST_BYTES = ceil(k * a / 8) = ceil(52 * 5 / 8) = 33.
    uint16 internal constant COMPACT_DIGEST_BYTES = 33;
    // COMPACT_FORS_OFFSET = len(R32 || counter4) = 32 + 4 = 36.
    uint16 internal constant COMPACT_FORS_OFFSET = 36;
    // COMPACT_FORS_ENTRY_BYTES = secretLeaf32 + authPath(5 * 32) = 192.
    uint16 internal constant COMPACT_FORS_ENTRY_BYTES = 192;
    // COMPACT_Q_OFFSET = 36 + 51 * 192 = 9828.
    uint16 internal constant COMPACT_Q_OFFSET = 9828;
    // COMPACT_MERKLE_AUTH_OFFSET = COMPACT_Q_OFFSET + q1 = 9829.
    uint16 internal constant COMPACT_MERKLE_AUTH_OFFSET = 9829;
    // COMPACT_SIGNATURE_BYTES = 32 + 4 + 51 * 192 + 1 + 7 * 32 = 10053.
    uint16 internal constant COMPACT_SIGNATURE_BYTES = 10053;
    // COMPACT_FORS_PK_INPUT_BYTES = pkSeed32 || FORS_ROOTS_ADRS32 || roots[51]32 = 1696.
    uint16 internal constant COMPACT_FORS_PK_INPUT_BYTES = 1696;
    uint8 internal constant NUM_HYPERTREE_LAYERS = 8;

    // keygen: Build a deterministic stateless SHRINCS test key bundle from seed material.
    // 1. Derive independent stateless and public seeds.
    // 2. Build the stateless hypertree root.
    // 3. Return the public pkSeed/root pair used by account wrappers.
    function keygen(bytes memory seedMaterial)
        internal
        pure
        returns (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok)
    {
        // Derive the stateless FORS/WOTS hypertree secret seed.
        bytes32 statelessSkSeed = derive32("shrincs-stateless-sk-seed", seedMaterial, "");
        // Derive the stateless message-randomization seed.
        bytes32 statelessPrfSeed = derive32("shrincs-stateless-prf-seed", seedMaterial, "");
        // Derive the shared public seed for stateless hashes.
        bytes32 pkSeed = derive32("shrincs-pk-seed", seedMaterial, "");
        // Compute the deterministic virtual hypertree root for this test key.
        bytes32 hypertreeRoot = hypertreePublicRoot(statelessSkSeed, pkSeed);

        // Store all signing material needed by the test-only signer helpers.
        signingKey = ShrincsTypes.SigningKey({
            statelessSkSeed: statelessSkSeed,
            statelessPrfSeed: statelessPrfSeed,
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });

        // Build the public key object consumed by tests and account wrappers.
        publicKey =
            ShrincsTypes.PublicKey({pkSeed: abi.encodePacked(pkSeed), hypertreeRoot: abi.encodePacked(hypertreeRoot)});
        return (signingKey, publicKey, true);
    }

    // derive32: Deterministically derive one fixture word under a human-readable domain.
    function derive32(bytes memory domain, bytes memory seed, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, seed, data));
    }

    // compactSingleLaneKeygen: Build a deterministic JARDIN compact key for lane q.
    // 1. Derive compact SK.seed and PK.seed from the fixture seed.
    // 2. Materialize all 128 FORS+C lane public keys and commit them to subPkRoot.
    function compactSingleLaneKeygen(bytes memory seedMaterial, uint8 q)
        internal
        pure
        returns (bytes32 skSeed, bytes32 pkSeed, bytes32 pkRoot, bool ok)
    {
        // Compact q is encoded as one byte but only 128 Merkle leaves are supported.
        if (q >= ShrincsTypes.COMPACT_Q_MAX) return (bytes32(0), bytes32(0), bytes32(0), false);
        // Derive the compact FORS+C secret seed from the fixture seed.
        skSeed = derive32("shrincs-compact-sk-seed", seedMaterial, "");
        // Derive the compact public seed used by tweakable hashes.
        pkSeed = derive32("shrincs-compact-pk-seed", seedMaterial, "");
        // Commit all 128 lane FORS+C public keys through the 7-level compact Merkle tree.
        (pkRoot,) = compactMerkleRootAndAuth(skSeed, pkSeed, q);
        return (skSeed, pkSeed, pkRoot, true);
    }

    // signCompactAction: Sign a canonical compact account action with the raw Type 2 fixture signer.
    function signCompactAction(
        bytes32 skSeed,
        bytes32 pkSeed,
        bytes32 pkRoot,
        ShrincsTypes.ActionContext memory context,
        uint8 q
    ) internal pure returns (bytes memory signature, bool ok) {
        // The account layer signs the compact action hash; the raw compact signer handles Type 2.
        return signCompactRaw(skSeed, pkSeed, pkRoot, SHRINCS.compactActionMessageHash(context), q);
    }

    // signCompactActionWithAuth: Sign a compact action with a precomputed Merkle path.
    function signCompactActionWithAuth(
        bytes32 skSeed,
        bytes32 pkSeed,
        bytes32 pkRoot,
        ShrincsTypes.ActionContext memory context,
        uint8 q,
        bytes32[7] memory merkleAuth
    ) internal pure returns (bytes memory signature, bool ok) {
        // Reuse the caller-supplied Merkle path; verification still checks the final root.
        return signCompactRawWithAuth(skSeed, pkSeed, pkRoot, SHRINCS.compactActionMessageHash(context), q, merkleAuth);
    }

    // signCompactRaw: Build the fixed 10,053-byte JARDIN Type 2 compact signature.
    // 1. Grind H_msg until the omitted FORS+C tree selects leaf zero.
    // 2. Write 51 FORS+C openings for the selected digest digits.
    // 3. Append q and the 7-node compact Merkle authentication path.
    function signCompactRaw(bytes32 skSeed, bytes32 pkSeed, bytes32 pkRoot, bytes32 message, uint8 q)
        internal
        pure
        returns (bytes memory signature, bool ok)
    {
        // Reject out-of-range compact Merkle leaves before deriving any signature bytes.
        if (q >= ShrincsTypes.COMPACT_Q_MAX) return (signature, false);

        // Build the real JARDIN compact Merkle auth path from all 128 lane public keys.
        (bytes32 computedRoot, bytes32[7] memory merkleAuth) = compactMerkleRootAndAuth(skSeed, pkSeed, q);
        if (computedRoot != pkRoot) return (signature, false);

        return signCompactRawWithAuth(skSeed, pkSeed, pkRoot, message, q, merkleAuth);
    }

    // signCompactRawWithAuth: Build a compact signature using a supplied Merkle path.
    function signCompactRawWithAuth(
        bytes32 skSeed,
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        uint8 q,
        bytes32[7] memory merkleAuth
    ) internal pure returns (bytes memory signature, bool ok) {
        // Reject out-of-range compact Merkle leaves before deriving any signature bytes.
        if (q >= ShrincsTypes.COMPACT_Q_MAX) return (signature, false);

        // Use deterministic fixture randomness so tests are reproducible.
        bytes32 randomizer = keccak256(abi.encodePacked("jardin-r", skSeed, pkSeed, pkRoot, q, message));
        // md is the 33-byte H_msg digest interpreted as 52 base-32 FORS digits.
        bytes memory md;
        // counter is encoded as uint32_be immediately after R in the raw compact signature.
        uint32 counter;
        // Grind until the omitted 52nd FORS tree has digit zero, matching the FORS+C rule.
        for (; counter < COMPACT_C_MAX_GRIND_COUNTER;) {
            // Recompute H_msg for this candidate counter.
            md = compactHMsg(pkSeed, pkRoot, message, randomizer, counter, q);
            // The omitted tree is index 51; accept only when its selected leaf is zero.
            if (compactBase2b(md, ShrincsTypes.COMPACT_OPEN_FORS_TREES) == 0) break;
            unchecked {
                // The loop bound above makes this increment safe.
                ++counter;
            }
        }
        // Fail if no acceptable counter was found inside the test-only search bound.
        if (counter == COMPACT_C_MAX_GRIND_COUNTER) return (signature, false);

        // Allocate the exact fixed-length raw compact signature buffer.
        signature = new bytes(COMPACT_SIGNATURE_BYTES);
        // Write R at byte offset 0.
        setSlice32(signature, randomizer, 0);
        // Write uint32_be(counter) at byte offset 32.
        setUint32(signature, 32, counter);
        // Write q at byte offset 9828.
        setUint8(signature, COMPACT_Q_OFFSET, q);

        // Write the 51 opened FORS+C leaves and auth paths.
        for (uint32 i = 0; i < ShrincsTypes.COMPACT_OPEN_FORS_TREES;) {
            // Read the selected 5-bit leaf digit for FORS tree i.
            uint32 idx = compactBase2b(md, i);
            // Hold the 5 sibling nodes for this FORS tree's auth path.
            bytes32[5] memory auth;
            // Hold the secret leaf revealed by this FORS opening.
            bytes32 secret;
            // Derive the selected secret leaf and its auth path.
            (secret, auth) = compactForsSecretAndAuth(skSeed, pkSeed, q, i, idx);
            // Each FORS entry is secretLeaf32 || auth[5]32.
            uint256 offset = uint256(COMPACT_FORS_OFFSET) + uint256(i) * COMPACT_FORS_ENTRY_BYTES;
            // Write the revealed FORS secret leaf.
            setSlice32(signature, secret, offset);
            // Write the five authentication siblings immediately after the secret leaf.
            for (uint32 j = 0; j < ShrincsTypes.COMPACT_FORS_TREE_HEIGHT;) {
                // auth[j] begins at entry offset + 32 + j * 32.
                setSlice32(signature, auth[j], offset + 32 + uint256(j) * 32);
                unchecked {
                    // The loop bound is the fixed FORS tree height.
                    ++j;
                }
            }
            unchecked {
                // The loop bound is the fixed count of opened FORS trees.
                ++i;
            }
        }

        // Append the 7-node compact Merkle authentication path.
        for (uint32 j = 0; j < ShrincsTypes.COMPACT_MERKLE_HEIGHT;) {
            // Each Merkle sibling occupies one 32-byte word after q.
            setSlice32(signature, merkleAuth[j], uint256(COMPACT_MERKLE_AUTH_OFFSET) + uint256(j) * 32);
            unchecked {
                // The loop bound is the fixed compact Merkle height.
                ++j;
            }
        }

        return (signature, true);
    }

    // compactMerkleRootAndAllAuth: Compute one root and every q authentication path.
    function compactMerkleRootAndAllAuth(bytes32 skSeed, bytes32 pkSeed)
        internal
        pure
        returns (bytes32 root, bytes32[7][128] memory authPaths)
    {
        // Materialize every JARDIN compact Merkle leaf as a FORS+C public key once.
        bytes32[128] memory nodes;
        for (uint32 lane = 0; lane < ShrincsTypes.COMPACT_Q_MAX;) {
            // Each lane has ci=q inside its FORS addresses.
            nodes[lane] = compactForsPk(skSeed, pkSeed, uint8(lane));
            unchecked {
                // The loop bound is the fixed 128-lane compact tree.
                ++lane;
            }
        }

        // Fold the tree upward while recording every lane's sibling at each level.
        uint32 nodeCount = ShrincsTypes.COMPACT_Q_MAX;
        for (uint32 j = 0; j < ShrincsTypes.COMPACT_MERKLE_HEIGHT;) {
            // Every lane reads the sibling beside its current path node.
            for (uint32 lane = 0; lane < ShrincsTypes.COMPACT_Q_MAX;) {
                // q's path index at level j is q >> j.
                authPaths[lane][j] = nodes[(lane >> j) ^ 1];
                unchecked {
                    // The loop bound is the fixed 128-lane compact tree.
                    ++lane;
                }
            }

            // JARDIN ADRS x uses top-down level numbering for Merkle parents.
            uint32 level = uint32(ShrincsTypes.COMPACT_MERKLE_HEIGHT) - 1 - j;
            // Fold adjacent pairs into the next parent level.
            for (uint32 parent = 0; parent < nodeCount >> 1;) {
                // JARDIN ADRS y is the parent index at this level.
                nodes[parent] = compactH(
                    pkSeed,
                    compactAdrs(ShrincsTypes.AddressTypeJardinMerkle, 0, 0, level, parent),
                    nodes[parent << 1],
                    nodes[(parent << 1) | 1]
                );
                unchecked {
                    // The loop bound is the parent count at this level.
                    ++parent;
                }
            }
            // The active node count halves at each Merkle level.
            nodeCount >>= 1;
            unchecked {
                // The loop bound is the fixed compact Merkle height.
                ++j;
            }
        }
        root = nodes[0];
    }

    // compactMerkleRootAndAuth: Compute the 128-lane compact Merkle root and auth path for q.
    function compactMerkleRootAndAuth(bytes32 skSeed, bytes32 pkSeed, uint8 q)
        internal
        pure
        returns (bytes32 root, bytes32[7] memory authPath)
    {
        // Materialize every JARDIN compact Merkle leaf as a FORS+C public key.
        bytes32[128] memory nodes;
        for (uint32 lane = 0; lane < ShrincsTypes.COMPACT_Q_MAX;) {
            // Each lane has ci=q inside its FORS addresses.
            nodes[lane] = compactForsPk(skSeed, pkSeed, uint8(lane));
            unchecked {
                // The loop bound is the fixed 128-lane compact tree.
                ++lane;
            }
        }

        // Fold the 128 leaves upward while recording q's sibling at each level.
        uint32 pathIndex = q;
        uint32 nodeCount = ShrincsTypes.COMPACT_Q_MAX;
        for (uint32 j = 0; j < ShrincsTypes.COMPACT_MERKLE_HEIGHT;) {
            // The sibling beside q's current path node is pathIndex xor 1.
            authPath[j] = nodes[pathIndex ^ 1];
            // JARDIN ADRS x uses top-down level numbering for Merkle parents.
            uint32 level = uint32(ShrincsTypes.COMPACT_MERKLE_HEIGHT) - 1 - j;
            // Fold adjacent pairs into the next parent level.
            for (uint32 parent = 0; parent < nodeCount >> 1;) {
                // JARDIN ADRS y is the parent index at this level.
                nodes[parent] = compactH(
                    pkSeed,
                    compactAdrs(ShrincsTypes.AddressTypeJardinMerkle, 0, 0, level, parent),
                    nodes[parent << 1],
                    nodes[(parent << 1) | 1]
                );
                unchecked {
                    // The loop bound is the parent count at this level.
                    ++parent;
                }
            }
            // Move q's path index to its parent.
            pathIndex >>= 1;
            // The active node count halves at each Merkle level.
            nodeCount >>= 1;
            unchecked {
                // The loop bound is the fixed compact Merkle height.
                ++j;
            }
        }
        root = nodes[0];
    }

    // compactForsPk: Compute the JARDIN FORS+C public key from the 51 opened FORS tree roots.
    function compactForsPk(bytes32 skSeed, bytes32 pkSeed, uint8 q) internal pure returns (bytes32 pk) {
        // Input is pkSeed32 || ADRS(FORS_ROOTS)32 || roots[51]32.
        bytes memory input = new bytes(COMPACT_FORS_PK_INPUT_BYTES);
        // Bind the public seed exactly as the verifier does.
        setSlice32(input, pkSeed, 0);
        // Bind ADRS(type=FORS_ROOTS, ci=q).
        setSlice32(input, compactAdrs(ShrincsTypes.AddressTypeForsRoots, 0, q, 0, 0), 32);
        // Append the root of each opened FORS tree.
        for (uint32 i = 0; i < ShrincsTypes.COMPACT_OPEN_FORS_TREES;) {
            // Roots start after pkSeed32 || adrs32.
            setSlice32(input, compactForsTreeRoot(skSeed, pkSeed, q, i), 64 + uint256(i) * 32);
            unchecked {
                // The loop bound is the fixed count of opened FORS trees.
                ++i;
            }
        }
        // Hash the packed roots into the compact FORS+C public key.
        pk = keccak256(input);
    }

    // compactForsTreeRoot: Compute one compact FORS tree root for fixture public-key generation.
    function compactForsTreeRoot(bytes32 skSeed, bytes32 pkSeed, uint8 q, uint32 tree) internal pure returns (bytes32) {
        // A height-5 FORS tree has 32 leaves.
        bytes32[32] memory nodes;
        // Derive every leaf so the root can be folded deterministically.
        for (uint32 leaf = 0; leaf < 32;) {
            // Derive the FORS_PRF secret leaf.
            bytes32 secret = compactForsSecret(skSeed, pkSeed, q, tree, leaf);
            // FIPS/JARDIN treeIndex is continuous across all FORS trees.
            uint32 treeIndex = (tree << ShrincsTypes.COMPACT_FORS_TREE_HEIGHT) + leaf;
            // Hash the secret leaf into the public FORS_TREE leaf node.
            nodes[leaf] = compactF(pkSeed, compactAdrs(ShrincsTypes.AddressTypeForsTree, 0, q, 0, treeIndex), secret);
            unchecked {
                // The loop bound is the fixed number of leaves in a height-5 tree.
                ++leaf;
            }
        }
        // Fold the 32 leaf nodes to one FORS root.
        return compactForsTreeRootFromLeaves(pkSeed, q, tree, nodes);
    }

    // compactForsSecretAndAuth: Reveal one FORS leaf and its a=5 authentication path.
    function compactForsSecretAndAuth(bytes32 skSeed, bytes32 pkSeed, uint8 q, uint32 tree, uint32 idx)
        internal
        pure
        returns (bytes32 secret, bytes32[5] memory auth)
    {
        // Reveal the selected secret leaf for this FORS tree.
        secret = compactForsSecret(skSeed, pkSeed, q, tree, idx);
        // Build all 32 public leaves so auth siblings can be read at each level.
        bytes32[32] memory nodes;
        // Fill the working node array with FORS public leaf nodes.
        for (uint32 leaf = 0; leaf < 32;) {
            // Derive each candidate FORS_PRF secret leaf.
            bytes32 leafSecret = compactForsSecret(skSeed, pkSeed, q, tree, leaf);
            // Use continuous FIPS/JARDIN treeIndex across the k FORS trees.
            uint32 treeIndex = (tree << ShrincsTypes.COMPACT_FORS_TREE_HEIGHT) + leaf;
            // Store the corresponding FORS_TREE public leaf node.
            nodes[leaf] =
                compactF(pkSeed, compactAdrs(ShrincsTypes.AddressTypeForsTree, 0, q, 0, treeIndex), leafSecret);
            unchecked {
                // The loop bound is the fixed number of leaves in a height-5 tree.
                ++leaf;
            }
        }

        // Fold the tree upward while recording the sibling beside the selected path.
        for (uint32 level = 0; level < ShrincsTypes.COMPACT_FORS_TREE_HEIGHT;) {
            // The sibling of the current selected node is idx ^ 1.
            auth[level] = nodes[idx ^ 1];
            // Each fold halves the active node count.
            uint32 parentCount = uint32(1) << (ShrincsTypes.COMPACT_FORS_TREE_HEIGHT - 1 - level);
            // Hash adjacent node pairs into the next level.
            for (uint32 parent = 0; parent < parentCount;) {
                // ADRS x is the parent height above the leaves.
                uint32 height = level + 1;
                // ADRS y follows FIPS/JARDIN continuous treeIndex at this height.
                uint32 treeIndex = (tree << (ShrincsTypes.COMPACT_FORS_TREE_HEIGHT - height)) + parent;
                // Hash left/right children into this parent node.
                nodes[parent] = compactH(
                    pkSeed,
                    compactAdrs(ShrincsTypes.AddressTypeForsTree, 0, q, height, treeIndex),
                    nodes[parent << 1],
                    nodes[(parent << 1) | 1]
                );
                unchecked {
                    // The loop bound is the number of parents at this height.
                    ++parent;
                }
            }
            // Move the selected path index up one level.
            idx >>= 1;
            unchecked {
                // The loop bound is the fixed FORS tree height.
                ++level;
            }
        }
    }

    // compactForsTreeRootFromLeaves: Fold 32 FORS leaves to their root using JARDIN ADRS coordinates.
    function compactForsTreeRootFromLeaves(bytes32 pkSeed, uint8 q, uint32 tree, bytes32[32] memory nodes)
        internal
        pure
        returns (bytes32)
    {
        // Repeatedly fold the working node array until only the root remains.
        for (uint32 level = 0; level < ShrincsTypes.COMPACT_FORS_TREE_HEIGHT;) {
            // A height-5 tree has 16, 8, 4, 2, then 1 parent at successive levels.
            uint32 parentCount = uint32(1) << (ShrincsTypes.COMPACT_FORS_TREE_HEIGHT - 1 - level);
            // Hash adjacent node pairs into parent nodes in-place.
            for (uint32 parent = 0; parent < parentCount;) {
                // ADRS x is the parent height above the leaves.
                uint32 height = level + 1;
                // ADRS y follows FIPS/JARDIN continuous treeIndex at this height.
                uint32 treeIndex = (tree << (ShrincsTypes.COMPACT_FORS_TREE_HEIGHT - height)) + parent;
                // Replace the left child slot with the parent hash.
                nodes[parent] = compactH(
                    pkSeed,
                    compactAdrs(ShrincsTypes.AddressTypeForsTree, 0, q, height, treeIndex),
                    nodes[parent << 1],
                    nodes[(parent << 1) | 1]
                );
                unchecked {
                    // The loop bound is the number of parents at this height.
                    ++parent;
                }
            }
            unchecked {
                // The loop bound is the fixed FORS tree height.
                ++level;
            }
        }
        // nodes[0] is now the root of this FORS tree.
        return nodes[0];
    }

    // compactForsSecret: Derive the test fixture FORS secret leaf at ADRS(type=FORS_PRF, ci=q).
    function compactForsSecret(bytes32 skSeed, bytes32 pkSeed, uint8 q, uint32 tree, uint32 leaf)
        internal
        pure
        returns (bytes32 out)
    {
        // FIPS/JARDIN treeIndex is continuous across all compact FORS trees.
        uint32 treeIndex = (tree << ShrincsTypes.COMPACT_FORS_TREE_HEIGHT) + leaf;
        // Domain-separated PRF preimage:
        //   "jardin-fors-prf" || skSeed32 || pkSeed32 || ADRS(FORS_PRF, ci=q)32.
        bytes32 addressWord = compactAdrs(ShrincsTypes.AddressTypeForsPrf, 0, q, 0, treeIndex);
        assembly {
            // Use free-memory scratch without allocating.
            let ptr := mload(0x40)
            // Write the 15-byte domain tag.
            mstore(ptr, "jardin-fors-prf")
            // Write skSeed immediately after the tag.
            mstore(add(ptr, 15), skSeed)
            // Write pkSeed.
            mstore(add(ptr, 47), pkSeed)
            // Write ADRS(type=FORS_PRF, ci=q).
            mstore(add(ptr, 79), addressWord)
            // Hash the exact packed preimage length.
            out := keccak256(ptr, 111)
        }
    }

    // compactHMsg: Mirror ShrincsCompact.hMsg for memory-based test signing.
    function compactHMsg(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes32 randomizer, uint32 counter, uint8 q)
        internal
        pure
        returns (bytes memory out)
    {
        // H_msg output needs 260 bits, rounded up to 33 bytes.
        out = new bytes(COMPACT_DIGEST_BYTES);
        // Build the same domain-separated preimage shape as ShrincsCompact.hMsg.
        bytes memory prefix = abi.encodePacked(
            "JARDIN/H_MSG/v1",
            randomizer,
            pkSeed,
            pkRoot,
            counter,
            "JARDIN/TYPE2/v1",
            pkSeed,
            pkRoot,
            bytes1(q),
            message
        );
        // First block supplies bytes 0..31 of the 33-byte digest.
        bytes32 first = keccak256(abi.encodePacked(prefix, uint32(0)));
        // Second block supplies the final digest byte.
        bytes32 second = keccak256(abi.encodePacked(prefix, uint32(1)));
        // Copy the first 32 digest bytes.
        setSlice32(out, first, 0);
        // Copy byte 33.
        out[32] = second[0];
    }

    // compactBase2b: Read one 5-bit FORS+C digit from the compact digest.
    function compactBase2b(bytes memory md, uint32 i) internal pure returns (uint32) {
        // Each compact FORS tree consumes one a=5 bit digit from H_msg.
        return ShrincsUtils.readBits32(
            md, uint256(i) * ShrincsTypes.COMPACT_FORS_TREE_HEIGHT, ShrincsTypes.COMPACT_FORS_TREE_HEIGHT
        );
    }

    // compactAdrs: Pack JARDIN ADRS = layer:4 || tree:8 || type:4 || kp:4 || ci:4 || x:4 || y:4.
    function compactAdrs(uint32 addressType, uint32 kp, uint32 ci, uint32 x, uint32 y) internal pure returns (bytes32) {
        // This compact fixture always uses layer=0 and tree=0, so those high words remain zero.
        uint256 value = uint256(addressType) << 128;
        // Write kp into the fourth 32-bit address word.
        value |= uint256(kp) << 96;
        // Write ci into the fifth 32-bit address word.
        value |= uint256(ci) << 64;
        // Write x into the sixth 32-bit address word.
        value |= uint256(x) << 32;
        // Write y into the seventh 32-bit address word.
        value |= uint256(y);
        // Return the packed 32-byte ADRS word.
        return bytes32(value);
    }

    // compactF: JARDIN/FIPS tweakable hash for a compact FORS leaf.
    function compactF(bytes32 pkSeed, bytes32 addressWord, bytes32 input) internal pure returns (bytes32 out) {
        // F(pkSeed, ADRS, secretLeaf) is modeled with keccak256 for the Solidity fixture.
        assembly {
            // Use free-memory scratch without allocating.
            let ptr := mload(0x40)
            // Write pkSeed.
            mstore(ptr, pkSeed)
            // Write ADRS.
            mstore(add(ptr, 32), addressWord)
            // Write secretLeaf.
            mstore(add(ptr, 64), input)
            // Hash pkSeed32 || ADRS32 || secretLeaf32.
            out := keccak256(ptr, 96)
        }
    }

    // compactH: JARDIN/FIPS tweakable hash for compact FORS or Merkle parent nodes.
    function compactH(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        // H(pkSeed, ADRS, left, right) is modeled with keccak256 for the Solidity fixture.
        assembly {
            // Use free-memory scratch without allocating.
            let ptr := mload(0x40)
            // Write pkSeed.
            mstore(ptr, pkSeed)
            // Write ADRS.
            mstore(add(ptr, 32), addressWord)
            // Write left child.
            mstore(add(ptr, 64), left)
            // Write right child.
            mstore(add(ptr, 96), right)
            // Hash pkSeed32 || ADRS32 || left32 || right32.
            out := keccak256(ptr, 128)
        }
    }

    // hypertreePublicRoot: Compute the deterministic virtual stateless hypertree root.
    function hypertreePublicRoot(bytes32 statelessSkSeed, bytes32 pkSeed) internal pure returns (bytes32) {
        // Derive independent fixture seeds for all hypertree layers.
        bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds = hypertreeLayerSeeds(statelessSkSeed);
        // The public root lives at the top layer.
        uint32 topLayer = NUM_HYPERTREE_LAYERS - 1;
        // Split total hypertree height evenly across fixture layers.
        uint32 subtreeHeight = uint32(ShrincsTypes.HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
        // Compute the root of the top subtree at tree index zero.
        return hypertreeVirtualNode(pkSeed, layerSeeds[topLayer], topLayer, 0, subtreeHeight, 0);
    }

    // hypertreeLayerSeeds: Derive one deterministic seed per virtual hypertree layer.
    function hypertreeLayerSeeds(bytes32 statelessSkSeed)
        internal
        pure
        returns (bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds)
    {
        // Fill each layer slot with a domain-separated seed.
        for (uint8 layer = 0; layer < NUM_HYPERTREE_LAYERS;) {
            // bytes1(layer) is safe because layer is bounded by NUM_HYPERTREE_LAYERS=8.
            layerSeeds[layer] = keccak256(abi.encodePacked("hypertree-layer-seed", statelessSkSeed, bytes1(layer)));
            unchecked {
                // The loop bound is NUM_HYPERTREE_LAYERS.
                ++layer;
            }
        }
    }

    // hypertreeVirtualNode: Recursively compute one virtual hypertree node.
    function hypertreeVirtualNode(
        bytes32 pkSeed,
        bytes32 layerSeed,
        uint32 layer,
        uint64 tree,
        uint32 height,
        uint32 index
    ) internal pure returns (bytes32) {
        // Height zero is a WOTS-C public-key leaf.
        if (height == 0) {
            return hypertreeLeaf(pkSeed, layerSeed, layer, tree, index);
        }
        // Recursively compute the left child.
        bytes32 left = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, height - 1, index << 1);
        // The right child index is the next sibling.
        uint32 rightIndex = (index << 1) | 1;
        // Recursively compute the right child.
        bytes32 right = hypertreeVirtualNode(pkSeed, layerSeed, layer, tree, height - 1, rightIndex);
        // Build the address for this tree node.
        bytes32 addressWord = hypertreeAddressWord(layer, tree, height, index);
        // Hash the two children into the parent node.
        return keccak256(abi.encodePacked("hypertree-node", pkSeed, addressWord, left, right));
    }

    // hypertreeLeaf: Compute one virtual stateless WOTS-C public-key leaf.
    function hypertreeLeaf(bytes32 pkSeed, bytes32 layerSeed, uint32 layer, uint64 tree, uint32 leaf)
        internal
        pure
        returns (bytes32)
    {
        // Derive a unique leaf seed inside this layer/tree.
        bytes32 leafSeed = keccak256(abi.encodePacked("hypertree-leaf-seed", layerSeed, tree, leaf));
        // Derive the WOTS-C secret seed for this virtual leaf.
        bytes32 skSeed = keccak256(abi.encodePacked("hypertree-wots-sk-seed", leafSeed));
        // Compress the WOTS-C public key for this virtual leaf.
        return statelessWotsCPublicKey(pkSeed, skSeed, layer, tree, leaf);
    }

    // statelessWotsCPublicKey: Compress all stateless WOTS-C chain endpoints into one leaf hash.
    function statelessWotsCPublicKey(bytes32 pkSeed, bytes32 skSeed, uint32 layer, uint64 tree, uint32 keypair)
        internal
        pure
        returns (bytes32)
    {
        // Allocate the packed endpoint buffer.
        bytes memory endpoints = new bytes(uint256(ShrincsTypes.NUM_WOTS_CHAINS) * 32);
        // Derive each chain endpoint.
        for (uint32 chain = 0; chain < ShrincsTypes.NUM_WOTS_CHAINS;) {
            // Derive the chain secret.
            bytes32 secret = statelessWotsCSecret(skSeed, chain);
            // Advance to the final public chain value.
            bytes32 endpoint =
                statelessWotsCChain(pkSeed, layer, tree, keypair, chain, secret, 0, ShrincsTypes.WOTS_CHAIN_LEN - 1);
            // Store the endpoint at chain * 32.
            setSlice32(endpoints, endpoint, uint256(chain) * 32);
            unchecked {
                // The loop bound is NUM_WOTS_CHAINS.
                ++chain;
            }
        }
        // Hash the packed endpoints into one WOTS-C public-key hash.
        return keccak256(abi.encodePacked("wots-c-pk", pkSeed, endpoints));
    }

    // statelessWotsCSecret: Derive one stateless WOTS-C chain secret.
    function statelessWotsCSecret(bytes32 skSeed, uint32 chain) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("wots-c-secret", skSeed, chain));
    }

    // statelessWotsCChain: Advance a stateless WOTS-C chain without masks.
    function statelessWotsCChain(
        bytes32 pkSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        uint32 chain,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        // Start from the supplied secret or intermediate chain value.
        out = value;
        // Apply exactly `steps` hash-chain links.
        for (uint32 step = start; step < start + steps;) {
            // Build the WOTS_HASH address for this step.
            bytes32 addressWord =
                ShrincsUtils.addressWord32(layer, tree, ShrincsTypes.AddressTypeWotsHash, keypair, chain, step);
            // Hash one step forward in the chain.
            out = keccak256(abi.encodePacked("wots-c-chain", pkSeed, addressWord, out));
            unchecked {
                // The loop bound is start + steps.
                ++step;
            }
        }
    }

    // hypertreeAddressWord: Pack the test fixture hypertree address word.
    function hypertreeAddressWord(uint32 layer, uint64 treeIndex, uint32 nodeHeight, uint32 parentIndex)
        internal
        pure
        returns (bytes32)
    {
        // Accumulate the packed 32-byte address in one word.
        bytes32 out;
        assembly {
            // layer:4 || tree:8.
            out := or(shl(224, layer), shl(128, treeIndex))
            // type:4 = TREE.
            out := or(out, shl(96, 2))
            // x:4=nodeHeight || y:4=parentIndex.
            out := or(out, or(shl(32, nodeHeight), parentIndex))
        }
        return out;
    }

    // setSlice32: Store one bytes32 word into a mutable bytes buffer at offset.
    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            // Skip the bytes length word and write the source word at the requested payload offset.
            mstore(add(add(dst, 32), offset), src)
        }
    }

    // setUint32: Write a big-endian uint32 into a mutable packed byte buffer.
    function setUint32(bytes memory dst, uint256 offset, uint32 value) internal pure {
        // The shift leaves exactly the high byte in the low 8 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        dst[offset] = bytes1(uint8(value >> 24));
        // The shift leaves exactly the second byte in the low 8 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        dst[offset + 1] = bytes1(uint8(value >> 16));
        // The shift leaves exactly the third byte in the low 8 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        dst[offset + 2] = bytes1(uint8(value >> 8));
        // The low byte of a uint32 fits in uint8 by construction.
        // forge-lint: disable-next-line(unsafe-typecast)
        dst[offset + 3] = bytes1(uint8(value));
    }

    // setUint8: Write one byte into a mutable packed byte buffer.
    function setUint8(bytes memory dst, uint256 offset, uint8 value) internal pure {
        dst[offset] = bytes1(value);
    }

    // baseW16Digit: Read one base-16 digit from a packed 32-byte digest.
    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32 digit) {
        // Two base-16 digits are packed into each byte.
        uint8 b = uint8(digest[index >> 1]);
        // Even indexes use the high nibble; odd indexes use the low nibble.
        return index & 1 == 0 ? uint32(b >> 4) : uint32(b & 0x0f);
    }
}
