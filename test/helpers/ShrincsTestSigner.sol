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

/// @notice TEST-ONLY Solidity signer helpers that mirror the Rust signer for stateful flows.
/// @dev This library is kept under `test/helpers` so it does not become part of the
/// production Solidity surface. It is used for deterministic keygen and stateful-signing tests.
library ShrincsTestSigner {
    uint32 internal constant INITIAL_STATEFUL_LEAF_INDEX = 1;
    uint32 internal constant MAX_STATEFUL_SIGNATURES_LIMIT = 4096;
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

    // keygen: Build a deterministic SHRINCS test key bundle from seed material.
    // 1. Reject impossible stateful signing budgets.
    // 2. Derive independent stateful, stateless, and public seeds.
    // 3. Build the stateful subtree root and stateless hypertree root.
    // 4. Commit the public key parts into the wrapper-facing public-key commitment.
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        internal
        pure
        returns (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok)
    {
        // A stateful key with zero allowed signatures is unusable.
        if (maxStatefulSignatures == 0) return (signingKey, publicKey, false);
        // Keep the test helper inside the verifier profile's supported stateful range.
        if (maxStatefulSignatures > MAX_STATEFUL_SIGNATURES_LIMIT) return (signingKey, publicKey, false);

        // Derive the stateful WOTS-C secret seed.
        bytes32 statefulSkSeed = derive32("shrincs-stateful-sk-seed", seedMaterial, "");
        // Derive the stateful WOTS-C PRF seed.
        bytes32 statefulPrfSeed = derive32("shrincs-stateful-prf-seed", seedMaterial, "");
        // Derive the stateful WOTS-C public seed.
        bytes32 statefulPkSeed = derive32("shrincs-stateful-pk-seed", seedMaterial, "");
        // Build the stateful Merkle root for leaves [1, maxStatefulSignatures].
        bytes32 statefulRoot =
            statefulSubtreeRoot(statefulSkSeed, statefulPkSeed, INITIAL_STATEFUL_LEAF_INDEX, maxStatefulSignatures);
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
            statefulSkSeed: statefulSkSeed,
            statefulPrfSeed: statefulPrfSeed,
            statefulPkSeed: statefulPkSeed,
            statefulRoot: statefulRoot,
            maxStatefulSignatures: maxStatefulSignatures,
            nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
            statelessSkSeed: statelessSkSeed,
            statelessPrfSeed: statelessPrfSeed,
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });

        // Encode the stateful public key in the verifier's fixed public-key layout.
        bytes memory statefulPublicKey = encodeStatefulPublicKey(statefulPkSeed, statefulRoot, maxStatefulSignatures);
        // Commit the full public bundle as statefulPk || pkSeed || hypertreeRoot.
        bytes32 publicKeyCommitment = ShrincsUtils.publicKeyCommitmentFromParts(
            statefulPublicKey, abi.encodePacked(pkSeed), abi.encodePacked(hypertreeRoot)
        );
        // Build the public key object consumed by tests and account wrappers.
        publicKey = ShrincsTypes.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(publicKeyCommitment),
            pkSeed: abi.encodePacked(pkSeed),
            hypertreeRoot: abi.encodePacked(hypertreeRoot)
        });
        return (signingKey, publicKey, true);
    }

    // signStatefulRaw: Sign raw message bytes with the next available stateful leaf.
    // 1. Reject an exhausted or uninitialized stateful cursor.
    // 2. Sign at the current leaf.
    // 3. Return a copied signing key with the leaf cursor advanced.
    function signStatefulRaw(ShrincsTypes.SigningKey memory signingKey, bytes memory message)
        internal
        pure
        returns (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.StatefulSignature memory signature,
            bool ok
        )
    {
        // Read the next leaf before signing so the caller's input key remains immutable.
        uint32 leafIndex = signingKey.nextStatefulLeafIndex;
        // Zero is reserved as an invalid cursor value.
        if (leafIndex == 0) return (nextSigningKey, signature, false);
        // Stop once the configured stateful signing budget is exhausted.
        if (leafIndex > signingKey.maxStatefulSignatures) return (nextSigningKey, signature, false);

        // Produce the WOTS-C signature and stateful auth path at this exact leaf.
        (signature, ok) = signStatefulRawAtLeaf(signingKey, leafIndex, message);
        // Keep the original cursor unchanged on signing failure.
        if (!ok) return (nextSigningKey, signature, false);

        // Copy the caller's key and advance only the returned key.
        nextSigningKey = signingKey;
        // The next call will consume the next stateful leaf.
        nextSigningKey.nextStatefulLeafIndex = leafIndex + 1;
        return (nextSigningKey, signature, true);
    }

    // signStatefulAction: Sign a canonical account action with the stateful path.
    // 1. Extract the public-key commitment expected by the verifier.
    // 2. Build SHRINCS.statefulActionMessageHash(...).
    // 3. Delegate to the raw stateful signer.
    function signStatefulAction(
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.ActionContext memory context
    )
        internal
        pure
        returns (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.StatefulSignature memory signature,
            bool ok
        )
    {
        // The commitment is loaded as one word below, so it must be exactly 32 bytes.
        if (publicKey.publicKeyCommitment.length != 32) return (nextSigningKey, signature, false);
        // Hold the installed public-key commitment as a bytes32 for hashing.
        bytes32 expectedPublicKeyCommitment;
        // Cache the dynamic bytes pointer used by the assembly load.
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            // Load the first 32 bytes of publicKey.publicKeyCommitment.
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }
        // Build the canonical wrapper action message and sign its 32-byte hash as bytes.
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(expectedPublicKeyCommitment, context));
        return signStatefulRaw(signingKey, message);
    }

    // derive32: Deterministically derive one fixture word under a human-readable domain.
    function derive32(bytes memory domain, bytes memory seed, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, seed, data));
    }

    // compactSingleLaneKeygen: Build a deterministic test-only JARDIN compact lane.
    // 1. Derive compact SK.seed and PK.seed from the fixture seed.
    // 2. Commit one FORS+C lane plus deterministic Merkle siblings into subPkRoot.
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
        // Commit this lane's FORS+C public key through the 7-level compact Merkle tree.
        pkRoot = compactSingleLaneRoot(skSeed, pkSeed, q);
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
            setSlice32(
                signature,
                compactMerkleAuth(skSeed, pkSeed, q, j),
                uint256(COMPACT_MERKLE_AUTH_OFFSET) + uint256(j) * 32
            );
            unchecked {
                // The loop bound is the fixed compact Merkle height.
                ++j;
            }
        }

        return (signature, true);
    }

    // compactSingleLaneRoot: Compute subPkRoot for the FORS+C instance at compact Merkle leaf q.
    function compactSingleLaneRoot(bytes32 skSeed, bytes32 pkSeed, uint8 q) internal pure returns (bytes32 node) {
        // The compact Merkle leaf is the FORS+C public key for index q.
        node = compactForsPk(skSeed, pkSeed, q);
        // Fold that FORS+C public key up the 7-level balanced Merkle tree.
        for (uint32 j = 0; j < ShrincsTypes.COMPACT_MERKLE_HEIGHT;) {
            // Derive the deterministic sibling for this compact Merkle level.
            bytes32 auth = compactMerkleAuth(skSeed, pkSeed, q, j);
            // Place the current node on the left or right according to bit j of q.
            (bytes32 left, bytes32 right) = uint32(q) & (uint32(1) << j) == 0 ? (node, auth) : (auth, node);
            // JARDIN ADRS x uses top-down level numbering for Merkle parents.
            uint32 level = uint32(ShrincsTypes.COMPACT_MERKLE_HEIGHT) - 1 - j;
            // JARDIN ADRS y is the parent index at this level.
            uint32 parentIndex = uint32(q) >> (j + 1);
            // Hash the ordered pair into its parent with ADRS(type=JARDIN_MERKLE).
            node = compactH(
                pkSeed, compactAdrs(ShrincsTypes.AddressTypeJardinMerkle, 0, 0, level, parentIndex), left, right
            );
            unchecked {
                // The loop bound is the fixed compact Merkle height.
                ++j;
            }
        }
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
        returns (bytes32)
    {
        // FIPS/JARDIN treeIndex is continuous across all compact FORS trees.
        uint32 treeIndex = (tree << ShrincsTypes.COMPACT_FORS_TREE_HEIGHT) + leaf;
        // Domain-separate the test fixture PRF and bind ADRS(type=FORS_PRF, ci=q).
        return keccak256(
            abi.encodePacked(
                "jardin-fors-prf", skSeed, pkSeed, compactAdrs(ShrincsTypes.AddressTypeForsPrf, 0, q, 0, treeIndex)
            )
        );
    }

    // compactMerkleAuth: Deterministically derive one compact Merkle sibling for leaf q.
    function compactMerkleAuth(bytes32 skSeed, bytes32 pkSeed, uint8 q, uint32 level) internal pure returns (bytes32) {
        // The fixture does not build all 128 FORS+C leaves; it derives stable sibling nodes instead.
        return keccak256(abi.encodePacked("jardin-merkle-auth", skSeed, pkSeed, q, level));
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
    function compactF(bytes32 pkSeed, bytes32 addressWord, bytes32 input) internal pure returns (bytes32) {
        // F(pkSeed, ADRS, secretLeaf) is modeled with keccak256 for the Solidity fixture.
        return keccak256(abi.encodePacked(pkSeed, addressWord, input));
    }

    // compactH: JARDIN/FIPS tweakable hash for compact FORS or Merkle parent nodes.
    function compactH(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        // H(pkSeed, ADRS, left, right) is modeled with keccak256 for the Solidity fixture.
        return keccak256(abi.encodePacked(pkSeed, addressWord, left, right));
    }

    // signStatefulRawAtLeaf: Sign raw bytes at one explicit stateful WOTS-C leaf.
    // 1. Reject leaves outside the configured stateful signing budget.
    // 2. Build the WOTS-C signature for this leaf.
    // 3. Attach the auth path proving this WOTS-C public key to the stateful root.
    function signStatefulRawAtLeaf(ShrincsTypes.SigningKey memory signingKey, uint32 leafIndex, bytes memory message)
        internal
        pure
        returns (ShrincsTypes.StatefulSignature memory signature, bool ok)
    {
        // Leaf zero is reserved as invalid for this fixture.
        if (leafIndex == 0) return (signature, false);
        // Reject signatures beyond the stateful key's declared budget.
        if (leafIndex > signingKey.maxStatefulSignatures) return (signature, false);

        // Sign with WOTS-C at the requested stateful leaf.
        (signature, ok) = signStatefulWotsC(
            signingKey.statefulSkSeed, signingKey.statefulPrfSeed, signingKey.statefulPkSeed, leafIndex, message
        );
        // Preserve the empty return value on WOTS-C grinding failure.
        if (!ok) return (signature, false);
        // Attach the authentication path from this leaf to the stateful subtree root.
        signature.authPath = statefulAuthPath(
            signingKey.statefulSkSeed, signingKey.statefulPkSeed, leafIndex, signingKey.maxStatefulSignatures
        );
        return (signature, true);
    }

    // encodeStatefulPublicKey: Pack pkSeed32 || root32 || maxSignatures4.
    function encodeStatefulPublicKey(bytes32 pkSeed, bytes32 root, uint32 maxSignatures)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(pkSeed, root, maxSignatures);
    }

    // statefulSubtreeRoot: Build the right-folded stateful subtree root used by tests.
    // 1. Start with the empty tail after maxSignatures.
    // 2. Walk backward from maxSignatures to leafIndex.
    // 3. Fold each WOTS-C public-key hash into the root accumulator.
    function statefulSubtreeRoot(bytes32 skSeed, bytes32 pkSeed, uint32 leafIndex, uint32 maxSignatures)
        internal
        pure
        returns (bytes32 right)
    {
        // The right edge after the final usable leaf is a deterministic empty tail.
        right = statefulEmptyTail(pkSeed, maxSignatures);
        // Fold leaves backward until the requested starting leaf has been included.
        for (uint32 currentLeaf = maxSignatures; currentLeaf >= leafIndex;) {
            // Recompute this leaf's WOTS-C public key hash.
            bytes32 leaf = statefulWotsPkHash(skSeed, pkSeed, currentLeaf);
            // Parent the current leaf with the accumulated right subtree.
            right = statefulParentHash(pkSeed, currentLeaf, leaf, right);
            // Stop before underflowing the unsigned loop counter.
            if (currentLeaf == leafIndex) break;
            unchecked {
                // Safe because the break above handles the lower bound.
                --currentLeaf;
            }
        }
    }

    // statefulWotsPkHash: Compute the compressed WOTS-C public key for one stateful leaf.
    function statefulWotsPkHash(bytes32 skSeed, bytes32 pkSeed, uint32 leafIndex) internal pure returns (bytes32) {
        // The stateful WOTS-C public key is the concatenation of all chain endpoints.
        bytes memory endpoints = new bytes(uint256(ShrincsTypes.WOTS_CHAINS_STATEFUL) * 32);
        // Derive every WOTS-C chain endpoint for this leaf.
        for (uint32 chainIndex = 0; chainIndex < ShrincsTypes.WOTS_CHAINS_STATEFUL;) {
            // Derive the chain secret for this leaf and chain.
            bytes32 secret = statefulChainSecret(skSeed, pkSeed, leafIndex, chainIndex);
            // Advance the chain to its public endpoint.
            bytes32 endpoint =
                statefulChainNoMask(pkSeed, leafIndex, chainIndex, secret, 0, ShrincsTypes.WOTS_BASE_STATEFUL - 1);
            // Store the endpoint in the packed public-key buffer.
            setSlice32(endpoints, endpoint, uint256(chainIndex) * 32);
            unchecked {
                // The loop bound is the fixed stateful WOTS-C chain count.
                ++chainIndex;
            }
        }
        // Compress all endpoints into the stateful WOTS-C public-key hash.
        return keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, endpoints));
    }

    // signStatefulWotsC: Build one WOTS-C signature by grinding to the target digit sum.
    function signStatefulWotsC(bytes32 skSeed, bytes32 prfSeed, bytes32 pkSeed, uint32 leafIndex, bytes memory message)
        internal
        pure
        returns (ShrincsTypes.StatefulSignature memory signature, bool ok)
    {
        // Derive deterministic per-signature randomness.
        bytes32 randomizer = keccak256(abi.encodePacked("uxmss-wots-randomizer", prfSeed, leafIndex, message));

        // Grind the counter until the WOTS-C checksum/digit-sum rule is satisfied.
        for (uint32 counter = 0; counter < WOTS_C_MAX_GRIND_COUNTER;) {
            // Expand message, randomizer, and counter into WOTS-C base-16 digits.
            bytes32 digest =
                keccak256(abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, randomizer, counter, message));
            // Track the digit sum required by WOTS-C verification.
            uint32 digitSum;
            // Allocate one revealed chain value per WOTS-C chain.
            bytes32[] memory chains = new bytes32[](ShrincsTypes.WOTS_CHAINS_STATEFUL);
            // Reveal each chain at the position selected by its digest digit.
            for (uint32 chainIndex = 0; chainIndex < ShrincsTypes.WOTS_CHAINS_STATEFUL;) {
                // Read this chain's base-16 digit.
                uint32 digit = baseW16Digit(digest, chainIndex);
                // Add it to the target-sum accumulator.
                digitSum += digit;
                // Derive the chain secret.
                bytes32 secret = statefulChainSecret(skSeed, pkSeed, leafIndex, chainIndex);
                // Advance the chain only to the selected digit position.
                chains[chainIndex] = statefulChainNoMask(pkSeed, leafIndex, chainIndex, secret, 0, digit);
                unchecked {
                    // The loop bound is the fixed stateful WOTS-C chain count.
                    ++chainIndex;
                }
            }
            // Accept this counter only when the WOTS-C target sum is met.
            if (digitSum == ShrincsTypes.WOTS_TARGET_SUM_STATEFUL) {
                // Auth path is filled by signStatefulRawAtLeaf after WOTS-C succeeds.
                signature = ShrincsTypes.StatefulSignature({
                    randomizer: randomizer, counter: counter, chains: chains, authPath: new bytes32[](0)
                });
                return (signature, true);
            }
            unchecked {
                // The loop bound is WOTS_C_MAX_GRIND_COUNTER.
                ++counter;
            }
        }
        return (signature, false);
    }

    // statefulChainSecret: Derive the secret starting value for one stateful WOTS-C chain.
    function statefulChainSecret(bytes32 skSeed, bytes32 pkSeed, uint32 leafIndex, uint32 chainIndex)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("uxmss-wots-chain-secret", skSeed, pkSeed, leafIndex, chainIndex));
    }

    // statefulChainNoMask: Advance a stateful WOTS-C chain without randomization masks.
    function statefulChainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIndex,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        // Start from the caller-supplied chain value.
        out = value;
        // Apply exactly `steps` chain hashes beginning at `start`.
        for (uint32 stepOffset = 0; stepOffset < steps;) {
            // Build the WOTS_HASH address for this chain step.
            bytes32 addressWord = ShrincsUtils.addressWord32(
                0, 0, ShrincsTypes.AddressTypeWotsHash, leafIndex, chainIndex, start + stepOffset
            );
            // Hash one step forward in the WOTS-C chain.
            out = keccak256(abi.encodePacked("wots-c-chain", pkSeed, addressWord, out));
            unchecked {
                // The loop bound is caller supplied and checked by the surrounding test profile.
                ++stepOffset;
            }
        }
    }

    // statefulParentHash: Hash a stateful leaf/subtree pair into its parent.
    function statefulParentHash(bytes32 pkSeed, uint32 leftLeafIndex, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("uxmss-node", pkSeed, leftLeafIndex, left, right));
    }

    // statefulEmptyTail: Derive the deterministic empty right edge after the final usable leaf.
    function statefulEmptyTail(bytes32 pkSeed, uint32 leafIndex) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("uxmss-empty-tail", pkSeed, leafIndex));
    }

    // statefulAuthPath: Build the stateful authentication path used by the verifier tests.
    function statefulAuthPath(bytes32 skSeed, bytes32 pkSeed, uint32 leafIndex, uint32 maxSignatures)
        internal
        pure
        returns (bytes32[] memory path)
    {
        // This fixture path contains one right subtree plus all previous leaf public keys.
        path = new bytes32[](leafIndex);
        // The first sibling is the subtree to the right, or the empty tail at the final leaf.
        if (leafIndex < maxSignatures) {
            path[0] = statefulSubtreeRoot(skSeed, pkSeed, leafIndex + 1, maxSignatures);
        } else {
            path[0] = statefulEmptyTail(pkSeed, leafIndex);
        }
        // Remaining entries are prior leaf WOTS-C public-key hashes.
        uint256 offset = 1;
        // Walk left from leafIndex - 1 down to leaf 1.
        for (uint32 previousLeaf = leafIndex - 1; previousLeaf >= 1;) {
            // Store the previous leaf's WOTS-C public-key hash.
            path[offset] = statefulWotsPkHash(skSeed, pkSeed, previousLeaf);
            unchecked {
                // offset is bounded by path.length == leafIndex.
                ++offset;
            }
            // Stop before underflowing previousLeaf.
            if (previousLeaf == 1) break;
            unchecked {
                // Safe because the break above handles the lower bound.
                --previousLeaf;
            }
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
