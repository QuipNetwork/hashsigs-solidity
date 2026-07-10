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

import {ShrincsParams} from "shrincs-profile/ShrincsParams.sol";

library ShrincsTypes {
    // Hash-suite identifiers bound into canonical action and rotation hashes.
    uint32 internal constant HASH_SUITE_KECCAK_256 = 1;
    // Sentinel for an unsupported hash suite. Referenced only by tests
    // today; kept as a named constant so fail-closed suite checks and
    // negative tests have a stable non-keccak identifier.
    uint32 internal constant HASH_SUITE_UNSUPPORTED = 2;
    // Operation tags domain-separating each signed message family.
    bytes32 internal constant OP_VERIFY_STATEFUL =
        keccak256("shrincs-verify-stateful");
    bytes32 internal constant OP_VERIFY_STATELESS =
        keccak256("shrincs-verify-stateless");
    bytes32 internal constant OP_ROTATE_STATEFUL =
        keccak256("shrincs-rotate-stateful");
    bytes32 internal constant OP_ROTATE_FULL =
        keccak256("shrincs-rotate-full");

    // Address-type words for the SPHINCS-style keyed hash inputs. These
    // are the ADRS type constants [FIPS205 §4.2]: WOTS+ hash (0), tree
    // (2), and FORS tree (3).
    uint32 internal constant AddressTypeWotsHash = 0;
    uint32 internal constant AddressTypeTree = 2;
    uint32 internal constant AddressTypeForsTree = 3;

    // Per-profile SHRINCS/SPHINCS parameter tuple, re-exported as
    // aliases from the profile-selected `ShrincsParams` library (see
    // contracts/profiles/<profile>/ShrincsParams.sol, chosen by the
    // `shrincs-profile/` Foundry remapping). The full §1/§2 citations
    // and §4 derivation comments live at each constant's declaration
    // in ShrincsParams; these aliases keep every `ShrincsTypes.X`
    // reference site profile-agnostic. via-ir folds a constant defined
    // from another constant, so no runtime cost is introduced.
    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES =
        ShrincsParams.STATEFUL_PUBLIC_KEY_BYTES;
    uint16 internal constant WOTS_CHAINS_STATEFUL =
        ShrincsParams.WOTS_CHAINS_STATEFUL;
    uint16 internal constant WOTS_BASE_STATEFUL =
        ShrincsParams.WOTS_BASE_STATEFUL;
    uint32 internal constant WOTS_TARGET_SUM_STATEFUL =
        ShrincsParams.WOTS_TARGET_SUM_STATEFUL;
    uint64 internal constant STATELESS_SIGNATURE_LIMIT =
        ShrincsParams.STATELESS_SIGNATURE_LIMIT;
    uint16 internal constant HASH_LEN = ShrincsParams.HASH_LEN;
    bytes32 internal constant HASH_MASK = ShrincsParams.HASH_MASK;
    uint8 internal constant HYPERTREE_HEIGHT =
        ShrincsParams.HYPERTREE_HEIGHT;
    uint8 internal constant NUM_HYPERTREE_LAYERS =
        ShrincsParams.NUM_HYPERTREE_LAYERS;
    uint8 internal constant FORS_TREE_HEIGHT =
        ShrincsParams.FORS_TREE_HEIGHT;
    uint8 internal constant NUM_FORS_TREES = ShrincsParams.NUM_FORS_TREES;
    uint16 internal constant WOTS_CHAIN_LEN = ShrincsParams.WOTS_CHAIN_LEN;
    uint16 internal constant NUM_WOTS_CHAINS = ShrincsParams.NUM_WOTS_CHAINS;

    struct ForsDigest {
        // Hypertree subtree selected for this stateless signature.
        uint64 treeIndex;
        // Leaf inside that subtree.
        uint32 leafIndex;
        // Message-derived FORS digest bits used to choose revealed leaves.
        bytes digest;
    }

    struct PublicKey {
        // Encoded stateful fast-path public key.
        bytes statefulPublicKey;
        // Commitment binding the full hybrid public-key bundle together.
        bytes publicKeyCommitment;
        // Stateless SPHINCS-style public seed.
        bytes pkSeed;
        // Stateless SPHINCS-style public root.
        bytes hypertreeRoot;
    }

    struct StatefulPublicKey {
        // Public seed for stateful WOTS-C and tree hashing.
        bytes32 pkSeed;
        // Root of the custom stateful tree.
        bytes32 root;
        // Maximum number of stateful leaves/signatures under this key.
        uint32 maxSignatures;
    }

    struct SigningKey {
        // Secret seed used to derive stateful WOTS-C chain secrets.
        bytes32 statefulSkSeed;
        // Secret PRF seed used to derive stateful WOTS-C message randomizers.
        bytes32 statefulPrfSeed;
        // Public seed used in stateful WOTS-C and stateful tree hashing.
        bytes32 statefulPkSeed;
        // Root of the stateful unbalanced tree committed in the public key.
        bytes32 statefulRoot;
        // Highest stateful leaf index this key may sign with.
        uint32 maxStatefulSignatures;
        // Next monotonic stateful leaf index to consume.
        uint32 nextStatefulLeafIndex;
        // Stateless SK.seed-style material used to derive FORS-C and
        // hypertree WOTS-C secrets.
        bytes32 statelessSkSeed;
        // Stateless SK.prf-style material used to derive stateless message
        // randomizers.
        bytes32 statelessPrfSeed;
        // Global public seed used in FORS-C, hypertree WOTS-C, and Merkle
        // node hashing.
        bytes32 pkSeed;
        // Top hypertree root committed in the public key.
        bytes32 hypertreeRoot;
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

    struct WotsCSignature {
        // Per-layer randomizer for this WOTS-C signature.
        bytes randomizer;
        // Grinding counter for the WOTS-C target-sum constraint.
        uint32 counter;
        // Revealed WOTS-C chain values for this layer.
        bytes[] chains;
    }

    struct HypertreeLayerSignature {
        // Subtree index at this hypertree layer.
        uint64 treeIndex;
        // Leaf selected inside that subtree.
        uint32 leafIndex;
        // Commitment to the reconstructed WOTS-C public key for this layer.
        bytes wotsCPkHash;
        // WOTS-C signature carrying the previous layer's root upward.
        WotsCSignature wotsCSignature;
        // Authentication path from the WOTS leaf to the next layer root.
        bytes[] authPath;
    }

    struct StatelessSignature {
        // Message-signing few-time signature at the bottom of the stateless
        // path.
        ForsSignature fors;
        // Hypertree layers authenticating the FORS root to the public root.
        HypertreeLayerSignature[] hypertree;
    }

    struct StatefulRotationTarget {
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
    }

    struct RotationContext {
        // Contract/application domain binding for the rotation intent.
        bytes32 domainSeparator;
        // Replay-protection nonce consumed by the wrapper.
        uint256 nonce;
        // Installed-key epoch that this rotation authorizes from.
        uint256 keyVersion;
    }

    struct ActionContext {
        // Contract/application domain binding for the action intent.
        bytes32 domainSeparator;
        // Replay-protection nonce consumed by the wrapper.
        uint256 nonce;
        // Installed-key epoch that this action is valid under.
        uint256 keyVersion;
        // Typed action discriminator chosen by the integrating account logic.
        bytes32 actionType;
        // Hash of the typed payload authorized by the signature.
        bytes32 payloadHash;
    }

    struct RotationTarget {
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
        // Replacement stateless public seed.
        bytes pkSeed;
        // Replacement stateless public root.
        bytes hypertreeRoot;
    }
}
