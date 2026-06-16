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

library ShrincsTypes {
    // Hash-suite identifiers bound into canonical action and rotation hashes.
    uint32 internal constant HASH_SUITE_KECCAK_256 = 1;
    uint32 internal constant HASH_SUITE_UNSUPPORTED = 2;
    // Operation tags domain-separating each signed message family.
    bytes32 internal constant OP_VERIFY_STATEFUL = keccak256("shrincs-verify-stateful");
    bytes32 internal constant OP_VERIFY_STATELESS = keccak256("shrincs-verify-stateless");
    bytes32 internal constant OP_ROTATE_STATEFUL = keccak256("shrincs-rotate-stateful");
    bytes32 internal constant OP_ROTATE_FULL = keccak256("shrincs-rotate-full");

    // Address-type words for the SPHINCS-style keyed hash inputs.
    uint32 internal constant AddressTypeWotsHash = 0;
    uint32 internal constant AddressTypeTree = 2;
    uint32 internal constant AddressTypeForsTree = 3;

    // Encoded stateful public key layout:
    // 32-byte pkSeed || 32-byte root || 4-byte maxSignatures.
    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES = 68;
    // Stateful WOTS-C uses 64 chains in the current supported profile.
    uint16 internal constant WOTS_CHAINS_STATEFUL = 64;
    // Stateful WOTS-C uses base-16 digits for message expansion.
    uint16 internal constant WOTS_BASE_STATEFUL = 16;
    // The 64 base-16 digits reconstructed from the stateful message digest must
    // sum to 480 in the current supported profile.
    uint32 internal constant WOTS_TARGET_SUM_STATEFUL = 480;

    enum ParameterSetId {
        // The only production SHRINCS/SPHINCS profile currently supported.
        Sphincs256sKeccakQ20,
        // Reserved sentinel used by negative tests and validation failures.
        Unsupported
    }

    struct ParamsView {
        // Which parameter set these concrete values correspond to.
        ParameterSetId parameterSetId;
        // Hash family used by this profile.
        uint32 hashSuiteId;
        // Intended upper bound on stateless signatures per installed key.
        uint64 statelessSignatureLimit;
        // Digest/output size in bytes.
        uint16 hashLen;
        // Total hypertree height.
        uint8 hypertreeHeight;
        // Number of XMSS-style layers in the hypertree.
        uint8 numHypertreeLayers;
        // Height of each FORS tree.
        uint8 forsTreeHeight;
        // Number of FORS trees opened per signature.
        uint8 numForsTrees;
        // Winternitz/base-w parameter.
        uint16 chainLen;
        // Number of WOTS-C chains in this profile.
        uint16 numWotsChains;
        // Fixed WOTS-C digit-sum target replacing an explicit checksum.
        uint32 wotsTargetSum;
    }

    struct ForsDigest {
        // Hypertree subtree selected for this stateless signature.
        uint64 treeIndex;
        // Leaf inside that subtree.
        uint32 leafIndex;
        // Message-derived FORS digest bits used to choose revealed leaves.
        bytes digest;
    }

    struct PublicKey {
        // Declared SHRINCS/SPHINCS profile.
        ParameterSetId parameterSetId;
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

    struct StatefulSignature {
        // Per-signature randomizer committed into the stateful message digest.
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
        // Message-signing few-time signature at the bottom of the stateless path.
        ForsSignature fors;
        // Hypertree layers authenticating the FORS root to the public root.
        HypertreeLayerSignature[] hypertree;
    }

    struct StatefulRotationTarget {
        // Parameter set for the next installed stateful key.
        ParameterSetId parameterSetId;
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
        // Parameter set for the next full SHRINCS bundle.
        ParameterSetId parameterSetId;
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
        // Replacement stateless public seed.
        bytes pkSeed;
        // Replacement stateless public root.
        bytes hypertreeRoot;
    }

    // defaultParamsView: Resolve the fixed parameter table for a supported profile or test sentinel.
    // 1. Return the full production parameter table for the supported SHRINCS/SPHINCS profile.
    // 2. Return an all-zero sentinel table for the explicit Unsupported test profile.
    // 3. Revert for any unknown identifier that is not part of the declared enum surface.
    function defaultParamsView(ParameterSetId parameterSetId) internal pure returns (ParamsView memory) {
        // Return the concrete production profile used throughout the current implementation.
        if (parameterSetId == ParameterSetId.Sphincs256sKeccakQ20) {
            return ParamsView({
                // Bind the concrete table back to the supported profile identifier.
                parameterSetId: ParameterSetId.Sphincs256sKeccakQ20,
                // Use the Keccak-256 hash suite throughout this profile.
                hashSuiteId: HASH_SUITE_KECCAK_256,
                // Budget stateless signatures up to the configured wrapper/account limit.
                statelessSignatureLimit: 1_048_576,
                // All hash outputs are 32 bytes wide.
                hashLen: 32,
                // Use a total hypertree height of 64.
                hypertreeHeight: 64,
                // Split the hypertree into 8 XMSS-style layers.
                numHypertreeLayers: 8,
                // Use FORS trees of height 14.
                forsTreeHeight: 14,
                // Use 22 FORS trees in the stateless message-signing layer.
                numForsTrees: 22,
                // Use base-16 WOTS chains.
                chainLen: 16,
                // Use 64 WOTS chains per signature.
                numWotsChains: 64,
                // Enforce the fixed compressed-WOTS target sum for this profile.
                wotsTargetSum: WOTS_TARGET_SUM_STATEFUL
            });
        }

        // Return the all-zero sentinel profile used by negative tests and validation failures.
        if (parameterSetId == ParameterSetId.Unsupported) {
            return ParamsView({
                // Bind the concrete table back to the explicit unsupported sentinel identifier.
                parameterSetId: ParameterSetId.Unsupported,
                // No hash suite is associated with the unsupported sentinel.
                hashSuiteId: 0,
                // No stateless signing budget is available for the unsupported sentinel.
                statelessSignatureLimit: 0,
                // All structural dimensions are zeroed out in the unsupported sentinel.
                hashLen: 0,
                hypertreeHeight: 0,
                numHypertreeLayers: 0,
                forsTreeHeight: 0,
                numForsTrees: 0,
                chainLen: 0,
                numWotsChains: 0,
                wotsTargetSum: 0
            });
        }

        // Reject any identifier that is outside the known supported/sentinel set.
        revert("unknown parameterSetId");
    }
}
