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
    uint32 internal constant HASH_SUITE_KECCAK_256 = 1;
    uint32 internal constant HASH_SUITE_UNSUPPORTED = 2;
    bytes32 internal constant OP_VERIFY_STATEFUL = keccak256("shrincs-verify-stateful");
    bytes32 internal constant OP_VERIFY_STATELESS = keccak256("shrincs-verify-stateless");
    bytes32 internal constant OP_ROTATE_STATEFUL = keccak256("shrincs-rotate-stateful");
    bytes32 internal constant OP_ROTATE_FULL = keccak256("shrincs-rotate-full");

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
        Sphincs256sKeccakQ20,
        Unsupported
    }

    struct ParamsView {
        ParameterSetId parameterSetId;
        uint32 hashSuiteId;
        uint64 statelessSignatureLimit;
        uint16 hashLen;
        uint8 hypertreeHeight;
        uint8 numHypertreeLayers;
        uint8 forsTreeHeight;
        uint8 numForsTrees;
        uint16 chainLen;
        uint16 numWotsChains;
        uint32 wotsTargetSum;
    }

    struct ForsDigest {
        uint64 treeIndex;
        uint32 leafIndex;
        bytes digest;
    }

    struct PublicKey {
        ParameterSetId parameterSetId;
        bytes statefulPublicKey;
        bytes publicKeyCommitment;
        bytes pkSeed;
        bytes hypertreeRoot;
    }

    struct StatefulPublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    struct StatefulSignature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[] chains;
        bytes32[] authPath;
    }

    struct ForsEntry {
        bytes secretLeaf;
        bytes[] authPath;
    }

    struct ForsSignature {
        bytes randomizer;
        uint32 counter;
        ForsEntry[] entries;
    }

    struct WotsCSignature {
        bytes randomizer;
        uint32 counter;
        bytes[] chains;
    }

    struct HypertreeLayerSignature {
        uint64 treeIndex;
        uint32 leafIndex;
        bytes wotsCPkHash;
        WotsCSignature wotsCSignature;
        bytes[] authPath;
    }

    struct StatelessSignature {
        ForsSignature fors;
        HypertreeLayerSignature[] hypertree;
    }

    struct StatefulRotationTarget {
        ParameterSetId parameterSetId;
        bytes statefulPublicKey;
        bytes publicKeyCommitment;
    }

    struct RotationContext {
        bytes32 domainSeparator;
        uint256 nonce;
        uint256 keyVersion;
    }

    struct ActionContext {
        bytes32 domainSeparator;
        uint256 nonce;
        uint256 keyVersion;
        bytes32 actionType;
        bytes32 payloadHash;
    }

    struct RotationTarget {
        ParameterSetId parameterSetId;
        bytes statefulPublicKey;
        bytes publicKeyCommitment;
        bytes pkSeed;
        bytes hypertreeRoot;
    }

    function defaultParamsView(ParameterSetId parameterSetId) internal pure returns (ParamsView memory) {
        if (parameterSetId == ParameterSetId.Sphincs256sKeccakQ20) {
            return ParamsView({
                parameterSetId: ParameterSetId.Sphincs256sKeccakQ20,
                hashSuiteId: HASH_SUITE_KECCAK_256,
                statelessSignatureLimit: 1_048_576,
                hashLen: 32,
                hypertreeHeight: 64,
                numHypertreeLayers: 8,
                forsTreeHeight: 14,
                numForsTrees: 22,
                chainLen: 16,
                numWotsChains: 64,
                wotsTargetSum: WOTS_TARGET_SUM_STATEFUL
            });
        }

        if (parameterSetId == ParameterSetId.Unsupported) {
            return ParamsView({
                parameterSetId: ParameterSetId.Unsupported,
                hashSuiteId: 0,
                statelessSignatureLimit: 0,
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

        revert("unknown parameterSetId");
    }
}
