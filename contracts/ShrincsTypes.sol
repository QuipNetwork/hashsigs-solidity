// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library ShrincsType {
    uint32 internal constant HASH_SUITE_KECCAK_256 = 1;

    uint32 internal constant WOTS_HASH_TYPE = 0;
    uint32 internal constant TREE_TYPE = 2;
    uint32 internal constant FORS_TREE_TYPE = 3;

    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES = 68; // pkSeed || root || maxSignatures
    uint16 internal constant WOTS_CHAINS_STATEFUL = 64;
    uint16 internal constant WOTS_BASE_STATEFUL = 16;
    uint32 internal constant WOTS_TARGET_SUM_STATEFUL = 480;

    enum VerificationPath {
        Stateful,
        Stateless
    }

    enum ParameterSetId {
        Sphincs256sKeccak
    }

    struct ParamsView {
        ParameterSetId parameterSetId;
        uint32 hashSuiteId;
        uint16 nBytes;
        uint8 h;
        uint8 d;
        uint8 a;
        uint8 k;
        uint16 w;
        uint16 l;
        uint32 wotsTargetSum;
    }

    struct WotsContext {
        uint16 w;
        uint32 layer;
        uint64 tree;
        uint32 keypair;
    }

    struct ForsDigest {
        uint64 xmssTree;
        uint32 xmssKeypair;
        bytes digest;
    }

    struct PublicKey {
        ParameterSetId parameterSetId;
        bytes compositePublicKey;
        bytes statefulPublicKey;
        bytes messagePkSeed;
        bytes messageRoot;
        bytes hypertreePkSeed;
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
        bytes sk;
        bytes[] auth;
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
    }

    struct RotationTarget {
        ParameterSetId parameterSetId;
        bytes compositePublicKey;
        bytes statefulPublicKey;
        bytes messagePkSeed;
        bytes messageRoot;
        bytes hypertreePkSeed;
        bytes hypertreeRoot;
    }

    function defaultParamsView(ParameterSetId parameterSetId)
        internal
        pure
        returns (ParamsView memory)
    {
        if (parameterSetId == ParameterSetId.Sphincs256sKeccak) {
            return ParamsView({
                parameterSetId: ParameterSetId.Sphincs256sKeccak,
                hashSuiteId: HASH_SUITE_KECCAK_256,
                nBytes: 32,
                h: 64,
                d: 8,
                a: 14,
                k: 22,
                w: 16,
                l: 64,
                wotsTargetSum: WOTS_TARGET_SUM_STATEFUL
            });
        }

        revert("unknown parameterSetId");
    }
}
