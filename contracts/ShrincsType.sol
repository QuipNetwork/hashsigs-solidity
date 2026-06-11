// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract ShrincsType {
    uint32 internal constant WOTS_HASH_TYPE = 0;
    uint32 internal constant TREE_TYPE = 2;
    uint32 internal constant FORS_TREE_TYPE = 3;
    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES = 68; // pkSeed || root || maxSignatures

    enum VerificationPath {
        Stateful,
        Stateless
    }

    struct Params {
        uint32 parameterSetId;
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

    struct ParamsView {
        uint32 parameterSetId;
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

    struct PublicKey {
        uint32 parameterSetId;
        uint32 hashSuiteId;
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
        uint32 parameterSetId;
        uint32 hashSuiteId;
        bytes statefulPublicKey;
    }

    struct RotationTarget {
        uint32 parameterSetId;
        uint32 hashSuiteId;
        bytes compositePublicKey;
        bytes statefulPublicKey;
        bytes messagePkSeed;
        bytes messageRoot;
        bytes hypertreePkSeed;
        bytes hypertreeRoot;
    }
}
