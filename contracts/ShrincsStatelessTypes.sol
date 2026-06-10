// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Hashing } from "../../src/Hashing.sol";

abstract contract ShrincsStatelessTypes {
    uint8 public constant MODE_FORS_C = 1;
    uint8 public constant MODE_PORS_FP = 2;

    uint32 internal constant WOTS_HASH_TYPE = 0;
    uint32 internal constant TREE_TYPE = 2;
    uint32 internal constant FORS_TREE_TYPE = 3;
    uint32 internal constant PORS_TREE_TYPE = 128;
    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES = 68; // pkSeed || root || maxSignatures

    struct Params {
        uint8 mode;
        uint16 nBytes;
        uint8 h;
        uint8 d;
        uint8 a;
        uint8 k;
        uint16 w;
        uint16 l;
        uint32 wotsTargetSum;
        uint16 porsMaxAuth;
        bool wotsMask;
    }

    struct VariantParams {
        uint16 nBytes;
        uint8 h;
        uint8 d;
        uint8 a;
        uint8 k;
        uint16 w;
        uint16 l;
        uint32 wotsTargetSum;
        uint16 porsMaxAuth;
    }

    struct ParamsView {
        uint8 mode;
        uint16 nBytes;
        uint8 h;
        uint8 d;
        uint8 a;
        uint8 k;
        uint16 w;
        uint16 l;
        uint32 wotsTargetSum;
        uint16 porsMaxAuth;
        bool wotsMask;
    }

    struct PublicKey {
        bytes compositePublicKey;
        bytes statefulPublicKey;
        bytes messagePkSeed;
        bytes messageRoot;
        bytes hypertreePkSeed;
        bytes hypertreeRoot;
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

    struct PorsLeaf {
        uint32 leafIndex;
        bytes sk;
    }

    struct PorsAuthNode {
        uint32 level;
        uint32 index;
        bytes value;
    }

    struct PorsFpSignature {
        bytes randomizer;
        uint32 counter;
        PorsLeaf[] leaves;
        PorsAuthNode[] authSet;
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
        PorsFpSignature pors;
        HypertreeLayerSignature[] hypertree;
    }

    function paramsView(Params calldata params) internal pure returns (ParamsView memory) {
        return ParamsView({
            mode: params.mode,
            nBytes: params.nBytes,
            h: params.h,
            d: params.d,
            a: params.a,
            k: params.k,
            w: params.w,
            l: params.l,
            wotsTargetSum: params.wotsTargetSum,
            porsMaxAuth: params.porsMaxAuth,
            wotsMask: params.wotsMask
        });
    }

    function variantParamsView(VariantParams calldata params, uint8 mode, bool wotsMask) internal pure returns (ParamsView memory) {
        return ParamsView({
            mode: mode,
            nBytes: params.nBytes,
            h: params.h,
            d: params.d,
            a: params.a,
            k: params.k,
            w: params.w,
            l: params.l,
            wotsTargetSum: params.wotsTargetSum,
            porsMaxAuth: params.porsMaxAuth,
            wotsMask: wotsMask // True for Mask variant, False for NoMask variant
        });
    }

    function validParams(ParamsView memory params, PublicKey calldata publicKey) internal pure returns (bool) {
        if (params.nBytes != 32) return false;
        if (params.h == 0 || params.d == 0 || params.h % params.d != 0) return false;
        if (params.a == 0 || params.k == 0 || params.l == 0) return false;
        if (params.h > 64 || params.a >= 32 || params.h / params.d >= 32) return false;
        if (params.w != 16 && params.w != 256) return false;
        if (
            publicKey.compositePublicKey.length != 32 || publicKey.statefulPublicKey.length != STATEFUL_PUBLIC_KEY_BYTES
                || publicKey.messagePkSeed.length != 32 || publicKey.messageRoot.length != 32 || publicKey.hypertreePkSeed.length != 32
                || publicKey.hypertreeRoot.length != 32
        ) {
            return false;
        }
        if (!validCompositePublicKey(publicKey)) return false;
        if (uint256(params.k) * (uint256(1) << params.a) > type(uint32).max) return false;
        if (params.mode == MODE_PORS_FP && params.porsMaxAuth == 0) return false;
        return true;
    }

    function validCompositePublicKey(PublicKey calldata publicKey) internal pure returns (bool) {
        bytes calldata compositePublicKey = publicKey.compositePublicKey;
        bytes calldata statefulPublicKey = publicKey.statefulPublicKey;
        bytes calldata messagePkSeed = publicKey.messagePkSeed;
        bytes calldata messageRoot = publicKey.messageRoot;
        bytes calldata hypertreePkSeed = publicKey.hypertreePkSeed;
        bytes calldata hypertreeRoot = publicKey.hypertreeRoot;
        bytes32 computed;
        bytes32 expected;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "shrincs-public-key")
            calldatacopy(add(ptr, 18), statefulPublicKey.offset, 68)
            calldatacopy(add(ptr, 86), messagePkSeed.offset, 32)
            calldatacopy(add(ptr, 118), messageRoot.offset, 32)
            calldatacopy(add(ptr, 150), hypertreePkSeed.offset, 32)
            calldatacopy(add(ptr, 182), hypertreeRoot.offset, 32)
            computed := keccak256(ptr, 214)
            expected := calldataload(compositePublicKey.offset)
            mstore(0x40, add(ptr, 224))
        }
        return computed == expected;
    }

    function domainKeccakBytes(bytes memory domain, bytes memory seed, bytes memory data, uint256 outLen)
        internal
        pure
        returns (bytes memory)
    {
        if (outLen <= 32) return firstBytes(Hashing.hash(abi.encodePacked(domain, seed, data)), outLen);

        bytes memory out = new bytes(outLen);
        uint256 offset;
        uint32 counter;
        while (offset < outLen) {
            bytes32 blockHash = Hashing.hash(abi.encodePacked(domain, seed, data, counter));
            uint256 chunk = outLen - offset;
            if (chunk > 32) chunk = 32;
            for (uint256 i = 0; i < chunk;) {
                out[offset + i] = blockHash[i];
                unchecked {
                    ++i;
                }
            }
            offset += chunk;
            unchecked {
                ++counter;
            }
        }
        return out;
    }

    function firstBytes(bytes32 word, uint256 outLen) internal pure returns (bytes memory out) {
        out = new bytes(outLen);
        for (uint256 i = 0; i < outLen;) {
            out[i] = word[i];
            unchecked {
                ++i;
            }
        }
    }

    function baseWDigit(uint16 w, bytes memory digest, uint256 index) internal pure returns (uint32) {
        if (w == 256) return uint8(digest[index]);
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? b >> 4 : b & 0x0f;
    }

    function readBits(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint32 out) {
        return uint32(readBits64(input, startBit, bitLen));
    }

    function readBits64(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint64 out) {
        for (uint256 offset = 0; offset < bitLen;) {
            uint256 bitIndex = startBit + offset;
            uint8 bit = (uint8(input[bitIndex / 8]) >> (7 - (bitIndex % 8))) & 1;
            out = (out << 1) | uint64(bit);
            unchecked {
                ++offset;
            }
        }
    }

    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    function setSlice(bytes memory dst, bytes memory src, uint256 offset) internal pure {
        for (uint256 i = 0; i < src.length;) {
            dst[offset + i] = src[i];
            unchecked {
                ++i;
            }
        }
    }

    function eq(bytes memory left, bytes calldata right) internal pure returns (bool) {
        return keccak256(left) == keccak256(right);
    }

    function log2ceil(uint32 value) internal pure returns (uint32) {
        if (value <= 1) return 0;
        uint32 v = value - 1;
        uint32 out;
        while (v > 0) {
            v >>= 1;
            unchecked {
                ++out;
            }
        }
        return out;
    }

    function forsAddress(uint32 addressType, uint64 tree, uint32 keypair, uint32 height, uint32 index) internal pure returns (bytes32) {
        return addressWord32(0, tree, addressType, keypair, height, index);
    }

    function hashTreeAddress(uint32 layer, uint64 tree, uint32 height, uint32 index) internal pure returns (bytes32) {
        return addressWord32(layer, tree, TREE_TYPE, 0, height, index);
    }

    function forsTreeIndex(uint32 forsTree, uint32 forsHeight, uint32 nodeHeight, uint32 nodeIndex) internal pure returns (uint32) {
        return (forsTree << (forsHeight - nodeHeight)) + nodeIndex;
    }

    function addressWord32(uint32 layer, uint64 tree, uint32 addressType, uint32 keypair, uint32 chain, uint32 step)
        internal
        pure
        returns (bytes32)
    {
        return bytes32(
            (uint256(layer) << 224) | (uint256(tree) << 128) | (uint256(addressType) << 96) | (uint256(keypair) << 64)
                | (uint256(chain) << 32) | uint256(step)
        );
    }
}
