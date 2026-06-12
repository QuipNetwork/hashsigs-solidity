// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import { ShrincsTypes } from "./ShrincsTypes.sol";

library ShrincsUtils {
    function paramsView(ShrincsTypes.ParameterSetId parameterSetId)
        internal
        pure
        returns (ShrincsTypes.ParamsView memory)
    {
        return ShrincsTypes.defaultParamsView(parameterSetId);
    }

    function validParams(ShrincsTypes.ParamsView memory params, ShrincsTypes.PublicKey calldata publicKey)
        internal
        pure
        returns (bool)
    {
        if (params.parameterSetId != ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20) return false;
        if (params.nBytes != 32) return false;
        if (params.parameterSetId != publicKey.parameterSetId) return false;
        if (params.h != 64 || params.d != 8 || params.a != 14) return false;
        if (params.k != 22 || params.w != 16 || params.l != 64) return false;
        if (params.wotsTargetSum != ShrincsTypes.WOTS_TARGET_SUM_STATEFUL) return false;
        if (!validStatefulCompositePublicKey(publicKey)) return false;
        if (uint256(params.k) * (uint256(1) << params.a) > type(uint32).max) return false;
        return true;
    }

    function validParameterSetBinding(
        ShrincsTypes.ParamsView memory params,
        ShrincsTypes.ParameterSetId requestedParameterSetId,
        ShrincsTypes.ParameterSetId declaredParameterSetId
    ) internal pure returns (bool) {
        return params.parameterSetId == requestedParameterSetId && declaredParameterSetId == requestedParameterSetId
            && params.hashSuiteId == ShrincsTypes.HASH_SUITE_KECCAK_256;
    }

    function validActionContext(ShrincsTypes.ActionContext memory context) internal pure returns (bool) {
        return context.domainSeparator != bytes32(0) && context.actionType != bytes32(0)
            && context.payloadHash != bytes32(0);
    }

    function validRotationContext(ShrincsTypes.RotationContext memory context) internal pure returns (bool) {
        return context.domainSeparator != bytes32(0);
    }

    function matchesExpectedCompositePublicKey(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 expectedCompositePublicKey
    ) internal pure returns (bool) {
        if (expectedCompositePublicKey == bytes32(0)) return false;
        return compositePublicKeyWord(publicKey.compositePublicKey) == expectedCompositePublicKey;
    }

    function compositePublicKeyWord(bytes calldata compositePublicKey) internal pure returns (bytes32 word) {
        if (compositePublicKey.length != 32) return bytes32(0);
        assembly {
            word := calldataload(compositePublicKey.offset)
        }
    }

    function validStatefulCompositePublicKey(ShrincsTypes.PublicKey calldata publicKey) internal pure returns (bool) {
        if (publicKey.compositePublicKey.length != 32) return false;
        if (publicKey.statefulPublicKey.length != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES) return false;
        if (publicKey.messagePkSeed.length != 32) return false;
        if (publicKey.messageRoot.length != 32) return false;
        if (publicKey.hypertreePkSeed.length != 32) return false;
        if (publicKey.hypertreeRoot.length != 32) return false;

        bytes32 expected;
        bytes calldata compositePublicKey = publicKey.compositePublicKey;
        assembly {
            expected := calldataload(compositePublicKey.offset)
        }
        return compositePublicKeyCommitment(
            publicKey.statefulPublicKey,
            publicKey.messagePkSeed,
            publicKey.messageRoot,
            publicKey.hypertreePkSeed,
            publicKey.hypertreeRoot
        ) == expected;
    }

    function compositePublicKeyCommitment(
        bytes calldata statefulPublicKey,
        bytes calldata messagePkSeed,
        bytes calldata messageRoot,
        bytes calldata hypertreePkSeed,
        bytes calldata hypertreeRoot
    ) internal pure returns (bytes32 computed) {
        uint256 statefulPkLen = ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES;
        uint256 compositeInputLen = 18 + statefulPkLen + 32 + 32 + 32 + 32;

        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "shrincs-public-key")
            calldatacopy(add(ptr, 18), statefulPublicKey.offset, statefulPkLen)
            calldatacopy(add(ptr, add(18, statefulPkLen)), messagePkSeed.offset, 32)
            calldatacopy(add(ptr, add(50, statefulPkLen)), messageRoot.offset, 32)
            calldatacopy(add(ptr, add(82, statefulPkLen)), hypertreePkSeed.offset, 32)
            calldatacopy(add(ptr, add(114, statefulPkLen)), hypertreeRoot.offset, 32)
            computed := keccak256(ptr, compositeInputLen)
            mstore(0x40, add(ptr, 224))
        }
    }

    function decodeStatefulPublicKey(bytes calldata encoded)
        internal
        pure
        returns (ShrincsTypes.StatefulPublicKey memory publicKey, bool ok)
    {
        if (encoded.length != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES) return (publicKey, false);
        assembly {
            publicKey := mload(0x40)
            mstore(publicKey, calldataload(encoded.offset))
            mstore(add(publicKey, 0x20), calldataload(add(encoded.offset, 32)))
            mstore(add(publicKey, 0x40), shr(224, calldataload(add(encoded.offset, 64))))
            mstore(0x40, add(publicKey, 0x60))
        }
        return (publicKey, true);
    }

    function addressWord32(uint32 layer, uint64 tree, uint32 addressType, uint32 keypair, uint32 chain, uint32 step)
        internal
        pure
        returns (bytes32)
    {
        uint256 shiftedLayer = uint256(layer) << 224;
        uint256 shiftedTree = uint256(tree) << 128;
        uint256 shiftedAddressType = uint256(addressType) << 96;
        uint256 shiftedKeypair = uint256(keypair) << 64;
        uint256 shiftedChain = uint256(chain) << 32;
        uint256 shiftedStep = uint256(step);

        return bytes32(
            shiftedLayer | shiftedTree | shiftedAddressType | shiftedKeypair | shiftedChain | shiftedStep
        );
    }

    function baseWDigit(uint16 w, bytes memory digest, uint256 index) internal pure returns (uint32) {
        if (w == 256) return uint8(digest[index]);
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? b >> 4 : b & 0x0f;
    }

    function setHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) internal pure {
        for (uint256 i = 0; i < chunk;) {
            out[offset + i] = blockHash[i];
            unchecked {
                ++i;
            }
        }
    }

    function readBits32Fast(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint32) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        return uint32(shifted & mask);
    }

    function readBits64Fast(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint64) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        return uint64(shifted & mask);
    }
}
