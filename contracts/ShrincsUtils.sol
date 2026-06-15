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
        if (params.hashLen != 32) return false;
        if (params.parameterSetId != publicKey.parameterSetId) return false;
        if (params.hypertreeHeight != 64 || params.numHypertreeLayers != 8 || params.forsTreeHeight != 14) {
            return false;
        }
        if (params.numForsTrees != 22 || params.chainLen != 16 || params.numWotsChains != 64) return false;
        if (params.wotsTargetSum != ShrincsTypes.WOTS_TARGET_SUM_STATEFUL) return false;
        if (!validPublicKey(publicKey)) return false;
        if (uint256(params.numForsTrees) * (uint256(1) << params.forsTreeHeight) > type(uint32).max) return false;
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
        return
            context.domainSeparator != bytes32(0) && context.actionType != bytes32(0)
                && context.payloadHash != bytes32(0);
    }

    function validRotationContext(ShrincsTypes.RotationContext memory context) internal pure returns (bool) {
        return context.domainSeparator != bytes32(0);
    }

    function publicKeyCommitment(ShrincsTypes.PublicKey calldata publicKey) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                uint8(publicKey.parameterSetId),
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    function publicKeyCommitmentFromParts(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("shrincs-public-key", uint8(parameterSetId), statefulPublicKey, pkSeed, hypertreeRoot)
        );
    }

    function matchesExpectedPublicKeyCommitment(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 expectedPublicKeyCommitment
    ) internal pure returns (bool) {
        if (expectedPublicKeyCommitment == bytes32(0)) return false;
        if (publicKey.publicKeyCommitment.length != 32) return false;
        bytes calldata encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 actualCommitment;
        assembly {
            actualCommitment := calldataload(encodedCommitment.offset)
        }
        return actualCommitment == expectedPublicKeyCommitment
            && publicKeyCommitment(publicKey) == expectedPublicKeyCommitment;
    }

    function validPublicKey(ShrincsTypes.PublicKey calldata publicKey) internal pure returns (bool) {
        if (publicKey.statefulPublicKey.length != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES) return false;
        if (publicKey.publicKeyCommitment.length != 32) return false;
        if (publicKey.pkSeed.length != 32) return false;
        if (publicKey.hypertreeRoot.length != 32) return false;
        bytes calldata encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 expectedCommitment;
        assembly {
            expectedCommitment := calldataload(encodedCommitment.offset)
        }
        return publicKeyCommitment(publicKey) == expectedCommitment;
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

        return bytes32(shiftedLayer | shiftedTree | shiftedAddressType | shiftedKeypair | shiftedChain | shiftedStep);
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

    function readBits32(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint32) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        // casting to 'uint32' is safe because the mask bounds the result to at most 32 bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(shifted & mask);
    }

    function readBits64(bytes memory input, uint256 startBit, uint32 bitLen) internal pure returns (uint64) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        // casting to 'uint64' is safe because the mask bounds the result to at most 64 bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(shifted & mask);
    }
}
