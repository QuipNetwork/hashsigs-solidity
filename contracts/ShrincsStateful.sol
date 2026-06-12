// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import { ShrincsTypes } from "./ShrincsTypes.sol";
import { ShrincsUtils } from "./ShrincsUtils.sol";

library ShrincsStateful {
    function verifyStatefulUnsafeRaw(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        if (!ShrincsUtils.validParameterSetBinding(p, parameterSetId, publicKey.parameterSetId)) return false;
        if (!ShrincsUtils.matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        if (!ShrincsUtils.validStatefulCompositePublicKey(publicKey)) return false;
        (ShrincsTypes.StatefulPublicKey memory statefulKey, bool ok) =
            ShrincsUtils.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        uint32 leafIndex = uint32(signature.authPath.length);
        if (leafIndex == 0 || leafIndex > statefulKey.maxSignatures) return false;
        if (signature.chains.length != ShrincsTypes.WOTS_CHAINS_STATEFUL) return false;

        (bytes32 pkHash, bool validWots) =
            compactStatefulWotsPublicKeyFromSignature(statefulKey.pkSeed, leafIndex, message, signature);
        if (!validWots) return false;

        (bytes32 root, bool validPath) = rootFromUnbalancedPath(statefulKey.pkSeed, leafIndex, pkHash, signature.authPath);
        return validPath && statefulKey.root == root;
    }

    function compactStatefulWotsPublicKeyFromSignature(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bytes32 pkHash, bool ok) {
        bytes32 digest = keccak256(
            abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, signature.randomizer, signature.counter, message)
        );

        uint32 digitSum;
        bytes memory segments = new bytes(ShrincsTypes.WOTS_CHAINS_STATEFUL * 32);
        for (uint256 i = 0; i < ShrincsTypes.WOTS_CHAINS_STATEFUL;) {
            uint32 digit = baseW16Digit(digest, i);
            digitSum += digit;
            bytes32 segment = statefulChainNoMask(
                pkSeed,
                leafIndex,
                uint32(i),
                signature.chains[i],
                digit,
                ShrincsTypes.WOTS_BASE_STATEFUL - 1 - digit
            );
            setSlice32(segments, segment, i * 32);
            unchecked {
                ++i;
            }
        }

        if (digitSum != ShrincsTypes.WOTS_TARGET_SUM_STATEFUL) return (bytes32(0), false);
        return (keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, segments)), true);
    }

    function rootFromUnbalancedPath(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] calldata authPath
    ) internal pure returns (bytes32 root, bool ok) {
        if (authPath.length != leafIndex || authPath.length == 0) return (bytes32(0), false);
        root = statefulParentHash(pkSeed, leafIndex, leaf, authPath[0]);
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            root = statefulParentHash(pkSeed, leafIndex - uint32(offset) - 1, authPath[offset + 1], root);
            unchecked {
                ++offset;
            }
        }
        ok = true;
    }

    function statefulParentHash(bytes32 pkSeed, uint32 leftLeafIndex, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "uxmss-node")
            mstore(add(ptr, 10), pkSeed)
            mstore(add(ptr, 42), shl(224, leftLeafIndex))
            mstore(add(ptr, 46), left)
            mstore(add(ptr, 78), right)
            out := keccak256(ptr, 110)
        }
    }

    function statefulChainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIdx,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        out = value;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord =
                ShrincsUtils.addressWord32(0, 0, ShrincsTypes.WOTS_HASH_TYPE, leafIndex, chainIdx, start + j);
            out = hashStatefulWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    function hashStatefulWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "wots-c-chain")
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), segment)
            out := keccak256(ptr, 108)
        }
    }

    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32 digit) {
        assembly {
            let b := byte(shr(1, index), digest)
            digit := and(b, 0x0f)
            if iszero(and(index, 1)) { digit := shr(4, b) }
        }
    }

    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }
}
