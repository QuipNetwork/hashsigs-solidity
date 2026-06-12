// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";
import {ShrincsCommitment} from "./ShrincsCommitment.sol";
import {ShrincsValidation} from "./ShrincsValidation.sol";

// Stateful SHRINCS path: recover the compact WOTS-C public-key hash from the
// signature and message, then verify the unbalanced XMSS authentication path up
// to the stateful root embedded in the composite public key.
library ShrincsStateful {
    // 1. Validate the composite SHRINCS public key and embedded stateful key bytes.
    // 2. Recover the compact WOTS-C public key hash from the signature and message.
    // 3. Verify the unbalanced XMSS authentication path to the stateful root.
    function verifyRaw(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        ShrincsType.ParamsView memory p = ShrincsValidation.paramsView(parameterSetId);
        if (!ShrincsValidation.validParameterSetBinding(p, parameterSetId, publicKey.parameterSetId)) return false;
        if (!ShrincsCommitment.matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        if (!ShrincsCommitment.validStatefulCompositePublicKey(publicKey)) return false;
        (ShrincsType.StatefulPublicKey memory statefulKey, bool ok) =
            ShrincsCodec.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        uint32 leafIndex = uint32(signature.authPath.length);
        if (leafIndex == 0 || leafIndex > statefulKey.maxSignatures) return false;
        if (signature.chains.length != ShrincsType.WOTS_CHAINS_STATEFUL) return false;

        (bytes32 pkHash, bool validWots) =
            _compactStatefulWotsPublicKeyFromSignature(statefulKey.pkSeed, leafIndex, message, signature);
        if (!validWots) return false;

        (bytes32 root, bool validPath) =
            _rootFromUnbalancedPath(statefulKey.pkSeed, leafIndex, pkHash, signature.authPath);
        return validPath && statefulKey.root == root;
    }

    // Rebuild the compact stateful WOTS-C public-key hash from the signature chains
    // and the message-derived base-16 digits.
    function _compactStatefulWotsPublicKeyFromSignature(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory message,
        ShrincsType.StatefulSignature calldata signature
    ) private pure returns (bytes32 pkHash, bool ok) {
        bytes32 digest = keccak256(
            abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, signature.randomizer, signature.counter, message)
        );

        uint32 digitSum;
        bytes memory segments = new bytes(ShrincsType.WOTS_CHAINS_STATEFUL * 32);
        for (uint256 i = 0; i < ShrincsType.WOTS_CHAINS_STATEFUL;) {
            uint32 digit = ShrincsCodec.baseW16Digit(digest, i);
            digitSum += digit;
            bytes32 segment = _statefulChainNoMask(
                pkSeed, leafIndex, uint32(i), signature.chains[i], digit, ShrincsType.WOTS_BASE_STATEFUL - 1 - digit
            );
            ShrincsCodec.writeSegment32(segments, segment, i * 32);
            unchecked {
                ++i;
            }
        }

        if (digitSum != ShrincsType.WOTS_TARGET_SUM_STATEFUL) return (bytes32(0), false);
        return (keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, segments)), true);
    }

    // Verify the unbalanced XMSS-style authentication path used by the SHRINCS
    // stateful path.
    function _rootFromUnbalancedPath(bytes32 pkSeed, uint32 leafIndex, bytes32 leaf, bytes32[] calldata authPath)
        private
        pure
        returns (bytes32 root, bool ok)
    {
        if (authPath.length != leafIndex || authPath.length == 0) return (bytes32(0), false);
        root = _statefulParentHash(pkSeed, leafIndex, leaf, authPath[0]);
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            root = _statefulParentHash(pkSeed, leafIndex - uint32(offset) - 1, authPath[offset + 1], root);
            unchecked {
                ++offset;
            }
        }
        ok = true;
    }

    // Hash two stateful XMSS nodes into their parent under the unbalanced XMSS node
    // domain.
    function _statefulParentHash(bytes32 pkSeed, uint32 leftLeafIndex, bytes32 left, bytes32 right)
        private
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

    // Finish one stateful WOTS-C chain from its signed digit to the chain endpoint
    // used in the compact public-key hash.
    function _statefulChainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIdx,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) private pure returns (bytes32 out) {
        out = value;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord =
                ShrincsCodec.addressWord32(0, 0, ShrincsType.WOTS_HASH_TYPE, leafIndex, chainIdx, start + j);
            out = _hashStatefulWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    // Hash one stateful WOTS-C chain step under the shared WOTS chain domain.
    function _hashStatefulWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        private
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
}
