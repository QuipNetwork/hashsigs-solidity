// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import { ShrincsTypes } from "./ShrincsTypes.sol";
import { ShrincsUtils } from "./ShrincsUtils.sol";
import { ShrincsStateful } from "./ShrincsStateful.sol";
import { ShrincsForsC } from "./ShrincsForsC.sol";
import { ShrincsHypertree } from "./ShrincsHypertree.sol";

library SHRINCS {
    function verifyStatefulUnsafeRaw(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        return ShrincsStateful.verifyStatefulUnsafeRaw(
            parameterSetId, expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verifyStateful(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext memory context,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        if (!ShrincsUtils.validActionContext(context)) return false;
        bytes memory message = abi.encodePacked(
            statefulActionMessageHash(parameterSetId, expectedCompositePublicKey, context)
        );
        return verifyStatefulUnsafeRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    function verifyStatelessUnsafeRaw(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        if (!ShrincsUtils.validParameterSetBinding(p, parameterSetId, publicKey.parameterSetId)) return false;
        if (!ShrincsUtils.matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        return _verifyStatelessMemory(parameterSetId, publicKey, message, signature);
    }

    function verifyStateless(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext memory context,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        if (!ShrincsUtils.validActionContext(context)) return false;
        bytes memory message = abi.encodePacked(
            statelessActionMessageHash(parameterSetId, expectedCompositePublicKey, context)
        );
        return _verifyStatelessRawMemory(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    function rotateStatefulViaStateless(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32 nextStatefulKeyCommitment) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        if (!ShrincsUtils.validParameterSetBinding(p, parameterSetId, currentPublicKey.parameterSetId)) return bytes32(0);
        if (!ShrincsUtils.matchesExpectedCompositePublicKey(currentPublicKey, expectedCompositePublicKey)) return bytes32(0);
        if (!ShrincsUtils.validRotationContext(context)) return bytes32(0);
        if (!ShrincsUtils.validParams(p, currentPublicKey)) return bytes32(0);
        if (!ShrincsUtils.validParameterSetBinding(p, parameterSetId, nextStatefulKey.parameterSetId)) return bytes32(0);
        if (nextStatefulKey.statefulPublicKey.length != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES) return bytes32(0);
        {
            (ShrincsTypes.StatefulPublicKey memory decodedNextStatefulKey, bool ok) =
                ShrincsUtils.decodeStatefulPublicKey(nextStatefulKey.statefulPublicKey);
            if (!ok || decodedNextStatefulKey.maxSignatures == 0) return bytes32(0);
        }
        bytes memory recoveryMessage = abi.encodePacked(
            statefulRotationMessageHash(parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextStatefulKey)
        );
        if (!_verifyStatelessRawMemory(parameterSetId, expectedCompositePublicKey, currentPublicKey, recoveryMessage, recoverySignature)) return bytes32(0);

        return ShrincsUtils.compositePublicKeyCommitment(
            nextStatefulKey.statefulPublicKey,
            currentPublicKey.messagePkSeed,
            currentPublicKey.messageRoot,
            currentPublicKey.hypertreePkSeed,
            currentPublicKey.hypertreeRoot
        );
    }

    function rotateFullShrincsKey(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) internal pure returns (bytes32 nextCompositePublicKey) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        if (!ShrincsUtils.validParameterSetBinding(p, parameterSetId, currentPublicKey.parameterSetId)) return bytes32(0);
        if (!ShrincsUtils.matchesExpectedCompositePublicKey(currentPublicKey, expectedCompositePublicKey)) return bytes32(0);
        if (!ShrincsUtils.validRotationContext(context)) return bytes32(0);
        if (!ShrincsUtils.validParams(p, currentPublicKey)) return bytes32(0);
        if (!ShrincsUtils.validParameterSetBinding(p, parameterSetId, nextKey.parameterSetId)) return bytes32(0);
        if (
            nextKey.statefulPublicKey.length != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES
                || nextKey.compositePublicKey.length != 32
                || nextKey.messagePkSeed.length != 32
                || nextKey.messageRoot.length != 32
                || nextKey.hypertreePkSeed.length != 32
                || nextKey.hypertreeRoot.length != 32
        ) return bytes32(0);
        {
            (ShrincsTypes.StatefulPublicKey memory decodedNextStatefulKey, bool ok) =
                ShrincsUtils.decodeStatefulPublicKey(nextKey.statefulPublicKey);
            if (!ok || decodedNextStatefulKey.maxSignatures == 0) return bytes32(0);
        }

        nextCompositePublicKey = ShrincsUtils.compositePublicKeyCommitment(
            nextKey.statefulPublicKey,
            nextKey.messagePkSeed,
            nextKey.messageRoot,
            nextKey.hypertreePkSeed,
            nextKey.hypertreeRoot
        );

        bytes32 nextCompositePublicKeyWord;
        bytes calldata compositePublicKey = nextKey.compositePublicKey;
        assembly {
            nextCompositePublicKeyWord := calldataload(compositePublicKey.offset)
        }
        if (nextCompositePublicKey != nextCompositePublicKeyWord) return bytes32(0);

        bytes memory recoveryMessage =
            abi.encodePacked(fullRotationMessageHash(parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextKey));
        if (!_verifyStatelessRawMemory(parameterSetId, expectedCompositePublicKey, currentPublicKey, recoveryMessage, recoverySignature)) return bytes32(0);
    }

    function statefulActionMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.ActionContext memory context
    ) internal pure returns (bytes32) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_VERIFY_STATEFUL,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    function statelessActionMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.ActionContext memory context
    ) internal pure returns (bytes32) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_VERIFY_STATELESS,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    function statefulRotationMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_ROTATE_STATEFUL,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.compositePublicKey,
                nextStatefulKey.statefulPublicKey
            )
        );
    }

    function fullRotationMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        bytes32 nextKeyBundleHash = keccak256(
            abi.encodePacked(
                nextKey.compositePublicKey,
                nextKey.statefulPublicKey,
                nextKey.messagePkSeed,
                nextKey.messageRoot,
                nextKey.hypertreePkSeed,
                nextKey.hypertreeRoot
            )
        );
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_ROTATE_FULL,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.compositePublicKey,
                nextKeyBundleHash
            )
        );
    }

    function _verifyStatelessMemory(
        ShrincsTypes.ParameterSetId parameterSetId,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature calldata signature
    ) private pure returns (bool) {
        return _verifyStatelessRawMemory(
            parameterSetId,
            ShrincsUtils.compositePublicKeyWord(publicKey.compositePublicKey),
            publicKey,
            message,
            signature
        );
    }

    function _verifyStatelessRawMemory(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature calldata signature
    ) private pure returns (bool) {
        if (!ShrincsUtils.matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        ShrincsTypes.ParamsView memory p = ShrincsUtils.paramsView(parameterSetId);
        if (!ShrincsUtils.validParams(p, publicKey)) return false;
        if (signature.hypertree.length == 0) return false;

        (bytes32 messageRoot, bool ok) = ShrincsForsC.verifyForsCAndReturnRoot(
            p, publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
        );
        if (!ok) return false;
        return ShrincsHypertree.verifyHypertree(p, publicKey, messageRoot, signature.hypertree);
    }
}
