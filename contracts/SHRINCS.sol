// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "./ShrincsTypes.sol";
import {ShrincsCodec} from "./shrincs/ShrincsCodec.sol";
import {ShrincsCommitment} from "./shrincs/ShrincsCommitment.sol";
import {ShrincsValidation} from "./shrincs/ShrincsValidation.sol";
import {ShrincsMessages} from "./shrincs/ShrincsMessages.sol";
import {ShrincsStateless} from "./shrincs/ShrincsStateless.sol";
import {ShrincsStateful} from "./shrincs/ShrincsStateful.sol";

// Public entry points for SHRINCS verification and key rotation. The facade binds
// the requested parameter set, builds the canonical signed message, and delegates
// to the stateful/stateless verifier modules. All cryptographic work lives under
// ./shrincs.
library SHRINCS {
    function verifyStatefulUnsafeRaw(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        return ShrincsStateful.verifyRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    function verifyStateful(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        ShrincsType.ActionContext memory context,
        ShrincsType.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        if (!ShrincsValidation.validActionContext(context)) {
            return false;
        }
        bytes memory message = abi.encodePacked(
            ShrincsMessages.statefulActionMessageHash(parameterSetId, expectedCompositePublicKey, context)
        );
        return verifyStatefulUnsafeRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    function verifyStatelessUnsafeRaw(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        ShrincsType.ParamsView memory p = ShrincsValidation.paramsView(parameterSetId);
        if (!ShrincsValidation.validParameterSetBinding(p, parameterSetId, publicKey.parameterSetId)) return false;
        if (!ShrincsCommitment.matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        return ShrincsStateless.verifyMemory(parameterSetId, publicKey, message, signature);
    }

    function verifyStateless(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        ShrincsType.ActionContext memory context,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        if (!ShrincsValidation.validActionContext(context)) {
            return false;
        }
        bytes memory message = abi.encodePacked(
            ShrincsMessages.statelessActionMessageHash(parameterSetId, expectedCompositePublicKey, context)
        );
        return ShrincsStateless.verifyRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    // Placeholder for a future on-chain flow where a stateless signature authorizes
    // replacement of only the stateful SHRINCS component.
    function rotateStatefulViaStateless(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext memory context,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32 nextStatefulKeyCommitment) {
        ShrincsType.ParamsView memory p = ShrincsValidation.paramsView(parameterSetId);
        if (!ShrincsValidation.validParameterSetBinding(p, parameterSetId, currentPublicKey.parameterSetId)) {
            return bytes32(0);
        }
        if (!ShrincsCommitment.matchesExpectedCompositePublicKey(currentPublicKey, expectedCompositePublicKey)) {
            return bytes32(0);
        }
        if (!ShrincsValidation.validRotationContext(context)) return bytes32(0);
        if (!ShrincsValidation.validParams(p, currentPublicKey)) return bytes32(0);
        if (!ShrincsValidation.validParameterSetBinding(p, parameterSetId, nextStatefulKey.parameterSetId)) {
            return bytes32(0);
        }
        if (nextStatefulKey.statefulPublicKey.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES) return bytes32(0);
        {
            (ShrincsType.StatefulPublicKey memory decodedNextStatefulKey, bool ok) =
                ShrincsCodec.decodeStatefulPublicKey(nextStatefulKey.statefulPublicKey);
            if (!ok || decodedNextStatefulKey.maxSignatures == 0) return bytes32(0);
        }
        bytes memory recoveryMessage = abi.encodePacked(
            ShrincsMessages.statefulRotationMessageHash(
                parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextStatefulKey
            )
        );
        if (!ShrincsStateless.verifyRaw(
                parameterSetId, expectedCompositePublicKey, currentPublicKey, recoveryMessage, recoverySignature
            )) return bytes32(0);

        return ShrincsCommitment.compositePublicKeyCommitment(
            nextStatefulKey.statefulPublicKey,
            currentPublicKey.messagePkSeed,
            currentPublicKey.messageRoot,
            currentPublicKey.hypertreePkSeed,
            currentPublicKey.hypertreeRoot
        );
    }

    // Placeholder for a future on-chain flow where a stateless signature authorizes
    // a full SHRINCS key rotation to a fresh composite public key.
    function rotateFullShrincsKey(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext memory context,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) internal pure returns (bytes32 nextCompositePublicKey) {
        ShrincsType.ParamsView memory p = ShrincsValidation.paramsView(parameterSetId);
        if (!ShrincsValidation.validParameterSetBinding(p, parameterSetId, currentPublicKey.parameterSetId)) {
            return bytes32(0);
        }
        if (!ShrincsCommitment.matchesExpectedCompositePublicKey(currentPublicKey, expectedCompositePublicKey)) {
            return bytes32(0);
        }
        if (!ShrincsValidation.validRotationContext(context)) return bytes32(0);
        if (!ShrincsValidation.validParams(p, currentPublicKey)) return bytes32(0);
        if (!ShrincsValidation.validParameterSetBinding(p, parameterSetId, nextKey.parameterSetId)) return bytes32(0);
        if (
            nextKey.statefulPublicKey.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES
                || nextKey.compositePublicKey.length != 32 || nextKey.messagePkSeed.length != 32
                || nextKey.messageRoot.length != 32 || nextKey.hypertreePkSeed.length != 32
                || nextKey.hypertreeRoot.length != 32
        ) return bytes32(0);
        {
            (ShrincsType.StatefulPublicKey memory decodedNextStatefulKey, bool ok) =
                ShrincsCodec.decodeStatefulPublicKey(nextKey.statefulPublicKey);
            if (!ok || decodedNextStatefulKey.maxSignatures == 0) return bytes32(0);
        }

        nextCompositePublicKey = ShrincsCommitment.compositePublicKeyCommitment(
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

        bytes memory recoveryMessage = abi.encodePacked(
            ShrincsMessages.fullRotationMessageHash(
                parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextKey
            )
        );
        if (!ShrincsStateless.verifyRaw(
                parameterSetId, expectedCompositePublicKey, currentPublicKey, recoveryMessage, recoverySignature
            )) return bytes32(0);
    }

    // Message-hash builders re-exported so existing `SHRINCS.*` callers keep working;
    // the canonical construction lives in ShrincsMessages.
    function statefulActionMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.ActionContext memory context
    ) internal pure returns (bytes32) {
        return ShrincsMessages.statefulActionMessageHash(parameterSetId, expectedCompositePublicKey, context);
    }

    function statelessActionMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.ActionContext memory context
    ) internal pure returns (bytes32) {
        return ShrincsMessages.statelessActionMessageHash(parameterSetId, expectedCompositePublicKey, context);
    }

    function statefulRotationMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext memory context,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        return ShrincsMessages.statefulRotationMessageHash(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextStatefulKey
        );
    }

    function fullRotationMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext memory context,
        ShrincsType.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        return ShrincsMessages.fullRotationMessageHash(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextKey
        );
    }
}
