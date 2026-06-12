// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";

// Canonical signed-message preimage construction. Every operation a SHRINCS
// signature can authorize binds to exactly one domain-separated digest built
// here, so the domain separation lives in one auditable place.
library ShrincsMessages {
    function statefulActionMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.ActionContext memory context
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = ShrincsType.defaultParamsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_VERIFY_STATEFUL,
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
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.ActionContext memory context
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = ShrincsType.defaultParamsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_VERIFY_STATELESS,
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

    // Compute the canonical hash that a stateless recovery signature must cover when
    // authorizing replacement of only the stateful SHRINCS component.
    function statefulRotationMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext memory context,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = ShrincsType.defaultParamsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_ROTATE_STATEFUL,
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

    // Compute the canonical hash that a stateless recovery signature must cover when
    // authorizing a full next SHRINCS key bundle.
    function fullRotationMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext memory context,
        ShrincsType.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = ShrincsType.defaultParamsView(parameterSetId);
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
                ShrincsType.OP_ROTATE_FULL,
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
}
