// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { SHRINCS } from "../SHRINCS.sol";
import { ShrincsType } from "../ShrincsTypes.sol";

contract ShrincsAccountVerifierExample {
    bytes32 public currentShrincsPublicKey;
    ShrincsType.ParameterSetId public parameterSetId;
    uint256 public nonce;
    uint256 public keyVersion;
    uint64 public statelessSignaturesUsed;

    bytes32 internal constant DOMAIN_SEPARATOR = keccak256("shrincs-account-v1");

    constructor(bytes32 initialShrincsPublicKey) {
        currentShrincsPublicKey = initialShrincsPublicKey;
        parameterSetId = ShrincsType.ParameterSetId.Sphincs256sKeccakQ20;
    }

    function verifyStatefulAction(
        ShrincsType.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsType.StatefulSignature calldata signature
    ) external returns (bool) {
        ShrincsType.ActionContext memory context = ShrincsType.ActionContext({
            domainSeparator: DOMAIN_SEPARATOR,
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        bool ok = SHRINCS.verifyStateful(
            parameterSetId,
            currentShrincsPublicKey,
            publicKey,
            context,
            signature
        );
        if (!ok) return false;

        nonce += 1;
        return true;
    }

    function verifyStatelessAction(
        ShrincsType.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsType.StatelessSignature calldata signature
    ) external returns (bool) {
        uint64 limit = ShrincsType.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        ShrincsType.ActionContext memory context = ShrincsType.ActionContext({
            domainSeparator: DOMAIN_SEPARATOR,
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        bool ok = SHRINCS.verifyStateless(
            parameterSetId,
            currentShrincsPublicKey,
            publicKey,
            context,
            signature
        );
        if (!ok) return false;

        nonce += 1;
        statelessSignaturesUsed += 1;
        return true;
    }

    function rotateFullKey(
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) external returns (bool) {
        uint64 limit = ShrincsType.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        ShrincsType.RotationContext memory context = ShrincsType.RotationContext({
            domainSeparator: DOMAIN_SEPARATOR,
            nonce: nonce,
            keyVersion: keyVersion
        });

        bytes32 nextCompositePublicKey = SHRINCS.rotateFullShrincsKey(
            parameterSetId,
            currentShrincsPublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        currentShrincsPublicKey = nextCompositePublicKey;
        parameterSetId = nextKey.parameterSetId;
        nonce += 1;
        keyVersion += 1;
        statelessSignaturesUsed += 1;
        return true;
    }
}
