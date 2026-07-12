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

import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {ShrincsTypes} from "../../contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "../../contracts/ShrincsUtils.sol";
import {ShrincsAccountVerifierExample} from "../../contracts/examples/ShrincsAccountVerifierExample.sol";
import {ShrincsStatelessVectorSigner} from "./ShrincsStatelessVectorSigner.sol";
import {ShrincsStatelessVectorSigningFacade} from "./ShrincsStatelessVectorSigningFacade.sol";
import {ShrincsTestSigner} from "./ShrincsTestSigner.sol";

/// @notice TEST-ONLY account-aware signing facade for the canonical wrapper flows.
/// @dev This library reads the live wrapper nonce/keyVersion/domain state, builds the exact
/// canonical account messages the on-chain verifier expects, and signs them with the test-only
/// SHRINCS signer helpers. It is intended for tests and local vector generation only.
library ShrincsAccountSigningFacade {
    uint8 internal constant ERC1271_MODE_STATEFUL_ACTION = 1;
    uint8 internal constant ERC1271_MODE_STATELESS_ACTION = 2;
    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        internal
        pure
        returns (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok)
    {
        return ShrincsTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function actionContext(ShrincsAccountVerifierExample account, bytes32 actionType, bytes32 payloadHash)
        internal
        view
        returns (ShrincsTypes.ActionContext memory context)
    {
        context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(address(account)),
            nonce: account.nonce(),
            keyVersion: account.keyVersion(),
            actionType: actionType,
            payloadHash: payloadHash
        });
    }

    function rotationContext(ShrincsAccountVerifierExample account)
        internal
        view
        returns (ShrincsTypes.RotationContext memory context)
    {
        context = ShrincsTypes.RotationContext({
            domainSeparator: domainSeparator(address(account)), nonce: account.nonce(), keyVersion: account.keyVersion()
        });
    }

    function signStatefulActionNow(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        bytes32 actionType,
        bytes32 payloadHash
    )
        internal
        view
        returns (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.ActionContext memory context,
            ShrincsTypes.StatefulSignature memory signature,
            bool ok
        )
    {
        context = actionContext(account, actionType, payloadHash);
        bytes memory message =
            abi.encodePacked(SHRINCS.statefulActionMessageHash(account.currentShrincsPublicKey(), context));
        (nextSigningKey, signature, ok) = ShrincsTestSigner.signStatefulRaw(signingKey, message);
    }

    function beginStatelessActionSessionNow(
        ShrincsStatelessVectorSigner signer,
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal returns (ShrincsTypes.ActionContext memory context, bytes32 sessionId, bool ok) {
        context = actionContext(account, actionType, payloadHash);
        bytes memory message =
            abi.encodePacked(SHRINCS.statelessActionMessageHash(account.currentShrincsPublicKey(), context));
        (sessionId, ok) = signer.beginSession(signingKey, publicKey, message);
    }

    function beginStatefulOnlyRotationSessionNow(
        ShrincsStatelessVectorSigner signer,
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory currentPublicKey,
        ShrincsTypes.StatefulRotationTarget memory nextStatefulKey
    ) internal returns (ShrincsTypes.RotationContext memory context, bytes32 sessionId, bool ok) {
        context = rotationContext(account);
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    ShrincsTypes.OP_ROTATE_STATEFUL,
                    ShrincsTypes.HASH_SUITE_KECCAK_256,
                    account.currentShrincsPublicKey(),
                    context.domainSeparator,
                    context.nonce,
                    context.keyVersion,
                    currentPublicKey.publicKeyCommitment,
                    nextStatefulKey.publicKeyCommitment
                )
            )
        );
        (sessionId, ok) = signer.beginSession(signingKey, currentPublicKey, message);
    }

    function beginFullRotationSessionNow(
        ShrincsStatelessVectorSigner signer,
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory currentPublicKey,
        ShrincsTypes.RotationTarget memory nextKey
    ) internal returns (ShrincsTypes.RotationContext memory context, bytes32 sessionId, bool ok) {
        context = rotationContext(account);
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    ShrincsTypes.OP_ROTATE_FULL,
                    ShrincsTypes.HASH_SUITE_KECCAK_256,
                    account.currentShrincsPublicKey(),
                    context.domainSeparator,
                    context.nonce,
                    context.keyVersion,
                    currentPublicKey.publicKeyCommitment,
                    nextKey.publicKeyCommitment
                )
            )
        );
        (sessionId, ok) = signer.beginSession(signingKey, currentPublicKey, message);
    }

    function beginCompactSlotRegistrationSessionNow(
        ShrincsStatelessVectorSigner signer,
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory currentPublicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal returns (ShrincsTypes.RotationContext memory context, bytes32 sessionId, bool ok) {
        context = rotationContext(account);
        bytes memory message =
            abi.encodePacked(SHRINCS.compactSlotRegistrationMessageHash(context, subPkSeed, subPkRoot));
        (sessionId, ok) = signer.beginSession(signingKey, currentPublicKey, message);
    }

    function beginCompactSlotRevocationSessionNow(
        ShrincsStatelessVectorSigner signer,
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory currentPublicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal returns (ShrincsTypes.RotationContext memory context, bytes32 sessionId, bool ok) {
        context = rotationContext(account);
        bytes memory message = abi.encodePacked(SHRINCS.compactSlotRevocationMessageHash(context, subPkSeed, subPkRoot));
        (sessionId, ok) = signer.beginSession(signingKey, currentPublicKey, message);
    }

    function statefulRotationTarget(ShrincsTypes.PublicKey memory currentPublicKey, bytes memory nextStatefulPublicKey)
        internal
        pure
        returns (ShrincsTypes.StatefulRotationTarget memory nextKey)
    {
        bytes32 commitment = ShrincsUtils.publicKeyCommitmentFromParts(
            nextStatefulPublicKey, currentPublicKey.pkSeed, currentPublicKey.hypertreeRoot
        );
        nextKey = ShrincsTypes.StatefulRotationTarget({
            statefulPublicKey: nextStatefulPublicKey, publicKeyCommitment: abi.encodePacked(commitment)
        });
    }

    function fullRotationTarget(ShrincsTypes.PublicKey memory nextPublicKey)
        internal
        pure
        returns (ShrincsTypes.RotationTarget memory nextKey)
    {
        nextKey = ShrincsTypes.RotationTarget({
            statefulPublicKey: nextPublicKey.statefulPublicKey,
            publicKeyCommitment: nextPublicKey.publicKeyCommitment,
            pkSeed: nextPublicKey.pkSeed,
            hypertreeRoot: nextPublicKey.hypertreeRoot
        });
    }

    function encodeStateful1271Envelope(
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatefulSignature memory signature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(ERC1271_MODE_STATEFUL_ACTION), abi.encode(publicKey, actionType, payloadHash, signature)
        );
    }

    function encodeStateless1271Envelope(
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature memory signature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(ERC1271_MODE_STATELESS_ACTION), abi.encode(publicKey, actionType, payloadHash, signature)
        );
    }

    function publicKeyCommitmentWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 word) {
        bytes memory encoded = publicKey.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }

    function publicKeyCommitmentWord(ShrincsTypes.StatefulRotationTarget memory nextKey)
        internal
        pure
        returns (bytes32 word)
    {
        bytes memory encoded = nextKey.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }

    function domainSeparator(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, account));
    }

    function completeStatelessSession(ShrincsStatelessVectorSigner signer, bytes32 sessionId)
        internal
        returns (ShrincsTypes.StatelessSignature memory signature, bool ok)
    {
        (, signature, ok) = ShrincsStatelessVectorSigningFacade.completeSession(signer, sessionId);
    }
}
