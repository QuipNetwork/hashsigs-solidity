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
import {SPHINCSPlusC} from "../../contracts/SPHINCSPlusC.sol";
import {
    SHRINCSAccountVerifierExample
} from "../../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSStatelessVectorSigningFacade
} from "./SHRINCSStatelessVectorSigningFacade.sol";
import {SHRINCSTestSigner} from "./SHRINCSTestSigner.sol";

/// @notice TEST-ONLY account-aware signing facade for the canonical wrapper
/// flows.
/// @dev This library reads the live wrapper nonce/keyVersion/domain state,
/// builds the exact canonical account messages the on-chain verifier expects,
/// and signs them with the test-only SHRINCS signer helpers. It is intended
/// for tests and local vector generation only.
library SHRINCSAccountSigningFacade {
    uint8 internal constant ERC1271_MODE_STATEFUL_ACTION = 1;
    uint8 internal constant ERC1271_MODE_STATELESS_ACTION = 2;
    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        internal
        pure
        returns (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        )
    {
        return SHRINCSTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function actionContext(
        SHRINCSAccountVerifierExample account,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal view returns (SHRINCS.ActionContext memory context) {
        context = SHRINCS.ActionContext({
            domainSeparator: domainSeparator(address(account)),
            nonce: account.nonce(),
            keyVersion: account.keyVersion(),
            actionType: actionType,
            payloadHash: payloadHash
        });
    }

    function rotationContext(SHRINCSAccountVerifierExample account)
        internal
        view
        returns (SHRINCS.RotationContext memory context)
    {
        context = SHRINCS.RotationContext({
            domainSeparator: domainSeparator(address(account)),
            nonce: account.nonce(),
            keyVersion: account.keyVersion()
        });
    }

    function signStatefulActionNow(
        SHRINCSAccountVerifierExample account,
        SHRINCS.SigningKey memory signingKey,
        bytes32 actionType,
        bytes32 payloadHash
    )
        internal
        view
        returns (
            SHRINCS.SigningKey memory nextSigningKey,
            SHRINCS.ActionContext memory context,
            SHRINCS.Signature memory signature,
            bool ok
        )
    {
        context = actionContext(account, actionType, payloadHash);
        bytes memory message = abi.encodePacked(
            SHRINCS.statefulActionMessageHash(
                account.currentSHRINCSPublicKey(), context
            )
        );
        (nextSigningKey, signature, ok) =
            SHRINCSTestSigner.signStatefulRaw(signingKey, message);
    }

    function beginStatelessActionSessionNow(
        SHRINCSStatelessVectorSigner signer,
        SHRINCSAccountVerifierExample account,
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash
    )
        internal
        returns (
            SHRINCS.ActionContext memory context,
            bytes32 sessionId,
            bool ok
        )
    {
        context = actionContext(account, actionType, payloadHash);
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessActionMessageHash(
                account.currentSHRINCSPublicKey(), context
            )
        );
        (sessionId, ok) = signer.beginSession(signingKey, publicKey, message);
    }

    function beginStatefulOnlyRotationSessionNow(
        SHRINCSStatelessVectorSigner signer,
        SHRINCSAccountVerifierExample account,
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory currentPublicKey,
        SHRINCS.StatefulRotationTarget memory nextStatefulKey
    )
        internal
        returns (
            SHRINCS.RotationContext memory context,
            bytes32 sessionId,
            bool ok
        )
    {
        context = rotationContext(account);
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    SHRINCS.OP_ROTATE_STATEFUL,
                    SHRINCS.HASH_SUITE_KECCAK_256,
                    account.currentSHRINCSPublicKey(),
                    context.domainSeparator,
                    context.nonce,
                    context.keyVersion,
                    currentPublicKey.publicKeyCommitment,
                    nextStatefulKey.publicKeyCommitment
                )
            )
        );
        (sessionId, ok) =
            signer.beginSession(signingKey, currentPublicKey, message);
    }

    function beginFullRotationSessionNow(
        SHRINCSStatelessVectorSigner signer,
        SHRINCSAccountVerifierExample account,
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory currentPublicKey,
        SHRINCS.RotationTarget memory nextKey
    )
        internal
        returns (
            SHRINCS.RotationContext memory context,
            bytes32 sessionId,
            bool ok
        )
    {
        context = rotationContext(account);
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    SHRINCS.OP_ROTATE_FULL,
                    SHRINCS.HASH_SUITE_KECCAK_256,
                    account.currentSHRINCSPublicKey(),
                    context.domainSeparator,
                    context.nonce,
                    context.keyVersion,
                    currentPublicKey.publicKeyCommitment,
                    nextKey.publicKeyCommitment
                )
            )
        );
        (sessionId, ok) =
            signer.beginSession(signingKey, currentPublicKey, message);
    }

    function statefulRotationTarget(
        SHRINCS.PublicKey memory currentPublicKey,
        bytes memory nextStatefulPublicKey
    ) internal pure returns (SHRINCS.StatefulRotationTarget memory nextKey) {
        bytes32 commitment = SHRINCS.publicKeyCommitmentFromParts(
            nextStatefulPublicKey,
            currentPublicKey.pkSeed,
            currentPublicKey.hypertreeRoot
        );
        nextKey = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: nextStatefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment)
        });
    }

    function fullRotationTarget(SHRINCS.PublicKey memory nextPublicKey)
        internal
        pure
        returns (SHRINCS.RotationTarget memory nextKey)
    {
        nextKey = SHRINCS.RotationTarget({
            statefulPublicKey: nextPublicKey.statefulPublicKey,
            publicKeyCommitment: nextPublicKey.publicKeyCommitment,
            pkSeed: nextPublicKey.pkSeed,
            hypertreeRoot: nextPublicKey.hypertreeRoot
        });
    }

    function encodeStateful1271Envelope(
        SHRINCS.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        SHRINCS.Signature memory signature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(ERC1271_MODE_STATEFUL_ACTION),
            abi.encode(publicKey, actionType, payloadHash, signature)
        );
    }

    function encodeStateless1271Envelope(
        SHRINCS.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        SPHINCSPlusC.Signature memory signature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(ERC1271_MODE_STATELESS_ACTION),
            abi.encode(publicKey, actionType, payloadHash, signature)
        );
    }

    function publicKeyCommitmentWord(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 word)
    {
        bytes memory encoded = publicKey.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }

    function publicKeyCommitmentWord(
        SHRINCS.StatefulRotationTarget memory nextKey
    ) internal pure returns (bytes32 word) {
        bytes memory encoded = nextKey.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }

    function domainSeparator(address account)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, account));
    }

    function completeStatelessSession(
        SHRINCSStatelessVectorSigner signer,
        bytes32 sessionId
    ) internal returns (SPHINCSPlusC.Signature memory signature, bool ok) {
        (, signature, ok) =
            SHRINCSStatelessVectorSigningFacade.completeSession(
                signer, sessionId
            );
    }
}
