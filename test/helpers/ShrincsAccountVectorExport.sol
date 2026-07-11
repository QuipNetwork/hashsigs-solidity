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
import {ShrincsStateful} from "../../contracts/ShrincsStateful.sol";
import {
    ShrincsAccountVerifierExample
} from "../../contracts/examples/ShrincsAccountVerifierExample.sol";
import {
    ShrincsAccountSigningFacade
} from "./ShrincsAccountSigningFacade.sol";

/// @notice TEST-ONLY wrapper-feedable vector export helpers for canonical
/// account flows.
library ShrincsAccountVectorExport {
    struct StatefulActionVector {
        bytes32 currentShrincsPublicKey;
        SHRINCS.PublicKey publicKey;
        SHRINCS.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        ShrincsStateful.StatefulSignature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct StatelessActionVector {
        bytes32 currentShrincsPublicKey;
        SHRINCS.PublicKey publicKey;
        SHRINCS.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        SHRINCS.StatelessSignature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct StatefulOnlyRotationVector {
        bytes32 currentShrincsPublicKey;
        SHRINCS.PublicKey currentPublicKey;
        SHRINCS.RotationContext context;
        SHRINCS.StatefulRotationTarget nextKey;
        SHRINCS.StatelessSignature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    struct FullRotationVector {
        bytes32 currentShrincsPublicKey;
        SHRINCS.PublicKey currentPublicKey;
        SHRINCS.RotationContext context;
        SHRINCS.RotationTarget nextKey;
        SHRINCS.StatelessSignature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    function statefulActionVector(
        ShrincsAccountVerifierExample account,
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsStateful.StatefulSignature memory signature
    ) internal view returns (StatefulActionVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(
            SHRINCS.statefulActionMessageHash(current, context)
        );
        vector_ = StatefulActionVector({
            currentShrincsPublicKey: current,
            publicKey: publicKey,
            context: context,
            actionType: actionType,
            payloadHash: payloadHash,
            signature: signature,
            message: message,
            verifyCalldata: abi.encodeCall(
                account.verifyStatefulAction,
                (publicKey, actionType, payloadHash, signature)
            ),
            // line-length: allow — fmt canonical field head exceeds cap
            erc1271Envelope: ShrincsAccountSigningFacade.encodeStateful1271Envelope(
                publicKey, actionType, payloadHash, signature
            )
        });
    }

    function statelessActionVector(
        ShrincsAccountVerifierExample account,
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        SHRINCS.StatelessSignature memory signature
    ) internal view returns (StatelessActionVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessActionMessageHash(current, context)
        );
        vector_ = StatelessActionVector({
            currentShrincsPublicKey: current,
            publicKey: publicKey,
            context: context,
            actionType: actionType,
            payloadHash: payloadHash,
            signature: signature,
            message: message,
            verifyCalldata: abi.encodeCall(
                account.verifyStatelessAction,
                (publicKey, actionType, payloadHash, signature)
            ),
            // line-length: allow — fmt canonical field head exceeds cap
            erc1271Envelope: ShrincsAccountSigningFacade.encodeStateless1271Envelope(
                publicKey, actionType, payloadHash, signature
            )
        });
    }

    function statefulOnlyRotationVector(
        ShrincsAccountVerifierExample account,
        SHRINCS.PublicKey memory currentPublicKey,
        SHRINCS.RotationContext memory context,
        SHRINCS.StatefulRotationTarget memory nextKey,
        SHRINCS.StatelessSignature memory recoverySignature
    ) internal view returns (StatefulOnlyRotationVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    SHRINCS.OP_ROTATE_STATEFUL,
                    SHRINCS.HASH_SUITE_KECCAK_256,
                    current,
                    context.domainSeparator,
                    context.nonce,
                    context.keyVersion,
                    currentPublicKey.publicKeyCommitment,
                    nextKey.publicKeyCommitment
                )
            )
        );
        vector_ = StatefulOnlyRotationVector({
            currentShrincsPublicKey: current,
            currentPublicKey: currentPublicKey,
            context: context,
            nextKey: nextKey,
            recoverySignature: recoverySignature,
            message: message,
            rotateCalldata: abi.encodeCall(
                account.rotateToFreshKey,
                (currentPublicKey, recoverySignature, nextKey)
            )
        });
    }

    function fullRotationVector(
        ShrincsAccountVerifierExample account,
        SHRINCS.PublicKey memory currentPublicKey,
        SHRINCS.RotationContext memory context,
        SHRINCS.RotationTarget memory nextKey,
        SHRINCS.StatelessSignature memory recoverySignature
    ) internal view returns (FullRotationVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    SHRINCS.OP_ROTATE_FULL,
                    SHRINCS.HASH_SUITE_KECCAK_256,
                    current,
                    context.domainSeparator,
                    context.nonce,
                    context.keyVersion,
                    currentPublicKey.publicKeyCommitment,
                    nextKey.publicKeyCommitment
                )
            )
        );
        vector_ = FullRotationVector({
            currentShrincsPublicKey: current,
            currentPublicKey: currentPublicKey,
            context: context,
            nextKey: nextKey,
            recoverySignature: recoverySignature,
            message: message,
            rotateCalldata: abi.encodeCall(
                account.rotateFullKey,
                (currentPublicKey, recoverySignature, nextKey)
            )
        });
    }
}
