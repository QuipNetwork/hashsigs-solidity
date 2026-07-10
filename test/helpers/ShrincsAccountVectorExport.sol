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
import {ShrincsAccountVerifierExample} from "../../contracts/examples/ShrincsAccountVerifierExample.sol";
import {ShrincsAccountSigningFacade} from "./ShrincsAccountSigningFacade.sol";

/// @notice TEST-ONLY wrapper-feedable vector export helpers for canonical account flows.
library ShrincsAccountVectorExport {
    struct StatefulActionVector {
        bytes32 currentShrincsPublicKey;
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        ShrincsTypes.StatefulSignature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct StatelessActionVector {
        bytes32 currentShrincsPublicKey;
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        ShrincsTypes.StatelessSignature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct StatefulOnlyRotationVector {
        bytes32 currentShrincsPublicKey;
        ShrincsTypes.PublicKey currentPublicKey;
        ShrincsTypes.RotationContext context;
        ShrincsTypes.StatefulRotationTarget nextKey;
        ShrincsTypes.StatelessSignature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    struct FullRotationVector {
        bytes32 currentShrincsPublicKey;
        ShrincsTypes.PublicKey currentPublicKey;
        ShrincsTypes.RotationContext context;
        ShrincsTypes.RotationTarget nextKey;
        ShrincsTypes.StatelessSignature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    function statefulActionVector(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatefulSignature memory signature
    ) internal view returns (StatefulActionVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(current, context));
        vector_ = StatefulActionVector({
            currentShrincsPublicKey: current,
            publicKey: publicKey,
            context: context,
            actionType: actionType,
            payloadHash: payloadHash,
            signature: signature,
            message: message,
            verifyCalldata: abi.encodeCall(account.verifyStatefulAction, (publicKey, actionType, payloadHash, signature)),
            erc1271Envelope: ShrincsAccountSigningFacade.encodeStateful1271Envelope(publicKey, actionType, payloadHash, signature)
        });
    }

    function statelessActionVector(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature memory signature
    ) internal view returns (StatelessActionVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(SHRINCS.statelessActionMessageHash(current, context));
        vector_ = StatelessActionVector({
            currentShrincsPublicKey: current,
            publicKey: publicKey,
            context: context,
            actionType: actionType,
            payloadHash: payloadHash,
            signature: signature,
            message: message,
            verifyCalldata: abi.encodeCall(account.verifyStatelessAction, (publicKey, actionType, payloadHash, signature)),
            erc1271Envelope: ShrincsAccountSigningFacade.encodeStateless1271Envelope(publicKey, actionType, payloadHash, signature)
        });
    }

    function statefulOnlyRotationVector(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.PublicKey memory currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatefulRotationTarget memory nextKey,
        ShrincsTypes.StatelessSignature memory recoverySignature
    ) internal view returns (StatefulOnlyRotationVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    ShrincsTypes.OP_ROTATE_STATEFUL,
                    ShrincsTypes.HASH_SUITE_KECCAK_256,
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
            rotateCalldata: abi.encodeCall(account.rotateToFreshKey, (currentPublicKey, recoverySignature, nextKey))
        });
    }

    function fullRotationVector(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.PublicKey memory currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.RotationTarget memory nextKey,
        ShrincsTypes.StatelessSignature memory recoverySignature
    ) internal view returns (FullRotationVector memory vector_) {
        bytes32 current = account.currentShrincsPublicKey();
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    ShrincsTypes.OP_ROTATE_FULL,
                    ShrincsTypes.HASH_SUITE_KECCAK_256,
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
            rotateCalldata: abi.encodeCall(account.rotateFullKey, (currentPublicKey, recoverySignature, nextKey))
        });
    }
}
