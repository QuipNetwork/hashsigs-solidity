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
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SPHINCSPlusC} from "../../contracts/SPHINCSPlusC.sol";
import {
    SHRINCSAccountVerifierExample
} from "../../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSAccountSigningFacade
} from "./SHRINCSAccountSigningFacade.sol";

/// @notice TEST-ONLY wrapper-feedable vector export helpers for canonical
/// account flows.
library SHRINCSAccountVectorExport {
    struct StatefulActionVector {
        bytes32 currentSHRINCSPublicKey;
        SHRINCS.PublicKey publicKey;
        SHRINCS.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        SHRINCS.Signature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct StatelessActionVector {
        bytes32 currentSHRINCSPublicKey;
        SHRINCS.PublicKey publicKey;
        SHRINCS.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        SPHINCSPlusC.Signature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct StatefulOnlyRotationVector {
        bytes32 currentSHRINCSPublicKey;
        SHRINCS.PublicKey currentPublicKey;
        SHRINCS.RotationContext context;
        SHRINCS.StatefulRotationTarget nextKey;
        SPHINCSPlusC.Signature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    struct FullRotationVector {
        bytes32 currentSHRINCSPublicKey;
        SHRINCS.PublicKey currentPublicKey;
        SHRINCS.RotationContext context;
        SHRINCS.RotationTarget nextKey;
        SPHINCSPlusC.Signature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    function statefulActionVector(
        SHRINCSAccountVerifierExample account,
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        SHRINCS.Signature memory signature
    ) internal view returns (StatefulActionVector memory vector_) {
        bytes32 current = account.currentSHRINCSPublicKey();
        bytes memory message = abi.encodePacked(
            SHRINCS.statefulActionMessageHash(current, context)
        );
        vector_ = StatefulActionVector({
            currentSHRINCSPublicKey: current,
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
            erc1271Envelope: SHRINCSAccountSigningFacade.encodeStateful1271Envelope(
                publicKey, actionType, payloadHash, signature
            )
        });
    }

    function statelessActionVector(
        SHRINCSAccountVerifierExample account,
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        SPHINCSPlusC.Signature memory signature
    ) internal view returns (StatelessActionVector memory vector_) {
        bytes32 current = account.currentSHRINCSPublicKey();
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessActionMessageHash(current, context)
        );
        vector_ = StatelessActionVector({
            currentSHRINCSPublicKey: current,
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
            erc1271Envelope: SHRINCSAccountSigningFacade.encodeStateless1271Envelope(
                publicKey, actionType, payloadHash, signature
            )
        });
    }

    function statefulOnlyRotationVector(
        SHRINCSAccountVerifierExample account,
        SHRINCS.PublicKey memory currentPublicKey,
        SHRINCS.RotationContext memory context,
        SHRINCS.StatefulRotationTarget memory nextKey,
        SPHINCSPlusC.Signature memory recoverySignature
    ) internal view returns (StatefulOnlyRotationVector memory vector_) {
        bytes32 current = account.currentSHRINCSPublicKey();
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    SHRINCS.OP_ROTATE_STATEFUL,
                    HashSuite.HASH_SUITE_ID,
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
            currentSHRINCSPublicKey: current,
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
        SHRINCSAccountVerifierExample account,
        SHRINCS.PublicKey memory currentPublicKey,
        SHRINCS.RotationContext memory context,
        SHRINCS.RotationTarget memory nextKey,
        SPHINCSPlusC.Signature memory recoverySignature
    ) internal view returns (FullRotationVector memory vector_) {
        bytes32 current = account.currentSHRINCSPublicKey();
        bytes memory message = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    SHRINCS.OP_ROTATE_FULL,
                    HashSuite.HASH_SUITE_ID,
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
            currentSHRINCSPublicKey: current,
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
