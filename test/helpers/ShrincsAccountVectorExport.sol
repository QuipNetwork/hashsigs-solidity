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
    struct StatelessActionVector {
        bytes32 currentPkSeed;
        bytes32 currentHypertreeRoot;
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.ActionContext context;
        bytes32 actionType;
        bytes32 payloadHash;
        ShrincsTypes.StatelessSignature signature;
        bytes message;
        bytes verifyCalldata;
        bytes erc1271Envelope;
    }

    struct FullRotationVector {
        bytes32 currentPkSeed;
        bytes32 currentHypertreeRoot;
        ShrincsTypes.PublicKey currentPublicKey;
        ShrincsTypes.RotationContext context;
        ShrincsTypes.RotationTarget nextKey;
        ShrincsTypes.StatelessSignature recoverySignature;
        bytes message;
        bytes rotateCalldata;
    }

    function statelessActionVector(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.ActionContext memory context,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature memory signature
    ) internal view returns (StatelessActionVector memory vector_) {
        bytes32 currentPkSeed = account.currentPkSeed();
        bytes32 currentHypertreeRoot = account.currentHypertreeRoot();
        bytes memory message =
            abi.encodePacked(SHRINCS.statelessActionMessageHash(currentPkSeed, currentHypertreeRoot, context));
        vector_ = StatelessActionVector({
            currentPkSeed: currentPkSeed,
            currentHypertreeRoot: currentHypertreeRoot,
            publicKey: publicKey,
            context: context,
            actionType: actionType,
            payloadHash: payloadHash,
            signature: signature,
            message: message,
            verifyCalldata: abi.encodeCall(
                account.verifyStatelessAction, (publicKey, actionType, payloadHash, signature)
            ),
            erc1271Envelope: ShrincsAccountSigningFacade.encodeStateless1271Envelope(
                publicKey, actionType, payloadHash, signature
            )
        });
    }

    function fullRotationVector(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.PublicKey memory currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.RotationTarget memory nextKey,
        ShrincsTypes.StatelessSignature memory recoverySignature
    ) internal view returns (FullRotationVector memory vector_) {
        bytes32 currentPkSeed = account.currentPkSeed();
        bytes32 currentHypertreeRoot = account.currentHypertreeRoot();
        bytes memory message = abi.encodePacked(
            SHRINCS.fullRotationMessageHash(currentPkSeed, currentHypertreeRoot, currentPublicKey, context, nextKey)
        );
        vector_ = FullRotationVector({
            currentPkSeed: currentPkSeed,
            currentHypertreeRoot: currentHypertreeRoot,
            currentPublicKey: currentPublicKey,
            context: context,
            nextKey: nextKey,
            recoverySignature: recoverySignature,
            message: message,
            rotateCalldata: abi.encodeCall(account.rotateFullKey, (currentPublicKey, recoverySignature, nextKey))
        });
    }
}
