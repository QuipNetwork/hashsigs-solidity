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

import {Test} from "../lib/forge-std/src/Test.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsAccountVerifierExample} from "../contracts/examples/ShrincsAccountVerifierExample.sol";
import {ShrincsStatelessVectorSigner} from "./helpers/ShrincsStatelessVectorSigner.sol";
import {ShrincsAccountSigningFacade} from "./helpers/ShrincsAccountSigningFacade.sol";
import {ShrincsAccountVectorExport} from "./helpers/ShrincsAccountVectorExport.sol";

contract ShrincsAccountVectorExportHarness is ShrincsStatelessVectorSigner {}

contract ShrincsAccountVectorExportTest is Test {
    ShrincsAccountVectorExportHarness internal signer;

    function setUp() public {
        signer = new ShrincsAccountVectorExportHarness();
    }

    function testExportStatefulActionBundle() public {
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("export-stateful-current-key"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));

        (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.ActionContext memory context,
            ShrincsTypes.StatefulSignature memory signature,
            bool signOk
        ) = ShrincsAccountSigningFacade.signStatefulActionNow(account, signingKey, actionType, payloadHash);
        assertTrue(signOk, "stateful signing must succeed");

        ShrincsAccountVectorExport.StatefulActionVector memory vector_ =
            ShrincsAccountVectorExport.statefulActionVector(
                account, publicKey, context, actionType, payloadHash, signature
            );

        emit log_named_bytes("stateful_vector_abi", abi.encode(vector_));
        emit log_named_bytes("stateful_verify_calldata", vector_.verifyCalldata);
        emit log_named_bytes("stateful_1271_envelope", vector_.erc1271Envelope);

        bool verifyOk = account.verifyStatefulAction(publicKey, actionType, payloadHash, signature);
        assertTrue(verifyOk, "exported stateful vector must feed the wrapper");
        assertEq(nextSigningKey.nextStatefulLeafIndex, 2, "stateful export should advance one leaf");
    }

    function testExportStatelessActionBundle() public {
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("export-stateless-current-key"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));

        (
            ShrincsTypes.ActionContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            signer, account, signingKey, publicKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateless signing must start");

        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "stateless signing must complete");

        ShrincsAccountVectorExport.StatelessActionVector memory vector_ =
            ShrincsAccountVectorExport.statelessActionVector(
                account, publicKey, context, actionType, payloadHash, signature
            );

        emit log_named_bytes("stateless_vector_abi", abi.encode(vector_));
        emit log_named_bytes("stateless_verify_calldata", vector_.verifyCalldata);
        emit log_named_bytes("stateless_1271_envelope", vector_.erc1271Envelope);

        bool verifyOk = account.verifyStatelessAction(publicKey, actionType, payloadHash, signature);
        assertTrue(verifyOk, "exported stateless vector must feed the wrapper");
    }

    function testExportStatefulOnlyRotationBundle() public {
        (ShrincsTypes.SigningKey memory currentSigningKey, ShrincsTypes.PublicKey memory currentPublicKey, bool currentOk)
            = ShrincsAccountSigningFacade.keygen(bytes("export-rotation-current-key"), 4);
        assertTrue(currentOk, "current keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(currentPublicKey));
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("export-rotation-next-key"), 4);
        assertTrue(nextOk, "next keygen must succeed");

        ShrincsTypes.StatefulRotationTarget memory nextKey =
            ShrincsAccountSigningFacade.statefulRotationTarget(currentPublicKey, nextPublicKey.statefulPublicKey);

        (
            ShrincsTypes.RotationContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = ShrincsAccountSigningFacade.beginStatefulOnlyRotationSessionNow(
            signer, account, currentSigningKey, currentPublicKey, nextKey
        );
        assertTrue(signOk, "stateful-only rotation must start");

        (ShrincsTypes.StatelessSignature memory recoverySignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "stateful-only rotation must complete");

        ShrincsAccountVectorExport.StatefulOnlyRotationVector memory vector_ =
            ShrincsAccountVectorExport.statefulOnlyRotationVector(
                account, currentPublicKey, context, nextKey, recoverySignature
            );

        emit log_named_bytes("stateful_rotation_vector_abi", abi.encode(vector_));
        emit log_named_bytes("stateful_rotation_calldata", vector_.rotateCalldata);

        bool rotateOk = account.rotateToFreshKey(currentPublicKey, recoverySignature, nextKey);
        assertTrue(rotateOk, "exported stateful-only rotation vector must feed the wrapper");
    }

    function testExportFullRotationBundle() public {
        (ShrincsTypes.SigningKey memory currentSigningKey, ShrincsTypes.PublicKey memory currentPublicKey, bool currentOk)
            = ShrincsAccountSigningFacade.keygen(bytes("account-aware full rotation current key"), 4);
        assertTrue(currentOk, "current keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(currentPublicKey));
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware full rotation next key"), 4);
        assertTrue(nextOk, "next keygen must succeed");

        ShrincsTypes.RotationTarget memory nextKey =
            ShrincsAccountSigningFacade.fullRotationTarget(nextPublicKey);

        (
            ShrincsTypes.RotationContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = ShrincsAccountSigningFacade.beginFullRotationSessionNow(
            signer, account, currentSigningKey, currentPublicKey, nextKey
        );
        assertTrue(signOk, "full rotation must start");

        (ShrincsTypes.StatelessSignature memory recoverySignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "full rotation must complete");

        ShrincsAccountVectorExport.FullRotationVector memory vector_ =
            ShrincsAccountVectorExport.fullRotationVector(
                account, currentPublicKey, context, nextKey, recoverySignature
            );

        emit log_named_bytes("full_rotation_vector_abi", abi.encode(vector_));
        emit log_named_bytes("full_rotation_calldata", vector_.rotateCalldata);

        bool rotateOk = account.rotateFullKey(currentPublicKey, recoverySignature, nextKey);
        assertTrue(rotateOk, "exported full rotation vector must feed the wrapper");
    }
}
