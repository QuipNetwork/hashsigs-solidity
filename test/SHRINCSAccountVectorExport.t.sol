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
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSAccountVectorExport
} from "./helpers/SHRINCSAccountVectorExport.sol";

contract SHRINCSAccountVectorExportHarness is SHRINCSStatelessVectorSigner {}

contract SHRINCSAccountVectorExportTest is Test {
    SHRINCSAccountVectorExportHarness internal signer;

    function setUp() public {
        signer = new SHRINCSAccountVectorExportHarness();
    }

    function testExportStatefulActionBundle() public {
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("export-stateful-current-key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );

        (
            SHRINCS.SigningKey memory nextSigningKey,
            SHRINCS.ActionContext memory context,
            SHRINCS.Signature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateful signing must succeed");

        SHRINCSAccountVectorExport.StatefulActionVector memory vector_ =
            SHRINCSAccountVectorExport.statefulActionVector(
                account,
                publicKey,
                context,
                actionType,
                payloadHash,
                signature
            );

        emit log_named_bytes("stateful_vector_abi", abi.encode(vector_));
        emit log_named_bytes(
            "stateful_verify_calldata", vector_.verifyCalldata
        );
        emit log_named_bytes(
            "stateful_1271_envelope", vector_.erc1271Envelope
        );

        bool verifyOk = account.verifyStatefulAction(
            publicKey, actionType, payloadHash, signature
        );
        assertTrue(
            verifyOk, "exported stateful vector must feed the wrapper"
        );
        assertEq(
            nextSigningKey.nextStatefulLeafIndex,
            2,
            "stateful export should advance one leaf"
        );
    }

    function testExportStatelessActionBundle() public {
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("export-stateless-current-key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );

        (
            SHRINCS.ActionContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = SHRINCSAccountSigningFacade.beginStatelessActionSessionNow(
                signer,
                account,
                signingKey,
                publicKey,
                actionType,
                payloadHash
            );
        assertTrue(signOk, "stateless signing must start");

        // line-length: allow — fmt canonical tuple head exceeds cap
        SPHINCSPlusC.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        assertTrue(completeOk, "stateless signing must complete");

        SHRINCSAccountVectorExport.StatelessActionVector memory vector_ =
            SHRINCSAccountVectorExport.statelessActionVector(
                account,
                publicKey,
                context,
                actionType,
                payloadHash,
                signature
            );

        emit log_named_bytes("stateless_vector_abi", abi.encode(vector_));
        emit log_named_bytes(
            "stateless_verify_calldata", vector_.verifyCalldata
        );
        emit log_named_bytes(
            "stateless_1271_envelope", vector_.erc1271Envelope
        );

        bool verifyOk = account.verifyStatelessAction(
            publicKey, actionType, payloadHash, signature
        );
        assertTrue(
            verifyOk, "exported stateless vector must feed the wrapper"
        );
    }

    function testExportStatefulOnlyRotationBundle() public {
        (
            SHRINCS.SigningKey memory currentSigningKey,
            SHRINCS.PublicKey memory currentPublicKey,
            bool currentOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("export-rotation-current-key"), 4
        );
        assertTrue(currentOk, "current keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    currentPublicKey
                )
            );
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        // line-length: allow — fmt canonical tuple head exceeds cap
        (, SHRINCS.PublicKey memory nextPublicKey, bool nextOk) = SHRINCSAccountSigningFacade.keygen(
            bytes("export-rotation-next-key"), 4
        );
        assertTrue(nextOk, "next keygen must succeed");

        SHRINCS.StatefulRotationTarget memory nextKey =
            SHRINCSAccountSigningFacade.statefulRotationTarget(
                currentPublicKey, nextPublicKey.statefulPublicKey
            );

        (
            SHRINCS.RotationContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = SHRINCSAccountSigningFacade.beginStatefulOnlyRotationSessionNow(
                signer, account, currentSigningKey, currentPublicKey, nextKey
            );
        assertTrue(signOk, "stateful-only rotation must start");

        SPHINCSPlusC.Signature memory recoverySignature;
        bool completeOk;
        (recoverySignature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        assertTrue(completeOk, "stateful-only rotation must complete");

        SHRINCSAccountVectorExport.StatefulOnlyRotationVector memory
            vector_ =
            SHRINCSAccountVectorExport.statefulOnlyRotationVector(
                account,
                currentPublicKey,
                context,
                nextKey,
                recoverySignature
            );

        emit log_named_bytes(
            "stateful_rotation_vector_abi", abi.encode(vector_)
        );
        emit log_named_bytes(
            "stateful_rotation_calldata", vector_.rotateCalldata
        );

        bool rotateOk = account.rotateToFreshKey(
            currentPublicKey, recoverySignature, nextKey
        );
        assertTrue(
            rotateOk,
            "exported stateful-only rotation vector must feed the wrapper"
        );
    }

    function testExportFullRotationBundle() public {
        (
            SHRINCS.SigningKey memory currentSigningKey,
            SHRINCS.PublicKey memory currentPublicKey,
            bool currentOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware full rotation current key"), 4
        );
        assertTrue(currentOk, "current keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    currentPublicKey
                )
            );
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        // line-length: allow — fmt canonical tuple head exceeds cap
        (, SHRINCS.PublicKey memory nextPublicKey, bool nextOk) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware full rotation next key"), 4
        );
        assertTrue(nextOk, "next keygen must succeed");

        SHRINCS.RotationTarget memory nextKey =
            SHRINCSAccountSigningFacade.fullRotationTarget(nextPublicKey);

        (
            SHRINCS.RotationContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = SHRINCSAccountSigningFacade.beginFullRotationSessionNow(
                signer, account, currentSigningKey, currentPublicKey, nextKey
            );
        assertTrue(signOk, "full rotation must start");

        SPHINCSPlusC.Signature memory recoverySignature;
        bool completeOk;
        (recoverySignature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        assertTrue(completeOk, "full rotation must complete");

        SHRINCSAccountVectorExport.FullRotationVector memory vector_ =
            SHRINCSAccountVectorExport.fullRotationVector(
                account,
                currentPublicKey,
                context,
                nextKey,
                recoverySignature
            );

        emit log_named_bytes("full_rotation_vector_abi", abi.encode(vector_));
        emit log_named_bytes(
            "full_rotation_calldata", vector_.rotateCalldata
        );

        bool rotateOk = account.rotateFullKey(
            currentPublicKey, recoverySignature, nextKey
        );
        assertTrue(
            rotateOk, "exported full rotation vector must feed the wrapper"
        );
    }
}
