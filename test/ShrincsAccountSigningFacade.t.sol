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
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsAccountVerifierExample} from "../contracts/examples/ShrincsAccountVerifierExample.sol";
import {ShrincsStatelessVectorSigner} from "./helpers/ShrincsStatelessVectorSigner.sol";
import {ShrincsAccountSigningFacade} from "./helpers/ShrincsAccountSigningFacade.sol";

contract ShrincsAccountSigningFacadeHarness is ShrincsStatelessVectorSigner {}

contract ShrincsAccountSigningFacadeTest is Test {
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    ShrincsAccountSigningFacadeHarness internal signer;

    function setUp() public {
        signer = new ShrincsAccountSigningFacadeHarness();
    }

    function testAccountAwareStatefulActionSignerFeedsWrapper() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware current key"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.ActionContext memory context,
            ShrincsTypes.StatefulSignature memory signature,
            bool signOk
        ) = ShrincsAccountSigningFacade.signStatefulActionNow(account, signingKey, actionType, payloadHash);

        assertTrue(signOk, "stateful action signing must succeed");
        assertEq(nextSigningKey.nextStatefulLeafIndex, 2, "stateful signing must advance one leaf");
        assertEq(context.nonce, 0, "stateful action should sign the current wrapper nonce");

        bool verifyOk = account.verifyStatefulAction(publicKey, actionType, payloadHash, signature);
        assertTrue(verifyOk, "wrapper must accept the account-aware stateful signature");
        assertEq(account.nonce(), 1, "wrapper nonce must advance");
    }

    // Checks that a stateful ERC-1271 signature works now, then fails after the nonce is used.
    function testAccountAwareStateful1271SnapshotIsValidBeforeNonceUseAndInvalidAfter() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware 1271 stateful current key"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (, ShrincsTypes.ActionContext memory context, ShrincsTypes.StatefulSignature memory signature, bool signOk) =
            ShrincsAccountSigningFacade.signStatefulActionNow(account, signingKey, actionType, payloadHash);
        assertTrue(signOk, "stateful action signing must succeed");

        bytes32 hash = SHRINCS.statefulActionMessageHash(account.currentShrincsPublicKey(), context);
        bytes memory envelope =
            ShrincsAccountSigningFacade.encodeStateful1271Envelope(publicKey, actionType, payloadHash, signature);

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "stateful ERC-1271 snapshot must verify before nonce use"
        );

        bool verifyOk = account.verifyStatefulAction(publicKey, actionType, payloadHash, signature);
        assertTrue(verifyOk, "wrapper must accept the stateful action");
        assertEq(
            account.isValidSignature(hash, envelope),
            INVALID_SIGNATURE,
            "stateful ERC-1271 snapshot must fail after nonce advances"
        );
    }

    function testAccountAwareStatelessActionSignerFeedsWrapper() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware stateless current key"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (ShrincsTypes.ActionContext memory context, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            signer, account, signingKey, publicKey, actionType, payloadHash
        );

        assertTrue(signOk, "stateless action signing must succeed");
        assertEq(context.nonce, 0, "stateless action should sign the current wrapper nonce");

        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "stateless session completion must succeed");

        bool verifyOk = account.verifyStatelessAction(publicKey, actionType, payloadHash, signature);
        assertTrue(verifyOk, "wrapper must accept the account-aware stateless signature");
        assertEq(account.nonce(), 1, "wrapper nonce must advance");
        assertEq(account.statelessSignaturesUsed(), 1, "wrapper must count one stateless use");
    }

    // Checks that a stateless ERC-1271 signature works now, then fails after the nonce is used.
    function testAccountAwareStateless1271SnapshotIsValidBeforeNonceUseAndInvalidAfter() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware 1271 stateless current key"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (ShrincsTypes.ActionContext memory context, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            signer, account, signingKey, publicKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateless action signing must succeed");

        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "stateless session completion must succeed");

        bytes32 hash = SHRINCS.statelessActionMessageHash(account.currentShrincsPublicKey(), context);
        bytes memory envelope =
            ShrincsAccountSigningFacade.encodeStateless1271Envelope(publicKey, actionType, payloadHash, signature);

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "stateless ERC-1271 snapshot must verify before nonce use"
        );

        bool verifyOk = account.verifyStatelessAction(publicKey, actionType, payloadHash, signature);
        assertTrue(verifyOk, "wrapper must accept the stateless action");
        assertEq(
            account.isValidSignature(hash, envelope),
            INVALID_SIGNATURE,
            "stateless ERC-1271 snapshot must fail after nonce advances"
        );
    }

    function testAccountAwareStatefulOnlyRotationSignerFeedsWrapper() public {
        (
            ShrincsTypes.SigningKey memory currentSigningKey,
            ShrincsTypes.PublicKey memory currentPublicKey,
            bool currentOk
        ) = ShrincsAccountSigningFacade.keygen(bytes("account-aware rotation current key"), 4);
        assertTrue(currentOk, "current keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(currentPublicKey));
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware rotation next key"), 4);
        assertTrue(nextOk, "next keygen must succeed");

        ShrincsTypes.StatefulRotationTarget memory nextKey =
            ShrincsAccountSigningFacade.statefulRotationTarget(currentPublicKey, nextPublicKey.statefulPublicKey);

        (ShrincsTypes.RotationContext memory context, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginStatefulOnlyRotationSessionNow(
            signer, account, currentSigningKey, currentPublicKey, nextKey
        );

        assertTrue(signOk, "stateful-only rotation signing must succeed");
        assertEq(context.nonce, 0, "rotation should sign the current wrapper nonce");

        (ShrincsTypes.StatelessSignature memory recoverySignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "stateful-only rotation session completion must succeed");

        bool rotateOk = account.rotateToFreshKey(currentPublicKey, recoverySignature, nextKey);
        assertTrue(rotateOk, "wrapper must accept the account-aware stateful-only rotation");
        assertEq(account.currentShrincsPublicKey(), ShrincsAccountSigningFacade.publicKeyCommitmentWord(nextKey));
        assertEq(account.keyVersion(), 1, "key epoch must advance");
        assertEq(account.nonce(), 1, "rotation must consume the current nonce");
        assertEq(account.statelessSignaturesUsed(), 1, "rotation must consume one stateless use");
    }

    function testAccountAwareFullRotationSignerFeedsWrapper() public {
        (
            ShrincsTypes.SigningKey memory currentSigningKey,
            ShrincsTypes.PublicKey memory currentPublicKey,
            bool currentOk
        ) = ShrincsAccountSigningFacade.keygen(bytes("account-aware full rotation current key"), 4);
        assertTrue(currentOk, "current keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(currentPublicKey));
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware full rotation next key"), 4);
        assertTrue(nextOk, "next keygen must succeed");

        ShrincsTypes.RotationTarget memory nextKey = ShrincsAccountSigningFacade.fullRotationTarget(nextPublicKey);

        (ShrincsTypes.RotationContext memory context, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginFullRotationSessionNow(
            signer, account, currentSigningKey, currentPublicKey, nextKey
        );

        assertTrue(signOk, "full rotation signing must succeed");
        assertEq(context.nonce, 0, "rotation should sign the current wrapper nonce");

        (ShrincsTypes.StatelessSignature memory recoverySignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "full rotation session completion must succeed");

        bool rotateOk = account.rotateFullKey(currentPublicKey, recoverySignature, nextKey);
        assertTrue(rotateOk, "wrapper must accept the account-aware full rotation");
        assertEq(account.currentShrincsPublicKey(), ShrincsAccountSigningFacade.publicKeyCommitmentWord(nextPublicKey));
        assertEq(account.keyVersion(), 1, "key epoch must advance");
        assertEq(account.nonce(), 1, "rotation must consume the current nonce");
        assertEq(account.statelessSignaturesUsed(), 0, "full rotation must reset stateless usage");
    }
}
