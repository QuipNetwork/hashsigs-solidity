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
import {SHRINCSCore} from "../contracts/SHRINCSCore.sol";
import {SPHINCSPlusCCore} from "../contracts/SPHINCSPlusCCore.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";

contract SHRINCSAccountSigningFacadeHarness is
    SHRINCSStatelessVectorSigner
{}

contract SHRINCSAccountSigningFacadeTest is Test {
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    SHRINCSAccountSigningFacadeHarness internal signer;

    function setUp() public {
        signer = new SHRINCSAccountSigningFacadeHarness();
    }

    function testAccountAwareStatefulActionSignerFeedsWrapper() public {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware current key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            SHRINCSCore.SigningKey memory nextSigningKey,
            SHRINCSCore.ActionContext memory context,
            UXMSS.StatefulSignature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );

        assertTrue(signOk, "stateful action signing must succeed");
        assertEq(
            nextSigningKey.nextStatefulLeafIndex,
            2,
            "stateful signing must advance one leaf"
        );
        assertEq(
            context.nonce,
            0,
            "stateful action should sign the current wrapper nonce"
        );

        bool verifyOk = account.verifyStatefulAction(
            publicKey, actionType, payloadHash, signature
        );
        assertTrue(
            verifyOk,
            "wrapper must accept the account-aware stateful signature"
        );
        assertEq(account.nonce(), 1, "wrapper nonce must advance");
    }

    // Checks that a stateful ERC-1271 signature works now, then fails after
    // the nonce is used.
    // line-length: allow — test name is one unbreakable token
    function testAccountAwareStateful1271SnapshotIsValidBeforeNonceUseAndInvalidAfter()
        public
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware 1271 stateful current key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            ,
            SHRINCSCore.ActionContext memory context,
            UXMSS.StatefulSignature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateful action signing must succeed");

        bytes32 hash = SHRINCSCore.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory envelope =
            SHRINCSAccountSigningFacade.encodeStateful1271Envelope(
                publicKey, actionType, payloadHash, signature
            );

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "stateful ERC-1271 snapshot must verify before nonce use"
        );

        bool verifyOk = account.verifyStatefulAction(
            publicKey, actionType, payloadHash, signature
        );
        assertTrue(verifyOk, "wrapper must accept the stateful action");
        assertEq(
            account.isValidSignature(hash, envelope),
            INVALID_SIGNATURE,
            "stateful ERC-1271 snapshot must fail after nonce advances"
        );
    }

    // Checks that trailing bytes appended to a stateful ERC-1271 envelope
    // are rejected by the re-encode canonicity check.
    // line-length: allow — test name is one unbreakable token
    function testAccountAwareStateful1271EnvelopeRejectsTrailingBytes()
        public
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware 1271 stateful trailing key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            ,
            SHRINCSCore.ActionContext memory context,
            UXMSS.StatefulSignature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateful action signing must succeed");

        bytes32 hash = SHRINCSCore.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory envelope =
            SHRINCSAccountSigningFacade.encodeStateful1271Envelope(
                publicKey, actionType, payloadHash, signature
            );

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "canonical stateful envelope must verify"
        );

        bytes memory malformed = bytes.concat(envelope, hex"00");
        assertEq(
            account.isValidSignature(hash, malformed),
            INVALID_SIGNATURE,
            "trailing bytes must invalidate the stateful envelope"
        );
    }

    function testAccountAwareStatelessActionSignerFeedsWrapper() public {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware stateless current key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            SHRINCSCore.ActionContext memory context,
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

        assertTrue(signOk, "stateless action signing must succeed");
        assertEq(
            context.nonce,
            0,
            "stateless action should sign the current wrapper nonce"
        );

        // line-length: allow — fmt canonical tuple head exceeds cap
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(completeOk, "stateless session completion must succeed");

        bool verifyOk = account.verifyStatelessAction(
            publicKey, actionType, payloadHash, signature
        );
        assertTrue(
            verifyOk,
            "wrapper must accept the account-aware stateless signature"
        );
        assertEq(account.nonce(), 1, "wrapper nonce must advance");
        assertEq(
            account.statelessSignaturesUsed(),
            1,
            "wrapper must count one stateless use"
        );
    }

    // Checks that a stateless ERC-1271 signature works now, then fails after
    // the nonce is used.
    // line-length: allow — test name is one unbreakable token
    function testAccountAwareStateless1271SnapshotIsValidBeforeNonceUseAndInvalidAfter()
        public
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware 1271 stateless current key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            SHRINCSCore.ActionContext memory context,
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
        assertTrue(signOk, "stateless action signing must succeed");

        // line-length: allow — fmt canonical tuple head exceeds cap
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(completeOk, "stateless session completion must succeed");

        bytes32 hash = SHRINCSCore.statelessActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory envelope =
            SHRINCSAccountSigningFacade.encodeStateless1271Envelope(
                publicKey, actionType, payloadHash, signature
            );

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "stateless ERC-1271 snapshot must verify before nonce use"
        );

        bool verifyOk = account.verifyStatelessAction(
            publicKey, actionType, payloadHash, signature
        );
        assertTrue(verifyOk, "wrapper must accept the stateless action");
        assertEq(
            account.isValidSignature(hash, envelope),
            INVALID_SIGNATURE,
            "stateless ERC-1271 snapshot must fail after nonce advances"
        );
    }

    // Checks that trailing bytes appended to a stateless ERC-1271 envelope
    // are rejected by the re-encode canonicity check.
    // line-length: allow — test name is one unbreakable token
    function testAccountAwareStateless1271EnvelopeRejectsTrailingBytes()
        public
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware 1271 stateless trailing key"), 4
        );
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (
            SHRINCSCore.ActionContext memory context,
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
        assertTrue(signOk, "stateless action signing must succeed");

        // line-length: allow — fmt canonical tuple head exceeds cap
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(completeOk, "stateless session completion must succeed");

        bytes32 hash = SHRINCSCore.statelessActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory envelope =
            SHRINCSAccountSigningFacade.encodeStateless1271Envelope(
                publicKey, actionType, payloadHash, signature
            );

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "canonical stateless envelope must verify"
        );

        bytes memory malformed = bytes.concat(envelope, hex"00");
        assertEq(
            account.isValidSignature(hash, malformed),
            INVALID_SIGNATURE,
            "trailing bytes must invalidate the stateless envelope"
        );
    }

    function testAccountAwareStatefulOnlyRotationSignerFeedsWrapper()
        public
    {
        (
            SHRINCSCore.SigningKey memory currentSigningKey,
            SHRINCSCore.PublicKey memory currentPublicKey,
            bool currentOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware rotation current key"), 4
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
        (, SHRINCSCore.PublicKey memory nextPublicKey, bool nextOk) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware rotation next key"), 4
        );
        assertTrue(nextOk, "next keygen must succeed");

        SHRINCSCore.StatefulRotationTarget memory nextKey =
            SHRINCSAccountSigningFacade.statefulRotationTarget(
                currentPublicKey, nextPublicKey.statefulPublicKey
            );

        (
            SHRINCSCore.RotationContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = SHRINCSAccountSigningFacade.beginStatefulOnlyRotationSessionNow(
                signer, account, currentSigningKey, currentPublicKey, nextKey
            );

        assertTrue(signOk, "stateful-only rotation signing must succeed");
        assertEq(
            context.nonce,
            0,
            "rotation should sign the current wrapper nonce"
        );

        (
            SPHINCSPlusCCore.StatelessSignature memory recoverySignature,
            bool completeOk
        ) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(
            completeOk,
            "stateful-only rotation session completion must succeed"
        );

        bool rotateOk = account.rotateToFreshKey(
            currentPublicKey, recoverySignature, nextKey
        );
        assertTrue(
            rotateOk,
            "wrapper must accept the account-aware stateful-only rotation"
        );
        assertEq(
            account.currentSHRINCSPublicKey(),
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(nextKey)
        );
        assertEq(account.keyVersion(), 1, "key epoch must advance");
        assertEq(
            account.nonce(), 1, "rotation must consume the current nonce"
        );
        assertEq(
            account.statelessSignaturesUsed(),
            1,
            "rotation must consume one stateless use"
        );
    }

    function testAccountAwareFullRotationSignerFeedsWrapper() public {
        (
            SHRINCSCore.SigningKey memory currentSigningKey,
            SHRINCSCore.PublicKey memory currentPublicKey,
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
        (, SHRINCSCore.PublicKey memory nextPublicKey, bool nextOk) = SHRINCSAccountSigningFacade.keygen(
            bytes("account-aware full rotation next key"), 4
        );
        assertTrue(nextOk, "next keygen must succeed");

        SHRINCSCore.RotationTarget memory nextKey =
            SHRINCSAccountSigningFacade.fullRotationTarget(nextPublicKey);

        (
            SHRINCSCore.RotationContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = SHRINCSAccountSigningFacade.beginFullRotationSessionNow(
                signer, account, currentSigningKey, currentPublicKey, nextKey
            );

        assertTrue(signOk, "full rotation signing must succeed");
        assertEq(
            context.nonce,
            0,
            "rotation should sign the current wrapper nonce"
        );

        (
            SPHINCSPlusCCore.StatelessSignature memory recoverySignature,
            bool completeOk
        ) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(
            completeOk, "full rotation session completion must succeed"
        );

        bool rotateOk = account.rotateFullKey(
            currentPublicKey, recoverySignature, nextKey
        );
        assertTrue(
            rotateOk, "wrapper must accept the account-aware full rotation"
        );
        assertEq(
            account.currentSHRINCSPublicKey(),
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                nextPublicKey
            )
        );
        assertEq(account.keyVersion(), 1, "key epoch must advance");
        assertEq(
            account.nonce(), 1, "rotation must consume the current nonce"
        );
        assertEq(
            account.statelessSignaturesUsed(),
            0,
            "full rotation must reset stateless usage"
        );
    }
}
