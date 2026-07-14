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
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";

contract ShrincsAccountSigningFacadeHarness is ShrincsStatelessVectorSigner {}

contract ShrincsAccountSigningFacadeTest is Test {
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    uint8 internal constant ERC1271_MODE_COMPACT_ACTION = 3;
    uint256 internal constant COMPACT_SIGNATURE_BYTES = 10053;
    uint256 internal constant COMPACT_Q_OFFSET = 9828;

    ShrincsAccountSigningFacadeHarness internal signer;

    function setUp() public {
        signer = new ShrincsAccountSigningFacadeHarness();
    }

    function testAccountAwareStatelessActionSignerFeedsWrapper() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware stateless current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
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
            ShrincsAccountSigningFacade.keygen(bytes("account-aware 1271 stateless current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");

        (ShrincsTypes.ActionContext memory context, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            signer, account, signingKey, publicKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateless action signing must succeed");

        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "stateless session completion must succeed");

        bytes32 hash =
            SHRINCS.statelessActionMessageHash(account.currentPkSeed(), account.currentHypertreeRoot(), context);
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

    function testAccountAwareCompactSlotRegistrationAndRevocationSignerFeedsWrapper() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware compact slot current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        bytes32 subPkSeed = keccak256("compact sub seed");
        bytes32 subPkRoot = keccak256("compact sub root");
        bytes32 slotId = account.compactSlotId(subPkSeed, subPkRoot);
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        bytes memory malformedCompactSignature = new bytes(COMPACT_SIGNATURE_BYTES);

        bool unregisteredCompactActionOk =
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, payloadHash, malformedCompactSignature);
        assertEq(unregisteredCompactActionOk, false, "unregistered compact action must fail");
        assertEq(account.nonce(), 0, "unregistered compact action must not consume nonce");

        (ShrincsTypes.RotationContext memory registerContext, bytes32 registerSessionId, bool registerSignOk) = ShrincsAccountSigningFacade.beginCompactSlotRegistrationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(registerSignOk, "compact slot registration signing must succeed");
        assertEq(registerContext.nonce, 0, "registration should sign the current wrapper nonce");

        (ShrincsTypes.StatelessSignature memory registerSignature, bool registerCompleteOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, registerSessionId);
        assertTrue(registerCompleteOk, "registration session completion must succeed");

        bool registerOk = account.registerCompactSlot(publicKey, registerSignature, subPkSeed, subPkRoot);
        assertTrue(registerOk, "wrapper must accept account-aware compact slot registration");
        assertTrue(account.compactSlots(slotId), "compact slot must be registered");
        assertEq(account.nonce(), 1, "registration must consume the current nonce");
        assertEq(account.statelessSignaturesUsed(), 1, "registration must consume one stateless use");

        bool compactActionOk =
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, payloadHash, malformedCompactSignature);
        assertEq(compactActionOk, false, "malformed compact action must fail");
        assertEq(account.nonce(), 1, "failed compact action must not consume nonce");
        assertTrue(account.compactSlots(slotId), "failed compact action must not revoke slot");

        bool repeatRegisterOk = account.registerCompactSlot(publicKey, registerSignature, subPkSeed, subPkRoot);
        assertEq(repeatRegisterOk, false, "already-registered compact slot must not register again");
        assertEq(account.nonce(), 1, "no-op compact registration must not consume nonce");
        assertEq(account.statelessSignaturesUsed(), 1, "no-op compact registration must not consume stateless use");

        (ShrincsTypes.RotationContext memory revokeContext, bytes32 revokeSessionId, bool revokeSignOk) = ShrincsAccountSigningFacade.beginCompactSlotRevocationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(revokeSignOk, "compact slot revocation signing must succeed");
        assertEq(revokeContext.nonce, 1, "revocation should sign the current wrapper nonce");

        (ShrincsTypes.StatelessSignature memory revokeSignature, bool revokeCompleteOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, revokeSessionId);
        assertTrue(revokeCompleteOk, "revocation session completion must succeed");

        bool revokeOk = account.revokeCompactSlot(publicKey, revokeSignature, subPkSeed, subPkRoot);
        assertTrue(revokeOk, "wrapper must accept account-aware compact slot revocation");
        assertEq(account.compactSlots(slotId), false, "compact slot must be revoked");
        assertEq(account.nonce(), 2, "revocation must consume the current nonce");
        assertEq(account.statelessSignaturesUsed(), 2, "revocation must consume one more stateless use");

        bool repeatRevokeOk = account.revokeCompactSlot(publicKey, revokeSignature, subPkSeed, subPkRoot);
        assertEq(repeatRevokeOk, false, "already-revoked compact slot must not revoke again");
        assertEq(account.nonce(), 2, "no-op compact revocation must not consume nonce");
        assertEq(account.statelessSignaturesUsed(), 2, "no-op compact revocation must not consume stateless use");
    }

    function testCompact1271RejectsMalformedSignatureAndPreservesState() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware compact 1271 current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        bytes32 subPkSeed = keccak256("compact 1271 sub seed");
        bytes32 subPkRoot = keccak256("compact 1271 sub root");
        bytes32 slotId = account.compactSlotId(subPkSeed, subPkRoot);

        (, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginCompactSlotRegistrationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(signOk, "compact slot registration signing must succeed");
        (ShrincsTypes.StatelessSignature memory registrationSignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "registration session completion must succeed");
        assertTrue(
            account.registerCompactSlot(publicKey, registrationSignature, subPkSeed, subPkRoot),
            "registration must succeed"
        );

        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: ShrincsAccountSigningFacade.domainSeparator(address(account)),
            nonce: account.nonce(),
            keyVersion: account.keyVersion(),
            actionType: actionType,
            payloadHash: payloadHash
        });
        bytes32 hash = SHRINCS.compactActionMessageHash(context);
        bytes memory compactSignature = new bytes(COMPACT_SIGNATURE_BYTES);
        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_COMPACT_ACTION),
            abi.encode(subPkSeed, subPkRoot, actionType, payloadHash, compactSignature)
        );

        assertEq(
            account.isValidSignature(hash, envelope),
            INVALID_SIGNATURE,
            "compact ERC-1271 malformed signature must fail"
        );
        assertTrue(account.compactSlots(slotId), "compact 1271 failure must preserve slot");
        assertEq(account.nonce(), 1, "compact 1271 failure must not consume nonce");
        assertEq(account.statelessSignaturesUsed(), 1, "compact 1271 failure must not consume stateless use");
    }

    function testCompact1271AcceptsSignedSignatureBeforeNonceUseAndRejectsAfterNonceUse() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware compact 1271 signed key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        uint8 q = 9;
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool compactKeygenOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("account-aware compact 1271 slot"), q);
        assertTrue(compactKeygenOk, "compact fixture keygen must succeed");

        registerCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);

        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("compact 1271 signed payload");
        (ShrincsTypes.ActionContext memory context, bytes memory compactSignature) =
            signCompactActionNow(account, compactSkSeed, subPkSeed, subPkRoot, actionType, payloadHash, q);
        bytes32 hash = SHRINCS.compactActionMessageHash(context);
        bytes memory envelope =
            encodeCompact1271Envelope(subPkSeed, subPkRoot, actionType, payloadHash, compactSignature);

        assertEq(
            account.isValidSignature(hash, envelope),
            ERC1271_MAGIC_VALUE,
            "compact ERC-1271 snapshot must verify before nonce use"
        );

        assertTrue(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, payloadHash, compactSignature),
            "wrapper must accept the compact action"
        );
        assertEq(account.nonce(), 2, "compact action must consume nonce after registration");
        assertEq(
            account.isValidSignature(hash, envelope),
            INVALID_SIGNATURE,
            "compact ERC-1271 snapshot must fail after nonce advances"
        );
        assertFalse(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, payloadHash, compactSignature),
            "reused nonce compact action must fail"
        );
        assertEq(account.nonce(), 2, "reused nonce failure must not consume nonce");
    }

    function testCompactActionRejectsUnregisteredAndRevokedSlots() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware compact slot negative key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        uint8 q = 13;
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool compactKeygenOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("account-aware compact slot negative"), q);
        assertTrue(compactKeygenOk, "compact fixture keygen must succeed");

        bytes32 actionType = keccak256("execute");
        bytes32 unregisteredPayloadHash = keccak256("compact unregistered payload");
        (ShrincsTypes.ActionContext memory unregisteredContext, bytes memory unregisteredSignature) =
            signCompactActionNow(account, compactSkSeed, subPkSeed, subPkRoot, actionType, unregisteredPayloadHash, q);
        bytes32 unregisteredHash = SHRINCS.compactActionMessageHash(unregisteredContext);
        bytes memory unregisteredEnvelope =
            encodeCompact1271Envelope(subPkSeed, subPkRoot, actionType, unregisteredPayloadHash, unregisteredSignature);

        assertEq(
            account.isValidSignature(unregisteredHash, unregisteredEnvelope),
            INVALID_SIGNATURE,
            "unregistered compact ERC-1271 slot must fail"
        );
        assertFalse(
            account.verifyCompactAction(
                subPkSeed, subPkRoot, actionType, unregisteredPayloadHash, unregisteredSignature
            ),
            "unregistered compact slot must fail"
        );
        assertEq(account.nonce(), 0, "unregistered compact failure must not consume nonce");

        registerCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);
        revokeCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);

        bytes32 revokedPayloadHash = keccak256("compact revoked payload");
        (ShrincsTypes.ActionContext memory revokedContext, bytes memory revokedSignature) =
            signCompactActionNow(account, compactSkSeed, subPkSeed, subPkRoot, actionType, revokedPayloadHash, q);
        bytes32 revokedHash = SHRINCS.compactActionMessageHash(revokedContext);
        bytes memory revokedEnvelope =
            encodeCompact1271Envelope(subPkSeed, subPkRoot, actionType, revokedPayloadHash, revokedSignature);

        assertEq(
            account.isValidSignature(revokedHash, revokedEnvelope),
            INVALID_SIGNATURE,
            "revoked compact ERC-1271 slot must fail"
        );
        assertFalse(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, revokedPayloadHash, revokedSignature),
            "revoked compact slot must fail"
        );
        assertEq(account.nonce(), 2, "revoked compact failure must not consume nonce");
    }

    function testAccountAwareCompactActionSignerFeedsWrapperAndDoesNotTrackQ() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware compact action current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        uint8 q = 7;
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool compactKeygenOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("account-aware compact action slot"), q);
        assertTrue(compactKeygenOk, "compact fixture keygen must succeed");

        (, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginCompactSlotRegistrationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(signOk, "compact slot registration signing must succeed");
        (ShrincsTypes.StatelessSignature memory registrationSignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "registration session completion must succeed");
        assertTrue(
            account.registerCompactSlot(publicKey, registrationSignature, subPkSeed, subPkRoot),
            "registration must succeed"
        );

        bytes32 actionType = keccak256("execute");
        bytes32 firstPayloadHash = keccak256("compact payload one");
        ShrincsTypes.ActionContext memory firstContext = ShrincsTypes.ActionContext({
            domainSeparator: ShrincsAccountSigningFacade.domainSeparator(address(account)),
            nonce: account.nonce(),
            keyVersion: account.keyVersion(),
            actionType: actionType,
            payloadHash: firstPayloadHash
        });
        (bytes memory firstSignature, bool firstSignOk) =
            ShrincsTestSigner.signCompactAction(compactSkSeed, subPkSeed, subPkRoot, firstContext, q);
        assertTrue(firstSignOk, "first compact action signing must succeed");
        assertTrue(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, firstPayloadHash, firstSignature),
            "wrapper must accept first compact action"
        );
        assertEq(account.nonce(), 2, "first compact action must consume nonce after registration");

        bytes32 secondPayloadHash = keccak256("compact payload two");
        ShrincsTypes.ActionContext memory secondContext = ShrincsTypes.ActionContext({
            domainSeparator: ShrincsAccountSigningFacade.domainSeparator(address(account)),
            nonce: account.nonce(),
            keyVersion: account.keyVersion(),
            actionType: actionType,
            payloadHash: secondPayloadHash
        });
        (bytes memory secondSignature, bool secondSignOk) =
            ShrincsTestSigner.signCompactAction(compactSkSeed, subPkSeed, subPkRoot, secondContext, q);
        assertTrue(secondSignOk, "second compact action signing must succeed");
        assertTrue(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, secondPayloadHash, secondSignature),
            "wrapper must not track q on-chain"
        );
        assertEq(account.nonce(), 3, "second compact action must consume nonce");
    }

    // Checks that one registered compact root can verify signatures from different q lanes.
    function testCompactSlotAcceptsDifferentQLanesUnderSameRoot() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("compact multi q current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        uint8 firstQ = 3;
        uint8 secondQ = 79;
        (bytes32 skSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool firstKeygenOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact multi q slot"), firstQ);
        assertTrue(firstKeygenOk, "first compact fixture keygen must succeed");
        (bytes32 secondSkSeed, bytes32 secondSubPkSeed, bytes32 secondSubPkRoot, bool secondKeygenOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact multi q slot"), secondQ);
        assertTrue(secondKeygenOk, "second compact fixture keygen must succeed");
        assertEq(secondSkSeed, skSeed, "same slot seed must derive the same compact SK.seed");
        assertEq(secondSubPkSeed, subPkSeed, "same slot seed must derive the same subPkSeed");
        assertEq(secondSubPkRoot, subPkRoot, "same compact tree must have one root");

        registerCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);

        bytes32 actionType = keccak256("multi-q execute");
        bytes32 firstPayloadHash = keccak256("compact q three payload");
        (, bytes memory firstSignature) =
            signCompactActionNow(account, skSeed, subPkSeed, subPkRoot, actionType, firstPayloadHash, firstQ);
        assertTrue(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, firstPayloadHash, firstSignature),
            "first compact q lane must verify"
        );
        assertEq(account.nonce(), 2, "first compact q lane must consume nonce");

        bytes32 secondPayloadHash = keccak256("compact q seventy nine payload");
        (, bytes memory secondSignature) =
            signCompactActionNow(account, skSeed, subPkSeed, subPkRoot, actionType, secondPayloadHash, secondQ);
        assertTrue(
            account.verifyCompactAction(subPkSeed, subPkRoot, actionType, secondPayloadHash, secondSignature),
            "second compact q lane must verify"
        );
        assertEq(account.nonce(), 3, "second compact q lane must consume nonce");
        assertTrue(
            account.compactSlots(account.compactSlotId(subPkSeed, subPkRoot)), "compact slot must stay registered"
        );
    }

    // Checks that a signer can rotate through all 128 compact q lanes under one slot.
    function testCompactSlotAcceptsAll128RotatingQLanes() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("compact all q current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        (bytes32 skSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool compactKeygenOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact all q slot"), 0);
        assertTrue(compactKeygenOk, "compact fixture keygen must succeed");

        (bytes32 allAuthRoot, bytes32[7][128] memory authPaths) =
            ShrincsTestSigner.compactMerkleRootAndAllAuth(skSeed, subPkSeed);
        assertEq(allAuthRoot, subPkRoot, "precomputed compact auth paths must share root");
        registerCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);

        bytes32 actionType = keccak256("all-q execute");
        for (uint256 i = 0; i < ShrincsTypes.COMPACT_Q_MAX;) {
            uint8 q = uint8(i);
            bytes32 payloadHash = keccak256(abi.encodePacked("compact all q payload", q));
            ShrincsTypes.ActionContext memory context =
                ShrincsAccountSigningFacade.actionContext(account, actionType, payloadHash);
            (bytes memory signature, bool signOk) =
                ShrincsTestSigner.signCompactActionWithAuth(skSeed, subPkSeed, subPkRoot, context, q, authPaths[i]);
            assertTrue(signOk, "compact q signing must succeed");
            assertEq(uint8(signature[COMPACT_Q_OFFSET]), q, "signature must encode the rotated q");
            assertTrue(
                account.verifyCompactAction(subPkSeed, subPkRoot, actionType, payloadHash, signature),
                "rotated compact q lane must verify"
            );
            assertEq(account.nonce(), i + 2, "each rotated compact q lane must consume nonce");
            unchecked {
                ++i;
            }
        }

        assertEq(account.nonce(), uint256(ShrincsTypes.COMPACT_Q_MAX) + 1, "all compact q lanes must verify");
        assertTrue(
            account.compactSlots(account.compactSlotId(subPkSeed, subPkRoot)),
            "compact slot must remain registered after all q lanes"
        );
    }

    // Checks that independent compact device slots can coexist and revoke independently.
    function testCompactSlotsSupportMultipleIndependentDeviceLanes() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("compact multi device current key"));
        assertTrue(keygenOk, "keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        (bytes32 deviceASkSeed, bytes32 deviceASeed, bytes32 deviceARoot, bool deviceAOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact device a slot"), 5);
        assertTrue(deviceAOk, "device A keygen must succeed");
        (bytes32 deviceBSkSeed, bytes32 deviceBSeed, bytes32 deviceBRoot, bool deviceBOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact device b slot"), 91);
        assertTrue(deviceBOk, "device B keygen must succeed");

        bytes32 deviceASlot = account.compactSlotId(deviceASeed, deviceARoot);
        bytes32 deviceBSlot = account.compactSlotId(deviceBSeed, deviceBRoot);
        assertTrue(deviceASlot != deviceBSlot, "independent compact devices need distinct slots");

        registerCompactSlotNow(account, signingKey, publicKey, deviceASeed, deviceARoot);
        assertTrue(account.compactSlots(deviceASlot), "device A slot must register");
        assertFalse(account.compactSlots(deviceBSlot), "device B slot must remain unregistered");

        registerCompactSlotNow(account, signingKey, publicKey, deviceBSeed, deviceBRoot);
        assertTrue(account.compactSlots(deviceASlot), "device A slot must stay registered");
        assertTrue(account.compactSlots(deviceBSlot), "device B slot must register");

        bytes32 actionType = keccak256("multi-device execute");
        bytes32 deviceAPayloadHash = keccak256("compact device a payload");
        (, bytes memory deviceASignature) =
            signCompactActionNow(account, deviceASkSeed, deviceASeed, deviceARoot, actionType, deviceAPayloadHash, 5);
        assertTrue(
            account.verifyCompactAction(deviceASeed, deviceARoot, actionType, deviceAPayloadHash, deviceASignature),
            "device A compact action must verify"
        );

        bytes32 deviceBPayloadHash = keccak256("compact device b payload");
        (, bytes memory deviceBSignature) =
            signCompactActionNow(account, deviceBSkSeed, deviceBSeed, deviceBRoot, actionType, deviceBPayloadHash, 91);
        assertTrue(
            account.verifyCompactAction(deviceBSeed, deviceBRoot, actionType, deviceBPayloadHash, deviceBSignature),
            "device B compact action must verify"
        );

        revokeCompactSlotNow(account, signingKey, publicKey, deviceASeed, deviceARoot);
        assertFalse(account.compactSlots(deviceASlot), "device A slot must revoke");
        assertTrue(account.compactSlots(deviceBSlot), "device B slot must stay registered");

        bytes32 deviceBSecondPayloadHash = keccak256("compact device b second payload");
        (, bytes memory deviceBSecondSignature) = signCompactActionNow(
            account, deviceBSkSeed, deviceBSeed, deviceBRoot, actionType, deviceBSecondPayloadHash, 91
        );
        assertTrue(
            account.verifyCompactAction(
                deviceBSeed, deviceBRoot, actionType, deviceBSecondPayloadHash, deviceBSecondSignature
            ),
            "device B compact action must still verify after device A revocation"
        );

        bytes32 deviceASecondPayloadHash = keccak256("compact device a revoked payload");
        (, bytes memory deviceASecondSignature) = signCompactActionNow(
            account, deviceASkSeed, deviceASeed, deviceARoot, actionType, deviceASecondPayloadHash, 5
        );
        uint256 nonceBeforeRevokedAction = account.nonce();
        assertFalse(
            account.verifyCompactAction(
                deviceASeed, deviceARoot, actionType, deviceASecondPayloadHash, deviceASecondSignature
            ),
            "revoked device A compact action must fail"
        );
        assertEq(account.nonce(), nonceBeforeRevokedAction, "revoked device must not consume nonce");
    }

    function testAccountAwareFullRotationSignerFeedsWrapper() public {
        (
            ShrincsTypes.SigningKey memory currentSigningKey,
            ShrincsTypes.PublicKey memory currentPublicKey,
            bool currentOk
        ) = ShrincsAccountSigningFacade.keygen(bytes("account-aware full rotation current key"));
        assertTrue(currentOk, "current keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(currentPublicKey);

        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("account-aware full rotation next key"));
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
        assertEq(account.currentPkSeed(), ShrincsAccountSigningFacade.pkSeedWord(nextPublicKey));
        assertEq(account.currentHypertreeRoot(), ShrincsAccountSigningFacade.hypertreeRootWord(nextPublicKey));
        assertEq(account.keyVersion(), 1, "key epoch must advance");
        assertEq(account.nonce(), 1, "rotation must consume the current nonce");
        assertEq(account.statelessSignaturesUsed(), 0, "full rotation must reset stateless usage");
    }

    function registerCompactSlotNow(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal {
        (, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginCompactSlotRegistrationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(signOk, "compact slot registration signing must succeed");

        (ShrincsTypes.StatelessSignature memory registrationSignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "registration session completion must succeed");
        assertTrue(
            account.registerCompactSlot(publicKey, registrationSignature, subPkSeed, subPkRoot),
            "registration must succeed"
        );
    }

    function revokeCompactSlotNow(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal {
        (, bytes32 sessionId, bool signOk) = ShrincsAccountSigningFacade.beginCompactSlotRevocationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(signOk, "compact slot revocation signing must succeed");

        (ShrincsTypes.StatelessSignature memory revocationSignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "revocation session completion must succeed");
        assertTrue(
            account.revokeCompactSlot(publicKey, revocationSignature, subPkSeed, subPkRoot), "revocation must succeed"
        );
    }

    function signCompactActionNow(
        ShrincsAccountVerifierExample account,
        bytes32 compactSkSeed,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 actionType,
        bytes32 payloadHash,
        uint8 q
    ) internal view returns (ShrincsTypes.ActionContext memory context, bytes memory compactSignature) {
        context = ShrincsAccountSigningFacade.actionContext(account, actionType, payloadHash);
        bool signOk;
        (compactSignature, signOk) =
            ShrincsTestSigner.signCompactAction(compactSkSeed, subPkSeed, subPkRoot, context, q);
        assertTrue(signOk, "compact action signing must succeed");
    }

    function encodeCompact1271Envelope(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 actionType,
        bytes32 payloadHash,
        bytes memory compactSignature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(ERC1271_MODE_COMPACT_ACTION),
            abi.encode(subPkSeed, subPkRoot, actionType, payloadHash, compactSignature)
        );
    }

    function newAccount(ShrincsTypes.PublicKey memory publicKey)
        internal
        returns (ShrincsAccountVerifierExample account)
    {
        account = new ShrincsAccountVerifierExample(
            ShrincsAccountSigningFacade.pkSeedWord(publicKey), ShrincsAccountSigningFacade.hypertreeRootWord(publicKey)
        );
    }
}
