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
import {ShrincsAccountSigningFacade} from "./helpers/ShrincsAccountSigningFacade.sol";
import {ShrincsStatelessVectorSigner} from "./helpers/ShrincsStatelessVectorSigner.sol";
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";

contract ExampleAccountSignerHarness is ShrincsStatelessVectorSigner {}

contract ShrincsAccountVerifierExampleHarness is ShrincsAccountVerifierExample {
    constructor(bytes32 initialPkSeed, bytes32 initialHypertreeRoot)
        ShrincsAccountVerifierExample(initialPkSeed, initialHypertreeRoot)
    {}

    function setStatelessSignaturesUsed(uint64 value) external {
        statelessSignaturesUsed = value;
    }

    function installFreshKeyForTest(bytes32 nextPkSeed, bytes32 nextHypertreeRoot) external {
        installFreshKey(nextPkSeed, nextHypertreeRoot);
    }
}

contract ShrincsAccountVerifierExampleTest is Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    uint8 internal constant ERC1271_MODE_STATELESS_ACTION = 2;
    uint8 internal constant ERC1271_MODE_COMPACT_ACTION = 3;
    uint256 internal constant COMPACT_SIGNATURE_BYTES = 10053;
    bytes32 internal constant ACTION_TYPE = keccak256("execute");
    bytes32 internal constant PAYLOAD_HASH = keccak256("payload");
    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    ExampleAccountSignerHarness internal signer;

    function setUp() public {
        signer = new ExampleAccountSignerHarness();
    }

    function testExampleInitializesStoredState() public {
        (, ShrincsTypes.PublicKey memory publicKey,) = ShrincsAccountSigningFacade.keygen(bytes("init key"));
        bytes32 expectedPkSeed = ShrincsAccountSigningFacade.pkSeedWord(publicKey);
        bytes32 expectedHypertreeRoot = ShrincsAccountSigningFacade.hypertreeRootWord(publicKey);

        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedPkSeed, expectedHypertreeRoot);

        assertEq(account.currentPkSeed(), expectedPkSeed);
        assertEq(account.currentHypertreeRoot(), expectedHypertreeRoot);
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    function testExampleRejectsMalformedAndUnknown1271Envelopes() public {
        (, ShrincsTypes.PublicKey memory publicKey,) = ShrincsAccountSigningFacade.keygen(bytes("1271 malformed"));
        ShrincsAccountVerifierExample account = newAccount(publicKey);

        assertEq(account.isValidSignature(bytes32(0), hex""), INVALID_SIGNATURE, "empty envelope");
        assertEq(
            account.isValidSignature(bytes32(0), abi.encodePacked(bytes1(uint8(99)), bytes("junk"))),
            INVALID_SIGNATURE,
            "unknown mode"
        );
        assertEq(
            account.isValidSignature(
                bytes32(0), abi.encodePacked(bytes1(ERC1271_MODE_STATELESS_ACTION), hex"deadbeef")
            ),
            INVALID_SIGNATURE,
            "malformed stateless"
        );
        assertEq(account.nonce(), 0, "failed 1271 checks must not consume nonce");
        assertEq(account.statelessSignaturesUsed(), 0, "failed 1271 checks must not consume usage");
    }

    function testExampleStatelessActionFeedsWrapper() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(bytes("stateless action key"));
        assertTrue(ok, "keygen");
        ShrincsAccountVerifierExample account = newAccount(publicKey);

        (ShrincsTypes.ActionContext memory context, ShrincsTypes.StatelessSignature memory signature) =
            signStatelessAction(account, signingKey, publicKey, ACTION_TYPE, PAYLOAD_HASH);

        assertEq(context.nonce, 0, "signed current nonce");
        assertTrue(account.verifyStatelessAction(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature), "stateless action");
        assertEq(account.nonce(), 1, "nonce increments");
        assertEq(account.statelessSignaturesUsed(), 1, "usage increments");
    }

    function testExampleStateless1271SnapshotIsValidBeforeNonceUseAndInvalidAfter() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(bytes("stateless 1271 key"));
        assertTrue(ok, "keygen");
        ShrincsAccountVerifierExample account = newAccount(publicKey);

        (ShrincsTypes.ActionContext memory context, ShrincsTypes.StatelessSignature memory signature) =
            signStatelessAction(account, signingKey, publicKey, ACTION_TYPE, PAYLOAD_HASH);
        bytes32 hash =
            SHRINCS.statelessActionMessageHash(account.currentPkSeed(), account.currentHypertreeRoot(), context);
        bytes memory envelope =
            ShrincsAccountSigningFacade.encodeStateless1271Envelope(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature);

        assertEq(account.isValidSignature(hash, envelope), MAGIC_VALUE, "snapshot valid");
        assertTrue(account.verifyStatelessAction(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature), "consume nonce");
        assertEq(account.isValidSignature(hash, envelope), INVALID_SIGNATURE, "snapshot invalid after use");
    }

    function testExampleStatelessActionRejectsAtUsageLimit() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(bytes("stateless limit key"));
        assertTrue(ok, "keygen");
        ShrincsAccountVerifierExampleHarness account = newHarness(publicKey);
        (, ShrincsTypes.StatelessSignature memory signature) =
            signStatelessAction(account, signingKey, publicKey, ACTION_TYPE, PAYLOAD_HASH);

        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        account.setStatelessSignaturesUsed(limit);

        assertFalse(account.verifyStatelessAction(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature), "usage limit");
        assertEq(account.nonce(), 0, "nonce unchanged");
        assertEq(account.statelessSignaturesUsed(), limit, "usage unchanged");
    }

    function testExampleFullRotationFeedsWrapperAndResetsUsage() public {
        (
            ShrincsTypes.SigningKey memory currentSigningKey,
            ShrincsTypes.PublicKey memory currentPublicKey,
            bool currentOk
        ) = ShrincsAccountSigningFacade.keygen(bytes("rotation current key"));
        assertTrue(currentOk, "current keygen");
        ShrincsAccountVerifierExampleHarness account = newHarness(currentPublicKey);

        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("rotation next key"));
        assertTrue(nextOk, "next keygen");
        ShrincsTypes.RotationTarget memory nextKey = ShrincsAccountSigningFacade.fullRotationTarget(nextPublicKey);
        account.setStatelessSignaturesUsed(7);

        (bytes32 sessionId, bool signOk) = beginFullRotation(account, currentSigningKey, currentPublicKey, nextKey);
        assertTrue(signOk, "rotation signing starts");
        (ShrincsTypes.StatelessSignature memory recoverySignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "rotation signing completes");

        assertTrue(account.rotateFullKey(currentPublicKey, recoverySignature, nextKey), "full rotation");
        assertEq(account.currentPkSeed(), ShrincsAccountSigningFacade.pkSeedWord(nextPublicKey));
        assertEq(account.currentHypertreeRoot(), ShrincsAccountSigningFacade.hypertreeRootWord(nextPublicKey));
        assertEq(account.nonce(), 1, "rotation consumes nonce");
        assertEq(account.keyVersion(), 1, "key version increments");
        assertEq(account.statelessSignaturesUsed(), 0, "new stateless key starts fresh");
    }

    function testExampleFullRotationRejectsAtUsageLimit() public {
        (
            ShrincsTypes.SigningKey memory currentSigningKey,
            ShrincsTypes.PublicKey memory currentPublicKey,
            bool currentOk
        ) = ShrincsAccountSigningFacade.keygen(bytes("rotation limit current key"));
        assertTrue(currentOk, "current keygen");
        ShrincsAccountVerifierExampleHarness account = newHarness(currentPublicKey);
        (, ShrincsTypes.PublicKey memory nextPublicKey, bool nextOk) =
            ShrincsAccountSigningFacade.keygen(bytes("rotation limit next key"));
        assertTrue(nextOk, "next keygen");
        ShrincsTypes.RotationTarget memory nextKey = ShrincsAccountSigningFacade.fullRotationTarget(nextPublicKey);
        (bytes32 sessionId, bool signOk) = beginFullRotation(account, currentSigningKey, currentPublicKey, nextKey);
        assertTrue(signOk, "rotation signing starts");
        (ShrincsTypes.StatelessSignature memory recoverySignature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "rotation signing completes");

        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        account.setStatelessSignaturesUsed(limit);

        assertFalse(account.rotateFullKey(currentPublicKey, recoverySignature, nextKey), "rotation limit");
        assertEq(account.keyVersion(), 0, "key version unchanged");
        assertEq(account.statelessSignaturesUsed(), limit, "usage unchanged");
    }

    function testExampleCompactSlotRegistrationActionAndRevocation() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(bytes("compact slot key"));
        assertTrue(ok, "keygen");
        ShrincsAccountVerifierExample account = newAccount(publicKey);
        uint8 q = 9;
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool compactOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact slot"), q);
        assertTrue(compactOk, "compact keygen");
        bytes32 slotId = account.compactSlotId(subPkSeed, subPkRoot);

        bytes memory malformedCompactSignature = new bytes(COMPACT_SIGNATURE_BYTES);
        assertFalse(
            account.verifyCompactAction(subPkSeed, subPkRoot, ACTION_TYPE, PAYLOAD_HASH, malformedCompactSignature),
            "unregistered compact slot"
        );

        registerCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);
        assertTrue(account.compactSlots(slotId), "slot registered");
        assertEq(account.nonce(), 1, "registration consumes nonce");
        assertEq(account.statelessSignaturesUsed(), 1, "registration consumes usage");

        ShrincsTypes.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(account, ACTION_TYPE, PAYLOAD_HASH);
        (bytes memory compactSignature, bool signOk) =
            ShrincsTestSigner.signCompactAction(compactSkSeed, subPkSeed, subPkRoot, context, q);
        assertTrue(signOk, "compact signing");

        assertTrue(account.verifyCompactAction(subPkSeed, subPkRoot, ACTION_TYPE, PAYLOAD_HASH, compactSignature));
        assertEq(account.nonce(), 2, "compact action consumes nonce");
        assertEq(account.statelessSignaturesUsed(), 1, "compact action does not use stateless budget");

        revokeCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);
        assertFalse(account.compactSlots(slotId), "slot revoked");
        assertEq(account.nonce(), 3, "revocation consumes nonce");
        assertEq(account.statelessSignaturesUsed(), 2, "revocation consumes usage");
    }

    function testExampleCompact1271SnapshotIsValidBeforeNonceUseAndInvalidAfter() public {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(bytes("compact 1271 key"));
        assertTrue(ok, "keygen");
        ShrincsAccountVerifierExample account = newAccount(publicKey);
        uint8 q = 13;
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot, bool compactOk) =
            ShrincsTestSigner.compactSingleLaneKeygen(bytes("compact 1271 slot"), q);
        assertTrue(compactOk, "compact keygen");
        registerCompactSlotNow(account, signingKey, publicKey, subPkSeed, subPkRoot);

        ShrincsTypes.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(account, ACTION_TYPE, PAYLOAD_HASH);
        (bytes memory compactSignature, bool signOk) =
            ShrincsTestSigner.signCompactAction(compactSkSeed, subPkSeed, subPkRoot, context, q);
        assertTrue(signOk, "compact signing");
        bytes32 hash = SHRINCS.compactActionMessageHash(context);
        bytes memory envelope =
            encodeCompact1271Envelope(subPkSeed, subPkRoot, ACTION_TYPE, PAYLOAD_HASH, compactSignature);

        assertEq(account.isValidSignature(hash, envelope), MAGIC_VALUE, "snapshot valid");
        assertTrue(account.verifyCompactAction(subPkSeed, subPkRoot, ACTION_TYPE, PAYLOAD_HASH, compactSignature));
        assertEq(account.isValidSignature(hash, envelope), INVALID_SIGNATURE, "snapshot invalid after use");
    }

    function testExampleDomainSeparatorDiffersAcrossContractInstances() public {
        (, ShrincsTypes.PublicKey memory publicKey,) = ShrincsAccountSigningFacade.keygen(bytes("domain key"));

        ShrincsAccountVerifierExample accountA = newAccount(publicKey);
        ShrincsAccountVerifierExample accountB = newAccount(publicKey);

        assertTrue(domainSeparatorFor(address(accountA)) != domainSeparatorFor(address(accountB)));
    }

    function signStatelessAction(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal returns (ShrincsTypes.ActionContext memory context, ShrincsTypes.StatelessSignature memory signature) {
        bytes32 sessionId;
        bool ok;
        (context, sessionId, ok) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            signer, account, signingKey, publicKey, actionType, payloadHash
        );
        assertTrue(ok, "stateless session starts");
        (signature, ok) = ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(ok, "stateless session completes");
    }

    function newAccount(ShrincsTypes.PublicKey memory publicKey)
        internal
        returns (ShrincsAccountVerifierExample account)
    {
        account = new ShrincsAccountVerifierExample(
            ShrincsAccountSigningFacade.pkSeedWord(publicKey), ShrincsAccountSigningFacade.hypertreeRootWord(publicKey)
        );
    }

    function newHarness(ShrincsTypes.PublicKey memory publicKey)
        internal
        returns (ShrincsAccountVerifierExampleHarness account)
    {
        account = new ShrincsAccountVerifierExampleHarness(
            ShrincsAccountSigningFacade.pkSeedWord(publicKey), ShrincsAccountSigningFacade.hypertreeRootWord(publicKey)
        );
    }

    function beginFullRotation(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.RotationTarget memory nextKey
    ) internal returns (bytes32 sessionId, bool ok) {
        (, sessionId, ok) =
            ShrincsAccountSigningFacade.beginFullRotationSessionNow(signer, account, signingKey, publicKey, nextKey);
    }

    function registerCompactSlotNow(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal {
        bytes32 sessionId;
        bool ok;
        (, sessionId, ok) = ShrincsAccountSigningFacade.beginCompactSlotRegistrationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(ok, "registration session starts");
        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "registration session completes");
        assertTrue(account.registerCompactSlot(publicKey, signature, subPkSeed, subPkRoot), "register compact slot");
    }

    function revokeCompactSlotNow(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal {
        bytes32 sessionId;
        bool ok;
        (, sessionId, ok) = ShrincsAccountSigningFacade.beginCompactSlotRevocationSessionNow(
            signer, account, signingKey, publicKey, subPkSeed, subPkRoot
        );
        assertTrue(ok, "revocation session starts");
        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(signer, sessionId);
        assertTrue(completeOk, "revocation session completes");
        assertTrue(account.revokeCompactSlot(publicKey, signature, subPkSeed, subPkRoot), "revoke compact slot");
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

    function domainSeparatorFor(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, account));
    }
}
