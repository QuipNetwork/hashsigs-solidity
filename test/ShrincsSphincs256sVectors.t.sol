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

contract StatelessHarness {
    function verifyUnsafeRaw(
        bytes32 expectedPkSeed,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedPkSeed, publicKeyRoot(publicKey), publicKey, message, signature
        );
    }

    function verifyUnsafeRaw(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedPkSeed, expectedHypertreeRoot, publicKey, message, signature
        );
    }

    function verify(
        bytes32 expectedPkSeed,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(expectedPkSeed, publicKeyRoot(publicKey), publicKey, context, signature);
    }

    function verify(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(expectedPkSeed, expectedHypertreeRoot, publicKey, context, signature);
    }

    function actionMessageHash(bytes32 expectedPkSeed, ShrincsTypes.ActionContext calldata context)
        external
        pure
        returns (bytes32)
    {
        return SHRINCS.statelessActionMessageHash(expectedPkSeed, expectedPkSeed, context);
    }

    function actionMessageHash(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCS.statelessActionMessageHash(expectedPkSeed, expectedHypertreeRoot, context);
    }

    function publicKeyRoot(ShrincsTypes.PublicKey calldata publicKey) internal pure returns (bytes32 root) {
        if (publicKey.hypertreeRoot.length != 32) return bytes32(0);
        bytes calldata rootBytes = publicKey.hypertreeRoot;
        assembly {
            root := calldataload(rootBytes.offset)
        }
    }
}

contract CompactHarness {
    function verify(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        ShrincsTypes.ActionContext calldata context,
        bytes calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyCompact(subPkSeed, subPkRoot, context, signature);
    }

    function verifyUnsafeRaw(bytes32 subPkSeed, bytes32 subPkRoot, bytes32 message, bytes calldata signature)
        external
        pure
        returns (bool)
    {
        return SHRINCS.verifyCompactUncheckedMessage(subPkSeed, subPkRoot, message, signature);
    }

    function actionMessageHash(ShrincsTypes.ActionContext calldata context) external pure returns (bytes32) {
        return SHRINCS.compactActionMessageHash(context);
    }

    function registrationMessageHash(
        ShrincsTypes.RotationContext calldata context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) external pure returns (bytes32) {
        return SHRINCS.compactSlotRegistrationMessageHash(context, subPkSeed, subPkRoot);
    }

    function revocationMessageHash(ShrincsTypes.RotationContext calldata context, bytes32 subPkSeed, bytes32 subPkRoot)
        external
        pure
        returns (bytes32)
    {
        return SHRINCS.compactSlotRevocationMessageHash(context, subPkSeed, subPkRoot);
    }

    function slotId(bytes32 subPkSeed, bytes32 subPkRoot) external pure returns (bytes32) {
        return SHRINCS.compactSlotId(subPkSeed, subPkRoot);
    }
}

contract RotationHarness {
    function fullRotationMessageHash(
        bytes32 expectedPkSeed,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.fullRotationMessageHash(
            expectedPkSeed, publicKeyRoot(currentPublicKey), currentPublicKey, context, nextKey
        );
    }

    function fullRotationMessageHash(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.fullRotationMessageHash(
            expectedPkSeed, expectedHypertreeRoot, currentPublicKey, context, nextKey
        );
    }

    function statelessRotate(
        bytes32 expectedPkSeed,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bool) {
        return SHRINCS.statelessRotate(
            expectedPkSeed, publicKeyRoot(currentPublicKey), currentPublicKey, context, recoverySignature, nextKey
        );
    }

    function statelessRotate(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bool) {
        return SHRINCS.statelessRotate(
            expectedPkSeed, expectedHypertreeRoot, currentPublicKey, context, recoverySignature, nextKey
        );
    }

    function publicKeyRoot(ShrincsTypes.PublicKey calldata publicKey) internal pure returns (bytes32 root) {
        if (publicKey.hypertreeRoot.length != 32) return bytes32(0);
        bytes calldata rootBytes = publicKey.hypertreeRoot;
        assembly {
            root := calldataload(rootBytes.offset)
        }
    }
}

contract ShrincsSphincs256sVectorsTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";
    uint256 internal constant COMPACT_SIGNATURE_BYTES = 10053;
    uint256 internal constant COMPACT_FORS_OFFSET = 36;
    uint256 internal constant COMPACT_Q_OFFSET = 9828;
    uint256 internal constant COMPACT_MERKLE_AUTH_OFFSET = 9829;

    struct LegacyForsEntry {
        bytes secretLeaf;
        bytes[] authPath;
    }

    struct LegacyForsSignature {
        bytes randomizer;
        uint32 counter;
        LegacyForsEntry[] entries;
    }

    struct LegacyWotsCSignature {
        bytes randomizer;
        uint32 counter;
        bytes[] chains;
    }

    struct LegacyHypertreeLayerSignature {
        uint64 treeIndex;
        uint32 leafIndex;
        bytes wotsCPkHash;
        LegacyWotsCSignature wotsCSignature;
        bytes[] authPath;
    }

    struct LegacyStatelessSignature {
        LegacyForsSignature fors;
        LegacyHypertreeLayerSignature[] hypertree;
    }

    StatelessHarness internal stateless;
    CompactHarness internal compact;
    RotationHarness internal rotation;
    string internal vectors;

    function setUp() public {
        stateless = new StatelessHarness();
        compact = new CompactHarness();
        rotation = new RotationHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testStatelessSphincs256sValidSignatureVerifies() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertTrue(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsWrongMessage() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.wrongMessage.calldata");
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsTamperedFors() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.tamperedFors.calldata");
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeWotsPkHash() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.tamperedHypertreeWotsPkHash.calldata");
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeAuth() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.tamperedHypertreeAuth.calldata");
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsWrongExpectedCompositePublicKey() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 wrongExpectedCompositePublicKey = compositePublicKeyWord(publicKey) ^ bytes32(uint256(1));
        assertFalse(stateless.verifyUnsafeRaw(wrongExpectedCompositePublicKey, publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsMismatchedPublicRoot() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 arbitraryCommitment = keccak256("arbitrary-stateless-commitment");
        publicKey.hypertreeRoot = abi.encodePacked(arbitraryCommitment);
        assertFalse(stateless.verifyUnsafeRaw(arbitraryCommitment, publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsZeroExpectedCompositePublicKey() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertFalse(stateless.verifyUnsafeRaw(bytes32(0), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsMalformedPkSeedLength() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.pkSeed = hex"1234";
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsMalformedHypertreeRootLength() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedPublicRoot = compositePublicKeyWord(publicKey);
        publicKey.hypertreeRoot = hex"1234";
        assertFalse(stateless.verifyUnsafeRaw(expectedPublicRoot, publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsWrongPublicRootVector() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.wrongPublicRoot.calldata");
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsTamperedComponentPublicKeyVector() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.tamperedComponentPublicKey.calldata");
        assertFalse(stateless.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature));
    }

    function testStatelessSphincs256sRejectsMalformedSignatureShapes() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 commitment = compositePublicKeyWord(publicKey);

        signature.hypertree = new ShrincsTypes.HypertreeLayerSignature[](0);
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "empty hypertree");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        ShrincsTypes.HypertreeLayerSignature[] memory shortened =
            new ShrincsTypes.HypertreeLayerSignature[](signature.hypertree.length - 1);
        for (uint256 i = 0; i < shortened.length; ++i) {
            shortened[i] = signature.hypertree[i];
        }
        signature.hypertree = shortened;
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "dropped hypertree layer");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries = dropLastForsEntries(signature.fors.entries);
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "dropped FORS entry");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.randomizer = hex"1234";
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "short FORS randomizer");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].secretLeaf = hex"1234";
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "short FORS leaf");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath = dropLastBytes(signature.fors.entries[0].authPath);
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "short FORS auth path");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath[0] = hex"1234";
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "short FORS auth node");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].leafIndex = 256;
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "leaf out of range");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].wotsCSignature.chains[0] = hex"1234";
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "short WOTS-C chain");

        (, message, signature) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath = dropLastBytes(signature.hypertree[0].authPath);
        assertFalse(stateless.verifyUnsafeRaw(commitment, publicKey, message, signature), "short hypertree auth");
    }

    function testStatelessActionMessageHashBindsContext() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = compositePublicKeyWord(publicKey);
        ShrincsTypes.ActionContext memory first = ShrincsTypes.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 9,
            keyVersion: 4,
            actionType: keccak256("rotate"),
            payloadHash: keccak256("payload")
        });
        ShrincsTypes.ActionContext memory second = ShrincsTypes.ActionContext({
            domainSeparator: first.domainSeparator,
            nonce: 10,
            keyVersion: first.keyVersion,
            actionType: first.actionType,
            payloadHash: first.payloadHash
        });

        assertTrue(
            stateless.actionMessageHash(expectedCompositePublicKey, first)
                != stateless.actionMessageHash(expectedCompositePublicKey, second),
            "stateless action hash must bind nonce"
        );
    }

    function testStatelessVerifyRejectsMalformedActionContexts() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = compositePublicKeyWord(publicKey);
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: bytes32(0),
            nonce: 1,
            keyVersion: 1,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });
        assertFalse(stateless.verify(expectedCompositePublicKey, publicKey, context, signature), "zero domain");

        context.domainSeparator = keccak256("shrincs-account");
        context.actionType = bytes32(0);
        assertFalse(stateless.verify(expectedCompositePublicKey, publicKey, context, signature), "zero action type");

        context.actionType = keccak256("execute");
        context.payloadHash = bytes32(0);
        assertFalse(stateless.verify(expectedCompositePublicKey, publicKey, context, signature), "zero payload");
    }

    function testCompactSlotIdMatchesJardinMappingKey() public view {
        bytes32 subPkSeed = keccak256("compact seed");
        bytes32 subPkRoot = keccak256("compact root");

        assertEq(compact.slotId(subPkSeed, subPkRoot), keccak256(abi.encodePacked(subPkSeed, subPkRoot)));
    }

    function testCompactSlotUpdateHashesMatchPackedEncoding() public view {
        bytes32 subPkSeed = keccak256("compact seed");
        bytes32 subPkRoot = keccak256("compact root");
        ShrincsTypes.RotationContext memory registerContext =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-account"), nonce: 7, keyVersion: 2});
        ShrincsTypes.RotationContext memory revokeContext =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-account"), nonce: 8, keyVersion: 3});
        bytes32 slotId = keccak256(abi.encodePacked(subPkSeed, subPkRoot));

        bytes32 expectedRegister = keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_REGISTER_COMPACT_SLOT,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
                registerContext.domainSeparator,
                registerContext.nonce,
                registerContext.keyVersion,
                slotId,
                subPkSeed,
                subPkRoot
            )
        );
        bytes32 expectedRevoke = keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_REVOKE_COMPACT_SLOT,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
                revokeContext.domainSeparator,
                revokeContext.nonce,
                revokeContext.keyVersion,
                slotId,
                subPkSeed,
                subPkRoot
            )
        );

        assertEq(compact.registrationMessageHash(registerContext, subPkSeed, subPkRoot), expectedRegister);
        assertEq(compact.revocationMessageHash(revokeContext, subPkSeed, subPkRoot), expectedRevoke);
    }

    function testCompactActionMessageHashMatchesPackedEncodingAndBindsPayload() public view {
        ShrincsTypes.ActionContext memory first = ShrincsTypes.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 12,
            keyVersion: 5,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload-a")
        });
        ShrincsTypes.ActionContext memory second = ShrincsTypes.ActionContext({
            domainSeparator: first.domainSeparator,
            nonce: first.nonce,
            keyVersion: first.keyVersion,
            actionType: first.actionType,
            payloadHash: keccak256("payload-b")
        });
        bytes32 expected = keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_VERIFY_COMPACT,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
                first.domainSeparator,
                first.nonce,
                first.keyVersion,
                first.actionType,
                first.payloadHash
            )
        );

        assertEq(compact.actionMessageHash(first), expected);
        assertTrue(compact.actionMessageHash(first) != compact.actionMessageHash(second));
    }

    function testCompactVerifyRejectsMalformedRawSignature() public view {
        bytes32 subPkSeed = keccak256("compact seed");
        bytes32 subPkRoot = keccak256("compact root");
        bytes memory malformedSignature = new bytes(COMPACT_SIGNATURE_BYTES - 1);
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 1,
            keyVersion: 1,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });

        assertFalse(compact.verify(subPkSeed, subPkRoot, context, malformedSignature));
    }

    function testCompactVerifyAcceptsRustSignedRawVector() public {
        (bytes32 subPkSeed, bytes32 subPkRoot, bytes32 message, bytes memory signature) =
            decodeCompactVector(".compact.cases.valid.calldata");

        assertTrue(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, message, signature));
        assertFalse(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, keccak256("wrong compact raw message"), signature));
    }

    function testCompactVerifyAcceptsRustSignedActionVectors() public {
        (
            bytes32 firstSeed,
            bytes32 firstRoot,
            ShrincsTypes.ActionContext memory firstContext,
            bytes memory firstSignature
        ) = decodeCompactActionVector(".compact.actionCases.first.calldata");
        (
            bytes32 secondSeed,
            bytes32 secondRoot,
            ShrincsTypes.ActionContext memory secondContext,
            bytes memory secondSignature
        ) = decodeCompactActionVector(".compact.actionCases.sameQSecond.calldata");

        assertTrue(compact.verify(firstSeed, firstRoot, firstContext, firstSignature));
        assertTrue(compact.verify(secondSeed, secondRoot, secondContext, secondSignature));
        assertEq(firstSeed, secondSeed);
        assertEq(firstRoot, secondRoot);
        assertEq(readCompactQ(firstSignature), readCompactQ(secondSignature));
        assertFalse(compact.verify(firstSeed, firstRoot, secondContext, firstSignature));
        assertFalse(compact.verify(secondSeed, secondRoot, firstContext, secondSignature));
    }

    function testCompactVerifyRejectsTamperedRawVectors() public {
        (bytes32 subPkSeed, bytes32 subPkRoot, bytes32 message, bytes memory signature) =
            decodeCompactVector(".compact.cases.valid.calldata");

        bytes memory tampered = cloneBytes(signature);
        flipByte(tampered, COMPACT_Q_OFFSET);
        assertFalse(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, message, tampered), "wrong q");

        assertFalse(
            compact.verifyUnsafeRaw(subPkSeed, bytes32(uint256(subPkRoot) ^ uint256(1)), message, signature),
            "wrong root"
        );

        tampered = cloneBytes(signature);
        flipByte(tampered, COMPACT_MERKLE_AUTH_OFFSET);
        assertFalse(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, message, tampered), "wrong Merkle auth");

        tampered = cloneBytes(signature);
        flipByte(tampered, COMPACT_FORS_OFFSET + 32);
        assertFalse(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, message, tampered), "wrong FORS auth");

        tampered = cloneBytes(signature);
        flipByte(tampered, 0);
        assertFalse(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, message, tampered), "wrong R");

        tampered = cloneBytes(signature);
        flipByte(tampered, 35);
        assertFalse(compact.verifyUnsafeRaw(subPkSeed, subPkRoot, message, tampered), "wrong counter");
    }

    function testCompactVerifyRejectsZeroDomainSeparator() public view {
        bytes32 subPkSeed = keccak256("compact seed");
        bytes32 subPkRoot = keccak256("compact root");
        bytes memory signature = new bytes(COMPACT_SIGNATURE_BYTES);
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: bytes32(0),
            nonce: 1,
            keyVersion: 1,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });

        assertFalse(compact.verify(subPkSeed, subPkRoot, context, signature));
    }

    function testRotateFullShrincsKeyMessageHashBindsNextKeyBundle() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
        bytes memory nextPkSeed = bytes.concat(publicKey.pkSeed);
        nextPkSeed[0] = bytes1(uint8(nextPkSeed[0]) ^ 0x01);
        bytes memory nextHypertreeRoot = bytes.concat(publicKey.hypertreeRoot);
        nextHypertreeRoot[0] = bytes1(uint8(nextHypertreeRoot[0]) ^ 0x01);

        ShrincsTypes.RotationTarget memory target = rotationTargetFromParts(nextPkSeed, nextHypertreeRoot);
        bytes32 first = rotation.fullRotationMessageHash(compositePublicKeyWord(publicKey), publicKey, context, target);
        nextHypertreeRoot[0] = bytes1(uint8(nextHypertreeRoot[0]) ^ 0x01);
        target = rotationTargetFromParts(nextPkSeed, nextHypertreeRoot);
        bytes32 second = rotation.fullRotationMessageHash(compositePublicKeyWord(publicKey), publicKey, context, target);
        assertTrue(first != second, "full rotation hash must bind next key bundle");
    }

    function testRotateFullShrincsKeyRejectsLegacyVectorAuthorization() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
        ShrincsTypes.RotationTarget memory target = rotationTargetFromParts(publicKey.pkSeed, publicKey.hypertreeRoot);

        assertFalse(rotation.statelessRotate(compositePublicKeyWord(publicKey), publicKey, context, signature, target));
    }

    function testRotateFullShrincsKeyRejectsZeroDomainSeparator() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: bytes32(0), nonce: 11, keyVersion: 2});
        ShrincsTypes.RotationTarget memory target = rotationTargetFromParts(publicKey.pkSeed, publicKey.hypertreeRoot);

        assertFalse(rotation.statelessRotate(compositePublicKeyWord(publicKey), publicKey, context, signature, target));
    }

    function compositePublicKeyWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 word) {
        bytes memory pkSeed = publicKey.pkSeed;
        if (pkSeed.length != 32) return bytes32(0);
        assembly {
            word := mload(add(pkSeed, 32))
        }
    }

    function decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            ShrincsTypes.PublicKey memory decodedPublicKey,
            bytes memory legacyMessage,
            LegacyStatelessSignature memory legacySignature
        ) = abi.decode(args, (ShrincsTypes.PublicKey, bytes, LegacyStatelessSignature));

        publicKey = decodedPublicKey;
        message = legacyMessage;
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    function decodeCompactVector(string memory vectorKey)
        internal
        returns (bytes32 subPkSeed, bytes32 subPkRoot, bytes32 message, bytes memory signature)
    {
        bytes memory args = vectorArgs(vectorKey);
        (subPkSeed, subPkRoot, message, signature) = abi.decode(args, (bytes32, bytes32, bytes32, bytes));
    }

    function decodeCompactActionVector(string memory vectorKey)
        internal
        returns (
            bytes32 subPkSeed,
            bytes32 subPkRoot,
            ShrincsTypes.ActionContext memory context,
            bytes memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (subPkSeed, subPkRoot, context, signature) =
            abi.decode(args, (bytes32, bytes32, ShrincsTypes.ActionContext, bytes));
    }

    function convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (ShrincsTypes.StatelessSignature memory signature)
    {
        ShrincsTypes.ForsEntry[] memory entries = new ShrincsTypes.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = ShrincsTypes.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf, authPath: legacy.fors.entries[i].authPath
            });
        }

        ShrincsTypes.HypertreeLayerSignature[] memory layers =
            new ShrincsTypes.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = ShrincsTypes.HypertreeLayerSignature({
                treeIndex: legacy.hypertree[i].treeIndex,
                leafIndex: legacy.hypertree[i].leafIndex,
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: ShrincsTypes.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature.randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = ShrincsTypes.StatelessSignature({
            fors: ShrincsTypes.ForsSignature({
                randomizer: legacy.fors.randomizer, counter: legacy.fors.counter, entries: entries
            }),
            hypertree: layers
        });
    }

    function publicKeyFromParts(bytes memory pkSeed, bytes memory hypertreeRoot)
        internal
        pure
        returns (ShrincsTypes.PublicKey memory)
    {
        return ShrincsTypes.PublicKey({pkSeed: pkSeed, hypertreeRoot: hypertreeRoot});
    }

    function rotationTargetFromParts(bytes memory pkSeed, bytes memory hypertreeRoot)
        internal
        pure
        returns (ShrincsTypes.RotationTarget memory)
    {
        return ShrincsTypes.RotationTarget({pkSeed: pkSeed, hypertreeRoot: hypertreeRoot});
    }

    function dropLastBytes(bytes[] memory input) internal pure returns (bytes[] memory output) {
        output = new bytes[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function dropLastForsEntries(ShrincsTypes.ForsEntry[] memory input)
        internal
        pure
        returns (ShrincsTypes.ForsEntry[] memory output)
    {
        output = new ShrincsTypes.ForsEntry[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function vectorArgs(string memory vectorKey) internal returns (bytes memory) {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
    }

    function trimCalldataSuffix(string memory path) internal pure returns (string memory trimmed) {
        bytes memory source = bytes(path);
        bytes memory suffix = bytes(".calldata");
        require(source.length >= suffix.length, "path too short");
        uint256 trimmedLength = source.length - suffix.length;
        bytes memory out = new bytes(trimmedLength);
        for (uint256 i = 0; i < trimmedLength; ++i) {
            out[i] = source[i];
        }
        trimmed = string(out);
    }

    function stripSelector(bytes memory input) internal pure returns (bytes memory output) {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }

    function cloneBytes(bytes memory source) internal pure returns (bytes memory out) {
        out = new bytes(source.length);
        for (uint256 i = 0; i < source.length; ++i) {
            out[i] = source[i];
        }
    }

    function flipByte(bytes memory data, uint256 offset) internal pure {
        data[offset] = bytes1(uint8(data[offset]) ^ uint8(1));
    }

    function readCompactQ(bytes memory signature) internal pure returns (uint8) {
        return uint8(signature[COMPACT_Q_OFFSET]);
    }
}
