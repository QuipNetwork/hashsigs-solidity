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
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";

contract StatefulHarness {
    function verifyUnsafeRaw(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata publicKey,
        bytes calldata message,
        UXMSS.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCSCore.verifyStatefulUncheckedMessage(
            expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verify(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata publicKey,
        SHRINCSCore.ActionContext calldata context,
        UXMSS.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCSCore.verifyStateful(
            expectedCompositePublicKey, publicKey, context, signature
        );
    }

    function actionMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCSCore.statefulActionMessageHash(
            expectedCompositePublicKey, context
        );
    }
}

contract StatelessHarness {
    function verifyUnsafeRaw(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusCCore.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCSCore.verifyStatelessUncheckedMessage(
            expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verify(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata publicKey,
        SHRINCSCore.ActionContext calldata context,
        SPHINCSPlusCCore.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCSCore.verifyStateless(
            expectedCompositePublicKey, publicKey, context, signature
        );
    }

    function actionMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCSCore.statelessActionMessageHash(
            expectedCompositePublicKey, context
        );
    }
}

contract RotationHarness {
    function statefulRotationMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext calldata context,
        SHRINCSCore.StatefulRotationTarget calldata nextStatefulKey
    ) external pure returns (bytes32) {
        return SHRINCSCore.statefulRotationMessageHash(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            nextStatefulKey
        );
    }

    function fullRotationMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext calldata context,
        SHRINCSCore.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCSCore.fullRotationMessageHash(
            expectedCompositePublicKey, currentPublicKey, context, nextKey
        );
    }

    function rotateStatefulViaStateless(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext calldata context,
        SPHINCSPlusCCore.StatelessSignature calldata recoverySignature,
        SHRINCSCore.StatefulRotationTarget calldata nextStatefulKey
    ) external pure returns (bytes32) {
        return SHRINCSCore.rotateStatefulViaStateless(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextStatefulKey
        );
    }

    function statelessRotate(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext calldata context,
        SPHINCSPlusCCore.StatelessSignature calldata recoverySignature,
        SHRINCSCore.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCSCore.statelessRotate(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
    }
}

contract SHRINCSSphincs256sVectorsTest is Test {
    string internal constant VECTOR_PATH =
        "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    struct LegacyStatefulPublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    struct LegacyStatefulSignature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[64] chains;
        bytes32[] authPath;
    }

    struct LegacyPublicKey {
        bytes statefulPublicKey;
        bytes pkSeed;
        bytes hypertreeRoot;
    }

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

    StatefulHarness internal stateful;
    StatelessHarness internal stateless;
    RotationHarness internal rotation;
    string internal vectors;

    function setUp() public {
        stateful = new StatefulHarness();
        stateless = new StatelessHarness();
        rotation = new RotationHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testStatefulSphincs256sValidSignatureVerifies() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            true,
            "stateful valid"
        );
    }

    function testStatefulSphincs256sRejectsWrongMessage() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.wrongMessage.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful wrong message"
        );
    }

    function testStatefulSphincs256sRejectsWrongPublicKey() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.wrongPublicKey.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful wrong public key"
        );
    }

    function testStatefulSphincs256sRejectsWrongExpectedCompositePublicKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 wrongExpectedCompositePublicKey =
            compositePublicKeyWord(publicKey) ^ bytes32(uint256(1));
        assertEq(
            stateful.verifyUnsafeRaw(
                wrongExpectedCompositePublicKey,
                publicKey,
                message,
                signature
            ),
            false,
            "stateful wrong expected composite public key"
        );
    }

    function testStatefulSphincs256sRejectsMismatchedStatelessRoot() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 arbitraryCommitment =
            keccak256("arbitrary-stateful-commitment");
        publicKey.hypertreeRoot = abi.encodePacked(arbitraryCommitment);
        assertEq(
            stateful.verifyUnsafeRaw(
                arbitraryCommitment, publicKey, message, signature
            ),
            false,
            "stateful mismatched stateless root"
        );
    }

    function testStatefulSphincs256sRejectsZeroExpectedCompositePublicKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                bytes32(0), publicKey, message, signature
            ),
            false,
            "stateful zero expected composite public key"
        );
    }

    function testStatefulSphincs256sRejectsCorruptedSignature() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(
            ".stateful.cases.corruptedSignature.calldata"
        );
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful corrupted signature"
        );
    }

    function testStatefulSphincs256sRejectsTamperedAuthPath() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.authPath[0] = signature.authPath[0] ^ bytes32(uint256(1));
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful tampered auth path"
        );
    }

    function testStatefulSphincs256sAcceptsMaxSignaturesBoundary() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        setStatefulMaxSignatures(
            publicKey, uint32(signature.authPath.length)
        );
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            true,
            "stateful max signatures boundary"
        );
    }

    function testStatefulSphincs256sRejectsExceededMaxSignatures() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        setStatefulMaxSignatures(
            publicKey, uint32(signature.authPath.length - 1)
        );
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful exceeds max signatures"
        );
    }

    function testStatefulSphincs256sRejectsMalformedPkSeedLength() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        publicKey.pkSeed = hex"1234";
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful malformed pkSeed length"
        );
    }

    function testStatefulSphincs256sRejectsWrongWotsChainCount() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.chains = dropLastBytes32(signature.chains);
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful wrong WOTS chain count"
        );
    }

    function testStatefulSphincs256sRejectsEmptyAuthPath() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.authPath = new bytes32[](0);
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful empty auth path"
        );
    }

    function testStatefulSphincs256sRejectsMalformedStatefulPublicKeyLength()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        publicKey.statefulPublicKey = hex"1234";
        assertEq(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateful malformed stateful public key length"
        );
    }

    function testStatelessSphincs256sValidSignatureVerifies() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            true,
            "stateless valid"
        );
    }

    function testStatelessSphincs256sRejectsWrongMessage() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.wrongMessage.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless wrong message"
        );
    }

    function testStatelessSphincs256sRejectsTamperedFors() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.tamperedFors.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless tampered FORS"
        );
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeWotsPkHash()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(
            ".stateless.cases.tamperedHypertreeWotsPkHash.calldata"
        );
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless tampered wots pk hash"
        );
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeAuth() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(
            ".stateless.cases.tamperedHypertreeAuth.calldata"
        );
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless tampered auth"
        );
    }

    function testStatelessSphincs256sRejectsWrongExpectedCompositePublicKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 wrongExpectedCompositePublicKey =
            compositePublicKeyWord(publicKey) ^ bytes32(uint256(1));
        assertEq(
            stateless.verifyUnsafeRaw(
                wrongExpectedCompositePublicKey,
                publicKey,
                message,
                signature
            ),
            false,
            "stateless wrong expected composite public key"
        );
    }

    function testStatelessSphincs256sRejectsMismatchedPublicRoot() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 arbitraryCommitment =
            keccak256("arbitrary-stateless-commitment");
        publicKey.hypertreeRoot = abi.encodePacked(arbitraryCommitment);
        assertEq(
            stateless.verifyUnsafeRaw(
                arbitraryCommitment, publicKey, message, signature
            ),
            false,
            "stateless mismatched public root"
        );
    }

    function testStatelessSphincs256sRejectsZeroExpectedCompositePublicKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                bytes32(0), publicKey, message, signature
            ),
            false,
            "stateless zero expected composite public key"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testStatelessSphincs256sRejectsMalformedHypertreeRootAsPublicRootLength()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.hypertreeRoot = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                bytes32(0), publicKey, message, signature
            ),
            false,
            "stateless malformed hypertreeRoot length"
        );
    }

    function testStatelessSphincs256sRejectsMalformedPkSeedLength() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.pkSeed = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless malformed pkSeed length"
        );
    }

    function testStatelessSphincs256sRejectsMalformedHypertreeRootLength()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedPublicRoot = compositePublicKeyWord(publicKey);
        publicKey.hypertreeRoot = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                expectedPublicRoot, publicKey, message, signature
            ),
            false,
            "stateless malformed hypertreeRoot length"
        );
    }

    function testStatelessSphincs256sRejectsWrongPublicRootVector() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(
            ".stateless.cases.wrongPublicRoot.calldata"
        );
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless wrong composite public key vector"
        );
    }

    function testStatelessSphincs256sRejectsTamperedComponentPublicKeyVector()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(
            ".stateless.cases.tamperedComponentPublicKey.calldata"
        );
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless tampered component public key vector"
        );
    }

    function testStatelessSphincs256sRejectsEmptyHypertree() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree = new Hypertree.HypertreeLayerSignature[](0);
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless empty hypertree"
        );
    }

    function testStatelessSphincs256sRejectsDroppedHypertreeLayer() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        // forgefmt: disable-next-line
        Hypertree.HypertreeLayerSignature[] memory shortened =
            new Hypertree
                .HypertreeLayerSignature[](signature.hypertree.length - 1);
        for (uint256 i = 0; i < shortened.length; ++i) {
            shortened[i] = signature.hypertree[i];
        }
        signature.hypertree = shortened;
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless dropped hypertree layer"
        );
    }

    function testStatelessSphincs256sRejectsDroppedForsEntry() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries = dropLastForsEntries(signature.fors.entries);
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless dropped FORS entry"
        );
    }

    function testStatelessSphincs256sRejectsShortForsRandomizer() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.randomizer = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless short FORS randomizer"
        );
    }

    function testStatelessSphincs256sRejectsShortForsSecretLeaf() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].secretLeaf = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless short FORS secret leaf"
        );
    }

    function testStatelessSphincs256sRejectsTruncatedForsAuthPath() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath =
            dropLastBytes(signature.fors.entries[0].authPath);
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless truncated FORS auth path"
        );
    }

    function testStatelessSphincs256sRejectsShortForsAuthNode() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath[0] = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless short FORS auth node"
        );
    }

    function testStatelessSphincs256sRejectsHypertreeLeafIndexOutOfRange()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].leafIndex = 256;
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless hypertree leaf index out of range"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testStatelessSphincs256sRejectsMalformedHypertreeWotsChainLength()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].wotsCSignature.chains[0] = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless malformed hypertree WOTS chain length"
        );
    }

    function testStatelessSphincs256sRejectsWrongHypertreeAuthPathLength()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath =
            dropLastBytes(signature.hypertree[0].authPath);
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless wrong hypertree auth path length"
        );
    }

    function testStatefulActionMessageHashBindsContext() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSCore.ActionContext memory first = SHRINCSCore.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 1,
            keyVersion: 3,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload-a")
        });
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory second =
            SHRINCSCore.ActionContext({
                domainSeparator: first.domainSeparator,
                nonce: first.nonce,
                keyVersion: first.keyVersion,
                actionType: first.actionType,
                payloadHash: keccak256("payload-b")
            });

        assertTrue(
            stateful.actionMessageHash(expectedCompositePublicKey, first)
                != stateful.actionMessageHash(
                    expectedCompositePublicKey, second
                ),
            "stateful action hash must bind payload"
        );
    }

    function testStatefulVerifyRejectsZeroDomainSeparator() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory context =
            SHRINCSCore.ActionContext({
                domainSeparator: bytes32(0),
                nonce: 1,
                keyVersion: 1,
                actionType: keccak256("execute"),
                payloadHash: keccak256("payload")
            });
        message;
        assertEq(
            stateful.verify(
                expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateful zero domain separator"
        );
    }

    function testStatefulVerifyRejectsZeroActionType() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory context =
            SHRINCSCore.ActionContext({
                domainSeparator: keccak256("shrincs-account"),
                nonce: 1,
                keyVersion: 1,
                actionType: bytes32(0),
                payloadHash: keccak256("payload")
            });
        assertEq(
            stateful.verify(
                expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateful zero action type"
        );
    }

    function testStatefulVerifyRejectsZeroPayloadHash() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory context =
            SHRINCSCore.ActionContext({
                domainSeparator: keccak256("shrincs-account"),
                nonce: 1,
                keyVersion: 1,
                actionType: keccak256("execute"),
                payloadHash: bytes32(0)
            });
        assertEq(
            stateful.verify(
                expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateful zero payload hash"
        );
    }

    function testStatelessActionMessageHashBindsContext() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSCore.ActionContext memory first = SHRINCSCore.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 9,
            keyVersion: 4,
            actionType: keccak256("rotate"),
            payloadHash: keccak256("payload")
        });
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory second =
            SHRINCSCore.ActionContext({
                domainSeparator: first.domainSeparator,
                nonce: 10,
                keyVersion: first.keyVersion,
                actionType: first.actionType,
                payloadHash: first.payloadHash
            });

        assertTrue(
            stateless.actionMessageHash(expectedCompositePublicKey, first)
                != stateless.actionMessageHash(
                    expectedCompositePublicKey, second
                ),
            "stateless action hash must bind nonce"
        );
    }

    function testStatelessVerifyRejectsZeroDomainSeparator() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory context =
            SHRINCSCore.ActionContext({
                domainSeparator: bytes32(0),
                nonce: 1,
                keyVersion: 1,
                actionType: keccak256("execute"),
                payloadHash: keccak256("payload")
            });
        assertEq(
            stateless.verify(
                expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateless zero domain separator"
        );
    }

    function testStatelessVerifyRejectsZeroActionType() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory context =
            SHRINCSCore.ActionContext({
                domainSeparator: keccak256("shrincs-account"),
                nonce: 1,
                keyVersion: 1,
                actionType: bytes32(0),
                payloadHash: keccak256("payload")
            });
        assertEq(
            stateless.verify(
                expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateless zero action type"
        );
    }

    function testStatelessVerifyRejectsZeroPayloadHash() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSCore.ActionContext memory context =
            SHRINCSCore.ActionContext({
                domainSeparator: keccak256("shrincs-account"),
                nonce: 1,
                keyVersion: 1,
                actionType: keccak256("execute"),
                payloadHash: bytes32(0)
            });
        assertEq(
            stateless.verify(
                expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateless zero payload hash"
        );
    }

    function testRotateStatefulViaStatelessMessageHashBindsNextStatefulKey()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 7,
                keyVersion: 1
            });
        bytes memory nextStatefulPublicKey =
            bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[0] =
            bytes1(uint8(nextStatefulPublicKey[0]) ^ 0x01);
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(publicKey, nextStatefulPublicKey);
        bytes32 first = rotation.statefulRotationMessageHash(
            compositePublicKeyWord(publicKey), publicKey, context, target
        );
        nextStatefulPublicKey[1] =
            bytes1(uint8(nextStatefulPublicKey[1]) ^ 0x01);
        target = statefulRotationTargetFromParts(
            publicKey, nextStatefulPublicKey
        );
        bytes32 second = rotation.statefulRotationMessageHash(
            compositePublicKeyWord(publicKey), publicKey, context, target
        );
        assertTrue(
            first != second,
            "stateful rotation hash must bind next stateful key"
        );
    }

    function testRotateStatefulViaStatelessRejectsLegacyVectorAuthorization()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 7,
                keyVersion: 1
            });
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );

        bytes32 result = rotation.rotateStatefulViaStateless(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsMalformedNextStatefulKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 7,
                keyVersion: 1
            });
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(publicKey, hex"1234");

        bytes32 result = rotation.rotateStatefulViaStateless(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsZeroDomainSeparator()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: bytes32(0), nonce: 7, keyVersion: 1
            });
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );

        bytes32 result = rotation.rotateStatefulViaStateless(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    // line-length: allow — test name is one unbreakable token
    function testRotateStatefulViaStatelessRejectsZeroMaxSignaturesNextStatefulKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 7,
                keyVersion: 1
            });
        bytes memory nextStatefulPublicKey =
            bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[64] = bytes1(0);
        nextStatefulPublicKey[65] = bytes1(0);
        nextStatefulPublicKey[66] = bytes1(0);
        nextStatefulPublicKey[67] = bytes1(0);
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(publicKey, nextStatefulPublicKey);

        bytes32 result = rotation.rotateStatefulViaStateless(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullSHRINCSKeyMessageHashBindsNextKeyBundle() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 11,
                keyVersion: 2
            });
        bytes memory nextStatefulPublicKey =
            bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[0] =
            bytes1(uint8(nextStatefulPublicKey[0]) ^ 0x01);
        bytes memory nextPkSeed = bytes.concat(publicKey.pkSeed);
        nextPkSeed[0] = bytes1(uint8(nextPkSeed[0]) ^ 0x01);
        bytes memory nextHypertreeRoot =
            bytes.concat(publicKey.hypertreeRoot);
        nextHypertreeRoot[0] = bytes1(uint8(nextHypertreeRoot[0]) ^ 0x01);

        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            nextStatefulPublicKey, nextPkSeed, nextHypertreeRoot
        );
        bytes32 first = rotation.fullRotationMessageHash(
            compositePublicKeyWord(publicKey), publicKey, context, target
        );
        nextHypertreeRoot[0] = bytes1(uint8(nextHypertreeRoot[0]) ^ 0x01);
        target = rotationTargetFromParts(
            nextStatefulPublicKey, nextPkSeed, nextHypertreeRoot
        );
        bytes32 second = rotation.fullRotationMessageHash(
            compositePublicKeyWord(publicKey), publicKey, context, target
        );
        assertTrue(
            first != second, "full rotation hash must bind next key bundle"
        );
    }

    function testRotateFullSHRINCSKeyRejectsLegacyVectorAuthorization()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 11,
                keyVersion: 2
            });
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );

        bytes32 result = rotation.statelessRotate(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullSHRINCSKeyRejectsMismatchedCompositeCommitment()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 11,
                keyVersion: 2
            });
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );

        bytes32 result = rotation.statelessRotate(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullSHRINCSKeyRejectsZeroDomainSeparator() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: bytes32(0), nonce: 11, keyVersion: 2
            });
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );

        bytes32 result = rotation.statelessRotate(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullSHRINCSKeyRejectsZeroMaxSignaturesNextStatefulKey()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: keccak256("shrincs-test"),
                nonce: 11,
                keyVersion: 2
            });
        bytes memory nextStatefulPublicKey =
            bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[64] = bytes1(0);
        nextStatefulPublicKey[65] = bytes1(0);
        nextStatefulPublicKey[66] = bytes1(0);
        nextStatefulPublicKey[67] = bytes1(0);
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            nextStatefulPublicKey, publicKey.pkSeed, publicKey.hypertreeRoot
        );

        bytes32 result = rotation.statelessRotate(
            compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function compositePublicKeyWord(SHRINCSCore.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 word)
    {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    function decodeStatefulVector(string memory vectorKey)
        internal
        returns (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            LegacyStatefulPublicKey memory legacyKey,
            bytes memory legacyMessage,
            LegacyStatefulSignature memory legacySignature
        ) = abi.decode(
            args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature)
        );

        (SHRINCSCore.PublicKey memory statelessPublicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        bytes memory encodedStatefulKey = abi.encodePacked(
            legacyKey.pkSeed, legacyKey.root, bytes4(legacyKey.maxSignatures)
        );

        publicKey = publicKeyFromParts(
            encodedStatefulKey,
            statelessPublicKey.pkSeed,
            statelessPublicKey.hypertreeRoot
        );

        message = legacyMessage;
        signature = UXMSS.StatefulSignature({
            randomizer: legacySignature.randomizer,
            counter: legacySignature.counter,
            chains: fixedToDynamicChains(legacySignature.chains),
            authPath: legacySignature.authPath
        });
    }

    function decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusCCore.StatelessSignature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            LegacyPublicKey memory legacyPublicKey,
            bytes memory legacyMessage,
            LegacyStatelessSignature memory legacySignature
        ) = abi.decode(
            args, (LegacyPublicKey, bytes, LegacyStatelessSignature)
        );

        publicKey = publicKeyFromParts(
            legacyPublicKey.statefulPublicKey,
            legacyPublicKey.pkSeed,
            legacyPublicKey.hypertreeRoot
        );
        bytes memory encodedCommitment = vm.parseJsonBytes(
            vectors,
            string.concat(
                trimCalldataSuffix(vectorKey),
                ".publicKey.publicKeyCommitment"
            )
        );
        publicKey.publicKeyCommitment = encodedCommitment;

        message = legacyMessage;
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    // line-length: allow — fmt canonical header exceeds cap
    function convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (SPHINCSPlusCCore.StatelessSignature memory signature)
    {
        FORSMinusC.ForsEntry[] memory entries =
            new FORSMinusC.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = FORSMinusC.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf,
                authPath: legacy.fors.entries[i].authPath
            });
        }

        // forgefmt: disable-next-line
        Hypertree.HypertreeLayerSignature[] memory layers =
            new Hypertree.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = Hypertree.HypertreeLayerSignature({
                treeIndex: legacy.hypertree[i].treeIndex,
                leafIndex: legacy.hypertree[i].leafIndex,
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: WOTSPlusC.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature
                    .randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = SPHINCSPlusCCore.StatelessSignature({
            fors: FORSMinusC.ForsSignature({
                randomizer: legacy.fors.randomizer,
                counter: legacy.fors.counter,
                entries: entries
            }),
            hypertree: layers
        });
    }

    function fixedToDynamicChains(bytes32[64] memory fixedChains)
        internal
        pure
        returns (bytes32[] memory chains)
    {
        chains = new bytes32[](64);
        for (uint256 i = 0; i < 64; ++i) {
            chains[i] = fixedChains[i];
        }
    }

    function setStatefulMaxSignatures(
        SHRINCSCore.PublicKey memory publicKey,
        uint32 maxSignatures
    ) internal pure {
        // casting to 'uint8' is safe because each assigned byte extracts only
        // one 8-bit lane from maxSignatures
        // forge-lint: disable-next-line(unsafe-typecast)
        publicKey.statefulPublicKey[64] = bytes1(uint8(maxSignatures >> 24));
        // casting to 'uint8' is safe because each assigned byte extracts only
        // one 8-bit lane from maxSignatures
        // forge-lint: disable-next-line(unsafe-typecast)
        publicKey.statefulPublicKey[65] = bytes1(uint8(maxSignatures >> 16));
        // casting to 'uint8' is safe because each assigned byte extracts only
        // one 8-bit lane from maxSignatures
        // forge-lint: disable-next-line(unsafe-typecast)
        publicKey.statefulPublicKey[66] = bytes1(uint8(maxSignatures >> 8));
        // casting to 'uint8' is safe because each assigned byte extracts only
        // the low 8 bits from maxSignatures
        // forge-lint: disable-next-line(unsafe-typecast)
        publicKey.statefulPublicKey[67] = bytes1(uint8(maxSignatures));
        publicKey.publicKeyCommitment =
            abi.encodePacked(compositePublicKeyWord(publicKey));
    }

    function publicKeyFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (SHRINCSCore.PublicKey memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return SHRINCSCore.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment),
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
    }

    function statefulRotationTargetFromParts(
        SHRINCSCore.PublicKey memory currentPublicKey,
        bytes memory statefulPublicKey
    ) internal pure returns (SHRINCSCore.StatefulRotationTarget memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                statefulPublicKey,
                currentPublicKey.pkSeed,
                currentPublicKey.hypertreeRoot
            )
        );
        return SHRINCSCore.StatefulRotationTarget({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment)
        });
    }

    function rotationTargetFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (SHRINCSCore.RotationTarget memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return SHRINCSCore.RotationTarget({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment),
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
    }

    function dropLastBytes32(bytes32[] memory input)
        internal
        pure
        returns (bytes32[] memory output)
    {
        output = new bytes32[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function dropLastBytes(bytes[] memory input)
        internal
        pure
        returns (bytes[] memory output)
    {
        output = new bytes[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function trimCalldataSuffix(string memory path)
        internal
        pure
        returns (string memory trimmed)
    {
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

    function dropLastForsEntries(FORSMinusC.ForsEntry[] memory input)
        internal
        pure
        returns (FORSMinusC.ForsEntry[] memory output)
    {
        output = new FORSMinusC.ForsEntry[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function vectorArgs(string memory vectorKey)
        internal
        returns (bytes memory)
    {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
    }

    function stripSelector(bytes memory input)
        internal
        pure
        returns (bytes memory output)
    {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }
}
