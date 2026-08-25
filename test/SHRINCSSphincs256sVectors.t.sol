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
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSStatelessVectorSigningFacade
} from "./helpers/SHRINCSStatelessVectorSigningFacade.sol";

contract StatefulHarness {
    function verifyUnsafeRaw(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SHRINCS.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatefulUncheckedMessage(
            expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verify(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.ActionContext calldata context,
        SHRINCS.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStateful(
            expectedCompositePublicKey, publicKey, context, signature
        );
    }

    function actionMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCS.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCS.statefulActionMessageHash(
            expectedCompositePublicKey, context
        );
    }
}

contract StatelessHarness {
    function verifyUnsafeRaw(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verify(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.ActionContext calldata context,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStateless(
            expectedCompositePublicKey, publicKey, context, signature
        );
    }

    function actionMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCS.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCS.statelessActionMessageHash(
            expectedCompositePublicKey, context
        );
    }
}

contract RotationHarness {
    function statefulRotationMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext calldata context,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external pure returns (bytes32) {
        return SHRINCS.statefulRotationMessageHash(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            nextStatefulKey
        );
    }

    function fullRotationMessageHash(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext calldata context,
        SHRINCS.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.fullRotationMessageHash(
            expectedCompositePublicKey, currentPublicKey, context, nextKey
        );
    }

    function rotateStatefulViaStateless(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext calldata context,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external view returns (bytes32) {
        return SHRINCS.rotateStatefulViaStateless(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextStatefulKey
        );
    }

    function statelessRotate(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext calldata context,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey
    ) external view returns (bytes32) {
        return SHRINCS.statelessRotate(
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

    // Single in-Solidity signing baseline shared by every context-verify and
    // rotation positive control below. Keygen is heavy, so it runs exactly
    // once here (a second keygen in the same call frame hits MemoryLimitOOG);
    // each expensive stateless signature is then produced in its own test
    // call frame from this cached key. This is the real signer the vacuous
    // "Rejects..." cluster was missing: it signs the exact context-derived
    // message hash the entrypoints recompute, so a valid signature exists and
    // only the guard under test can reject it.
    SHRINCSStatelessVectorSigner internal statelessSigner;
    SHRINCS.SigningKey internal baseSigningKey;
    SHRINCS.PublicKey internal basePublicKey;
    bytes32 internal baseCommitment;

    function setUp() public {
        stateful = new StatefulHarness();
        stateless = new StatelessHarness();
        rotation = new RotationHarness();
        vectors = vm.readFile(VECTOR_PATH);

        statelessSigner = new SHRINCSStatelessVectorSigner();
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(
            bytes("shrincs-256s-vectors positive-control baseline"), 4
        );
        require(keygenOk, "baseline keygen must succeed");
        baseSigningKey = signingKey;
        basePublicKey = publicKey;
        baseCommitment = readWord(publicKey.publicKeyCommitment);
    }

    function testStatefulSphincs256sValidSignatureVerifies() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.chains = dropLastBytes32(signature.chains);
        // Post guard-pruning a short chains array reverts (Panic) at the
        // fixed WOTS loop read instead of returning false; both are
        // fail-closed. A plain revert expectation (no selector) suffices.
        vm.expectRevert();
        stateful.verifyUnsafeRaw(
            compositePublicKeyWord(publicKey), publicKey, message, signature
        );
    }

    function testStatefulSphincs256sRejectsEmptyAuthPath() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree = new Hypertree.HypertreeLayerSignature[](0);
        // T6: the layer coordinates are no longer read from hypertree[0]
        // before verifyHypertree, so an empty hypertree no longer Panics
        // there; it is rejected by the layers.length == d guard, returning
        // false. Fail-closed either way, never a wrong-accept.
        assertEq(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            false,
            "stateless empty hypertree must be rejected"
        );
    }

    // T6 negative pin (commitment profile binding). A bundle presenting the
    // PRE-T6 unbound commitment tag ("shrincs-public-key" without the
    // "/<profile>" suffix) must be rejected: the verifier recomputes the
    // commitment with the profile-bound tag, so pre-T6 (and cross-profile)
    // commitment material can never satisfy the installed-commitment check.
    function testStatelessSphincs256sRejectsPreT6UnboundCommitment() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        // Pre-T6 commitment: no "/<profile>" suffix.
        bytes32 unbound = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
        // The binding must actually change the commitment value.
        assertTrue(
            unbound != compositePublicKeyWord(publicKey),
            "profile binding must change the commitment"
        );
        // Present the pre-T6 commitment as both the embedded field and the
        // installed expectation; the profile-bound recompute rejects it.
        publicKey.publicKeyCommitment = abi.encodePacked(unbound);
        assertEq(
            stateless.verifyUnsafeRaw(
                unbound, publicKey, message, signature
            ),
            false,
            "pre-T6 unbound commitment must be rejected"
        );
    }

    function testStatelessSphincs256sRejectsDroppedHypertreeLayer() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries = dropLastForsEntries(signature.fors.entries);
        // Post guard-pruning a short FORS entries array reverts (Panic) at
        // the fixed k-1 loop read instead of returning false; both are
        // fail-closed.
        vm.expectRevert();
        stateless.verifyUnsafeRaw(
            compositePublicKeyWord(publicKey), publicKey, message, signature
        );
    }

    function testStatelessSphincs256sRejectsShortForsRandomizer() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath =
            dropLastBytes(signature.fors.entries[0].authPath);
        // Post guard-pruning a truncated FORS auth path reverts (Panic) at
        // the per-level read instead of returning false; both are
        // fail-closed.
        vm.expectRevert();
        stateless.verifyUnsafeRaw(
            compositePublicKeyWord(publicKey), publicKey, message, signature
        );
    }

    function testStatelessSphincs256sRejectsShortForsAuthNode() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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

    // (T6) The former "hypertree leaf index out of range" tamper test was
    // removed: layer coordinates are no longer carried in the signature, so
    // there is no carried leaf index to push out of range. The layer-0
    // coordinate is derived from the FORS digest (read as exactly
    // subtreeHeight bits, always < leaf_count) and upper layers by the
    // shift/mask recurrence, so an out-of-range coordinate cannot be
    // expressed. See the coordinate-derivation binding on Hypertree.

    // line-length: allow — test name is one unbreakable token
    function testStatelessSphincs256sRejectsMalformedHypertreeWotsChainLength()
        public
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath =
            dropLastBytes(signature.hypertree[0].authPath);
        // Issue 05 makes the helper contract explicit: malformed path
        // lengths return false instead of reaching an out-of-bounds Panic.
        assertFalse(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            )
        );
    }

    function testStatefulActionMessageHashBindsContext() public {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCS.ActionContext memory first = SHRINCS.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 1,
            keyVersion: 3,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload-a")
        });
        // forgefmt: disable-next-line
        SHRINCS.ActionContext memory second =
            SHRINCS.ActionContext({
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

    // Positive control for the stateful context-verify accept path. The
    // in-Solidity signer signs the exact hash verifyStateful recomputes, so a
    // well-formed action context verifies. Every stateful "Rejects..." case
    // below is a single-field flip away from this accepting baseline.
    function testStatefulVerifyAcceptsSignedActionContext() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        SHRINCS.Signature memory signature = signStatefulContext(context);
        assertTrue(
            stateful.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "signed stateful action context must verify"
        );
    }

    // Non-vacuous: the signature is valid over the zero-domain-separator
    // hash, so only validActionContext's domain-separator guard rejects it.
    // Delete that guard and verifyStateful accepts, failing this assertion.
    function testStatefulVerifyRejectsZeroDomainSeparator() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        context.domainSeparator = bytes32(0);
        SHRINCS.Signature memory signature = signStatefulContext(context);
        assertFalse(
            stateful.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "zero domain separator rejected despite valid signature"
        );
    }

    // Non-vacuous: valid signature over the zero-action-type hash; only the
    // action-type guard rejects it.
    function testStatefulVerifyRejectsZeroActionType() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        context.actionType = bytes32(0);
        SHRINCS.Signature memory signature = signStatefulContext(context);
        assertFalse(
            stateful.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "zero action type rejected despite valid signature"
        );
    }

    // Non-vacuous: valid signature over the zero-payload-hash hash; only the
    // payload-hash guard rejects it.
    function testStatefulVerifyRejectsZeroPayloadHash() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        context.payloadHash = bytes32(0);
        SHRINCS.Signature memory signature = signStatefulContext(context);
        assertFalse(
            stateful.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "zero payload hash rejected despite valid signature"
        );
    }

    function testStatelessActionMessageHashBindsContext() public {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCS.ActionContext memory first = SHRINCS.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 9,
            keyVersion: 4,
            actionType: keccak256("rotate"),
            payloadHash: keccak256("payload")
        });
        // forgefmt: disable-next-line
        SHRINCS.ActionContext memory second =
            SHRINCS.ActionContext({
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

    // Positive control for the stateless context-verify accept path. The
    // staged in-Solidity stateless signer signs the exact hash
    // verifyStateless recomputes, so a well-formed action context verifies.
    function testStatelessVerifyAcceptsSignedActionContext() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        SPHINCSPlusC.Signature memory signature =
            signStatelessContext(context);
        assertTrue(
            stateless.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "signed stateless action context must verify"
        );
    }

    // Non-vacuous: valid stateless signature over the zero-domain-separator
    // hash; only validActionContext's domain-separator guard rejects it.
    function testStatelessVerifyRejectsZeroDomainSeparator() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        context.domainSeparator = bytes32(0);
        SPHINCSPlusC.Signature memory signature =
            signStatelessContext(context);
        assertFalse(
            stateless.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "zero domain separator rejected despite valid signature"
        );
    }

    // Non-vacuous: valid stateless signature over the zero-action-type hash;
    // only the action-type guard rejects it.
    function testStatelessVerifyRejectsZeroActionType() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        context.actionType = bytes32(0);
        SPHINCSPlusC.Signature memory signature =
            signStatelessContext(context);
        assertFalse(
            stateless.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "zero action type rejected despite valid signature"
        );
    }

    // Non-vacuous: valid stateless signature over the zero-payload-hash hash;
    // only the payload-hash guard rejects it.
    function testStatelessVerifyRejectsZeroPayloadHash() public {
        SHRINCS.ActionContext memory context = acceptingActionContext();
        context.payloadHash = bytes32(0);
        SPHINCSPlusC.Signature memory signature =
            signStatelessContext(context);
        assertFalse(
            stateless.verify(
                baseCommitment, loadPublicKey(), context, signature
            ),
            "zero payload hash rejected despite valid signature"
        );
    }

    function testRotateStatefulViaStatelessMessageHashBindsNextStatefulKey()
        public
    {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCS.RotationContext memory context = SHRINCS.RotationContext({
            domainSeparator: keccak256("shrincs-test"),
            nonce: 7,
            keyVersion: 1
        });
        bytes memory nextStatefulPublicKey =
            bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[0] =
            bytes1(uint8(nextStatefulPublicKey[0]) ^ 0x01);
        SHRINCS.StatefulRotationTarget memory target =
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

    // Positive control for the stateful-subkey rotation accept path, with a
    // folded replay negative. A stateless recovery signature over the exact
    // statefulRotationMessageHash authorizes the rotation and returns the
    // next installed commitment; the SAME signature applied to a different
    // rotation context (bumped nonce) no longer authorizes it, exercising the
    // recovery signature-binding non-vacuously (delete that verify and the
    // replay succeeds).
    function testRotateStatefulViaStatelessAcceptsSignedRotation() public {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        SHRINCS.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );
        bytes32 hash = rotation.statefulRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.rotateStatefulViaStateless(
                baseCommitment, publicKey, context, recovery, target
            ),
            readWord(target.publicKeyCommitment),
            "valid stateful rotation must install the next commitment"
        );

        context.nonce += 1;
        assertEq(
            rotation.rotateStatefulViaStateless(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "recovery signature must not authorize a different rotation"
        );
    }

    // Non-vacuous: valid recovery signature over the zero-domain-separator
    // rotation hash; only validRotationContext rejects it.
    function testRotateStatefulViaStatelessRejectsZeroDomainSeparator()
        public
    {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        context.domainSeparator = bytes32(0);
        SHRINCS.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );
        bytes32 hash = rotation.statefulRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.rotateStatefulViaStateless(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "zero rotation domain separator rejected despite valid recovery"
        );
    }

    // Non-vacuous: the next stateful key is well-formed but carries
    // maxSignatures == 0, and the recovery signature is valid over its
    // rotation hash. Only the zero-budget guard rejects it; delete that guard
    // and the rotation installs an unusable key.
    // line-length: allow — test name is one unbreakable token
    function testRotateStatefulViaStatelessRejectsZeroMaxSignaturesNextStatefulKey()
        public
    {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        bytes memory nextStatefulPublicKey =
            zeroMaxSignatures(publicKey.statefulPublicKey);
        SHRINCS.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(publicKey, nextStatefulPublicKey);
        bytes32 hash = rotation.statefulRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.rotateStatefulViaStateless(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "zero-budget next stateful key rejected despite valid recovery"
        );
    }

    // Defense-in-depth pin (not a single-guard witness): a malformed next
    // stateful key is rejected by the fixed-width length guard before the
    // recovery signature is examined, so an empty recovery suffices. The
    // decode guard also rejects it, so no single guard removal flips this
    // assertion; the accept-path binding is proven by the positive control.
    function testRotateStatefulViaStatelessRejectsMalformedNextStatefulKey()
        public
    {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        SHRINCS.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(publicKey, hex"1234");
        SPHINCSPlusC.Signature memory emptyRecovery;

        assertEq(
            rotation.rotateStatefulViaStateless(
                baseCommitment, publicKey, context, emptyRecovery, target
            ),
            bytes32(0),
            "malformed next stateful key must be rejected"
        );
    }

    function testRotateFullSHRINCSKeyMessageHashBindsNextKeyBundle() public {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        SHRINCS.RotationContext memory context = SHRINCS.RotationContext({
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

        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
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

    // Positive control for the full-bundle rotation accept path, with a
    // folded replay negative. A stateless recovery signature over the exact
    // fullRotationMessageHash authorizes the rotation; the same signature
    // does not authorize a rotation under a bumped nonce.
    function testRotateFullSHRINCSKeyAcceptsSignedRotation() public {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );
        bytes32 hash = rotation.fullRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.statelessRotate(
                baseCommitment, publicKey, context, recovery, target
            ),
            readWord(target.publicKeyCommitment),
            "valid full rotation must install the next commitment"
        );

        context.nonce += 1;
        assertEq(
            rotation.statelessRotate(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "recovery signature must not authorize a different rotation"
        );
    }

    // Non-vacuous: valid recovery signature over the zero-domain-separator
    // full-rotation hash; only validRotationContext rejects it.
    function testRotateFullSHRINCSKeyRejectsZeroDomainSeparator() public {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        context.domainSeparator = bytes32(0);
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );
        bytes32 hash = rotation.fullRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.statelessRotate(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "zero rotation domain separator rejected despite valid recovery"
        );
    }

    // Non-vacuous: the next bundle's stateful key carries maxSignatures == 0,
    // and the recovery signature is valid over its rotation hash. Only the
    // zero-budget guard rejects it.
    // line-length: allow — test name is one unbreakable token
    function testRotateFullSHRINCSKeyRejectsZeroMaxSignaturesNextStatefulKey()
        public
    {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        bytes memory nextStatefulPublicKey =
            zeroMaxSignatures(publicKey.statefulPublicKey);
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
            nextStatefulPublicKey, publicKey.pkSeed, publicKey.hypertreeRoot
        );
        bytes32 hash = rotation.fullRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.statelessRotate(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "zero-budget next stateful key rejected despite valid recovery"
        );
    }

    // Non-vacuous: the recovery signature is valid over a rotation hash that
    // binds the DECLARED next commitment, but that commitment does not match
    // the recomputed commitment of the declared next-key parts. Only the
    // commitment-consistency guard rejects it; delete that guard and the
    // rotation installs a bundle whose commitment lies about its contents.
    function testRotateFullSHRINCSKeyRejectsMismatchedCompositeCommitment()
        public
    {
        SHRINCS.PublicKey memory publicKey = loadPublicKey();
        SHRINCS.RotationContext memory context = acceptingRotationContext();
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );
        // Declare a commitment that does not match the recomputed parts.
        target.publicKeyCommitment =
            abi.encodePacked(keccak256("mismatched-next-commitment"));
        bytes32 hash = rotation.fullRotationMessageHash(
            baseCommitment, publicKey, context, target
        );
        SPHINCSPlusC.Signature memory recovery = signStatelessMessage(hash);

        assertEq(
            rotation.statelessRotate(
                baseCommitment, publicKey, context, recovery, target
            ),
            bytes32(0),
            "mismatched next commitment rejected despite valid recovery"
        );
    }

    // ---- positive-control signing helpers ------------------------------

    function loadPublicKey()
        internal
        view
        returns (SHRINCS.PublicKey memory)
    {
        return basePublicKey;
    }

    function acceptingActionContext()
        internal
        pure
        returns (SHRINCS.ActionContext memory)
    {
        return SHRINCS.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 1,
            keyVersion: 1,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });
    }

    function acceptingRotationContext()
        internal
        pure
        returns (SHRINCS.RotationContext memory)
    {
        return SHRINCS.RotationContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 7,
            keyVersion: 1
        });
    }

    function signStatefulContext(SHRINCS.ActionContext memory context)
        internal
        view
        returns (SHRINCS.Signature memory signature)
    {
        bytes memory message = abi.encodePacked(
            SHRINCS.statefulActionMessageHash(baseCommitment, context)
        );
        bool ok;
        (signature, ok) = SHRINCSTestSigner.signStatefulRawAtLeaf(
            baseSigningKey, 1, message
        );
        require(ok, "stateful signing must succeed");
    }

    function signStatelessContext(SHRINCS.ActionContext memory context)
        internal
        returns (SPHINCSPlusC.Signature memory)
    {
        return signStatelessMessage(
            SHRINCS.statelessActionMessageHash(baseCommitment, context)
        );
    }

    function signStatelessMessage(bytes32 messageHash)
        internal
        returns (SPHINCSPlusC.Signature memory signature)
    {
        (bytes32 sessionId, bool beginOk) = statelessSigner.beginSession(
            baseSigningKey, basePublicKey, abi.encodePacked(messageHash)
        );
        require(beginOk, "stateless session begin must succeed");
        bool completeOk;
        (, signature, completeOk) =
            SHRINCSStatelessVectorSigningFacade.completeSession(
                statelessSigner, sessionId
            );
        require(completeOk, "stateless signing must succeed");
    }

    function zeroMaxSignatures(bytes memory statefulPublicKey)
        internal
        pure
        returns (bytes memory nextStatefulPublicKey)
    {
        nextStatefulPublicKey = bytes.concat(statefulPublicKey);
        nextStatefulPublicKey[64] = bytes1(0);
        nextStatefulPublicKey[65] = bytes1(0);
        nextStatefulPublicKey[66] = bytes1(0);
        nextStatefulPublicKey[67] = bytes1(0);
    }

    function readWord(bytes memory data)
        internal
        pure
        returns (bytes32 word)
    {
        // Reads the first 32-byte word of a >=32-byte buffer (commitment).
        assembly {
            word := mload(add(data, 32))
        }
    }

    function compositePublicKeyWord(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 word)
    {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    function decodeStatefulVector(string memory vectorKey)
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
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

        (SHRINCS.PublicKey memory statelessPublicKey,,) =
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
        signature = SHRINCS.Signature({
            randomizer: legacySignature.randomizer,
            counter: legacySignature.counter,
            chains: fixedToDynamicChains(legacySignature.chains),
            authPath: legacySignature.authPath
        });
    }

    function decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
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
        returns (SPHINCSPlusC.Signature memory signature)
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

        signature = SPHINCSPlusC.Signature({
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
        SHRINCS.PublicKey memory publicKey,
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
    ) internal pure returns (SHRINCS.PublicKey memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return SHRINCS.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment),
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
    }

    function statefulRotationTargetFromParts(
        SHRINCS.PublicKey memory currentPublicKey,
        bytes memory statefulPublicKey
    ) internal pure returns (SHRINCS.StatefulRotationTarget memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                statefulPublicKey,
                currentPublicKey.pkSeed,
                currentPublicKey.hypertreeRoot
            )
        );
        return SHRINCS.StatefulRotationTarget({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment)
        });
    }

    function rotationTargetFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (SHRINCS.RotationTarget memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return SHRINCS.RotationTarget({
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
