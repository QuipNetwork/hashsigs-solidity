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
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";

contract ExampleStatefulHarness {
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
}

contract ExampleStatelessHarness {
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
}

contract ExampleRotationHarness {
    function rotateStatefulViaStateless(
        bytes32 expectedCompositePublicKey,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext calldata context,
        SPHINCSPlusCCore.StatelessSignature calldata recoverySignature,
        SHRINCSCore.StatefulRotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCSCore.rotateStatefulViaStateless(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
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

contract ShrincsAccountVerifierExampleHarness is
    SHRINCSAccountVerifierExample
{
    constructor(bytes32 initialSHRINCSPublicKey)
        SHRINCSAccountVerifierExample(initialSHRINCSPublicKey)
    {}

    function verifyStatefulUncheckedForTest(
        SHRINCSCore.PublicKey calldata publicKey,
        bytes calldata message,
        UXMSS.StatefulSignature calldata signature
    ) external returns (bool) {
        return verifyStatefulUncheckedMessage(publicKey, message, signature);
    }

    function setStatelessSignaturesUsed(uint64 value) external {
        statelessSignaturesUsed = value;
    }

    function installFreshKeyForTest(bytes32 nextCompositePublicKey)
        external
    {
        installFreshKey(nextCompositePublicKey);
    }

    function installFreshStatefulKeyForTest(bytes32 nextCompositePublicKey)
        external
    {
        installFreshStatefulKey(nextCompositePublicKey);
    }

    function installFreshFullKeyForTest(bytes32 nextCompositePublicKey)
        external
    {
        installFreshFullKey(nextCompositePublicKey);
    }

    // line-length: allow — fmt canonical header exceeds cap
    function applySuccessfulStatefulRotationForTest(bytes32 nextCompositePublicKey)
        external
    {
        consumeStatelessRotationUse(nextCompositePublicKey, false);
        installFreshStatefulKey(nextCompositePublicKey);
    }

    // line-length: allow — fmt canonical header exceeds cap
    function applySuccessfulFullRotationForTest(bytes32 nextCompositePublicKey)
        external
    {
        consumeStatelessRotationUse(nextCompositePublicKey, true);
        installFreshFullKey(nextCompositePublicKey);
    }
}

contract ExampleNonOwnerCaller {
    function setStatefulPolicyMonotonicIndex(
        SHRINCSAccountVerifierExample target,
        uint32 initialLeafIndex
    ) external {
        target.setStatefulPolicyMonotonicIndex(initialLeafIndex);
    }

    function trySetStatefulPolicyMonotonicIndex(
        SHRINCSAccountVerifierExample target,
        uint32 initialLeafIndex
    ) external returns (bool) {
        (bool ok,) = address(target)
            .call(
                abi.encodeCall(
                    target.setStatefulPolicyMonotonicIndex,
                    (initialLeafIndex)
                )
            );
        return ok;
    }

    // line-length: allow — fmt canonical header exceeds cap
    function setStatefulPolicyRecoveryRotation(SHRINCSAccountVerifierExample target)
        external
    {
        target.setStatefulPolicyRecoveryRotation();
    }

    // line-length: allow — fmt canonical header exceeds cap
    function trySetStatefulPolicyRecoveryRotation(SHRINCSAccountVerifierExample target)
        external
        returns (bool)
    {
        (bool ok,) = address(target)
            .call(
                abi.encodeCall(target.setStatefulPolicyRecoveryRotation, ())
            );
        return ok;
    }

    function setStatefulPolicyLeafBitmap(SHRINCSAccountVerifierExample target)
        external
    {
        target.setStatefulPolicyLeafBitmap();
    }

    // line-length: allow — fmt canonical header exceeds cap
    function trySetStatefulPolicyLeafBitmap(SHRINCSAccountVerifierExample target)
        external
        returns (bool)
    {
        (bool ok,) = address(target)
            .call(abi.encodeCall(target.setStatefulPolicyLeafBitmap, ()));
        return ok;
    }

    function enterRecoveryMode(SHRINCSAccountVerifierExample target)
        external
    {
        target.enterRecoveryMode();
    }

    function tryEnterRecoveryMode(SHRINCSAccountVerifierExample target)
        external
        returns (bool)
    {
        (bool ok,) = address(target)
            .call(abi.encodeCall(target.enterRecoveryMode, ()));
        return ok;
    }
}

contract ShrincsAccountVerifierExampleTest is Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    uint8 internal constant ERC1271_MODE_STATEFUL_ACTION = 1;
    uint8 internal constant ERC1271_MODE_STATELESS_ACTION = 2;

    string internal constant VECTOR_PATH =
        "test/test_vectors/shrincs_sphincs_256s_keccak.json";
    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    event StatelessRotationConsumed(
        uint64 usedCount,
        uint256 indexed nonce,
        uint256 indexed keyVersion,
        bytes32 indexed nextSHRINCSPublicKey,
        bool fullRotation
    );

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

    ExampleStatefulHarness internal stateful;
    ExampleStatelessHarness internal stateless;
    ExampleRotationHarness internal rotation;
    ExampleNonOwnerCaller internal nonOwnerCaller;
    string internal vectors;

    function setUp() public {
        stateful = new ExampleStatefulHarness();
        stateless = new ExampleStatelessHarness();
        rotation = new ExampleRotationHarness();
        nonOwnerCaller = new ExampleNonOwnerCaller();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testExampleInitializesStoredState() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);

        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(
            bytes32(uint256(uint160(account.owner()))),
            bytes32(uint256(uint160(address(this))))
        );
        assertTrue(
            uint8(account.statefulPolicy())
                == uint8(
                    SHRINCSAccountVerifierExample.StatefulPolicy
                    .MonotonicIndex
                ),
            "stateful policy must initialize to monotonic index"
        );
        assertTrue(
            account.nextStatefulLeafIndex() == 1,
            "next stateful leaf index must initialize to one"
        );
        assertTrue(account.nonce() == 0, "nonce must initialize to zero");
        assertTrue(
            account.keyVersion() == 0, "key version must initialize to zero"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "stateless usage must initialize to zero"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleVerifyStatefulActionMatchesLibraryAndPreservesStateOnFailure()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.ActionContext memory context =
            actionContext(address(account), 0, 0);

        bool expected = stateful.verify(
            expectedCompositePublicKey, publicKey, context, signature
        );
        bool actual = account.verifyStatefulAction(
            publicKey, context.actionType, context.payloadHash, signature
        );

        assertEq(actual, expected, "wrapper must match library result");
        assertEq(
            actual,
            false,
            "legacy raw vector must not verify through canonical wrapper path"
        );
        assertTrue(
            account.nonce() == 0,
            "nonce must not change on failed stateful verify"
        );
        assertTrue(
            account.keyVersion() == 0,
            "key version must not change on failed stateful verify"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "stateless usage must not change on failed stateful verify"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleVerifyStatelessActionMatchesLibraryAndPreservesStateOnFailure()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.ActionContext memory context =
            actionContext(address(account), 0, 0);

        bool expected = stateless.verify(
            expectedCompositePublicKey, publicKey, context, signature
        );
        bool actual = account.verifyStatelessAction(
            publicKey, context.actionType, context.payloadHash, signature
        );

        assertEq(actual, expected, "wrapper must match library result");
        assertEq(
            actual,
            false,
            "legacy raw vector must not verify through canonical wrapper path"
        );
        assertTrue(
            account.nonce() == 0,
            "nonce must not change on failed stateless verify"
        );
        assertTrue(
            account.keyVersion() == 0,
            "key version must not change on failed stateless verify"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "stateless usage must not change on failed stateless verify"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsMalformedEnvelopeAndPreservesState()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes4 actual = account.isValidSignature(bytes32(0), hex"");

        assertEq(
            actual, INVALID_SIGNATURE, "empty envelope must be rejected"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    function testExampleIsValidSignatureRejectsUnknownModeAndPreservesState()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes memory envelope =
            abi.encodePacked(bytes1(uint8(99)), bytes("junk"));
        bytes4 actual = account.isValidSignature(bytes32(0), envelope);

        assertEq(
            actual,
            INVALID_SIGNATURE,
            "unknown envelope mode must be rejected"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsMalformedStatefulEnvelopeWithoutReverting()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATEFUL_ACTION), hex"01020304"
        );
        bytes4 actual = account.isValidSignature(bytes32(0), envelope);

        assertEq(
            actual,
            INVALID_SIGNATURE,
            "malformed stateful envelope must return invalid"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsMalformedStatelessEnvelopeWithoutReverting()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATELESS_ACTION), hex"deadbeef"
        );
        bytes4 actual = account.isValidSignature(bytes32(0), envelope);

        assertEq(
            actual,
            INVALID_SIGNATURE,
            "malformed stateless envelope must return invalid"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsLegacyStatefulVectorThroughCanonicalEnvelope()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.ActionContext memory context =
            actionContext(address(account), 0, 0);
        bytes32 hash = keccak256(
            abi.encodePacked(
                SHRINCSCore.OP_VERIFY_STATEFUL,
                SHRINCSCore.HASH_SUITE_KECCAK_256,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATEFUL_ACTION),
            abi.encode(
                publicKey, context.actionType, context.payloadHash, signature
            )
        );

        bytes4 actual = account.isValidSignature(hash, envelope);

        assertEq(
            actual,
            INVALID_SIGNATURE,
            // line-length: allow — one unbreakable string literal token
            "legacy raw stateful vector must not validate through canonical 1271 path"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsLegacyStatelessVectorThroughCanonicalEnvelope()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.ActionContext memory context =
            actionContext(address(account), 0, 0);
        bytes32 hash = keccak256(
            abi.encodePacked(
                SHRINCSCore.OP_VERIFY_STATELESS,
                SHRINCSCore.HASH_SUITE_KECCAK_256,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATELESS_ACTION),
            abi.encode(
                publicKey, context.actionType, context.payloadHash, signature
            )
        );

        bytes4 actual = account.isValidSignature(hash, envelope);

        assertEq(
            actual,
            INVALID_SIGNATURE,
            // line-length: allow — one unbreakable string literal token
            "legacy raw stateless vector must not validate through canonical 1271 path"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleRotateFullKeyMatchesLibraryAndPreservesStateOnFailure()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: domainSeparatorFor(address(account)),
                nonce: 0,
                keyVersion: 0
            });
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );

        bytes32 expected = rotation.statelessRotate(
            expectedCompositePublicKey, publicKey, context, signature, target
        );
        bool actual = account.rotateFullKey(publicKey, signature, target);

        assertEq(
            actual,
            expected != bytes32(0),
            "wrapper must match library rotation result"
        );
        assertEq(
            actual,
            false,
            "legacy raw vector must not authorize canonical rotation"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertTrue(
            account.nonce() == 0, "nonce must not change on failed rotation"
        );
        assertTrue(
            account.keyVersion() == 0,
            "key version must not change on failed rotation"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "stateless usage must not change on failed rotation"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleRotateToFreshKeyMatchesLibraryAndPreservesStateOnFailure()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.RotationContext memory context =
            SHRINCSCore.RotationContext({
                domainSeparator: domainSeparatorFor(address(account)),
                nonce: 0,
                keyVersion: 0
            });
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );

        bytes32 expected = rotation.rotateStatefulViaStateless(
            expectedCompositePublicKey, publicKey, context, signature, target
        );
        bool actual = account.rotateToFreshKey(publicKey, signature, target);

        assertEq(
            actual,
            expected != bytes32(0),
            "wrapper must match library stateful-only rotation result"
        );
        assertEq(
            actual,
            false,
            // line-length: allow — one unbreakable string literal token
            "legacy raw vector must not authorize canonical stateful-only rotation"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertTrue(
            account.nonce() == 0, "nonce must not change on failed rotation"
        );
        assertTrue(
            account.keyVersion() == 0,
            "key version must not change on failed rotation"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "stateless usage must not change on failed rotation"
        );
    }

    function testExampleRotateFullKeyRequiresRecoveryMode() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );

        bool withoutPolicy =
            account.rotateFullKey(publicKey, signature, target);
        assertEq(
            withoutPolicy,
            false,
            "full-key rotation must be blocked outside recovery policy"
        );

        account.setStatefulPolicyRecoveryRotation();

        bool withoutRecoveryMode =
            account.rotateFullKey(publicKey, signature, target);
        assertEq(
            withoutRecoveryMode,
            false,
            "full-key rotation must be blocked before entering recovery mode"
        );

        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(
            account.recoveryMode(),
            false,
            "failed full-key rotation must not toggle recovery mode"
        );
    }

    function testExampleVerifyStatelessActionRejectsAtUsageLimit() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCSCore.ActionContext memory context =
            actionContext(address(account), 0, 0);

        account.setStatelessSignaturesUsed(limit);
        bool actual = account.verifyStatelessAction(
            publicKey, context.actionType, context.payloadHash, signature
        );

        assertEq(
            actual,
            false,
            "wrapper must stop stateless actions at usage limit"
        );
        assertTrue(
            account.nonce() == 0, "nonce must stay unchanged at usage limit"
        );
        assertTrue(
            account.statelessSignaturesUsed() == limit,
            "usage must stay unchanged at usage limit"
        );
    }

    function testExampleRotateFullKeyRejectsAtUsageLimit() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCSCore.RotationTarget memory target = rotationTargetFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );

        account.setStatelessSignaturesUsed(limit);
        bool actual = account.rotateFullKey(publicKey, signature, target);

        assertEq(
            actual,
            false,
            "wrapper must stop stateless rotation at usage limit"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertTrue(
            account.nonce() == 0,
            "nonce must stay unchanged at rotation usage limit"
        );
        assertTrue(
            account.keyVersion() == 0,
            "key version must stay unchanged at rotation usage limit"
        );
        assertTrue(
            account.statelessSignaturesUsed() == limit,
            "usage must stay unchanged at rotation usage limit"
        );
    }

    function testExampleRotateToFreshKeyRejectsAtUsageLimit() public {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );

        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();
        account.setStatelessSignaturesUsed(limit);
        bool actual = account.rotateToFreshKey(publicKey, signature, target);

        assertEq(
            actual, false, "stateful-only rotation must stop at usage limit"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertTrue(
            account.nonce() == 0,
            "nonce must stay unchanged at stateful-only rotation usage limit"
        );
        assertTrue(
            account.keyVersion() == 0,
            // line-length: allow — one unbreakable string literal token
            "key version must stay unchanged at stateful-only rotation usage limit"
        );
        assertTrue(
            account.statelessSignaturesUsed() == limit,
            "usage must stay unchanged at stateful-only rotation usage limit"
        );
    }

    function testExampleDomainSeparatorDiffersAcrossContractInstances()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);

        SHRINCSAccountVerifierExample accountA =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCSAccountVerifierExample accountB =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes32 domainA = domainSeparatorFor(address(accountA));
        bytes32 domainB = domainSeparatorFor(address(accountB));

        assertTrue(
            domainA != domainB, "wrapper domains must bind contract identity"
        );
    }

    function testExampleRejectsNonOwnerPolicyChange() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bool ok = nonOwnerCaller.trySetStatefulPolicyLeafBitmap(account);

        assertEq(
            ok, false, "non-owner must not be able to change stateful policy"
        );
        assertTrue(
            uint8(account.statefulPolicy())
                == uint8(
                    SHRINCSAccountVerifierExample.StatefulPolicy
                    .MonotonicIndex
                ),
            "failed non-owner policy change must not update policy"
        );
    }

    function testExampleNonOwnerSetStatefulPolicyLeafBitmapReverts() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyLeafBitmap(account);
    }

    function testExampleRejectsNonOwnerSetStatefulPolicyMonotonicIndex()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bool ok =
            nonOwnerCaller.trySetStatefulPolicyMonotonicIndex(account, 5);

        assertEq(
            ok, false, "non-owner must not be able to set monotonic policy"
        );
        assertTrue(
            uint8(account.statefulPolicy())
                == uint8(
                    SHRINCSAccountVerifierExample.StatefulPolicy
                    .MonotonicIndex
                ),
            "failed non-owner monotonic set must not update policy"
        );
        assertTrue(
            account.nextStatefulLeafIndex() == 1,
            "failed non-owner monotonic set must not update index"
        );
    }

    function testExampleNonOwnerSetStatefulPolicyMonotonicIndexReverts()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyMonotonicIndex(account, 5);
    }

    function testExampleRejectsNonOwnerSetStatefulPolicyRecoveryRotation()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bool ok =
            nonOwnerCaller.trySetStatefulPolicyRecoveryRotation(account);

        assertEq(
            ok,
            false,
            "non-owner must not be able to set recovery rotation policy"
        );
        assertTrue(
            uint8(account.statefulPolicy())
                == uint8(
                    SHRINCSAccountVerifierExample.StatefulPolicy
                    .MonotonicIndex
                ),
            "failed non-owner recovery rotation set must not update policy"
        );
    }

    function testExampleNonOwnerSetStatefulPolicyRecoveryRotationReverts()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyRecoveryRotation(account);
    }

    function testExampleRejectsNonOwnerRecoveryModeToggle() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        bool ok = nonOwnerCaller.tryEnterRecoveryMode(account);

        assertEq(
            ok, false, "non-owner must not be able to enter recovery mode"
        );
        assertEq(
            account.recoveryMode(),
            false,
            "failed non-owner recovery toggle must not change state"
        );
    }

    function testExampleNonOwnerEnterRecoveryModeReverts() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.enterRecoveryMode(account);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleEnterRecoveryModeRevertsOutsideRecoveryRotationPolicy()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("recovery policy required"));
        account.enterRecoveryMode();
    }

    function testExampleSetStatefulPolicyMonotonicIndexRevertsOnRollback()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        account.setStatefulPolicyMonotonicIndex(17);

        vm.expectRevert(bytes("stateful index rollback"));
        account.setStatefulPolicyMonotonicIndex(16);
    }

    function testExamplePolicyChangesFreezeAfterSuccessfulStatefulUse()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        bool ok = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );
        assertEq(
            ok, true, "stateful signature must verify before freeze checks"
        );
        assertEq(
            account.statefulPolicyFrozen(),
            true,
            "successful stateful use must freeze policy changes"
        );

        vm.expectRevert(bytes("stateful policy frozen"));
        account.setStatefulPolicyLeafBitmap();
    }

    function testExampleFreshKeyInstallUnfreezesPolicyChanges() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        bool ok = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );
        assertEq(
            ok, true, "stateful signature must verify before freeze checks"
        );
        assertEq(
            account.statefulPolicyFrozen(),
            true,
            "successful stateful use must freeze policy changes"
        );

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey);

        assertEq(
            account.statefulPolicyFrozen(),
            false,
            "fresh key install must clear policy freeze"
        );
        account.setStatefulPolicyLeafBitmap();
        assertEq(
            uint8(account.statefulPolicy()),
            uint8(SHRINCSAccountVerifierExample.StatefulPolicy.LeafBitmap),
            "policy changes must be allowed again after fresh key install"
        );
    }

    function testExampleFreshKeyInstallResetsStatefulTrackingState() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();
        account.setStatefulPolicyMonotonicIndex(17);
        account.setStatelessSignaturesUsed(9);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey);

        assertEq(account.currentSHRINCSPublicKey(), nextCompositePublicKey);
        assertTrue(
            account.nextStatefulLeafIndex() == 1,
            "fresh key must reset next stateful leaf index"
        );
        assertTrue(
            uint8(account.statefulPolicy())
                == uint8(
                    SHRINCSAccountVerifierExample.StatefulPolicy
                    .MonotonicIndex
                ),
            "fresh key must reset stateful policy to monotonic index"
        );
        assertEq(
            account.recoveryMode(),
            false,
            "fresh key must exit recovery mode"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "fresh key must reset stateless usage when requested"
        );
    }

    function testExampleFreshKeyInstallResetsLeafBitmapNamespace() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint32 leafIndex = uint32(signature.authPath.length);

        account.setStatefulPolicyLeafBitmap();
        bool firstUse = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );
        assertEq(
            firstUse,
            true,
            "first leaf use should verify under bitmap policy"
        );
        assertEq(
            account.isLeafUsed(leafIndex),
            true,
            "leaf must be marked used in current key version"
        );

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey);

        assertEq(
            account.keyVersion(),
            1,
            "fresh key install must advance key version"
        );
        assertEq(
            account.isLeafUsed(leafIndex),
            false,
            "fresh key must start with a clean leaf bitmap namespace"
        );
    }

    function testExampleFreshKeyInstallAlwaysResetsStatelessUsage() public {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatelessSignaturesUsed(123);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey);

        assertEq(account.currentSHRINCSPublicKey(), nextCompositePublicKey);
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "fresh key must always reset stateless usage"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleSuccessfulStatefulOnlyRotationPreservesAndIncrementsStatelessUsage()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatelessSignaturesUsed(123);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.applySuccessfulStatefulRotationForTest(
            nextCompositePublicKey
        );

        assertEq(account.currentSHRINCSPublicKey(), nextCompositePublicKey);
        assertEq(
            account.statelessSignaturesUsed(),
            124,
            // line-length: allow — one unbreakable string literal token
            "stateful-only rotation must carry forward prior usage plus the recovery signature"
        );
        assertEq(
            account.nonce(), 1, "stateful-only rotation must advance nonce"
        );
        assertEq(
            account.keyVersion(),
            1,
            "stateful-only rotation must advance key version"
        );
        assertEq(
            account.nextStatefulLeafIndex(),
            1,
            "stateful-only rotation must reset stateful tracking"
        );
        assertEq(
            uint8(account.statefulPolicy()),
            uint8(
                SHRINCSAccountVerifierExample.StatefulPolicy.MonotonicIndex
            )
        );
        assertEq(
            account.recoveryMode(),
            false,
            "stateful-only rotation must exit recovery mode"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleSuccessfulStatefulOnlyRotationEmitsDedicatedStatelessUsageEvent()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatelessSignaturesUsed(123);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        vm.expectEmit(true, true, true, true, address(account));
        emit StatelessRotationConsumed(
            124, 0, 0, nextCompositePublicKey, false
        );
        account.applySuccessfulStatefulRotationForTest(
            nextCompositePublicKey
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleRepeatedStatefulOnlyRotationDoesNotMintFreshStatelessBudget()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatelessSignaturesUsed(7);

        bytes32 nextCompositePublicKeyA =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        bytes32 nextCompositePublicKeyB =
            bytes32(uint256(expectedCompositePublicKey) ^ 2);
        account.applySuccessfulStatefulRotationForTest(
            nextCompositePublicKeyA
        );
        account.applySuccessfulStatefulRotationForTest(
            nextCompositePublicKeyB
        );

        assertEq(account.currentSHRINCSPublicKey(), nextCompositePublicKeyB);
        assertEq(
            account.statelessSignaturesUsed(),
            9,
            // line-length: allow — one unbreakable string literal token
            "repeated stateful-only rotation must continue consuming one stateless use each time"
        );
        assertEq(
            account.nonce(),
            2,
            "each stateful-only rotation must advance nonce"
        );
        assertEq(
            account.keyVersion(),
            2,
            "each stateful-only rotation must advance key version"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleStatefulOnlyRotationAtLimitMinusOneConsumesFinalStatelessUse()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCSCore.ActionContext memory context =
            actionContext(address(account), 1, 1);

        account.setStatelessSignaturesUsed(limit - 1);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.applySuccessfulStatefulRotationForTest(
            nextCompositePublicKey
        );

        assertEq(account.currentSHRINCSPublicKey(), nextCompositePublicKey);
        assertEq(
            account.statelessSignaturesUsed(),
            limit,
            // line-length: allow — one unbreakable string literal token
            "stateful-only rotation must consume the final available stateless use"
        );
        assertEq(
            account.nonce(), 1, "stateful-only rotation must advance nonce"
        );
        assertEq(
            account.keyVersion(),
            1,
            "stateful-only rotation must advance key version"
        );

        bool statelessActionOk = account.verifyStatelessAction(
            publicKey, context.actionType, context.payloadHash, signature
        );

        assertEq(
            statelessActionOk,
            false,
            // line-length: allow — one unbreakable string literal token
            "the next stateless use must be rejected once the limit is reached"
        );
        assertEq(
            account.statelessSignaturesUsed(),
            limit,
            "rejected post-limit stateless use must not change accounting"
        );
    }

    function testExampleSuccessfulFullRotationResetsStatelessUsageForNewKey()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatelessSignaturesUsed(123);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.applySuccessfulFullRotationForTest(nextCompositePublicKey);

        assertEq(account.currentSHRINCSPublicKey(), nextCompositePublicKey);
        assertEq(
            account.statelessSignaturesUsed(),
            0,
            // line-length: allow — one unbreakable string literal token
            "full rotation must reset stateless usage for the new stateless key"
        );
        assertEq(account.nonce(), 1, "full rotation must advance nonce");
        assertEq(
            account.keyVersion(), 1, "full rotation must advance key version"
        );
        assertEq(
            account.nextStatefulLeafIndex(),
            1,
            "full rotation must reset stateful tracking"
        );
        assertEq(
            uint8(account.statefulPolicy()),
            uint8(
                SHRINCSAccountVerifierExample.StatefulPolicy.MonotonicIndex
            )
        );
        assertEq(
            account.recoveryMode(),
            false,
            "full rotation must exit recovery mode"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleSuccessfulFullRotationEmitsDedicatedStatelessUsageEvent()
        public
    {
        (SHRINCSCore.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );

        account.setStatelessSignaturesUsed(123);

        bytes32 nextCompositePublicKey =
            bytes32(uint256(expectedCompositePublicKey) ^ 1);
        vm.expectEmit(true, true, true, true, address(account));
        emit StatelessRotationConsumed(
            124, 0, 0, nextCompositePublicKey, true
        );
        account.applySuccessfulFullRotationForTest(nextCompositePublicKey);
    }

    function actionContext(
        address account,
        uint256 nonceValue,
        uint256 keyVersionValue
    ) internal view returns (SHRINCSCore.ActionContext memory) {
        return SHRINCSCore.ActionContext({
            domainSeparator: domainSeparatorFor(account),
            nonce: nonceValue,
            keyVersion: keyVersionValue,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });
    }

    function domainSeparatorFor(address account)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, account));
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
        publicKey.publicKeyCommitment = vm.parseJsonBytes(
            vectors,
            string.concat(
                trimCalldataSuffix(vectorKey),
                ".publicKey.publicKeyCommitment"
            )
        );

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

    function vectorArgs(string memory vectorKey)
        internal
        returns (bytes memory)
    {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
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
