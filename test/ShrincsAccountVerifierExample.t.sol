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

contract ExampleStatefulHarness {
    function verify(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(parameterSetId, expectedCompositePublicKey, publicKey, context, signature);
    }
}

contract ExampleStatelessHarness {
    function verify(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(parameterSetId, expectedCompositePublicKey, publicKey, context, signature);
    }
}

contract ExampleRotationHarness {
    function statelessRotate(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.statelessRotate(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, recoverySignature, nextKey
        );
    }
}

contract ShrincsAccountVerifierExampleHarness is ShrincsAccountVerifierExample {
    constructor(bytes32 initialShrincsPublicKey) ShrincsAccountVerifierExample(initialShrincsPublicKey) {}

    function setStatelessSignaturesUsed(uint64 value) external {
        statelessSignaturesUsed = value;
    }

    function installFreshKeyForTest(bytes32 nextCompositePublicKey, ShrincsTypes.ParameterSetId nextParameterSetId)
        external
    {
        _installFreshKey(nextCompositePublicKey, nextParameterSetId);
    }
}

contract ExampleNonOwnerCaller {
    function setStatefulPolicyNone(ShrincsAccountVerifierExample target) external {
        target.setStatefulPolicyNone();
    }

    function trySetStatefulPolicyNone(ShrincsAccountVerifierExample target) external returns (bool) {
        (bool ok,) = address(target).call(abi.encodeCall(target.setStatefulPolicyNone, ()));
        return ok;
    }

    function setStatefulPolicyMonotonicIndex(ShrincsAccountVerifierExample target, uint32 initialLeafIndex) external {
        target.setStatefulPolicyMonotonicIndex(initialLeafIndex);
    }

    function trySetStatefulPolicyMonotonicIndex(ShrincsAccountVerifierExample target, uint32 initialLeafIndex)
        external
        returns (bool)
    {
        (bool ok,) = address(target).call(abi.encodeCall(target.setStatefulPolicyMonotonicIndex, (initialLeafIndex)));
        return ok;
    }

    function setStatefulPolicyRecoveryRotation(ShrincsAccountVerifierExample target) external {
        target.setStatefulPolicyRecoveryRotation();
    }

    function trySetStatefulPolicyRecoveryRotation(ShrincsAccountVerifierExample target) external returns (bool) {
        (bool ok,) = address(target).call(abi.encodeCall(target.setStatefulPolicyRecoveryRotation, ()));
        return ok;
    }

    function setStatefulPolicyLeafBitmap(ShrincsAccountVerifierExample target) external {
        target.setStatefulPolicyLeafBitmap();
    }

    function trySetStatefulPolicyLeafBitmap(ShrincsAccountVerifierExample target) external returns (bool) {
        (bool ok,) = address(target).call(abi.encodeCall(target.setStatefulPolicyLeafBitmap, ()));
        return ok;
    }

    function enterRecoveryMode(ShrincsAccountVerifierExample target) external {
        target.enterRecoveryMode();
    }

    function tryEnterRecoveryMode(ShrincsAccountVerifierExample target) external returns (bool) {
        (bool ok,) = address(target).call(abi.encodeCall(target.enterRecoveryMode, ()));
        return ok;
    }
}

contract ShrincsAccountVerifierExampleTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";
    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

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

    struct LegacyParams {
        uint16 nBytes;
        uint8 h;
        uint8 d;
        uint8 a;
        uint8 k;
        uint16 w;
        uint16 l;
        uint32 wotsTargetSum;
    }

    struct LegacyPublicKey {
        ShrincsTypes.ParameterSetId parameterSetId;
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
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);

        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        assertEq(account.currentShrincsPublicKey(), expectedCompositePublicKey);
        assertEq(bytes32(uint256(uint160(account.owner()))), bytes32(uint256(uint160(address(this)))));
        assertTrue(
            uint8(account.parameterSetId()) == uint8(ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20),
            "parameter set must initialize to Q20 profile"
        );
        assertTrue(account.nonce() == 0, "nonce must initialize to zero");
        assertTrue(account.keyVersion() == 0, "key version must initialize to zero");
        assertTrue(account.statelessSignaturesUsed() == 0, "stateless usage must initialize to zero");
    }

    function testExampleVerifyStatefulActionMatchesLibraryAndPreservesStateOnFailure() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsTypes.ActionContext memory context = _actionContext(address(account), 0, 0);

        bool expected = stateful.verify(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature
        );
        bool actual = account.verifyStatefulAction(publicKey, context.actionType, context.payloadHash, signature);

        assertEq(actual, expected, "wrapper must match library result");
        assertEq(actual, false, "legacy raw vector must not verify through canonical wrapper path");
        assertTrue(account.nonce() == 0, "nonce must not change on failed stateful verify");
        assertTrue(account.keyVersion() == 0, "key version must not change on failed stateful verify");
        assertTrue(account.statelessSignaturesUsed() == 0, "stateless usage must not change on failed stateful verify");
    }

    function testExampleVerifyStatelessActionMatchesLibraryAndPreservesStateOnFailure() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsTypes.ActionContext memory context = _actionContext(address(account), 0, 0);

        bool expected = stateless.verify(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature
        );
        bool actual = account.verifyStatelessAction(publicKey, context.actionType, context.payloadHash, signature);

        assertEq(actual, expected, "wrapper must match library result");
        assertEq(actual, false, "legacy raw vector must not verify through canonical wrapper path");
        assertTrue(account.nonce() == 0, "nonce must not change on failed stateless verify");
        assertTrue(account.keyVersion() == 0, "key version must not change on failed stateless verify");
        assertTrue(account.statelessSignaturesUsed() == 0, "stateless usage must not change on failed stateless verify");
    }

    function testExampleRotateFullKeyMatchesLibraryAndPreservesStateOnFailure() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsTypes.RotationContext memory context = ShrincsTypes.RotationContext({
            domainSeparator: _domainSeparatorFor(address(account)), nonce: 0, keyVersion: 0
        });
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: publicKey.statefulPublicKey,
            pkSeed: publicKey.pkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 expected = rotation.statelessRotate(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            expectedCompositePublicKey,
            publicKey,
            context,
            signature,
            target
        );
        bool actual = account.rotateFullKey(publicKey, signature, target);

        assertEq(actual, expected != bytes32(0), "wrapper must match library rotation result");
        assertEq(actual, false, "legacy raw vector must not authorize canonical rotation");
        assertEq(account.currentShrincsPublicKey(), expectedCompositePublicKey);
        assertTrue(account.nonce() == 0, "nonce must not change on failed rotation");
        assertTrue(account.keyVersion() == 0, "key version must not change on failed rotation");
        assertTrue(account.statelessSignaturesUsed() == 0, "stateless usage must not change on failed rotation");
    }

    function testExampleVerifyStatelessActionRejectsAtUsageLimit() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);
        uint64 limit =
            ShrincsTypes.defaultParamsView(ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20).statelessSignatureLimit;
        ShrincsTypes.ActionContext memory context = _actionContext(address(account), 0, 0);

        account.setStatelessSignaturesUsed(limit);
        bool actual = account.verifyStatelessAction(publicKey, context.actionType, context.payloadHash, signature);

        assertEq(actual, false, "wrapper must stop stateless actions at usage limit");
        assertTrue(account.nonce() == 0, "nonce must stay unchanged at usage limit");
        assertTrue(account.statelessSignaturesUsed() == limit, "usage must stay unchanged at usage limit");
    }

    function testExampleRotateFullKeyRejectsAtUsageLimit() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);
        uint64 limit =
            ShrincsTypes.defaultParamsView(ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20).statelessSignatureLimit;
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: publicKey.statefulPublicKey,
            pkSeed: publicKey.pkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        account.setStatelessSignaturesUsed(limit);
        bool actual = account.rotateFullKey(publicKey, signature, target);

        assertEq(actual, false, "wrapper must stop stateless rotation at usage limit");
        assertEq(account.currentShrincsPublicKey(), expectedCompositePublicKey);
        assertTrue(account.nonce() == 0, "nonce must stay unchanged at rotation usage limit");
        assertTrue(account.keyVersion() == 0, "key version must stay unchanged at rotation usage limit");
        assertTrue(account.statelessSignaturesUsed() == limit, "usage must stay unchanged at rotation usage limit");
    }

    function testExampleDomainSeparatorDiffersAcrossContractInstances() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);

        ShrincsAccountVerifierExample accountA = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsAccountVerifierExample accountB = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        bytes32 domainA = _domainSeparatorFor(address(accountA));
        bytes32 domainB = _domainSeparatorFor(address(accountB));

        assertTrue(domainA != domainB, "wrapper domains must bind contract identity");
    }

    function testExampleRejectsNonOwnerPolicyChange() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        bool ok = nonOwnerCaller.trySetStatefulPolicyLeafBitmap(account);

        assertEq(ok, false, "non-owner must not be able to change stateful policy");
        assertTrue(
            uint8(account.statefulPolicy()) == uint8(ShrincsAccountVerifierExample.StatefulPolicy.None),
            "failed non-owner policy change must not update policy"
        );
    }

    function testExampleNonOwnerSetStatefulPolicyLeafBitmapReverts() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyLeafBitmap(account);
    }

    function testExampleRejectsNonOwnerSetStatefulPolicyNone() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyLeafBitmap();

        bool ok = nonOwnerCaller.trySetStatefulPolicyNone(account);

        assertEq(ok, false, "non-owner must not be able to clear stateful policy");
        assertTrue(
            uint8(account.statefulPolicy()) == uint8(ShrincsAccountVerifierExample.StatefulPolicy.LeafBitmap),
            "failed non-owner clear must not update policy"
        );
    }

    function testExampleNonOwnerSetStatefulPolicyNoneReverts() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyNone(account);
    }

    function testExampleRejectsNonOwnerSetStatefulPolicyMonotonicIndex() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        bool ok = nonOwnerCaller.trySetStatefulPolicyMonotonicIndex(account, 5);

        assertEq(ok, false, "non-owner must not be able to set monotonic policy");
        assertTrue(
            uint8(account.statefulPolicy()) == uint8(ShrincsAccountVerifierExample.StatefulPolicy.None),
            "failed non-owner monotonic set must not update policy"
        );
        assertTrue(account.nextStatefulLeafIndex() == 0, "failed non-owner monotonic set must not update index");
    }

    function testExampleNonOwnerSetStatefulPolicyMonotonicIndexReverts() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyMonotonicIndex(account, 5);
    }

    function testExampleRejectsNonOwnerSetStatefulPolicyRecoveryRotation() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        bool ok = nonOwnerCaller.trySetStatefulPolicyRecoveryRotation(account);

        assertEq(ok, false, "non-owner must not be able to set recovery rotation policy");
        assertTrue(
            uint8(account.statefulPolicy()) == uint8(ShrincsAccountVerifierExample.StatefulPolicy.None),
            "failed non-owner recovery rotation set must not update policy"
        );
    }

    function testExampleNonOwnerSetStatefulPolicyRecoveryRotationReverts() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyRecoveryRotation(account);
    }

    function testExampleRejectsNonOwnerRecoveryModeToggle() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        bool ok = nonOwnerCaller.tryEnterRecoveryMode(account);

        assertEq(ok, false, "non-owner must not be able to enter recovery mode");
        assertEq(account.recoveryMode(), false, "failed non-owner recovery toggle must not change state");
    }

    function testExampleNonOwnerEnterRecoveryModeReverts() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.enterRecoveryMode(account);
    }

    function testExampleEnterRecoveryModeRevertsOutsideRecoveryRotationPolicy() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("recovery policy required"));
        account.enterRecoveryMode();
    }

    function testExampleSetStatefulPolicyMonotonicIndexRevertsOnRollback() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        account.setStatefulPolicyMonotonicIndex(17);

        vm.expectRevert(bytes("stateful index rollback"));
        account.setStatefulPolicyMonotonicIndex(16);
    }

    function testExampleFreshKeyInstallResetsStatefulTrackingState() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);

        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();
        account.setStatefulPolicyMonotonicIndex(17);
        account.setStatelessSignaturesUsed(9);

        bytes32 nextCompositePublicKey = bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey, ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20);

        assertEq(account.currentShrincsPublicKey(), nextCompositePublicKey);
        assertTrue(account.nextStatefulLeafIndex() == 0, "fresh key must reset next stateful leaf index");
        assertTrue(
            uint8(account.statefulPolicy()) == uint8(ShrincsAccountVerifierExample.StatefulPolicy.None),
            "fresh key must clear stateful policy"
        );
        assertEq(account.recoveryMode(), false, "fresh key must exit recovery mode");
        assertTrue(account.statelessSignaturesUsed() == 0, "fresh key must reset stateless usage when requested");
    }

    function testExampleFreshKeyInstallResetsLeafBitmapNamespace() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);
        uint32 leafIndex = uint32(signature.authPath.length);

        account.setStatefulPolicyLeafBitmap();
        bool firstUse = account.verifyStatefulRaw(publicKey, message, signature);
        assertEq(firstUse, true, "first leaf use should verify under bitmap policy");
        assertEq(account.isLeafUsed(leafIndex), true, "leaf must be marked used in current key version");

        bytes32 nextCompositePublicKey = bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey, ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20);

        assertEq(account.keyVersion(), 1, "fresh key install must advance key version");
        assertEq(account.isLeafUsed(leafIndex), false, "fresh key must start with a clean leaf bitmap namespace");
    }

    function testExampleFreshKeyInstallAlwaysResetsStatelessUsage() public {
        (ShrincsTypes.PublicKey memory publicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account =
            new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);

        account.setStatelessSignaturesUsed(123);

        bytes32 nextCompositePublicKey = bytes32(uint256(expectedCompositePublicKey) ^ 1);
        account.installFreshKeyForTest(nextCompositePublicKey, ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20);

        assertEq(account.currentShrincsPublicKey(), nextCompositePublicKey);
        assertTrue(account.statelessSignaturesUsed() == 0, "fresh key must always reset stateless usage");
    }

    function _actionContext(address account, uint256 nonceValue, uint256 keyVersionValue)
        internal
        view
        returns (ShrincsTypes.ActionContext memory)
    {
        return ShrincsTypes.ActionContext({
            domainSeparator: _domainSeparatorFor(account),
            nonce: nonceValue,
            keyVersion: keyVersionValue,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });
    }

    function _domainSeparatorFor(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, account));
    }

    function _compositePublicKeyWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 word) {
        require(publicKey.hypertreeRoot.length == 32, "hypertree root length");
        bytes memory hypertreeRoot = publicKey.hypertreeRoot;
        assembly {
            word := mload(add(hypertreeRoot, 32))
        }
    }

    function _decodeStatefulVector(string memory vectorKey)
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        )
    {
        bytes memory args = _vectorArgs(vectorKey);
        (
            LegacyStatefulPublicKey memory legacyKey,
            bytes memory legacyMessage,
            LegacyStatefulSignature memory legacySignature
        ) = abi.decode(args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature));

        (ShrincsTypes.PublicKey memory statelessPublicKey,,) = _decodeStatelessVector(".stateless.cases.valid.calldata");

        bytes memory encodedStatefulKey =
            abi.encodePacked(legacyKey.pkSeed, legacyKey.root, bytes4(legacyKey.maxSignatures));

        publicKey = ShrincsTypes.PublicKey({
            parameterSetId: ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            statefulPublicKey: encodedStatefulKey,
            pkSeed: statelessPublicKey.pkSeed,
            hypertreeRoot: statelessPublicKey.hypertreeRoot
        });

        message = legacyMessage;
        signature = ShrincsTypes.StatefulSignature({
            randomizer: legacySignature.randomizer,
            counter: legacySignature.counter,
            chains: _fixedToDynamicChains(legacySignature.chains),
            authPath: legacySignature.authPath
        });
    }

    function _decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        )
    {
        bytes memory args = _vectorArgs(vectorKey);
        (
            LegacyParams memory legacyParams,
            LegacyPublicKey memory legacyPublicKey,
            bytes memory legacyMessage,
            LegacyStatelessSignature memory legacySignature
        ) = abi.decode(args, (LegacyParams, LegacyPublicKey, bytes, LegacyStatelessSignature));
        legacyParams;

        publicKey = ShrincsTypes.PublicKey({
            parameterSetId: legacyPublicKey.parameterSetId,
            statefulPublicKey: legacyPublicKey.statefulPublicKey,
            pkSeed: legacyPublicKey.pkSeed,
            hypertreeRoot: legacyPublicKey.hypertreeRoot
        });

        message = legacyMessage;
        signature = _convertLegacyStatelessSignature(legacySignature);
    }

    function _convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
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

    function _fixedToDynamicChains(bytes32[64] memory fixedChains) internal pure returns (bytes32[] memory chains) {
        chains = new bytes32[](64);
        for (uint256 i = 0; i < 64; ++i) {
            chains[i] = fixedChains[i];
        }
    }

    function _vectorArgs(string memory vectorKey) internal returns (bytes memory) {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return _stripSelector(callData);
    }

    function _stripSelector(bytes memory input) internal pure returns (bytes memory output) {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }
}
