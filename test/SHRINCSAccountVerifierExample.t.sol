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
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract ExampleStatefulHarness {
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
}

contract ExampleStatelessHarness {
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
}

contract ExampleRotationHarness {
    function rotateStatefulViaStateless(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext calldata context,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.StatefulRotationTarget calldata nextKey
    ) external view returns (bytes32) {
        return SHRINCS.rotateStatefulViaStateless(
            expectedCompositePublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
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

contract SHRINCSAccountVerifierExampleHarness is
    SHRINCSAccountVerifierExample
{
    constructor(bytes32 initialSHRINCSPublicKey)
        SHRINCSAccountVerifierExample(initialSHRINCSPublicKey)
    {}

    function verifyStatefulUncheckedForTest(
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SHRINCS.Signature calldata signature
    ) external returns (bool) {
        return verifyStatefulUncheckedMessage(publicKey, message, signature);
    }

    function setStatelessSignaturesUsed(uint64 value) external {
        statelessSignaturesUsed = value;
    }

    function installFreshKeyForTest(bytes32 nextCompositePublicKey)
        external
    {
        installFreshFullKey(nextCompositePublicKey);
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

contract SHRINCSAccountVerifierExampleTest is Test {
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
            SHRINCS.PublicKey memory publicKey,,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.ActionContext memory context =
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.ActionContext memory context =
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

    // Revert model: an empty signature carries no mode byte, so the mode read
    // reverts (Panic) instead of returning 0xffffffff; state is untouched.
    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRevertsOnEmptyEnvelopeAndPreservesState()
        public
    {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert();
        account.isValidSignature(bytes32(0), hex"");

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
        (SHRINCS.PublicKey memory publicKey,,) =
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

    // Revert model: the canonicity walk is gone, so a malformed stateful
    // envelope reverts inside abi.decode instead of returning 0xffffffff;
    // state is untouched.
    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRevertsOnMalformedStatefulEnvelope()
        public
    {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATEFUL_ACTION), hex"01020304"
        );
        vm.expectRevert();
        account.isValidSignature(bytes32(0), envelope);

        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // Re-tag model: the `deadbeef` payload re-tags to a publicKey head offset
    // whose top bit is set (0xde...), so it slips solc's signed bound and
    // the struct members read as empty (E1b). validPublicKey then rejects the
    // empty bundle, so this malformed stateless envelope is rejected with
    // 0xffffffff rather than a revert (a malformed case moving within
    // {revert, false}); state is untouched.
    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsMalformedStatelessEnvelope()
        public
    {
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATELESS_ACTION), hex"deadbeef"
        );
        assertEq(
            account.isValidSignature(bytes32(0), envelope),
            INVALID_SIGNATURE,
            "malformed stateless envelope must be rejected"
        );

        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // M2 pinning: deterministic wild-pointer (E1b) probes on the
    // offset-bearing head words of the two 4-tuple action re-tags
    // (SHRINCS.statefulActionEnvelope / statelessActionEnvelope). The
    // abi.encode head is publicKey offset (word 0), inline actionType and
    // payloadHash (words 1 and 2), signature offset (word 3); only words 0
    // and 3 are offsets. The supplied hash is the matching canonical action
    // hash, so the flow reaches and dereferences the probed offset: a head
    // offset >= 2^255 slips solc's signed tail bound, so the struct members
    // read empty (word 0 -> validPublicKey false -> 0xffffffff) or the tail
    // access reverts (word 3). Either way the wrapper stays in {revert,
    // false} and never returns the ERC-1271 magic value; state is untouched.
    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsE1bStatefulActionHeadProbes()
        public
    {
        (
            SHRINCS.PublicKey memory publicKey,,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.ActionContext memory context =
            actionContext(address(account), 0, 0);
        bytes32 hash = keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATEFUL,
                HashSuite.HASH_SUITE_ID,
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

        _assertActionNotAccepted(
            account, hash, _corruptActionHead(envelope, 0), "stateful head 0"
        );
        _assertActionNotAccepted(
            account, hash, _corruptActionHead(envelope, 3), "stateful head 3"
        );

        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsE1bStatelessActionHeadProbes()
        public
    {
        (
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.ActionContext memory context =
            actionContext(address(account), 0, 0);
        bytes32 hash = keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATELESS,
                HashSuite.HASH_SUITE_ID,
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

        _assertActionNotAccepted(
            account,
            hash,
            _corruptActionHead(envelope, 0),
            "stateless head 0"
        );
        _assertActionNotAccepted(
            account,
            hash,
            _corruptActionHead(envelope, 3),
            "stateless head 3"
        );

        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
        assertEq(account.nonce(), 0);
        assertEq(account.keyVersion(), 0);
        assertEq(account.statelessSignaturesUsed(), 0);
    }

    /// @dev Assert the wrapper's isValidSignature does not accept `envelope`:
    /// it either reverts or returns a non-magic value. Never asserts a
    /// specific error, so it holds across the {revert, false} rejection set.
    function _assertActionNotAccepted(
        SHRINCSAccountVerifierExample account,
        bytes32 hash,
        bytes memory envelope,
        string memory label
    ) internal view {
        try account.isValidSignature(hash, envelope) returns (bytes4 r) {
            assertTrue(r != MAGIC_VALUE, label);
        } catch {}
    }

    /// @dev Overwrite the abi.encode head word at index `headWord` (after the
    /// 1-byte mode prefix) with 2^255, past solc's signed tail bound (E1b).
    /// Only the offset-bearing head words 0 (publicKey) and 3 (signature) are
    /// meaningful; words 1 and 2 are inline bytes32 action fields.
    function _corruptActionHead(bytes memory envelope, uint256 headWord)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        uint256 e1b = 1 << 255;
        // Data starts at out+0x20; the mode byte occupies data[0], so head
        // word `headWord` begins at data byte 1 + headWord*32.
        uint256 slot = 32 + 1 + headWord * 32;
        assembly {
            mstore(add(out, slot), e1b)
        }
    }

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsLegacyStatefulVectorThroughCanonicalEnvelope()
        public
    {
        (
            SHRINCS.PublicKey memory publicKey,,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.ActionContext memory context =
            actionContext(address(account), 0, 0);
        bytes32 hash = keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATEFUL,
                HashSuite.HASH_SUITE_ID,
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.ActionContext memory context =
            actionContext(address(account), 0, 0);
        bytes32 hash = keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATELESS,
                HashSuite.HASH_SUITE_ID,
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.RotationContext memory context = SHRINCS.RotationContext({
            domainSeparator: domainSeparatorFor(address(account)),
            nonce: 0,
            keyVersion: 0
        });
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.RotationContext memory context = SHRINCS.RotationContext({
            domainSeparator: domainSeparatorFor(address(account)),
            nonce: 0,
            keyVersion: 0
        });
        SHRINCS.StatefulRotationTarget memory target =
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCS.ActionContext memory context =
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCS.RotationTarget memory target = rotationTargetFromParts(
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCS.StatefulRotationTarget memory target =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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

    // line-length: allow — test name is one unbreakable token
    function testExampleIsValidSignatureRejectsAfterChainIdChanges() public {
        bytes32 actionType = keccak256("execute");
        bytes32 payloadHash = keccak256("payload");
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("chainid-replay-current-key"), 4
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
            ,
            SHRINCS.ActionContext memory context,
            SHRINCS.Signature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );
        assertTrue(signOk, "stateful signing must succeed");

        bytes32 hash = SHRINCS.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory envelope = abi.encodePacked(
            bytes1(ERC1271_MODE_STATEFUL_ACTION),
            abi.encode(publicKey, actionType, payloadHash, signature)
        );

        // Positive control: a freshly self-signed action validates on the
        // chain it was signed for.
        bytes4 acceptedHere = account.isValidSignature(hash, envelope);
        assertEq(
            acceptedHere,
            MAGIC_VALUE,
            "freshly signed action must validate on the signing chain"
        );

        // domainSeparator() binds block.chainid; flipping it must invalidate
        // the same (hash, envelope) pair that just validated (cross-chain
        // replay pin).
        vm.chainId(block.chainid + 1);

        bytes4 afterChainIdFlip = account.isValidSignature(hash, envelope);
        assertTrue(
            afterChainIdFlip != MAGIC_VALUE,
            // line-length: allow — one unbreakable string literal token
            "a chain-id flip must invalidate a previously-valid ERC-1271 result"
        );
    }

    function testExampleRejectsNonOwnerPolicyChange() public {
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(expectedCompositePublicKey);

        vm.expectRevert(bytes("only owner"));
        nonOwnerCaller.setStatefulPolicyRecoveryRotation(account);
    }

    function testExampleRejectsNonOwnerRecoveryModeToggle() public {
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
        (SHRINCS.PublicKey memory publicKey,,) =
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
                expectedCompositePublicKey
            );
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        SHRINCS.ActionContext memory context =
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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
        (SHRINCS.PublicKey memory publicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
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

    // Regression for the over-reset fix: before the fix, rotateFullKey
    // always reset statelessSignaturesUsed to zero
    // (installFreshFullKey -> installRotatedKey(next, true)), even when the
    // rotation target reused the currently installed pkSeed/hypertreeRoot.
    // Resetting while the rotation target reuses the current stateless
    // material mints a fresh budget for the SAME few-time stateless key,
    // permitting over-use beyond its intended signature limit. This test
    // drives a real rotateFullKey call whose target keeps the current
    // stateless material and only replaces the stateful side, and proves
    // the usage counter carries forward (consuming exactly the one recovery
    // signature) instead of resetting.
    // line-length: allow — test name is one unbreakable token
    function testExampleRotateFullKeyPreservesStatelessUsageWhenStatelessMaterialUnchanged()
        public
    {
        (
            SHRINCS.SigningKey memory currentSigningKey,
            SHRINCS.PublicKey memory currentPublicKey,
            bool currentOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes(
                // line-length: allow — seed is one unbreakable token
                "account-example unchanged-stateless full rotation current key"
            ),
            4
        );
        assertTrue(currentOk, "current keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    currentPublicKey
                )
            );
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();
        account.setStatelessSignaturesUsed(9);

        // line-length: allow — fmt canonical tuple head exceeds cap
        (, SHRINCS.PublicKey memory nextPublicKey, bool nextOk) = SHRINCSAccountSigningFacade.keygen(
            bytes(
                "account-example unchanged-stateless full rotation next key"
            ),
            4
        );
        assertTrue(nextOk, "next keygen must succeed");

        // Replace only the stateful side; reuse the CURRENT stateless
        // material (pkSeed/hypertreeRoot) so this remains the SAME few-time
        // stateless key across the rotation.
        bytes32 nextCommitment = SHRINCS.publicKeyCommitmentFromParts(
            nextPublicKey.statefulPublicKey,
            currentPublicKey.pkSeed,
            currentPublicKey.hypertreeRoot
        );
        SHRINCS.RotationTarget memory nextKey = SHRINCS.RotationTarget({
            statefulPublicKey: nextPublicKey.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(nextCommitment),
            pkSeed: currentPublicKey.pkSeed,
            hypertreeRoot: currentPublicKey.hypertreeRoot
        });

        SHRINCSStatelessVectorSigner signer =
            new SHRINCSStatelessVectorSigner();
        // line-length: allow — fmt canonical tuple head exceeds cap
        (, bytes32 sessionId, bool signOk) = SHRINCSAccountSigningFacade.beginFullRotationSessionNow(
            signer, account, currentSigningKey, currentPublicKey, nextKey
        );
        assertTrue(signOk, "full rotation must start");

        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory recoverySignature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(completeOk, "full rotation must complete");

        bool rotateOk = account.rotateFullKey(
            currentPublicKey, recoverySignature, nextKey
        );

        assertTrue(
            rotateOk,
            "full rotation with unchanged stateless material must succeed"
        );
        assertEq(account.currentSHRINCSPublicKey(), nextCommitment);
        assertEq(
            account.statelessSignaturesUsed(),
            10,
            // line-length: allow — one unbreakable string literal token
            "reusing the current stateless key must preserve usage plus the consumed recovery signature"
        );
    }

    // Companion to the preservation test above: when the rotation target
    // DOES replace the stateless material, the budget must still reset to
    // zero (this is the safe case the Solidity source of truth always
    // took; the fix only makes the reset conditional, not disabled).
    // line-length: allow — test name is one unbreakable token
    function testExampleRotateFullKeyResetsStatelessUsageWhenStatelessMaterialChanges()
        public
    {
        (
            SHRINCS.SigningKey memory currentSigningKey,
            SHRINCS.PublicKey memory currentPublicKey,
            bool currentOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes(
                "account-example changed-stateless full rotation current key"
            ),
            4
        );
        assertTrue(currentOk, "current keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExampleHarness account =
            new SHRINCSAccountVerifierExampleHarness(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    currentPublicKey
                )
            );
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();
        account.setStatelessSignaturesUsed(9);

        // line-length: allow — fmt canonical tuple head exceeds cap
        (, SHRINCS.PublicKey memory nextPublicKey, bool nextOk) = SHRINCSAccountSigningFacade.keygen(
            bytes(
                "account-example changed-stateless full rotation next key"
            ),
            4
        );
        assertTrue(nextOk, "next keygen must succeed");

        SHRINCS.RotationTarget memory nextKey =
            SHRINCSAccountSigningFacade.fullRotationTarget(nextPublicKey);

        SHRINCSStatelessVectorSigner signer =
            new SHRINCSStatelessVectorSigner();
        // line-length: allow — fmt canonical tuple head exceeds cap
        (, bytes32 sessionId, bool signOk) = SHRINCSAccountSigningFacade.beginFullRotationSessionNow(
            signer, account, currentSigningKey, currentPublicKey, nextKey
        );
        assertTrue(signOk, "full rotation must start");

        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory recoverySignature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        assertTrue(completeOk, "full rotation must complete");

        bool rotateOk = account.rotateFullKey(
            currentPublicKey, recoverySignature, nextKey
        );

        assertTrue(
            rotateOk,
            "full rotation with changed stateless material must succeed"
        );
        assertEq(
            account.currentSHRINCSPublicKey(),
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                nextPublicKey
            )
        );
        assertEq(
            account.statelessSignaturesUsed(),
            0,
            "genuinely new stateless material must reset usage to zero"
        );
    }

    function actionContext(
        address account,
        uint256 nonceValue,
        uint256 keyVersionValue
    ) internal view returns (SHRINCS.ActionContext memory) {
        return SHRINCS.ActionContext({
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
