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
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";

contract ShrincsStatefulPolicyHarness is SHRINCSAccountVerifierExample {
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
}

contract ShrincsStatefulPolicyExamplesTest is Test {
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

    string internal vectors;

    function setUp() public {
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testDefaultMonotonicPolicyRejectsRepeatedValidStatefulUse()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        ShrincsStatefulPolicyHarness account =
            new ShrincsStatefulPolicyHarness(expectedCompositePublicKey);

        bool first = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );
        bool second = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );

        assertEq(
            first, true, "first raw stateful verification should succeed"
        );
        assertEq(
            second,
            false,
            // line-length: allow — one unbreakable string literal token
            "default monotonic policy must reject repeated raw stateful verification"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testMonotonicIndexExampleAcceptsExpectedLeafAndThenRejectsReplay()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        uint32 leafIndex = uint32(signature.authPath.length);
        ShrincsStatefulPolicyHarness account =
            new ShrincsStatefulPolicyHarness(expectedCompositePublicKey);
        account.setStatefulPolicyMonotonicIndex(leafIndex);

        bool first = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );
        bool second = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );

        assertEq(first, true, "expected leaf index should verify once");
        assertEq(
            second, false, "same leaf index must be rejected after increment"
        );
        assertTrue(
            account.nextStatefulLeafIndex() == leafIndex + 1,
            "next leaf index must advance"
        );
    }

    function testMonotonicIndexExampleRejectsUnexpectedLeafIndex() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        uint32 leafIndex = uint32(signature.authPath.length);
        ShrincsStatefulPolicyHarness account =
            new ShrincsStatefulPolicyHarness(expectedCompositePublicKey);
        account.setStatefulPolicyMonotonicIndex(leafIndex + 1);

        bool ok = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );

        assertEq(ok, false, "unexpected leaf index must be rejected");
        assertTrue(
            account.nextStatefulLeafIndex() == leafIndex + 1,
            "unexpected leaf must not advance state"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testRecoveryRotationExampleBlocksStatefulPathBeforeAndDuringRecoveryMode()
        public
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        ShrincsStatefulPolicyHarness account =
            new ShrincsStatefulPolicyHarness(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        assertEq(
            account.verifyStatefulUncheckedForTest(
                publicKey, message, signature
            ),
            false,
            // line-length: allow — one unbreakable string literal token
            "stateful raw path must be blocked as soon as recovery-rotation policy is selected"
        );
        account.enterRecoveryMode();
        assertEq(
            account.verifyStatefulUncheckedForTest(
                publicKey, message, signature
            ),
            false,
            "stateful raw path must be blocked in recovery mode"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testRecoveryRotationExampleKeepsLegacyRawStatelessVectorOutOfCanonicalWrapper()
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
        account.setStatefulPolicyRecoveryRotation();

        bytes32 actionType = keccak256("action");
        bytes32 payloadHash = keccak256("payload");

        assertEq(
            account.verifyStatelessAction(
                publicKey, actionType, payloadHash, signature
            ),
            false,
            "canonical stateless path should be blocked before recovery mode"
        );
        account.enterRecoveryMode();

        bool ok = account.verifyStatelessAction(
            publicKey, actionType, payloadHash, signature
        );

        assertEq(
            ok,
            false,
            // line-length: allow — one unbreakable string literal token
            "legacy raw vector must not verify through canonical stateless wrapper path"
        );
        assertTrue(
            account.statelessSignaturesUsed() == 0,
            "failed canonical stateless verify must not increment"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testRecoveryRotationExampleRejectsLegacyRotationAuthorizationAndKeepsRecoveryMode()
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
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        SHRINCSCore.StatefulRotationTarget memory target =
            statefulRotationTargetFromParts(
                publicKey, publicKey.statefulPublicKey
            );

        bool ok = account.rotateToFreshKey(publicKey, signature, target);

        assertEq(
            ok,
            false,
            // line-length: allow — one unbreakable string literal token
            "legacy raw stateless vector must not authorize canonical rotation"
        );
        assertEq(
            account.recoveryMode(),
            true,
            "failed rotation must keep recovery mode enabled"
        );
        assertEq(
            account.currentSHRINCSPublicKey(), expectedCompositePublicKey
        );
    }

    function testLeafBitmapExampleRejectsReuseOfSameLeaf() public {
        (
            SHRINCSCore.PublicKey memory publicKey,
            bytes memory message,
            UXMSS.StatefulSignature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey =
            compositePublicKeyWord(publicKey);
        uint32 leafIndex = uint32(signature.authPath.length);
        ShrincsStatefulPolicyHarness account =
            new ShrincsStatefulPolicyHarness(expectedCompositePublicKey);
        account.setStatefulPolicyLeafBitmap();

        bool first = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );
        bool second = account.verifyStatefulUncheckedForTest(
            publicKey, message, signature
        );

        assertEq(
            first,
            true,
            "first bitmap-tracked stateful verification should succeed"
        );
        assertEq(
            second, false, "same leaf must be rejected once marked used"
        );
        assertEq(
            account.isLeafUsed(leafIndex),
            true,
            "leaf bitmap must mark the leaf as used"
        );
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
