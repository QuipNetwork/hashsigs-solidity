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
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsAccountVerifierExample} from "../contracts/examples/ShrincsAccountVerifierExample.sol";

contract ShrincsStatefulPolicyExamplesTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";

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
        bytes compositePublicKey;
        bytes statefulPublicKey;
        bytes messagePkSeed;
        bytes messageRoot;
        bytes hypertreePkSeed;
        bytes hypertreeRoot;
    }

    struct LegacyForsEntry {
        bytes sk;
        bytes[] auth;
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

    function testNoStateTrackingExampleAllowsRepeatedValidStatefulUse() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyNone();

        bool first = account.verifyStatefulRaw(publicKey, message, signature);
        bool second = account.verifyStatefulRaw(publicKey, message, signature);

        assertEq(first, true, "first raw stateful verification should succeed");
        assertEq(second, true, "repeated raw stateful verification should still succeed");
    }

    function testMonotonicIndexExampleAcceptsExpectedLeafAndThenRejectsReplay() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        uint32 leafIndex = uint32(signature.authPath.length);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyMonotonicIndex(leafIndex);

        bool first = account.verifyStatefulRaw(publicKey, message, signature);
        bool second = account.verifyStatefulRaw(publicKey, message, signature);

        assertEq(first, true, "expected leaf index should verify once");
        assertEq(second, false, "same leaf index must be rejected after increment");
        assertTrue(account.nextStatefulLeafIndex() == leafIndex + 1, "next leaf index must advance");
    }

    function testMonotonicIndexExampleRejectsUnexpectedLeafIndex() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        uint32 leafIndex = uint32(signature.authPath.length);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyMonotonicIndex(leafIndex + 1);

        bool ok = account.verifyStatefulRaw(publicKey, message, signature);

        assertEq(ok, false, "unexpected leaf index must be rejected");
        assertTrue(account.nextStatefulLeafIndex() == leafIndex + 1, "unexpected leaf must not advance state");
    }

    function testRecoveryRotationExampleBlocksStatefulPathInRecoveryMode() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        assertEq(
            account.verifyStatefulRaw(publicKey, message, signature),
            true,
            "stateful raw path should work before recovery"
        );
        account.enterRecoveryMode();
        assertEq(
            account.verifyStatefulRaw(publicKey, message, signature),
            false,
            "stateful raw path must be blocked in recovery mode"
        );
    }

    function testRecoveryRotationExampleAllowsStatelessPathInRecoveryMode() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        ) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();

        assertEq(
            account.verifyStatelessRaw(publicKey, message, signature),
            false,
            "stateless raw path should be off before recovery mode"
        );
        account.enterRecoveryMode();

        bool ok = account.verifyStatelessRaw(publicKey, message, signature);

        assertEq(ok, true, "stateless raw path should work in recovery mode");
        assertTrue(account.statelessSignaturesUsed() == 1, "recovery stateless usage must increment");
    }

    function testRecoveryRotationExampleRejectsLegacyRotationAuthorizationAndKeepsRecoveryMode() public {
        (ShrincsTypes.PublicKey memory publicKey,, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyRecoveryRotation();
        account.enterRecoveryMode();

        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bool ok = account.rotateToFreshKey(publicKey, signature, target);

        assertEq(ok, false, "legacy raw stateless vector must not authorize canonical rotation");
        assertEq(account.recoveryMode(), true, "failed rotation must keep recovery mode enabled");
        assertEq(account.currentShrincsPublicKey(), expectedCompositePublicKey);
    }

    function testLeafBitmapExampleRejectsReuseOfSameLeaf() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        uint32 leafIndex = uint32(signature.authPath.length);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        account.setStatefulPolicyLeafBitmap();

        bool first = account.verifyStatefulRaw(publicKey, message, signature);
        bool second = account.verifyStatefulRaw(publicKey, message, signature);

        assertEq(first, true, "first bitmap-tracked stateful verification should succeed");
        assertEq(second, false, "same leaf must be rejected once marked used");
        assertEq(account.isLeafUsed(leafIndex), true, "leaf bitmap must mark the leaf as used");
    }

    function _compositePublicKeyWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 word) {
        require(publicKey.compositePublicKey.length == 32, "composite key length");
        bytes memory compositePublicKey = publicKey.compositePublicKey;
        assembly {
            word := mload(add(compositePublicKey, 32))
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
            compositePublicKey: abi.encodePacked(
                keccak256(
                    abi.encodePacked(
                        "shrincs-public-key",
                        encodedStatefulKey,
                        statelessPublicKey.messagePkSeed,
                        statelessPublicKey.messageRoot,
                        statelessPublicKey.hypertreePkSeed,
                        statelessPublicKey.hypertreeRoot
                    )
                )
            ),
            statefulPublicKey: encodedStatefulKey,
            messagePkSeed: statelessPublicKey.messagePkSeed,
            messageRoot: statelessPublicKey.messageRoot,
            hypertreePkSeed: statelessPublicKey.hypertreePkSeed,
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
            parameterSetId: ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            compositePublicKey: legacyPublicKey.compositePublicKey,
            statefulPublicKey: legacyPublicKey.statefulPublicKey,
            messagePkSeed: legacyPublicKey.messagePkSeed,
            messageRoot: legacyPublicKey.messageRoot,
            hypertreePkSeed: legacyPublicKey.hypertreePkSeed,
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
            entries[i] = ShrincsTypes.ForsEntry({sk: legacy.fors.entries[i].sk, auth: legacy.fors.entries[i].auth});
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
