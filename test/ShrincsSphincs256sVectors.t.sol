// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "../lib/forge-std/src/Test.sol";
import { SHRINCS } from "../contracts/SHRINCS.sol";
import { ShrincsType } from "../contracts/ShrincsTypes.sol";

contract StatefulHarness {
    function verify(
        ShrincsType.ParameterSetId parameterSetId,
        ShrincsType.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsType.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(parameterSetId, publicKey, message, signature);
    }
}

contract StatelessHarness {
    function verify(
        ShrincsType.ParameterSetId parameterSetId,
        ShrincsType.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsType.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(parameterSetId, publicKey, message, signature);
    }
}

contract RotationHarness {
    function rotateStatefulViaStateless(
        ShrincsType.ParameterSetId parameterSetId,
        ShrincsType.PublicKey calldata currentPublicKey,
        bytes calldata recoveryMessage,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) external pure returns (bytes32) {
        return SHRINCS.rotateStatefulViaStateless(
            parameterSetId, currentPublicKey, recoveryMessage, recoverySignature, nextStatefulKey
        );
    }

    function rotateFullShrincsKey(
        ShrincsType.ParameterSetId parameterSetId,
        ShrincsType.PublicKey calldata currentPublicKey,
        bytes calldata recoveryMessage,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.rotateFullShrincsKey(
            parameterSetId, currentPublicKey, recoveryMessage, recoverySignature, nextKey
        );
    }
}

contract ShrincsSphincs256sVectorsTest is Test {
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
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        assertEq(stateful.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), true, "stateful valid");
    }

    function testStatefulSphincs256sRejectsWrongMessage() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.wrongMessage.calldata");
        assertEq(stateful.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateful wrong message");
    }

    function testStatefulSphincs256sRejectsWrongPublicKey() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.wrongPublicKey.calldata");
        assertEq(stateful.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateful wrong public key");
    }

    function testStatefulSphincs256sRejectsCorruptedSignature() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.corruptedSignature.calldata");
        assertEq(stateful.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateful corrupted signature");
    }

    function testStatelessSphincs256sValidSignatureVerifies() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(stateless.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), true, "stateless valid");
    }

    function testStatelessSphincs256sRejectsWrongMessage() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.wrongMessage.calldata");
        assertEq(stateless.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateless wrong message");
    }

    function testStatelessSphincs256sRejectsTamperedFors() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.tamperedFors.calldata");
        assertEq(stateless.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateless tampered FORS");
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeWotsPkHash() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.tamperedHypertreeWotsPkHash.calldata");
        assertEq(stateless.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateless tampered wots pk hash");
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeAuth() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.tamperedHypertreeAuth.calldata");
        assertEq(stateless.verify(ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature), false, "stateless tampered auth");
    }

    function testRotateStatefulViaStatelessReturnsNextCompositeCommitment() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        bytes memory nextStatefulPublicKey = bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[0] = bytes1(uint8(nextStatefulPublicKey[0]) ^ 0x01);
        ShrincsType.StatefulRotationTarget memory target = ShrincsType.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: nextStatefulPublicKey
        });

        bytes32 expected = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                nextStatefulPublicKey,
                publicKey.messagePkSeed,
                publicKey.messageRoot,
                publicKey.hypertreePkSeed,
                publicKey.hypertreeRoot
            )
        );

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature, target
        );
        assertEq(result, expected);
    }

    function testRotateStatefulViaStatelessRejectsWrongRecoveryMessage() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsType.StatefulRotationTarget memory target = ShrincsType.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: publicKey.statefulPublicKey
        });

        message[0] = bytes1(uint8(message[0]) ^ 0x01);

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature, target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsMalformedNextStatefulKey() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsType.StatefulRotationTarget memory target = ShrincsType.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: hex"1234"
        });

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature, target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyReturnsNextCompositeCommitment() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        bytes memory nextStatefulPublicKey = bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[0] = bytes1(uint8(nextStatefulPublicKey[0]) ^ 0x01);
        bytes memory nextMessagePkSeed = bytes.concat(publicKey.messagePkSeed);
        nextMessagePkSeed[0] = bytes1(uint8(nextMessagePkSeed[0]) ^ 0x01);
        bytes memory nextMessageRoot = bytes.concat(publicKey.messageRoot);
        nextMessageRoot[0] = bytes1(uint8(nextMessageRoot[0]) ^ 0x01);
        bytes memory nextHypertreePkSeed = bytes.concat(publicKey.hypertreePkSeed);
        nextHypertreePkSeed[0] = bytes1(uint8(nextHypertreePkSeed[0]) ^ 0x01);
        bytes memory nextHypertreeRoot = bytes.concat(publicKey.hypertreeRoot);
        nextHypertreeRoot[0] = bytes1(uint8(nextHypertreeRoot[0]) ^ 0x01);

        bytes32 expected = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                nextStatefulPublicKey,
                nextMessagePkSeed,
                nextMessageRoot,
                nextHypertreePkSeed,
                nextHypertreeRoot
            )
        );

        ShrincsType.RotationTarget memory target = ShrincsType.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: abi.encodePacked(expected),
            statefulPublicKey: nextStatefulPublicKey,
            messagePkSeed: nextMessagePkSeed,
            messageRoot: nextMessageRoot,
            hypertreePkSeed: nextHypertreePkSeed,
            hypertreeRoot: nextHypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature, target
        );
        assertEq(result, expected);
    }

    function testRotateFullShrincsKeyRejectsWrongRecoveryMessage() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsType.RotationTarget memory target = ShrincsType.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        message[0] = bytes1(uint8(message[0]) ^ 0x01);

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature, target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyRejectsMismatchedCompositeCommitment() public {
        (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsType.RotationTarget memory target = ShrincsType.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: abi.encodePacked(bytes32(uint256(1))),
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsType.ParameterSetId.Sphincs256sKeccak, publicKey, message, signature, target
        );
        assertEq(result, bytes32(0));
    }

    function _decodeStatefulVector(string memory vectorKey)
        internal
        returns (ShrincsType.PublicKey memory publicKey, bytes memory message, ShrincsType.StatefulSignature memory signature)
    {
        bytes memory args = _vectorArgs(vectorKey);
        (LegacyStatefulPublicKey memory legacyKey, bytes memory legacyMessage, LegacyStatefulSignature memory legacySignature) =
            abi.decode(args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature));

        (ShrincsType.PublicKey memory statelessPublicKey, ,) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        bytes memory encodedStatefulKey =
            abi.encodePacked(legacyKey.pkSeed, legacyKey.root, bytes4(legacyKey.maxSignatures));

        publicKey = ShrincsType.PublicKey({
            parameterSetId: ShrincsType.ParameterSetId.Sphincs256sKeccak,
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
        signature = ShrincsType.StatefulSignature({
            randomizer: legacySignature.randomizer,
            counter: legacySignature.counter,
            chains: _fixedToDynamicChains(legacySignature.chains),
            authPath: legacySignature.authPath
        });
    }

    function _decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            ShrincsType.PublicKey memory publicKey,
            bytes memory message,
            ShrincsType.StatelessSignature memory signature
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

        publicKey = ShrincsType.PublicKey({
            parameterSetId: ShrincsType.ParameterSetId.Sphincs256sKeccak,
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
        returns (ShrincsType.StatelessSignature memory signature)
    {
        ShrincsType.ForsEntry[] memory entries = new ShrincsType.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = ShrincsType.ForsEntry({sk: legacy.fors.entries[i].sk, auth: legacy.fors.entries[i].auth});
        }

        ShrincsType.HypertreeLayerSignature[] memory layers =
            new ShrincsType.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = ShrincsType.HypertreeLayerSignature({
                treeIndex: legacy.hypertree[i].treeIndex,
                leafIndex: legacy.hypertree[i].leafIndex,
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: ShrincsType.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature.randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = ShrincsType.StatelessSignature({
            fors: ShrincsType.ForsSignature({
                randomizer: legacy.fors.randomizer,
                counter: legacy.fors.counter,
                entries: entries
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
