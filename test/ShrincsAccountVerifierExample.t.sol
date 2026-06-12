// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "../lib/forge-std/src/Test.sol";
import { SHRINCS } from "../contracts/SHRINCS.sol";
import { ShrincsType } from "../contracts/ShrincsTypes.sol";
import { ShrincsAccountVerifierExample } from "../contracts/examples/ShrincsAccountVerifierExample.sol";

contract ExampleStatefulHarness {
    function verify(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        ShrincsType.ActionContext calldata context,
        ShrincsType.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(parameterSetId, expectedCompositePublicKey, publicKey, context, signature);
    }
}

contract ExampleStatelessHarness {
    function verify(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        ShrincsType.ActionContext calldata context,
        ShrincsType.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(parameterSetId, expectedCompositePublicKey, publicKey, context, signature);
    }
}

contract ExampleRotationHarness {
    function rotateFullShrincsKey(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext calldata context,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.rotateFullShrincsKey(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, recoverySignature, nextKey
        );
    }
}

contract ShrincsAccountVerifierExampleHarness is ShrincsAccountVerifierExample {
    constructor(bytes32 initialShrincsPublicKey) ShrincsAccountVerifierExample(initialShrincsPublicKey) { }

    function setStatelessSignaturesUsed(uint64 value) external {
        statelessSignaturesUsed = value;
    }
}

contract ShrincsAccountVerifierExampleTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";
    bytes32 internal constant DOMAIN_SEPARATOR = keccak256("shrincs-account-v1");

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

    ExampleStatefulHarness internal stateful;
    ExampleStatelessHarness internal stateless;
    ExampleRotationHarness internal rotation;
    string internal vectors;

    function setUp() public {
        stateful = new ExampleStatefulHarness();
        stateless = new ExampleStatelessHarness();
        rotation = new ExampleRotationHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testExampleInitializesStoredState() public {
        (ShrincsType.PublicKey memory publicKey, , ) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);

        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);

        assertEq(account.currentShrincsPublicKey(), expectedCompositePublicKey);
        assertTrue(
            uint8(account.parameterSetId()) == uint8(ShrincsType.ParameterSetId.Sphincs256sKeccakQ20),
            "parameter set must initialize to Q20 profile"
        );
        assertTrue(account.nonce() == 0, "nonce must initialize to zero");
        assertTrue(account.keyVersion() == 0, "key version must initialize to zero");
        assertTrue(account.statelessSignaturesUsed() == 0, "stateless usage must initialize to zero");
    }

    function testExampleVerifyStatefulActionMatchesLibraryAndPreservesStateOnFailure() public {
        (ShrincsType.PublicKey memory publicKey, , ShrincsType.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsType.ActionContext memory context = _actionContext(0, 0);

        bool expected = stateful.verify(
            ShrincsType.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature
        );
        bool actual = account.verifyStatefulAction(publicKey, context.actionType, context.payloadHash, signature);

        assertEq(actual, expected, "wrapper must match library result");
        assertEq(actual, false, "legacy raw vector must not verify through canonical wrapper path");
        assertTrue(account.nonce() == 0, "nonce must not change on failed stateful verify");
        assertTrue(account.keyVersion() == 0, "key version must not change on failed stateful verify");
        assertTrue(
            account.statelessSignaturesUsed() == 0, "stateless usage must not change on failed stateful verify"
        );
    }

    function testExampleVerifyStatelessActionMatchesLibraryAndPreservesStateOnFailure() public {
        (ShrincsType.PublicKey memory publicKey, , ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsType.ActionContext memory context = _actionContext(0, 0);

        bool expected = stateless.verify(
            ShrincsType.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature
        );
        bool actual = account.verifyStatelessAction(publicKey, context.actionType, context.payloadHash, signature);

        assertEq(actual, expected, "wrapper must match library result");
        assertEq(actual, false, "legacy raw vector must not verify through canonical wrapper path");
        assertTrue(account.nonce() == 0, "nonce must not change on failed stateless verify");
        assertTrue(account.keyVersion() == 0, "key version must not change on failed stateless verify");
        assertTrue(
            account.statelessSignaturesUsed() == 0, "stateless usage must not change on failed stateless verify"
        );
    }

    function testExampleRotateFullKeyMatchesLibraryAndPreservesStateOnFailure() public {
        (ShrincsType.PublicKey memory publicKey, , ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(expectedCompositePublicKey);
        ShrincsType.RotationContext memory context =
            ShrincsType.RotationContext({domainSeparator: DOMAIN_SEPARATOR, nonce: 0, keyVersion: 0});
        ShrincsType.RotationTarget memory target = ShrincsType.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 expected = rotation.rotateFullShrincsKey(
            ShrincsType.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature, target
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
        (ShrincsType.PublicKey memory publicKey, , ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account = new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);
        uint64 limit = ShrincsType.defaultParamsView(ShrincsType.ParameterSetId.Sphincs256sKeccakQ20)
            .statelessSignatureLimit;
        ShrincsType.ActionContext memory context = _actionContext(0, 0);

        account.setStatelessSignaturesUsed(limit);
        bool actual = account.verifyStatelessAction(publicKey, context.actionType, context.payloadHash, signature);

        assertEq(actual, false, "wrapper must stop stateless actions at usage limit");
        assertTrue(account.nonce() == 0, "nonce must stay unchanged at usage limit");
        assertTrue(account.statelessSignaturesUsed() == limit, "usage must stay unchanged at usage limit");
    }

    function testExampleRotateFullKeyRejectsAtUsageLimit() public {
        (ShrincsType.PublicKey memory publicKey, , ShrincsType.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsAccountVerifierExampleHarness account = new ShrincsAccountVerifierExampleHarness(expectedCompositePublicKey);
        uint64 limit = ShrincsType.defaultParamsView(ShrincsType.ParameterSetId.Sphincs256sKeccakQ20)
            .statelessSignatureLimit;
        ShrincsType.RotationTarget memory target = ShrincsType.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
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

    function _actionContext(uint256 nonceValue, uint256 keyVersionValue)
        internal
        pure
        returns (ShrincsType.ActionContext memory)
    {
        return ShrincsType.ActionContext({
            domainSeparator: DOMAIN_SEPARATOR,
            nonce: nonceValue,
            keyVersion: keyVersionValue,
            actionType: keccak256("execute"),
            payloadHash: keccak256("payload")
        });
    }

    function _compositePublicKeyWord(ShrincsType.PublicKey memory publicKey) internal pure returns (bytes32 word) {
        require(publicKey.compositePublicKey.length == 32, "composite key length");
        bytes memory compositePublicKey = publicKey.compositePublicKey;
        assembly {
            word := mload(add(compositePublicKey, 32))
        }
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
            parameterSetId: ShrincsType.ParameterSetId.Sphincs256sKeccakQ20,
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
            parameterSetId: ShrincsType.ParameterSetId.Sphincs256sKeccakQ20,
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
