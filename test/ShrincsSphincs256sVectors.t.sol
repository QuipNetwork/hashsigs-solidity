// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "../lib/forge-std/src/Test.sol";
import { SHRINCS } from "../contracts/SHRINCS.sol";
import { ShrincsTypes } from "../contracts/ShrincsTypes.sol";

contract StatefulHarness {
    function verifyUnsafeRaw(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatefulUnsafeRaw(
            parameterSetId, expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verify(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(parameterSetId, expectedCompositePublicKey, publicKey, context, signature);
    }

    function actionMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCS.statefulActionMessageHash(parameterSetId, expectedCompositePublicKey, context);
    }
}

contract StatelessHarness {
    function verifyUnsafeRaw(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatelessUnsafeRaw(
            parameterSetId, expectedCompositePublicKey, publicKey, message, signature
        );
    }

    function verify(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(parameterSetId, expectedCompositePublicKey, publicKey, context, signature);
    }

    function actionMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.ActionContext calldata context
    ) external pure returns (bytes32) {
        return SHRINCS.statelessActionMessageHash(parameterSetId, expectedCompositePublicKey, context);
    }
}

contract RotationHarness {
    function statefulRotationMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) external pure returns (bytes32) {
        return SHRINCS.statefulRotationMessageHash(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextStatefulKey
        );
    }

    function fullRotationMessageHash(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.fullRotationMessageHash(parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextKey);
    }

    function rotateStatefulViaStateless(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) external pure returns (bytes32) {
        return SHRINCS.rotateStatefulViaStateless(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, recoverySignature, nextStatefulKey
        );
    }

    function rotateFullShrincsKey(
        ShrincsTypes.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext calldata context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external pure returns (bytes32) {
        return SHRINCS.rotateFullShrincsKey(
            parameterSetId, expectedCompositePublicKey, currentPublicKey, context, recoverySignature, nextKey
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
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            true,
            "stateful valid"
        );
    }

    function testStatefulSphincs256sRejectsWrongMessage() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.wrongMessage.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful wrong message"
        );
    }

    function testStatefulSphincs256sRejectsWrongPublicKey() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.wrongPublicKey.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful wrong public key"
        );
    }

    function testStatefulSphincs256sRejectsWrongExpectedCompositePublicKey() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 wrongExpectedCompositePublicKey = _compositePublicKeyWord(publicKey) ^ bytes32(uint256(1));
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
                wrongExpectedCompositePublicKey,
                publicKey,
                message,
                signature
            ),
            false,
            "stateful wrong expected composite public key"
        );
    }

    function testStatefulSphincs256sRejectsZeroExpectedCompositePublicKey() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, bytes32(0), publicKey, message, signature
            ),
            false,
            "stateful zero expected composite public key"
        );
    }

    function testStatefulSphincs256sRejectsUnsupportedRequestedParameterSet() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Unsupported, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful unsupported requested parameter set"
        );
    }

    function testStatefulSphincs256sRejectsMismatchedDeclaredParameterSet() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        publicKey.parameterSetId = ShrincsTypes.ParameterSetId.Unsupported;
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful mismatched declared parameter set"
        );
    }

    function testStatefulSphincs256sRejectsCorruptedSignature() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.corruptedSignature.calldata");
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful corrupted signature"
        );
    }

    function testStatefulSphincs256sRejectsTamperedAuthPath() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.authPath[0] = signature.authPath[0] ^ bytes32(uint256(1));
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful tampered auth path"
        );
    }

    function testStatefulSphincs256sAcceptsMaxSignaturesBoundary() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        _setStatefulMaxSignatures(publicKey, uint32(signature.authPath.length));
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            true,
            "stateful max signatures boundary"
        );
    }

    function testStatefulSphincs256sRejectsExceededMaxSignatures() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        _setStatefulMaxSignatures(publicKey, uint32(signature.authPath.length - 1));
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful exceeds max signatures"
        );
    }

    function testStatefulSphincs256sRejectsMalformedMessagePkSeedLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        publicKey.messagePkSeed = hex"1234";
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful malformed messagePkSeed length"
        );
    }

    function testStatefulSphincs256sRejectsWrongWotsChainCount() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.chains = _dropLastBytes32(signature.chains);
        assertEq(
            stateful.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateful wrong WOTS chain count"
        );
    }

    function testStatelessSphincs256sValidSignatureVerifies() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            true,
            "stateless valid"
        );
    }

    function testStatelessSphincs256sRejectsWrongMessage() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.wrongMessage.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless wrong message"
        );
    }

    function testStatelessSphincs256sRejectsTamperedFors() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.tamperedFors.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless tampered FORS"
        );
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeWotsPkHash() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.tamperedHypertreeWotsPkHash.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless tampered wots pk hash"
        );
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeAuth() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.tamperedHypertreeAuth.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless tampered auth"
        );
    }

    function testStatelessSphincs256sRejectsWrongExpectedCompositePublicKey() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 wrongExpectedCompositePublicKey = _compositePublicKeyWord(publicKey) ^ bytes32(uint256(1));
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
                wrongExpectedCompositePublicKey,
                publicKey,
                message,
                signature
            ),
            false,
            "stateless wrong expected composite public key"
        );
    }

    function testStatelessSphincs256sRejectsZeroExpectedCompositePublicKey() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, bytes32(0), publicKey, message, signature
            ),
            false,
            "stateless zero expected composite public key"
        );
    }

    function testStatelessSphincs256sRejectsUnsupportedRequestedParameterSet() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Unsupported, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless unsupported requested parameter set"
        );
    }

    function testStatelessSphincs256sRejectsMismatchedDeclaredParameterSet() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.parameterSetId = ShrincsTypes.ParameterSetId.Unsupported;
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless mismatched declared parameter set"
        );
    }

    function testStatelessSphincs256sRejectsMalformedCompositePublicKeyLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.compositePublicKey = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, bytes32(0), publicKey, message, signature
            ),
            false,
            "stateless malformed compositePublicKey length"
        );
    }

    function testStatelessSphincs256sRejectsMalformedMessagePkSeedLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.messagePkSeed = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless malformed messagePkSeed length"
        );
    }

    function testStatelessSphincs256sRejectsMalformedMessageRootLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.messageRoot = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless malformed messageRoot length"
        );
    }

    function testStatelessSphincs256sRejectsMalformedHypertreePkSeedLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.hypertreePkSeed = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless malformed hypertreePkSeed length"
        );
    }

    function testStatelessSphincs256sRejectsMalformedHypertreeRootLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        publicKey.hypertreeRoot = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless malformed hypertreeRoot length"
        );
    }

    function testStatelessSphincs256sRejectsHypertreeLeafIndexOutOfRange() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].leafIndex = 256;
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless hypertree leaf index out of range"
        );
    }

    function testStatelessSphincs256sRejectsMalformedHypertreeWotsChainLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].wotsCSignature.chains[0] = hex"1234";
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless malformed hypertree WOTS chain length"
        );
    }

    function testStatelessSphincs256sRejectsWrongHypertreeAuthPathLength() public {
        (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath = _dropLastBytes(signature.hypertree[0].authPath);
        assertEq(
            stateless.verifyUnsafeRaw(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, message, signature
            ),
            false,
            "stateless wrong hypertree auth path length"
        );
    }

    function testStatefulActionMessageHashBindsContext() public {
        (ShrincsTypes.PublicKey memory publicKey, , ) = _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsTypes.ActionContext memory first = ShrincsTypes.ActionContext({
            domainSeparator: keccak256("shrincs-account"),
            nonce: 1,
            keyVersion: 3,
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

        assertTrue(
            stateful.actionMessageHash(ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, first)
                != stateful.actionMessageHash(
                    ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, second
                ),
            "stateful action hash must bind payload"
        );
    }

    function testStatefulVerifyRejectsZeroActionContextFields() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatefulSignature memory signature) =
            _decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: bytes32(0),
            nonce: 1,
            keyVersion: 1,
            actionType: bytes32(0),
            payloadHash: bytes32(0)
        });
        assertEq(
            stateful.verify(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateful zero action context"
        );
    }

    function testStatelessActionMessageHashBindsContext() public {
        (ShrincsTypes.PublicKey memory publicKey, , ) = _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
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
            stateless.actionMessageHash(ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, first)
                != stateless.actionMessageHash(
                    ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, second
                ),
            "stateless action hash must bind nonce"
        );
    }

    function testStatelessVerifyRejectsZeroActionContextFields() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 expectedCompositePublicKey = _compositePublicKeyWord(publicKey);
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: bytes32(0),
            nonce: 1,
            keyVersion: 1,
            actionType: bytes32(0),
            payloadHash: bytes32(0)
        });
        assertEq(
            stateless.verify(
                ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, expectedCompositePublicKey, publicKey, context, signature
            ),
            false,
            "stateless zero action context"
        );
    }

    function testRotateStatefulViaStatelessReturnsNextCompositeCommitment() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 7, keyVersion: 1});
        bytes memory nextStatefulPublicKey = bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[0] = bytes1(uint8(nextStatefulPublicKey[0]) ^ 0x01);
        ShrincsTypes.StatefulRotationTarget memory target = ShrincsTypes.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: nextStatefulPublicKey
        });
        bytes32 first = rotation.statefulRotationMessageHash(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, context, target
        );
        nextStatefulPublicKey[1] = bytes1(uint8(nextStatefulPublicKey[1]) ^ 0x01);
        target.statefulPublicKey = nextStatefulPublicKey;
        bytes32 second = rotation.statefulRotationMessageHash(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, context, target
        );
        assertTrue(first != second, "stateful rotation hash must bind next stateful key");
    }

    function testRotateStatefulViaStatelessRejectsLegacyVectorAuthorization() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 7, keyVersion: 1});
        ShrincsTypes.StatefulRotationTarget memory target = ShrincsTypes.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: publicKey.statefulPublicKey
        });

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsMalformedNextStatefulKey() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 7, keyVersion: 1});
        ShrincsTypes.StatefulRotationTarget memory target = ShrincsTypes.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: hex"1234"
        });

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsUnsupportedNextParameterSet() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 7, keyVersion: 1});
        ShrincsTypes.StatefulRotationTarget memory target = ShrincsTypes.StatefulRotationTarget({
            parameterSetId: ShrincsTypes.ParameterSetId.Unsupported,
            statefulPublicKey: publicKey.statefulPublicKey
        });

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsZeroDomainSeparator() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: bytes32(0), nonce: 7, keyVersion: 1});
        ShrincsTypes.StatefulRotationTarget memory target = ShrincsTypes.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: publicKey.statefulPublicKey
        });

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateStatefulViaStatelessRejectsZeroMaxSignaturesNextStatefulKey() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 7, keyVersion: 1});
        bytes memory nextStatefulPublicKey = bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[64] = bytes1(0);
        nextStatefulPublicKey[65] = bytes1(0);
        nextStatefulPublicKey[66] = bytes1(0);
        nextStatefulPublicKey[67] = bytes1(0);
        ShrincsTypes.StatefulRotationTarget memory target = ShrincsTypes.StatefulRotationTarget({
            parameterSetId: publicKey.parameterSetId,
            statefulPublicKey: nextStatefulPublicKey
        });

        bytes32 result = rotation.rotateStatefulViaStateless(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyReturnsNextCompositeCommitment() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
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

        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: abi.encodePacked(expected),
            statefulPublicKey: nextStatefulPublicKey,
            messagePkSeed: nextMessagePkSeed,
            messageRoot: nextMessageRoot,
            hypertreePkSeed: nextHypertreePkSeed,
            hypertreeRoot: nextHypertreeRoot
        });
        bytes32 first = rotation.fullRotationMessageHash(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, context, target
        );
        nextHypertreeRoot[0] = bytes1(uint8(nextHypertreeRoot[0]) ^ 0x01);
        target.hypertreeRoot = nextHypertreeRoot;
        bytes32 second = rotation.fullRotationMessageHash(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20, _compositePublicKeyWord(publicKey), publicKey, context, target
        );
        assertTrue(first != second, "full rotation hash must bind next key bundle");
    }

    function testRotateFullShrincsKeyRejectsLegacyVectorAuthorization() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyRejectsMismatchedCompositeCommitment() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: abi.encodePacked(bytes32(uint256(1))),
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyRejectsUnsupportedNextParameterSet() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: ShrincsTypes.ParameterSetId.Unsupported,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyRejectsZeroDomainSeparator() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: bytes32(0), nonce: 11, keyVersion: 2});
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: publicKey.statefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
    }

    function testRotateFullShrincsKeyRejectsZeroMaxSignaturesNextStatefulKey() public {
        (ShrincsTypes.PublicKey memory publicKey, , ShrincsTypes.StatelessSignature memory signature) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: keccak256("shrincs-test"), nonce: 11, keyVersion: 2});
        bytes memory nextStatefulPublicKey = bytes.concat(publicKey.statefulPublicKey);
        nextStatefulPublicKey[64] = bytes1(0);
        nextStatefulPublicKey[65] = bytes1(0);
        nextStatefulPublicKey[66] = bytes1(0);
        nextStatefulPublicKey[67] = bytes1(0);
        ShrincsTypes.RotationTarget memory target = ShrincsTypes.RotationTarget({
            parameterSetId: publicKey.parameterSetId,
            compositePublicKey: publicKey.compositePublicKey,
            statefulPublicKey: nextStatefulPublicKey,
            messagePkSeed: publicKey.messagePkSeed,
            messageRoot: publicKey.messageRoot,
            hypertreePkSeed: publicKey.hypertreePkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });

        bytes32 result = rotation.rotateFullShrincsKey(
            ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20,
            _compositePublicKeyWord(publicKey),
            publicKey,
            context,
            signature,
            target
        );
        assertEq(result, bytes32(0));
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
        returns (ShrincsTypes.PublicKey memory publicKey, bytes memory message, ShrincsTypes.StatefulSignature memory signature)
    {
        bytes memory args = _vectorArgs(vectorKey);
        (LegacyStatefulPublicKey memory legacyKey, bytes memory legacyMessage, LegacyStatefulSignature memory legacySignature) =
            abi.decode(args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature));

        (ShrincsTypes.PublicKey memory statelessPublicKey, ,) =
            _decodeStatelessVector(".stateless.cases.valid.calldata");

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

    function _setStatefulMaxSignatures(ShrincsTypes.PublicKey memory publicKey, uint32 maxSignatures) internal pure {
        publicKey.statefulPublicKey[64] = bytes1(uint8(maxSignatures >> 24));
        publicKey.statefulPublicKey[65] = bytes1(uint8(maxSignatures >> 16));
        publicKey.statefulPublicKey[66] = bytes1(uint8(maxSignatures >> 8));
        publicKey.statefulPublicKey[67] = bytes1(uint8(maxSignatures));
        publicKey.compositePublicKey = abi.encodePacked(
            keccak256(
                abi.encodePacked(
                    "shrincs-public-key",
                    publicKey.statefulPublicKey,
                    publicKey.messagePkSeed,
                    publicKey.messageRoot,
                    publicKey.hypertreePkSeed,
                    publicKey.hypertreeRoot
                )
            )
        );
    }

    function _dropLastBytes32(bytes32[] memory input) internal pure returns (bytes32[] memory output) {
        output = new bytes32[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function _dropLastBytes(bytes[] memory input) internal pure returns (bytes[] memory output) {
        output = new bytes[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
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
