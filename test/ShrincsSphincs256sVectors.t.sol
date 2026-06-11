// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "../lib/forge-std/src/Test.sol";
import { ShrincsStatefulPathVerifier } from "../contracts/ShrincsStatefulPathVerifier.sol";
import { ShrincsStatelessPathVerifier } from "../contracts/ShrincsStatelessPathVerifier.sol";

contract ShrincsSphincs256sVectorsTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    ShrincsStatefulPathVerifier internal stateful;
    ShrincsStatelessPathVerifier internal stateless;
    string internal vectors;

    function setUp() public {
        stateful = new ShrincsStatefulPathVerifier();
        stateless = new ShrincsStatelessPathVerifier();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testStatefulSphincs256sValidSignatureVerifies() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.valid.calldata", true);
    }

    function testStatefulSphincs256sRejectsWrongMessage() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.wrongMessage.calldata", false);
    }

    function testStatefulSphincs256sRejectsWrongPublicKey() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.wrongPublicKey.calldata", false);
    }

    function testStatefulSphincs256sRejectsCorruptedSignature() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.corruptedSignature.calldata", false);
    }

    function testStatelessSphincs256sValidSignatureVerifies() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.valid.calldata", true);
    }

    function testStatelessSphincs256sRejectsWrongMessage() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.wrongMessage.calldata", false);
    }

    function testStatelessSphincs256sRejectsWrongCompositePublicKey() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.wrongCompositePublicKey.calldata", false);
    }

    function testStatelessSphincs256sRejectsTamperedComponentPublicKey() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.tamperedComponentPublicKey.calldata", false);
    }

    function testStatelessSphincs256sRejectsTamperedFors() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.tamperedFors.calldata", false);
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeWotsPkHash() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.tamperedHypertreeWotsPkHash.calldata", false);
    }

    function testStatelessSphincs256sRejectsTamperedHypertreeAuth() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.tamperedHypertreeAuth.calldata", false);
    }

    function _assertVerifierCall(address verifier, string memory vectorKey, bool expected) internal {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();

        (bool ok, bytes memory result) = verifier.staticcall(callData);

        vm.pauseGasMetering();
        assertTrue(ok, string.concat(vectorKey, " call reverted"));
        assertEq(abi.decode(result, (bool)), expected, vectorKey);
        vm.resumeGasMetering();
    }
}
