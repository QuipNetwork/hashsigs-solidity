// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "../lib/forge-std/src/Test.sol";
import { SHRINCS } from "../contracts/SHRINCS.sol";
import { ShrincsType } from "../contracts/ShrincsType.sol";

contract StatefulHarness {
    function verify(
        ShrincsType.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsType.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(publicKey, message, signature);
    }
}

contract StatelessHarness {
    function verify(
        ShrincsType.Params calldata params,
        ShrincsType.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsType.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateless(params, publicKey, message, signature);
    }
}

contract ShrincsSphincs256sVectorsTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    StatefulHarness internal stateful;
    StatelessHarness internal stateless;
    string internal vectors;

    function setUp() public {
        stateful = new StatefulHarness();
        stateless = new StatelessHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testStatefulSphincs256sValidSignatureVerifies() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.valid.calldata", true);
    }

    function testStatefulSphincs256sRejectsWrongMessage() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.wrongMessage.calldata", false);
    }

    //stateful public key root is tampered, so signature should be rejected
    function testStatefulSphincs256sRejectsWrongPublicKey() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.wrongPublicKey.calldata", false);
    }

    //one wots-c signature chain element is tampered, so reconstruct public key root should be wrong and signature should be rejected
    function testStatefulSphincs256sRejectsCorruptedSignature() public {
        _assertVerifierCall(address(stateful), ".stateful.cases.corruptedSignature.calldata", false);
    }

    function testStatelessSphincs256sValidSignatureVerifies() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.valid.calldata", true);
    }

    function testStatelessSphincs256sRejectsWrongMessage() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.wrongMessage.calldata", false);
    }

    //tamper with one of the revealed secret keys in the FORS signature so reconstructed FORS pk root will be wrong and signature should be rejected
    function testStatelessSphincs256sRejectsTamperedFors() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.tamperedFors.calldata", false);
    }

    //tamper with WOTS-C public key hash so reconstructed hypertree leaf will not match public hypertree leaf so root will not match public hypertree root and signature should be rejected
    function testStatelessSphincs256sRejectsTamperedHypertreeWotsPkHash() public {
        _assertVerifierCall(address(stateless), ".stateless.cases.tamperedHypertreeWotsPkHash.calldata", false);
    }

    //tamper authentication-path node so reconstructed XMSS root will not match public hypertree root
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
