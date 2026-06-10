// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessPathVerifier } from "../contracts/ShrincsStatelessPathVerifier.sol";
import { ShrincsForsCNoMaskVerifier } from "../contracts/ShrincsForsCNoMaskVerifier.sol";

contract ShrincsStatelessPathVerifierCompileTest {
    function testVerifierDeploys() external {
        ShrincsStatelessPathVerifier verifier = new ShrincsStatelessPathVerifier();
        assert(address(verifier) != address(0));
    }

    function testForsCNoMaskVerifierDeploys() external {
        ShrincsForsCNoMaskVerifier verifier = new ShrincsForsCNoMaskVerifier();
        assert(address(verifier) != address(0));
    }
}
