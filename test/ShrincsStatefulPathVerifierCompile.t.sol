// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatefulPathVerifier } from "../contracts/ShrincsStatefulPathVerifier.sol";

contract ShrincsStatefulPathVerifierCompileTest {
    function testVerifierDeploys() external {
        ShrincsStatefulPathVerifier verifier = new ShrincsStatefulPathVerifier();
        assert(address(verifier) != address(0));
    }
}
