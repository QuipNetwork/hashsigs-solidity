// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

/// @notice Acceptance tests for the required external-audit remediations.
/// @dev Each test fails while its corresponding finding remains unresolved.
contract ExternalAuditRemediationTest is Test {
    function test_issue03_rawAdaptersBindCommitment() public view {
        string memory s = vm.readFile("contracts/SHRINCSVerifier.sol");
        assertFalse(vm.contains(s, ".verify(delegateKey, hash,"));
        assertFalse(vm.contains(s, "publicKeyCommitment, hash, publicKey"));
    }

    function test_issue04_compressionsIncludeAddressTweaks() public view {
        string memory h = vm.readFile("contracts/Hypertree.sol");
        string memory f = vm.readFile("contracts/FORSMinusC.sol");
        assertTrue(vm.contains(h, "AddressTypeWotsPk"));
        assertTrue(vm.contains(f, "AddressTypeForsRoots"));
    }

    function test_issue05_helpersValidateBeforeSuccess() public view {
        string memory h = vm.readFile("contracts/Hypertree.sol");
        string memory u = vm.readFile("contracts/UXMSS.sol");
        string memory s = vm.readFile("contracts/SHRINCS.sol");
        assertTrue(vm.contains(h, "authPath.length != height"));
        assertTrue(vm.contains(u, "authPath.length == 0"));
        assertTrue(vm.contains(s, "encoded.length !="));
    }

    function test_issue06_rawStatefulDigestBindsKey() public view {
        string memory s = vm.readFile("contracts/SHRINCSVerifier.sol");
        assertFalse(vm.contains(s, "publicKeyCommitment, hash, publicKey"));
    }

    function test_issue07_mutabilityDocumentationIsAccurate() public view {
        string memory a = vm.readFile("contracts/SHRINCSVerifier.sol");
        string memory b = vm.readFile("contracts/SPHINCSPlusCVerifier.sol");
        assertFalse(vm.contains(a, "Every SHRINCS library is `pure`"));
        assertFalse(vm.contains(b, "library is `pure`"));
    }

    function test_issue08_forsShapeIsExplicitlyChecked() public view {
        string memory s = vm.readFile("contracts/FORSMinusC.sol");
        assertTrue(vm.contains(s, "signature.entries.length"));
        assertTrue(vm.contains(s, "signature.randomizer.length"));
    }

    function test_issue09_statefulRootIsMaskChecked() public view {
        string memory s = vm.readFile("contracts/SHRINCS.sol");
        assertTrue(vm.contains(s, "HASH_MASK"));
    }

    function test_issue10_sliceBoundsCheckedBeforeSubtraction() public view {
        string memory s = vm.readFile("contracts/SHRINCS.sol");
        assertTrue(vm.contains(s, "if lt(bodyEnd, signature)"));
        assertTrue(vm.contains(s, "calldatasize()"));
    }

    function test_issue11_sliceAllocationIsWordAligned() public view {
        string memory s = vm.readFile("contracts/SHRINCS.sol");
        assertFalse(
            vm.contains(
                s, "mstore(0x40, add(add(envelope, 0x20), add(0x20, body)))"
            )
        );
    }

    function test_issue12_128sBudgetsAreRevised() public view {
        string memory a =
            vm.readFile("contracts/profiles/128s-q18/SHRINCSParams.sol");
        string memory b =
            vm.readFile("contracts/profiles/128s-q20/SHRINCSParams.sol");
        assertFalse(vm.contains(a, "STATELESS_SIGNATURE_LIMIT = 262_144"));
        assertFalse(vm.contains(b, "STATELESS_SIGNATURE_LIMIT = 1_048_576"));
    }

    function test_issue13_secretHelpersAreNotDeployable() public view {
        string memory a = vm.readFile("contracts/WOTSPlus.sol");
        string memory b = vm.readFile("script/DeployWOTSPlus.s.sol");
        assertFalse(vm.contains(a, "function sign(bytes32 privateKey"));
        assertFalse(
            vm.contains(a, "function generateKeyPair(bytes32 privateSeed")
        );
        assertFalse(vm.contains(b, "WOTSPlus"));
    }

    function test_issue14_leafZeroGuardAndReviewAreFixed() public view {
        string memory u = vm.readFile("contracts/UXMSS.sol");
        string memory r = vm.readFile("docs/guard-applicability-review.md");
        assertTrue(vm.contains(u, "leafIndex == 0"));
        assertFalse(vm.contains(r, "**DROP** (duplicate; #18 kept)"));
    }

    function test_issue15_testHelpersLeaveProduction() public view {
        string memory h = vm.readFile("contracts/Hash.sol");
        string memory s = vm.readFile("contracts/SHRINCS.sol");
        assertFalse(vm.contains(h, "function addressWord32("));
        assertFalse(vm.contains(s, "function encodeStatefulEnvelope("));
        assertFalse(vm.contains(s, "function encodeStatelessEnvelope("));
    }
}
