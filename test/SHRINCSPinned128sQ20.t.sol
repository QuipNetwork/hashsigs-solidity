// Copyright (C) 2026 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "../lib/forge-std/src/Test.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCS128sQ20Keccak} from "../contracts/SHRINCS128sQ20Keccak.sol";
import {
    SPHINCSPlusC128sQ20Keccak
} from "../contracts/SPHINCSPlusC128sQ20Keccak.sol";

contract SHRINCS128sQ20PinHarness is SHRINCS128sQ20Keccak {
    constructor() SHRINCS128sQ20Keccak(address(0xBEEF)) {}

    function pinned() external view returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @notice Pins experimental profile identity and explicit sibling injection.
contract SHRINCSPinned128sQ20Test is Test {
    function testExperimentalSiblingIsExplicitlyConfigured() public {
        SHRINCS128sQ20PinHarness verifier = new SHRINCS128sQ20PinHarness();
        assertEq(verifier.pinned(), address(0xBEEF));
    }

    function testRejectsZeroSibling() public {
        vm.expectRevert("SHRINCS128sQ20: zero SPHINCSPlusC");
        new SHRINCS128sQ20Keccak(address(0));
    }

    function testProfileTagMatchesProfileId() public {
        SPHINCSPlusC128sQ20Keccak sibling = new SPHINCSPlusC128sQ20Keccak();
        assertEq(
            new SHRINCS128sQ20Keccak(address(sibling)).PROFILE_TAG(),
            SHRINCSParams.PROFILE_ID
        );
        assertEq(sibling.PROFILE_TAG(), SHRINCSParams.PROFILE_ID);
    }
}
