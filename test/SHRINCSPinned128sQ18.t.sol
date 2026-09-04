// Copyright (C) 2026 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "../lib/forge-std/src/Test.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCS128sQ18Keccak} from "../contracts/SHRINCS128sQ18Keccak.sol";
import {
    SPHINCSPlusC128sQ18Keccak
} from "../contracts/SPHINCSPlusC128sQ18Keccak.sol";

contract SHRINCS128sQ18PinHarness is SHRINCS128sQ18Keccak {
    constructor() SHRINCS128sQ18Keccak(address(0xBEEF)) {}

    function pinned() external view returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @notice Pins experimental profile identity and explicit sibling injection.
contract SHRINCSPinned128sQ18Test is Test {
    function testExperimentalSiblingIsExplicitlyConfigured() public {
        SHRINCS128sQ18PinHarness verifier = new SHRINCS128sQ18PinHarness();
        assertEq(verifier.pinned(), address(0xBEEF));
    }

    function testRejectsZeroSibling() public {
        vm.expectRevert("SHRINCS128sQ18: zero SPHINCSPlusC");
        new SHRINCS128sQ18Keccak(address(0));
    }

    function testProfileTagMatchesProfileId() public {
        SPHINCSPlusC128sQ18Keccak sibling = new SPHINCSPlusC128sQ18Keccak();
        assertEq(
            new SHRINCS128sQ18Keccak(address(sibling)).PROFILE_TAG(),
            SHRINCSParams.PROFILE_ID
        );
        assertEq(sibling.PROFILE_TAG(), SHRINCSParams.PROFILE_ID);
    }
}
