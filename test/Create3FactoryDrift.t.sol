// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "../lib/forge-std/src/Test.sol";
import {Create3Factory} from "../script/Create3.sol";

/// @notice Fails CI the moment Create3.sol changes the factory creation
/// code. The factory address (and every CREATE3 child address) is a
/// function of keccak256(factory creation code); without this guard a
/// Create3.sol edit passes every test on every profile and first fails at
/// deploy time, leaving the pinned constants and DEPLOYMENTS.md silently
/// stale on main. This file is in no `skip` list, so it compiles and runs
/// under all three ci-matrix profiles (ci / 128s-q18 / 128s-q20). The
/// factory is self-contained in script/Create3.sol (no `shrincs-profile`
/// remapping) and solc metadata is stripped, so its test-profile creation
/// code is identical across those profiles and this one pin covers them.
contract Create3FactoryDriftTest is Test {
    // Test-profile (200-run) keccak256 of the Create3Factory creation
    // code. This is NOT the production pin FACTORY_INITCODE_HASH in
    // DeployBase.s.sol: the production profiles optimize for 1,000,000
    // runs, so their factory creation code (and hash) differ. This value
    // exists only so a Create3.sol change fails CI immediately; on a
    // deliberate factory replacement, regenerate BOTH pins together.
    bytes32 internal constant TEST_FACTORY_INITCODE_HASH =
        0x44e83d27e2004604259869b72a26900cb9de06f43382efa570261a4889198764;

    function testFactoryCreationCodeUnchanged() public pure {
        assertEq(
            keccak256(type(Create3Factory).creationCode),
            TEST_FACTORY_INITCODE_HASH,
            "Create3Factory creation code changed; if deliberate, "
            "regenerate this test pin AND the production "
            "FACTORY_INITCODE_HASH in DeployBase.s.sol together"
        );
    }
}
