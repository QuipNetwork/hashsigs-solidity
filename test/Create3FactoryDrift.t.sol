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

/// @dev Two distinct artifacts that show a CREATE3 child address ignores
/// init code: both salt to the same address, but their runtime codehashes
/// differ, so the deploy tooling's codehash pin tells a squatter apart
/// from the intended artifact.
contract SquatCode {
    function tag() external pure returns (uint256) {
        return 0x50;
    }
}

contract LegitCode {
    function tag() external pure returns (uint256) {
        return 0x1e;
    }
}

/// @notice Locks the squatting hazard behind finding P2 (CREATE3 factory
/// salts): a permissionless factory whose child address depends only on
/// (factory, salt) lets a third party pre-deploy arbitrary code at a
/// documented salt. These tests prove the address is captured regardless
/// of init code and that the captured codehash differs from the intended
/// artifact's (the mismatch DeployBase._deploy fails closed on), and that
/// bumping the salt version recovers a fresh, unoccupied address.
contract Create3FactorySquatTest is Test {
    function testSquatterCapturesAdvertisedAddress() public {
        Create3Factory factory = new Create3Factory();
        bytes32 salt = keccak256("QUIP:test:squat");

        // The advertised address is a function of (factory, salt) ONLY.
        address advertised = factory.addressOf(salt);

        // A third party occupies it first with arbitrary code; CREATE3
        // ignores init code, so the squatter lands exactly there.
        address squatted = factory.deploy(salt, type(SquatCode).creationCode);
        assertEq(squatted, advertised, "squatter occupies advertised");

        // Its codehash is the squatter's, not the intended artifact's.
        // This is the mismatch DeployBase._deploy fails closed on; a
        // log-and-skip would publish the squatter as "already deployed".
        assertEq(
            advertised.codehash,
            keccak256(type(SquatCode).runtimeCode),
            "occupied codehash is the squatter's"
        );
        assertTrue(
            advertised.codehash != keccak256(type(LegitCode).runtimeCode),
            "squatted codehash differs from intended artifact"
        );
    }

    function testOccupiedSaltCannotBeRedeployed() public {
        Create3Factory factory = new Create3Factory();
        bytes32 salt = keccak256("QUIP:test:burned");
        factory.deploy(salt, type(SquatCode).creationCode);

        // The CREATE2 proxy at this salt now exists, so a second deploy
        // through the same salt reverts: a squatted salt is unrecoverable
        // except by bumping the salt version (DEPLOYMENTS.md).
        vm.expectRevert(bytes("Create3: proxy deploy failed"));
        factory.deploy(salt, type(LegitCode).creationCode);
    }

    function testBumpedSaltYieldsFreshUnoccupiedAddress() public {
        Create3Factory factory = new Create3Factory();
        bytes32 saltV1 = keccak256("QUIP:test:recover:V1.0");
        bytes32 saltV2 = keccak256("QUIP:test:recover:V2.0");
        factory.deploy(saltV1, type(SquatCode).creationCode);

        // Recovery (finding P2 fix b): a bumped salt is a new, unoccupied
        // address, so the intended artifact deploys cleanly there.
        address recovered = factory.addressOf(saltV2);
        assertTrue(
            recovered != factory.addressOf(saltV1),
            "bumped salt yields a different address"
        );
        assertEq(recovered.code.length, 0, "bumped salt is unoccupied");
        address deployed =
            factory.deploy(saltV2, type(LegitCode).creationCode);
        assertEq(deployed, recovered, "legit deploys at bumped address");
        assertEq(
            deployed.codehash,
            keccak256(type(LegitCode).runtimeCode),
            "recovered address carries the intended artifact"
        );
    }
}
