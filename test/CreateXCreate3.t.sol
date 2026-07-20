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
import {Create3} from "../script/Create3.sol";

/// @notice Anchors the local CREATE3 math (Create3.addressOf) to CreateX's
/// actual on-chain behavior with a known-answer test: quip's Deployer
/// contract was deployed through the canonical CreateX singleton in
/// permissionless mode (salt keccak256("QUIP:Deployer:V1"), guarded by
/// CreateX to keccak256(abi.encode(salt))) and landed at the address
/// asserted below. Every predicted address in this repo (DeployBase
/// _addressOf, the SHRINCSPinned* tests, DEPLOYMENTS.md) rides on this
/// equivalence, and _deploy re-checks it on-chain against CreateX's
/// computeCreate3Address before broadcasting. This file is in no `skip`
/// list, so it runs under all ci-matrix profiles.
contract CreateXDerivationTest is Test {
    // Canonical CreateX singleton; mirrors DeployBase.s.sol CREATEX.
    address internal constant CREATEX =
        0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    function testLocalMathMatchesOnChainCreateXDeployment() public pure {
        bytes32 salt = keccak256("QUIP:Deployer:V1");
        assertEq(
            Create3.addressOf(keccak256(abi.encode(salt)), CREATEX),
            0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1,
            "Create3.addressOf must reproduce CreateX's on-chain "
            "CREATE3 derivation (quip Deployer known answer)"
        );
    }
}

/// @dev In-test stand-in for CreateX's permissionless CREATE3 path (no
/// salt guard — guarding only remaps raw salts to effective ones and is
/// irrelevant to the hazard being locked). Deploys and predicts through
/// library Create3 exactly as CreateX's inner deployCreate3 does.
contract SquatFactoryHarness {
    function deploy(bytes32 salt, bytes calldata initCode)
        external
        returns (address)
    {
        return Create3.deploy(salt, initCode);
    }

    function addressOf(bytes32 salt) external view returns (address) {
        return Create3.addressOf(salt, address(this));
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
/// documented salt. CreateX's permissionless mode (the mode every QUIP:*
/// salt uses) has exactly this property — the guarded salt is public
/// math, so anyone can trigger it first. These tests prove the address is
/// captured regardless of init code and that the captured codehash
/// differs from the intended artifact's (the mismatch DeployBase._deploy
/// fails closed on), and that bumping the salt version recovers a fresh,
/// unoccupied address.
contract Create3SquatTest is Test {
    function testSquatterCapturesAdvertisedAddress() public {
        SquatFactoryHarness factory = new SquatFactoryHarness();
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
        SquatFactoryHarness factory = new SquatFactoryHarness();
        bytes32 salt = keccak256("QUIP:test:burned");
        factory.deploy(salt, type(SquatCode).creationCode);

        // The CREATE2 proxy at this salt now exists, so a second deploy
        // through the same salt reverts: a squatted salt is unrecoverable
        // except by bumping the salt version (DEPLOYMENTS.md).
        vm.expectRevert(bytes("Create3: proxy deploy failed"));
        factory.deploy(salt, type(LegitCode).creationCode);
    }

    function testBumpedSaltYieldsFreshUnoccupiedAddress() public {
        SquatFactoryHarness factory = new SquatFactoryHarness();
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
