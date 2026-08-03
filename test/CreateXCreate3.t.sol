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
import {CreateXSalt} from "../script/CreateXSalt.sol";
import {ICreateX} from "../script/ICreateX.sol";

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
/// @dev The known answer below was produced under CreateX's PERMISSIONLESS
/// guard, which the canonical deploys no longer use. It is kept, and stays
/// exactly as valid, because Create3.addressOf applies NO guard: it is
/// pure CREATE2-proxy + nonce-1 math over an already-guarded salt, so this
/// anchor is guard-independent. What it does not cover is the guard
/// formula itself; CreateXPermissionedGuardForkTest below covers that
/// against the real deployed CreateX.
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

    function testCreateXAddressMatchesDeployLibrary() public pure {
        assertEq(
            CREATEX,
            CreateXSalt.CREATEX,
            "this file's CREATEX must match the deploy library"
        );
    }
}

/// @dev Probe artifact for the fork test; any non-empty runtime works.
contract ForkProbe {
    function tag() external pure returns (uint256) {
        return 0xf0;
    }
}

/// @notice Anchors the PERMISSIONED guard formula to the real deployed
/// CreateX. This is the ground truth for every address the repo now
/// advertises: it executes CreateX's own bytecode on a fork and checks
/// both halves of the property the scheme depends on — the canonical
/// deployer reaches our address, and nobody else does.
/// @dev Opt-in: CI has no RPC credentials, so the test skips unless
/// CREATEX_FORK_RPC_URL is set. Run it before any canonical deploy:
///   CREATEX_FORK_RPC_URL=$RPC forge test --match-contract \
///       CreateXPermissionedGuardFork
contract CreateXPermissionedGuardForkTest is Test {
    function testForkedCreateXHonorsPermissionedGuard() public {
        string memory rpc = vm.envOr("CREATEX_FORK_RPC_URL", string(""));
        vm.skip(bytes(rpc).length == 0);
        vm.createSelectFork(rpc);
        assertTrue(
            CreateXSalt.CREATEX.code.length != 0, "no CreateX on this fork"
        );

        // A salt that is well-formed but not one we ever deploy, so the
        // fork's real state cannot already occupy either address.
        bytes32 raw = CreateXSalt.rawSalt(keccak256("QUIP:test:fork-probe"));
        bytes memory initCode = type(ForkProbe).creationCode;

        // Positive half: the canonical deployer lands where we predict.
        vm.prank(CreateXSalt.DEPLOYER);
        address ours =
            ICreateX(CreateXSalt.CREATEX).deployCreate3(raw, initCode);
        assertEq(
            ours,
            CreateXSalt.addressOf(raw),
            "CreateX's permissioned guard must match CreateXSalt"
        );

        // Negative half: anyone else using the SAME published raw salt
        // takes CreateX's permissionless branch and lands elsewhere.
        // This is the squatting surface being closed, proven on-chain.
        vm.prank(address(0xBAD));
        address theirs =
            ICreateX(CreateXSalt.CREATEX).deployCreate3(raw, initCode);
        assertTrue(theirs != ours, "a squatter must not reach our address");
        assertEq(
            theirs,
            Create3.addressOf(
                keccak256(abi.encode(raw)), CreateXSalt.CREATEX
            ),
            "a non-deployer must take the permissionless branch"
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
/// documented salt. These tests prove the address is captured regardless
/// of init code, that the captured codehash differs from the intended
/// artifact's (the mismatch DeployBase._deploy fails closed on), and that
/// bumping the salt version recovers a fresh, unoccupied address.
/// @dev This documents the mode the canonical deploys NO LONGER use.
/// Every QUIP:* salt is now sender-scoped (CreateXSalt), so the capture
/// modelled here is not reachable against our addresses — see
/// CreateXSaltInvariantsTest.testSquatSurfaceIsClosed for the local proof
/// and CreateXPermissionedGuardForkTest for the on-chain one. It is kept
/// because it is what makes the reason for the scheme legible, and
/// because the codehash pin it exercises is still live as defense in
/// depth against a stale pin or a drifted artifact.
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
