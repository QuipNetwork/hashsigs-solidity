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

import {Script, console} from "../lib/forge-std/src/Script.sol";
import {Create3Factory} from "./Create3.sol";

/// @title Create3Deployer
/// @notice Shared CREATE3 deploy logic for the SHRINCS verifiers and the
/// WOTS+ library (maintainer decision Q5: CREATE3 for all deploys). Each
/// concrete script pins its own salt and required build profile.
/// @dev CREATE3 addresses depend only on (factory, salt), so a child's
/// address is chain-invariant and independent of its init code (unlike
/// CREATE2, where a recompile moved the address). The factory itself is
/// a fixed-bytecode contract deployed once per chain at a deterministic
/// address through the canonical CREATE2 proxy, so it is chain-invariant
/// too. SHRINCS is testnet-only; see DEPLOYMENTS.md for the historical
/// CREATE2 (verifier) and Hardhat-Ignition (WOTS+) mechanisms this
/// replaces.
abstract contract Create3Deployer is Script {
    // Salt for the shared CREATE3 factory. Its address (and thus every
    // child address) is a function of this salt and the factory
    // bytecode; bump only for a deliberate factory replacement.
    bytes32 internal constant FACTORY_SALT =
        keccak256("QUIP:Create3Factory:V1.0");

    // HARD REQUIREMENT (F-17): the canonical deploy MUST run under the
    // expected build profile, or the wrong parameter set / bytecode is
    // deployed. Fail closed rather than publish a mislabeled artifact.
    function _requireProfile(string memory expected) internal view {
        string memory profile = vm.envOr("FOUNDRY_PROFILE", string(""));
        require(
            keccak256(bytes(profile)) == keccak256(bytes(expected)),
            "deploy: wrong FOUNDRY_PROFILE"
        );
    }

    // Return the chain's CREATE3 factory, deploying it deterministically
    // through the canonical CREATE2 proxy on first use.
    function _factory() internal returns (Create3Factory factory) {
        address predicted = vm.computeCreate2Address(
            FACTORY_SALT,
            keccak256(type(Create3Factory).creationCode),
            CREATE2_FACTORY
        );
        if (predicted.code.length == 0) {
            vm.broadcast();
            Create3Factory deployed =
                new Create3Factory{salt: FACTORY_SALT}();
            require(
                address(deployed) == predicted,
                "deploy: factory address mismatch"
            );
            return deployed;
        }
        return Create3Factory(predicted);
    }

    // Deploy `initCode` under `salt` via CREATE3, after asserting the
    // build profile. Idempotent: skips if the address already has code.
    function _deploy(
        string memory label,
        string memory expectedProfile,
        bytes32 salt,
        bytes memory initCode
    ) internal {
        _requireProfile(expectedProfile);
        Create3Factory factory = _factory();
        address expected = factory.addressOf(salt);

        console.log("CREATE3 factory:  ", address(factory));
        console.log(label);
        console.log("  expected addr:  ", expected);

        if (expected.code.length != 0) {
            console.log("  already deployed. Skipping.");
            console.log("  runtime codehash:");
            console.logBytes32(expected.codehash);
            return;
        }

        vm.broadcast();
        address deployed = factory.deploy(salt, initCode);
        require(deployed == expected, "deploy: address mismatch");

        console.log("  deployed at:    ", deployed);
        // The registry value; consumers pin (address, codehash) from
        // DEPLOYMENTS.md, never from a local rebuild.
        console.log("  runtime codehash (record in DEPLOYMENTS.md):");
        console.logBytes32(deployed.codehash);
    }
}
