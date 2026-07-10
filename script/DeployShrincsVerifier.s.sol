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
import {ShrincsVerifier} from "../contracts/ShrincsVerifier.sol";

/// @title DeployShrincsVerifier
/// @notice Deploys the canonical ShrincsVerifier singleton — THIS repo owns the
/// deployment (the EntryPoint/Multicall3 pattern: the artifact's author deploys it
/// deterministically once per chain; consumers pin the well-known address).
///
/// Determinism: CREATE2 through the canonical deterministic-deployment proxy
/// (0x4e59b44847b379578588920cA78FbF26c0B4956C — forge's default CREATE2 deployer,
/// present on virtually every chain). The verifier has no constructor args and no
/// immutables, so with the same factory + salt + init code the DEPLOYED ADDRESS and
/// the RUNTIME CODEHASH are both chain-invariant. HARD REQUIREMENT: every canonical
/// deploy MUST be run from the release commit with `FOUNDRY_PROFILE=production`, or
/// the init code (and thus the address) diverges across chains.
///
/// After each per-chain deploy, record (version, VERSION_TAG, address, runtime
/// codehash via `cast codehash <addr>`, chain) in RELEASES.md — consumers pin from
/// that registry, never from a local rebuild.
///
/// Usage:
///   FOUNDRY_PROFILE=production forge script script/DeployShrincsVerifier.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
contract DeployShrincsVerifier is Script {
    /// @notice CREATE2 salt for the V1 singleton. This salt lives HERE — the
    /// artifact owner's namespace. Bump the version string only for an
    /// intentional new deployment (a verifier V2 is a new address, never an
    /// upgrade in place).
    bytes32 internal constant SALT = keccak256("QUIP:ShrincsVerifier:V1.0");

    function run() external {
        bytes memory initCode = type(ShrincsVerifier).creationCode; // no ctor args
        address expected = vm.computeCreate2Address(SALT, keccak256(initCode));

        console.log("CREATE2 factory:           ", CREATE2_FACTORY);
        console.log("Expected ShrincsVerifier:  ", expected);

        if (expected.code.length > 0) {
            console.log("ShrincsVerifier already deployed. Skipping.");
            console.log("Runtime codehash:");
            console.logBytes32(expected.codehash);
            return;
        }

        vm.startBroadcast();
        ShrincsVerifier deployed = new ShrincsVerifier{salt: SALT}();
        vm.stopBroadcast();

        require(address(deployed) == expected, "ShrincsVerifier address mismatch");

        console.log("ShrincsVerifier deployed at:", address(deployed));
        console.log("VERSION_TAG:");
        console.logBytes32(deployed.VERSION_TAG());
        // the registry value; consumers pin (address, codehash) from RELEASES.md
        console.log("Runtime codehash (record in RELEASES.md):");
        console.logBytes32(address(deployed).codehash);
    }
}
