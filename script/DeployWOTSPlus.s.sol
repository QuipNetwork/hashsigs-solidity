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

import {CreateXDeployer} from "./DeployBase.s.sol";
import {WOTSPlus} from "../contracts/WOTSPlus.sol";

/// @title DeployWOTSPlus
/// @notice Deploys the standalone WOTS+ library via CREATE3 (maintainer
/// decision Q5). WOTS+ is profile-independent (its parameters are its
/// own constants, not SHRINCSParams), so it deploys under the 256s
/// production profile and its CREATE3 address is the same regardless.
/// Replaces the historical Hardhat-Ignition (plain CREATE) deployment;
/// see DEPLOYMENTS.md.
///   FOUNDRY_PROFILE=production forge script \
///       script/DeployWOTSPlus.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
contract DeployWOTSPlus is CreateXDeployer {
    // CREATE3 salt for the WOTS+ library deployment.
    bytes32 internal constant SALT = keccak256("QUIP:WOTSPlus:V1.0");

    // Pinned runtime codehash of this artifact (production profile).
    // _deploy fails closed if the CREATE3 address is occupied by code whose
    // hash differs from this pin (squatted salt or stale pin) and asserts a
    // fresh deploy matches it. Metadata is stripped (foundry.toml), so the
    // hash is chain-invariant and is the value published in DEPLOYMENTS.md;
    // regenerate per DEPLOYMENTS.md.
    bytes32 internal constant RUNTIME_CODEHASH =
        0x0efb1b18e06862b6b16d6b9fdb0563c5ceaf435af928034cbdb94af18ae2e683;

    function run() external {
        _deploy(
            "WOTSPlus:",
            "production",
            SALT,
            RUNTIME_CODEHASH,
            type(WOTSPlus).creationCode
        );
    }
}
