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

import {Create3Deployer} from "./DeployBase.s.sol";
import {
    ShrincsVerifier128sQ18
} from "../contracts/ShrincsVerifier128sQ18.sol";

/// @title DeployShrincsVerifier128sQ18
/// @notice Deploys the canonical 128s-q18 ShrincsVerifier via CREATE3.
/// Run from the release commit under the 128s-q18 production profile:
///   FOUNDRY_PROFILE=production-128s-q18 forge script \
///       script/DeployShrincsVerifier128sQ18.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// Record (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeployShrincsVerifier128sQ18 is Create3Deployer {
    // Per-profile CREATE3 salt. A new verifier version is a NEW salt →
    // new address; deployed artifacts are never upgraded in place.
    bytes32 internal constant SALT =
        keccak256("QUIP:ShrincsVerifier128sQ18:V1.0");

    function run() external {
        _deploy(
            "ShrincsVerifier128sQ18:",
            "production-128s-q18",
            SALT,
            type(ShrincsVerifier128sQ18).creationCode
        );
    }
}
