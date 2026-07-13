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
import {SPHINCSPlusC256sSha2} from "../contracts/SPHINCSPlusC256sSha2.sol";

/// @title DeploySPHINCSPlusC256sSha2
/// @notice Deploys the canonical 256s-sha2 SPHINCSPlusC verifier via CREATE3.
/// This is the stateless delegate SHRINCS256sSha2 pins, so deploy it BEFORE
/// the SHRINCS verifier (CREATE3 fixes the address either way, but
/// SHRINCS.verifyStateless reverts on empty code). Run from release commit
/// under the 256s-sha2 production profile:
///   FOUNDRY_PROFILE=production-256s-sha2 forge script \
///       script/DeploySPHINCSPlusC256sSha2.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// Record (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeploySPHINCSPlusC256sSha2 is Create3Deployer {
    // Per-profile CREATE3 salt. Byte-identical to the salt pinned into
    // SHRINCS256sSha2.SPHINCS_PLUS_C_VERIFIER; a new verifier version is a
    // NEW salt → new address, never an in-place upgrade.
    bytes32 internal constant SALT =
        keccak256("QUIP:SPHINCSPlusC256sSha2:V1.0");

    function run() external {
        _deploy(
            "SPHINCSPlusC256sSha2:",
            "production-256s-sha2",
            SALT,
            type(SPHINCSPlusC256sSha2).creationCode
        );
    }
}
