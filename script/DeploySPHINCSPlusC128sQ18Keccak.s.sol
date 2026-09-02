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
import {
    SPHINCSPlusC128sQ18Keccak
} from "../contracts/SPHINCSPlusC128sQ18Keccak.sol";

/// @title DeploySPHINCSPlusC128sQ18Keccak
/// @notice Deploys the canonical 128s-q18 SPHINCSPlusC verifier via
/// CREATE3. This is the stateless delegate SHRINCS128sQ18Keccak pins, so
/// deploy it BEFORE the SHRINCS verifier (CREATE3 fixes the address either
/// way, but SHRINCS.verifyStateless reverts on empty code). Run from the
/// release commit under the 128s-q18 production profile:
///   FOUNDRY_PROFILE=production-128s-q18 forge script \
///       script/DeploySPHINCSPlusC128sQ18Keccak.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// Record (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeploySPHINCSPlusC128sQ18Keccak is CreateXDeployer {
    // Per-profile CREATE3 salt. Byte-identical to the salt pinned into
    // SHRINCS128sQ18Keccak.SPHINCS_PLUS_C_VERIFIER; a new verifier version
    // is a NEW salt → new address, never an in-place upgrade.
    bytes32 internal constant SALT = bytes32(
        abi.encodePacked(
            bytes20(DEPLOYER),
            SALT_FLAG,
            bytes11(keccak256("QUIP:SPHINCSPlusC128sQ18Keccak:V3.0"))
        )
    );

    // Pinned runtime codehash of this artifact (production profile). _deploy
    // fails closed if the CREATE3 address is occupied by code whose hash
    // differs from this pin (stale pin or drifted artifact) and asserts a
    // fresh deploy matches it. Metadata is stripped (foundry.toml), so the
    // hash is chain-invariant and is the value published in DEPLOYMENTS.md;
    // regenerate per DEPLOYMENTS.md.
    bytes32 internal constant RUNTIME_CODEHASH =
        0xef582c503d8fc3403f349cd7247f463d5e1f9108b49789af36df4150963332e8;

    function run() external {
        _deploy(
            "SPHINCSPlusC128sQ18Keccak:",
            "production-128s-q18",
            SALT,
            RUNTIME_CODEHASH,
            type(SPHINCSPlusC128sQ18Keccak).creationCode
        );
    }
}
