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
import {SHRINCS256sSha2} from "../contracts/SHRINCS256sSha2.sol";

/// @title DeploySHRINCS256sSha2
/// @notice Deploys the canonical 256s-sha2 SHRINCS via CREATE3. Deploy the
/// SPHINCSPlusC sibling FIRST (script/DeploySPHINCSPlusC256sSha2.s.sol):
/// CREATE3 fixes the sibling address either way, but this verifier's
/// verifyStateless reverts on empty code, so the delegate must exist before
/// the verifier is used. Run from the release commit under the 256s-sha2
/// production profile:
///   FOUNDRY_PROFILE=production-256s-sha2 forge script \
///       script/DeploySHRINCS256sSha2.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// Record (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeploySHRINCS256sSha2 is CreateXDeployer {
    // Per-profile CREATE3 salt. A new verifier version is a NEW salt →
    // new address; deployed artifacts are never upgraded in place.
    bytes32 internal constant SALT = bytes32(
        abi.encodePacked(
            bytes20(DEPLOYER),
            SALT_FLAG,
            bytes11(keccak256("QUIP:SHRINCS256sSha2:V2.0"))
        )
    );

    // Stateless delegate. SPHINCS_PLUS_C_SALT is the sibling's CREATE3 salt;
    // SPHINCS_PLUS_C is its address and MUST equal the pinned
    // SPHINCS_PLUS_C_VERIFIER constant in SHRINCS256sSha2. _requireSibling
    // asserts the salt derives to this address, so a drift fails the deploy.
    bytes32 internal constant SPHINCS_PLUS_C_SALT = bytes32(
        abi.encodePacked(
            bytes20(DEPLOYER),
            SALT_FLAG,
            bytes11(keccak256("QUIP:SPHINCSPlusC256sSha2:V2.0"))
        )
    );
    address internal constant SPHINCS_PLUS_C =
        0xAa504387af27bEF16544Cc7e465271D5f8C8c8ee;

    // Pinned runtime codehash of this artifact (production profile).
    // _deploy fails closed if the CREATE3 address is occupied by code whose
    // hash differs from this pin (stale pin or drifted artifact) and
    // asserts a
    // fresh deploy matches it. Metadata is stripped (foundry.toml), so the
    // hash is chain-invariant and is the value published in DEPLOYMENTS.md;
    // regenerate per DEPLOYMENTS.md.
    bytes32 internal constant RUNTIME_CODEHASH =
        0x439c4f9239a41731908b816e50f51cc3489416736d44abf493239a4995b94ded;

    function run() external {
        // Assert the build profile FIRST so a wrong-profile run fails
        // with "wrong FOUNDRY_PROFILE", not a sibling-presence error.
        _requireProfile("production-256s-sha2");
        _requireSibling(SPHINCS_PLUS_C_SALT, SPHINCS_PLUS_C);
        _deploy(
            "SHRINCS256sSha2:",
            "production-256s-sha2",
            SALT,
            RUNTIME_CODEHASH,
            type(SHRINCS256sSha2).creationCode
        );
    }
}
