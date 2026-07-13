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
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";

/// @title DeploySHRINCS256sKeccak
/// @notice Deploys the canonical 256s SHRINCS via CREATE3. Deploy the
/// SPHINCSPlusC sibling FIRST (script/DeploySPHINCSPlusC256sKeccak.s.sol):
/// CREATE3 fixes the sibling address either way, but this verifier's
/// verifyStateless reverts on empty code, so the delegate must exist
/// before the verifier is used. Run from the release commit under the
/// 256s production profile:
///   FOUNDRY_PROFILE=production forge script \
///       script/DeploySHRINCS256sKeccak.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// Record (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeploySHRINCS256sKeccak is Create3Deployer {
    // Per-profile CREATE3 salt. A new verifier version is a NEW salt →
    // new address; deployed artifacts are never upgraded in place.
    bytes32 internal constant SALT =
        keccak256("QUIP:SHRINCS256sKeccak:V1.0");

    // Stateless delegate. SPHINCS_PLUS_C_SALT is the sibling's CREATE3
    // salt; SPHINCS_PLUS_C is its address and MUST equal the pinned
    // SPHINCS_PLUS_C_VERIFIER constant in SHRINCS256sKeccak. _requireSibling
    // asserts the salt derives to this address, so a drift fails the deploy.
    bytes32 internal constant SPHINCS_PLUS_C_SALT =
        keccak256("QUIP:SPHINCSPlusC256sKeccak:V1.0");
    address internal constant SPHINCS_PLUS_C =
        0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A;

    // Pinned runtime codehash of this artifact (production profile).
    // _deploy fails closed if the CREATE3 address is occupied by code whose
    // hash differs from this pin (squatted salt or stale pin) and asserts a
    // fresh deploy matches it. Metadata is stripped (foundry.toml), so the
    // hash is chain-invariant and is the value published in DEPLOYMENTS.md;
    // regenerate per DEPLOYMENTS.md.
    bytes32 internal constant RUNTIME_CODEHASH =
        0x22b7d973eb8481f2d0ae78f05a80499e1d318cf78c8bc5e4ece87b44f2f42113;

    function run() external {
        // Assert the build profile FIRST: _requireSibling reaches
        // _factory() (and its init-code-drift check), so a wrong-profile
        // run must fail with "wrong FOUNDRY_PROFILE", not "factory
        // init-code drift".
        _requireProfile("production");
        _requireSibling(SPHINCS_PLUS_C_SALT, SPHINCS_PLUS_C);
        _deploy(
            "SHRINCS256sKeccak:",
            "production",
            SALT,
            RUNTIME_CODEHASH,
            type(SHRINCS256sKeccak).creationCode
        );
    }
}
