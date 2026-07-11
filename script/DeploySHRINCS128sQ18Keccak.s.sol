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
import {SHRINCS128sQ18Keccak} from "../contracts/SHRINCS128sQ18Keccak.sol";

/// @title DeploySHRINCS128sQ18Keccak
/// @notice Deploys the canonical 128s-q18 SHRINCS via CREATE3. Deploy the
/// SPHINCSPlusC sibling FIRST
/// (script/DeploySPHINCSPlusC128sQ18Keccak.s.sol): CREATE3 fixes the
/// sibling address either way, but this verifier's verifyStateless reverts
/// on empty code, so the delegate must exist first. Run from the release
/// commit under the 128s-q18 production profile:
///   FOUNDRY_PROFILE=production-128s-q18 forge script \
///       script/DeploySHRINCS128sQ18Keccak.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// Record (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeploySHRINCS128sQ18Keccak is Create3Deployer {
    // Per-profile CREATE3 salt. A new verifier version is a NEW salt →
    // new address; deployed artifacts are never upgraded in place.
    bytes32 internal constant SALT =
        keccak256("QUIP:SHRINCS128sQ18Keccak:V1.0");

    // Stateless delegate. SPHINCS_PLUS_C_SALT is the sibling's CREATE3
    // salt; SPHINCS_PLUS_C is its address and MUST equal the pinned
    // SPHINCS_PLUS_C_VERIFIER constant in SHRINCS128sQ18Keccak.
    // _requireSibling asserts the salt derives to this address.
    bytes32 internal constant SPHINCS_PLUS_C_SALT =
        keccak256("QUIP:SPHINCSPlusC128sQ18Keccak:V1.0");
    address internal constant SPHINCS_PLUS_C =
        0xBc7Fefc3D757Fa81E3C7d65905e32722b1a044A6;

    function run() external {
        // Assert the build profile FIRST: _requireSibling reaches
        // _factory() (and its init-code-drift check), so a wrong-profile
        // run must fail with "wrong FOUNDRY_PROFILE", not "factory
        // init-code drift".
        _requireProfile("production-128s-q18");
        _requireSibling(SPHINCS_PLUS_C_SALT, SPHINCS_PLUS_C);
        _deploy(
            "SHRINCS128sQ18Keccak:",
            "production-128s-q18",
            SALT,
            type(SHRINCS128sQ18Keccak).creationCode
        );
    }
}
