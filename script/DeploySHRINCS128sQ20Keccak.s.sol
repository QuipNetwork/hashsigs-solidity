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
import {SHRINCS128sQ20Keccak} from "../contracts/SHRINCS128sQ20Keccak.sol";

/// @title DeploySHRINCS128sQ20Keccak
/// @notice Deploys the canonical 128s-q20 SHRINCS via CREATE3. Deploy the
/// SPHINCSPlusC sibling FIRST
/// (script/DeploySPHINCSPlusC128sQ20Keccak.s.sol): CREATE3 fixes the
/// sibling address either way, but this verifier's verifyStateless reverts
/// on empty code, so the delegate must exist first. Run from the release
/// commit under the 128s-q20 production profile:
///   FOUNDRY_PROFILE=production-128s-q20 forge script \
///       script/DeploySHRINCS128sQ20Keccak.s.sol \
///       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
/// The q20 stateless budget (2^20) wants profile security-analysis
/// backing before production use (maintainer decision Q1). Record
/// (profile, salt, address, codehash, chain) in DEPLOYMENTS.md.
contract DeploySHRINCS128sQ20Keccak is Create3Deployer {
    // Per-profile CREATE3 salt. A new verifier version is a NEW salt →
    // new address; deployed artifacts are never upgraded in place.
    bytes32 internal constant SALT =
        keccak256("QUIP:SHRINCS128sQ20Keccak:V1.0");

    // Stateless delegate. SPHINCS_PLUS_C_SALT is the sibling's CREATE3
    // salt; SPHINCS_PLUS_C is its address and MUST equal the pinned
    // SPHINCS_PLUS_C_VERIFIER constant in SHRINCS128sQ20Keccak.
    // _requireSibling asserts the salt derives to this address.
    bytes32 internal constant SPHINCS_PLUS_C_SALT =
        keccak256("QUIP:SPHINCSPlusC128sQ20Keccak:V1.0");
    address internal constant SPHINCS_PLUS_C =
        0x7C30ef553deE8F6DF59eE1FF4477f382607d330f;

    // Pinned runtime codehash of this artifact (production profile).
    // _deploy fails closed if the CREATE3 address is occupied by code whose
    // hash differs from this pin (squatted salt or stale pin) and asserts a
    // fresh deploy matches it. Metadata is stripped (foundry.toml), so the
    // hash is chain-invariant and is the value published in DEPLOYMENTS.md;
    // regenerate per DEPLOYMENTS.md.
    bytes32 internal constant RUNTIME_CODEHASH =
        0xf2e75ac078e1287a80b961e01bf722a2fc91c4e7ce3eff431183e552b5b77662;

    function run() external {
        // Assert the build profile FIRST: _requireSibling reaches
        // _factory() (and its init-code-drift check), so a wrong-profile
        // run must fail with "wrong FOUNDRY_PROFILE", not "factory
        // init-code drift".
        _requireProfile("production-128s-q20");
        _requireSibling(SPHINCS_PLUS_C_SALT, SPHINCS_PLUS_C);
        _deploy(
            "SHRINCS128sQ20Keccak:",
            "production-128s-q20",
            SALT,
            RUNTIME_CODEHASH,
            type(SHRINCS128sQ20Keccak).creationCode
        );
    }
}
