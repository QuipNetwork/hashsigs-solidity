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

import {SHRINCSVerifier} from "./SHRINCSVerifier.sol";

/// @title SHRINCS128sQ20Keccak
/// @notice Concrete 128s-q20-profile SHRINCS. Deploy this
/// artifact only from a build under the 128s-q20 profile
/// (FOUNDRY_PROFILE=production-128s-q20); the deploy script enforces it.
/// @dev Empty subclass beyond the profile tag and pinned sibling: the
/// reviewed verify/decode logic lives in the abstract base and takes its
/// parameter tuple from the compile-time SHRINCSParams selected by the build
/// profile. PROFILE_TAG identifies the compiled parameter set for on-chain
/// and registry cross-checks. The q20 stateless budget (2^20) wants profile
/// security-analysis backing before production use (maintainer decision Q1).
contract SHRINCS128sQ20Keccak is SHRINCSVerifier {
    // PROFILE_TAG: the compiled parameter-set identifier for this
    // verifier. Matches SHRINCSParams.PROFILE_ID for the 128s-q20
    // profile (stateless-signature budget 2^20).
    bytes32 public constant PROFILE_TAG =
        keccak256("shrincs-128s-q20-keccak");

    // Pinned CREATE3 address of the 128s-q20 SPHINCSPlusC sibling
    // (SPHINCSPlusC128sQ20Keccak) this verifier delegates stateless
    // verification to. Derivation (script/DeployBase.s.sol):
    //   CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed (canonical
    //     CreateX singleton, pre-deployed at that address on every chain)
    //   raw salt = [20B DEPLOYER][0x00 flag][leading 11B of
    //     keccak256("QUIP:SPHINCSPlusC128sQ20Keccak:V3.0")],
    //     which CreateX guards to
    //     keccak256(abi.encode(DEPLOYER, raw salt)) — its
    //     permissioned mode, so only DEPLOYER can deploy here
    //   address = CREATE3 child of (CREATEX, guarded salt)
    // Pinned by test/SHRINCSPinned128sQ20.t.sol (profile-gated) so C8's
    // deploy scripts cannot drift from this constant.
    address internal constant SPHINCS_PLUS_C_VERIFIER =
        0xf6e309c6795447584110404FbaE112E4236d40AD;

    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return SPHINCS_PLUS_C_VERIFIER;
    }
}
