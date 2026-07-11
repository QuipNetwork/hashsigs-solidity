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

import {SHRINCS} from "./SHRINCS.sol";

/// @title SHRINCS256sKeccak
/// @notice Concrete 256s-profile SHRINCS. Deploy this artifact
/// only from a build under the 256s profile (FOUNDRY_PROFILE=production);
/// the deploy script enforces the profile.
/// @dev Empty subclass beyond the profile tag and pinned sibling: the
/// reviewed verify/decode logic lives in the abstract base and takes its
/// parameter tuple from the compile-time SHRINCSParams selected by the build
/// profile. PROFILE_TAG identifies the compiled parameter set for on-chain
/// and registry cross-checks; the base VERSION_TAG stays the shared
/// format-family tag (constants cannot be virtual/override, so the profile
/// tag lives here).
contract SHRINCS256sKeccak is SHRINCS {
    // PROFILE_TAG: the compiled parameter-set identifier for this
    // verifier. Matches SHRINCSParams.PROFILE_ID for the 256s profile.
    bytes32 public constant PROFILE_TAG = keccak256("shrincs-256s");

    // Pinned CREATE3 address of the 256s SPHINCSPlusC sibling
    // (SPHINCSPlusC256sKeccak) this verifier delegates stateless
    // verification to. Derivation (script/Create3.sol + DeployBase.s.sol):
    //   factory = CREATE2(
    //     0x4e59b44847b379578588920cA78FbF26c0B4956C,
    //     keccak256("QUIP:Create3Factory:V1.0"),
    //     keccak256(type(Create3Factory).creationCode))
    //   address = CREATE3 child of (
    //     factory, keccak256("QUIP:SPHINCSPlusC256sKeccak:V1.0"))
    // Pinned by SHRINCSPinnedAddresses.t.sol (profile-gated) so C8's deploy
    // scripts cannot drift from this constant.
    address internal constant SPHINCS_PLUS_C_VERIFIER =
        0x44DF5b05d8f3EB979593e86871dA970fcfecbf1D;

    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return SPHINCS_PLUS_C_VERIFIER;
    }
}
