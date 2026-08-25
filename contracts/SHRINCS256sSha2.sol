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

/// @title SHRINCS256sSha2
/// @notice Concrete 256s-sha2-profile SHRINCS: the SHA-256 twin of
/// SHRINCS256sKeccak. Deploy this artifact only from a build under the
/// 256s-sha2 production profile (FOUNDRY_PROFILE=production-256s-sha2); the
/// deploy script enforces the profile.
/// @dev Empty subclass beyond the profile tag and pinned sibling: the
/// verify/decode logic lives in the abstract base and takes its parameter
/// tuple from the compile-time SHRINCSParams selected by the build profile
/// (the 256s-sha2 params duplicate) and hash suite from the sha2 HashSuite
/// remapping. PROFILE_TAG identifies the compiled parameter set; the base
/// VERSION_TAG stays the shared format-family tag.
contract SHRINCS256sSha2 is SHRINCSVerifier {
    // PROFILE_TAG: the compiled parameter-set identifier for this verifier.
    // Matches SHRINCSParams.PROFILE_ID for the 256s-sha2 profile. The tag
    // derivation stays keccak256 — it is an EVM-domain identifier, not a
    // scheme hash ([DESIGN §1.2]).
    bytes32 public constant PROFILE_TAG = keccak256("shrincs-256s-sha2");

    // Pinned CREATE3 address of the 256s-sha2 SPHINCSPlusC sibling
    // (SPHINCSPlusC256sSha2) this verifier delegates stateless verification
    // to. Derivation (script/DeployBase.s.sol):
    //   CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed (canonical
    //     CreateX singleton, pre-deployed at that address on every chain)
    //   raw salt = [20B DEPLOYER][0x00 flag][leading 11B of
    //     keccak256("QUIP:SPHINCSPlusC256sSha2:V2.0")],
    //     which CreateX guards to
    //     keccak256(abi.encode(DEPLOYER, raw salt)) — its
    //     permissioned mode, so only DEPLOYER can deploy here
    //   address = CREATE3 child of (CREATEX, guarded salt)
    // Pinned by test/SHRINCSPinned256sSha2.t.sol (profile-gated) so the
    // deploy scripts cannot drift from this constant.
    address internal constant SPHINCS_PLUS_C_VERIFIER =
        0xAa504387af27bEF16544Cc7e465271D5f8C8c8ee;

    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return SPHINCS_PLUS_C_VERIFIER;
    }
}
