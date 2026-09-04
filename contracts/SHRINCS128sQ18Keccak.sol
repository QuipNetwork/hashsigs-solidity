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

/// @title SHRINCS128sQ18Keccak
/// @notice Experimental 128s-q18 SHRINCS verifier for tests, vectors, and
/// security research. It is not approved or tooled for production deployment.
/// @dev Thin subclass beyond the profile tag and configured sibling: the
/// reviewed verify/decode logic lives in the abstract base and takes its
/// parameter tuple from the compile-time SHRINCSParams selected by the build
/// profile. PROFILE_TAG identifies the compiled parameter set for on-chain
/// and registry cross-checks.
contract SHRINCS128sQ18Keccak is SHRINCSVerifier {
    // PROFILE_TAG: the compiled parameter-set identifier for this
    // verifier. Matches SHRINCSParams.PROFILE_ID for the 128s-q18
    // profile (stateless-signature budget 2^18).
    bytes32 public constant PROFILE_TAG =
        keccak256("shrincs-128s-q18-keccak");

    // Supplied explicitly by an experimental harness. There is deliberately
    // no canonical production address for this profile.
    address internal immutable SPHINCS_PLUS_C_VERIFIER;

    constructor(address sphincsPlusCVerifier) {
        require(
            sphincsPlusCVerifier != address(0),
            "SHRINCS128sQ18: zero SPHINCSPlusC"
        );
        SPHINCS_PLUS_C_VERIFIER = sphincsPlusCVerifier;
    }

    function _pinnedSphincsPlusC() internal view override returns (address) {
        return SPHINCS_PLUS_C_VERIFIER;
    }
}
