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

import {SPHINCSPlusCVerifier} from "./SPHINCSPlusCVerifier.sol";

/// @title SPHINCSPlusC128sQ20Keccak
/// @notice Experimental 128s-q20 SPHINCSPlusC verifier for tests, vectors,
/// and security research. It is not approved or tooled for production
/// deployment.
/// @dev Empty subclass: the reviewed verify logic lives in the abstract base
/// and takes its parameter tuple from the compile-time SHRINCSParams selected
/// by the build profile. PROFILE_TAG identifies the compiled parameter set.
/// The q20 stateless budget (2^20) lacks approved birthday-bound security
/// analysis. Experimental SHRINCS128sQ20Keccak harnesses supply this
/// contract's address explicitly for stateless delegation tests.
contract SPHINCSPlusC128sQ20Keccak is SPHINCSPlusCVerifier {
    // PROFILE_TAG: the compiled parameter-set identifier for this
    // verifier. Matches SHRINCSParams.PROFILE_ID for the 128s-q20
    // profile (stateless-signature budget 2^20).
    bytes32 public constant PROFILE_TAG =
        keccak256("shrincs-128s-q20-keccak");
}
