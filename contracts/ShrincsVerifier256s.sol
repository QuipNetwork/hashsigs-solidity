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

import {ShrincsVerifier} from "./ShrincsVerifier.sol";

/// @title ShrincsVerifier256s
/// @notice Concrete 256s-profile ShrincsVerifier. Deploy this artifact
/// only from a build under the 256s profile (FOUNDRY_PROFILE=production);
/// the deploy script enforces the profile.
/// @dev Empty subclass: the reviewed verify/decode logic lives in the
/// abstract base and takes its parameter tuple from the compile-time
/// ShrincsParams selected by the build profile. PROFILE_TAG identifies
/// the compiled parameter set for on-chain and registry cross-checks;
/// the base VERSION_TAG stays the shared format-family tag (constants
/// cannot be virtual/override, so the profile tag lives here).
contract ShrincsVerifier256s is ShrincsVerifier {
    // PROFILE_TAG: the compiled parameter-set identifier for this
    // verifier. Matches ShrincsParams.PROFILE_ID for the 256s profile.
    bytes32 public constant PROFILE_TAG = keccak256("shrincs-256s");
}
