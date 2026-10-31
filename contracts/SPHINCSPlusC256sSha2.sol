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

/// @title SPHINCSPlusC256sSha2
/// @notice Concrete 256s-sha2-profile SPHINCSPlusC verifier: the SHA-256 twin
/// of SPHINCSPlusC256sKeccak. Deploy only from a build under the
/// 256s-sha2 production profile (FOUNDRY_PROFILE=production-256s-sha2); the
/// deploy script enforces the profile.
/// @dev Empty subclass: the reviewed verify logic lives in the abstract base
/// and takes its parameter tuple from the compile-time SHRINCSParams selected
/// by the build profile (the 256s-sha2 params duplicate) and its hash suite
/// from the sha2 HashSuite remapping. PROFILE_TAG identifies the compiled
/// parameter set for on-chain and registry cross-checks; the base VERSION_TAG
/// stays the shared format-family tag. The SHRINCS256sSha2 verifier pins this
/// contract's CREATE3 address for stateless delegation.
contract SPHINCSPlusC256sSha2 is SPHINCSPlusCVerifier {
    // PROFILE_TAG: the compiled parameter-set identifier for this verifier.
    // Matches SHRINCSParams.PROFILE_ID for the 256s-sha2 profile. The tag
    // derivation stays keccak256 — it is an EVM-domain identifier, not a
    // scheme hash ([DESIGN §1.2]).
    bytes32 public constant PROFILE_TAG = keccak256("shrincs-256s-sha2");
}
