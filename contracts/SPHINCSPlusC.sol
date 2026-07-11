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

import {FORSMinusC} from "./FORSMinusC.sol";
import {Hypertree} from "./Hypertree.sol";

/// @title SPHINCSPlusC
/// @notice Stateless SPHINCS+C-style verification ([SPHINCSPLUSC]): a FORS-C
/// few-time signature carried up a hypertree of WOTS-C layers to the public
/// root. Documented deviations from the paper: keccak-based tag hashes stand
/// in for the SPHINCS+ tweakable hash, and the hypertree coordinates are
/// chained sequentially per layer (the FIPS-205 §8.2 deviation note lives on
/// Hypertree, where the coordinate recurrence is enforced).
/// @dev Knows only the stateless primitives (public seed, public root,
/// FORS-C, hypertree). Commitments, contexts, and the stateful side belong
/// to the hybrid SHRINCS library above it.
library SPHINCSPlusC {
    struct StatelessSignature {
        // Message-signing few-time signature at the bottom of the stateless
        // path.
        FORSMinusC.ForsSignature fors;
        // Hypertree layers authenticating the FORS root to the public root.
        Hypertree.HypertreeLayerSignature[] hypertree;
    }

    // verify: Verify a stateless signature after the caller has already
    // constructed the exact signed message bytes.
    // 1. Validate the fixed public-seed and public-root layout.
    // 2. Reconstruct the FORS-C root from the signed message bytes and FORS
    // proof.
    // 3. Carry that root up the hypertree and compare it to the public root.
    function verify(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes memory message,
        StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // The stateless public seed is always one hash output wide.
        if (pkSeed.length != 32) return false;
        // The hypertree root is always one hash output wide.
        if (hypertreeRoot.length != 32) return false;
        // A stateless signature must carry at least one hypertree layer.
        if (signature.hypertree.length == 0) return false;

        // Reconstruct the FORS root from the message, FORS
        // randomness/counter, and revealed leaves.
        (bytes32 forsRoot, bool ok) = FORSMinusC.verifyForsCAndReturnRoot(
            pkSeed,
            hypertreeRoot,
            message,
            signature.fors,
            signature.hypertree[0].treeIndex,
            signature.hypertree[0].leafIndex
        );
        if (!ok) return false;
        // Carry the reconstructed FORS root up the hypertree until it matches
        // the public root.
        return Hypertree.verifyHypertree(
            pkSeed, hypertreeRoot, forsRoot, signature.hypertree
        );
    }
}
