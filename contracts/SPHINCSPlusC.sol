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
import {SHRINCSCodec} from "./SHRINCSCodec.sol";

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
    /// @notice The stateless SPHINCS+C signature.
    /// @dev A SHRINCS stateless signature is a SPHINCSPlusC.Signature:
    /// SHRINCS declares no stateless struct of its own (Solidity cannot alias
    /// structs), so the SHRINCS library handles the stateless path with this
    /// type directly.
    struct Signature {
        // Message-signing few-time signature at the bottom of the stateless
        // path.
        FORSMinusC.ForsSignature fors;
        // Hypertree layers authenticating the FORS root to the public root.
        Hypertree.HypertreeLayerSignature[] hypertree;
    }

    // decodeKey: Facade forward decoding the SPHINCSPlusCVerifier 64-byte key
    // into its two stateless seed slices. Keeps the adapter's only edge
    // pointed at this parent library.
    function decodeKey(bytes calldata key)
        internal
        pure
        returns (
            bytes calldata pkSeed,
            bytes calldata hypertreeRoot,
            bool ok
        )
    {
        return SHRINCSCodec.decodeStatelessKey(key);
    }

    // signatureEnvelope: Facade forward re-tagging the SPHINCSPlusCVerifier
    // stateless-signature envelope into a typed calldata Signature pointer
    // in place, with no copy. Keeps the adapter's only import edge pointed
    // here.
    function signatureEnvelope(bytes calldata envelope)
        internal
        pure
        returns (Signature calldata signature)
    {
        return SHRINCSCodec.statelessSignatureEnvelope(envelope);
    }

    // verify: Facade verify over a hash and the two seed slices. Wraps
    // the message-bytes verify below by packing the ERC-7913 hash into the
    // signed message bytes; the calldata seed slices are read in place.
    function verify(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes32 hash,
        Signature calldata signature
    ) internal pure returns (bool) {
        return verify(
            pkSeed, hypertreeRoot, SHRINCSCodec.toMessage(hash), signature
        );
    }

    // verify: Verify a stateless signature after the caller has already
    // constructed the exact signed message bytes.
    // 1. Reconstruct the FORS-C root from the signed message bytes and FORS
    // proof.
    // 2. Carry that root up the hypertree and compare it to the public root.
    /// @dev Callers must supply pkSeed and hypertreeRoot as exactly 32
    /// bytes each: in-repo callers are validPublicKey-checked or supplied as
    /// 32-byte key slices, and the calldataload-32 reads below assume it.
    function verify(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes memory message,
        Signature calldata signature
    ) internal pure returns (bool) {
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
