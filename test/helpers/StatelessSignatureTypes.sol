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

/// @notice Test-only struct form of the stateless SPHINCSPlusC signature.
/// @dev Production code reads the fixed StatelessLayout encoding and has no
/// stateless structs. The in-Solidity signers, the Rust vector decoders, and
/// the ABI-envelope fixtures still build signatures in this shape;
/// SHRINCSTestCodec.encodeCompactSignature turns one into the fixed layout.
/// The ABI encoding matches the pre-0.4.0 production structs.
library StatelessSignatureTypes {
    struct WotsCSignature {
        // Per-layer randomizer for this WOTS-C signature.
        bytes randomizer;
        // Grinding counter for the WOTS-C target-sum constraint.
        uint32 counter;
        // Revealed WOTS-C chain values for this layer.
        bytes[] chains;
    }

    struct HypertreeLayerSignature {
        // Expected WOTS-C public-key hash for this layer.
        bytes wotsCPkHash;
        // WOTS-C signature over the running message/root value.
        WotsCSignature wotsCSignature;
        // Authentication path for this layer's subtree.
        bytes[] authPath;
    }

    struct ForsEntry {
        // Revealed secret leaf for one FORS tree.
        bytes secretLeaf;
        // Authentication path from that leaf to the tree root.
        bytes[] authPath;
    }

    struct ForsSignature {
        // Per-signature randomizer used in FORS message hashing.
        bytes randomizer;
        // Grinding counter for the FORS-C constrained digest.
        uint32 counter;
        // Revealed FORS leaves and authentication paths.
        ForsEntry[] entries;
    }

    struct Signature {
        // Message-signing few-time signature at the bottom of the path.
        ForsSignature fors;
        // Hypertree layers authenticating the FORS root to the public root.
        HypertreeLayerSignature[] hypertree;
    }
}
