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

import {HashSuite} from "shrincs-hash/HashSuite.sol";

/// @title WOTSPlusC
/// @notice Shared WOTS+C chain machinery used by both the SHRINCS hypertree
/// (stateless) and stateful subsystems: the WOTS-C signature container,
/// base-16 digit extraction, the tag-parameterized chain-step hash, and the
/// chain-to-endpoint walk built on them.
/// @dev WOTS-C (WOTS+C in [SPHINCSPLUSC §3]) replaces the WOTS checksum
/// chains with a fixed target-sum check; construction [SHRINCS §5]. Each
/// verifier keeps its own message-digest, public-key, and target-sum logic
/// and calls into these shared primitives for the chain walk itself.
library WOTSPlusC {
    // Stateless WOTS-C chain-step domain tag and its byte length.
    // "wots-c-chain" is 12 bytes; the chain-step preimage is [tag | pkSeed
    // | addressWord | segment], so its length is WOTS_C_CHAIN_TAG_LEN + 96
    // = 108 bytes. Used by the stateless hypertree walk. The stateful
    // (UXMSS) walk uses its own UXMSS.UXMSS_WOTS_CHAIN_TAG
    // ("uxmss-wots-chain", 16 bytes) instead (F-08 split).
    bytes32 internal constant WOTS_C_CHAIN_TAG = "wots-c-chain";
    uint256 internal constant WOTS_C_CHAIN_TAG_LEN = 12;

    struct WotsCSignature {
        // Per-layer randomizer for this WOTS-C signature.
        bytes randomizer;
        // Grinding counter for the WOTS-C target-sum constraint.
        uint32 counter;
        // Revealed WOTS-C chain values for this layer.
        bytes[] chains;
    }

    // baseW16Digit32: Read one base-16 digit from a fixed 32-byte WOTS
    // digest.
    function baseW16Digit32(bytes32 digest, uint256 index)
        internal
        pure
        returns (uint32)
    {
        uint256 shift = 252 - ((index & 63) << 2);
        return uint32((uint256(digest) >> shift) & 0x0f);
    }

    // wotsChainNoMaskBase: Advance one WOTS-C chain from a revealed value to
    // its endpoint. Shared by the hypertree (stateless) and stateful walks.
    // 1. Start from the revealed chain value.
    // 2. Fold the chain index into the shared key address base.
    // 3. Compute how many steps remain until the end of the chain.
    // 4. Rebuild the per-step chain address from the shared key location and
    // chain index.
    // 5. Apply one unmasked chain hash per remaining step and return the
    // reconstructed endpoint for this chain.
    function wotsChainNoMaskBase(
        bytes32 tag,
        uint256 tagLen,
        uint16 chainBase,
        bytes32 pkSeed,
        uint256 addressBase,
        uint32 chainIdx,
        bytes32 value,
        uint32 digit
    ) internal pure returns (bytes32 out) {
        // Start from the revealed chain value supplied by the caller.
        out = value;
        uint256 chainAddressBase = addressBase | (uint256(chainIdx) << 32);
        // The chain must continue from the revealed digit position up to
        // chainBase - 1 (the WOTSPLUS `w` parameter).
        uint256 steps = uint256(chainBase - 1) - digit;
        for (uint256 j = 0; j < steps;) {
            // Encode the current position within that chain.
            uint256 chainStep = uint256(digit) + j;
            uint256 addressValue = chainAddressBase | chainStep;
            // Hash one step forward using the chain-specific address.
            out = HashSuite.hashWotsCChainNoMask32(
                tag, tagLen, pkSeed, bytes32(addressValue), out
            );
            unchecked {
                ++j;
            }
        }
    }
}
