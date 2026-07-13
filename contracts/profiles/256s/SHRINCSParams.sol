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

/// @title SHRINCSParams (256s profile)
/// @notice Compile-time SHRINCS/SPHINCS parameter tuple for the 256s
/// profile. One `SHRINCSParams` library exists per build profile under
/// contracts/profiles/<profile>/; the active one is selected by the
/// `shrincs-profile/` Foundry remapping (foundry.toml). Every module
/// imports this library directly through that remapping, so each
/// parameter reference site stays profile-agnostic.
/// @dev Every count here sizes arrays and bounds loops, so it must be a
/// compile-time constant (not a runtime value): via-ir does not
/// constant-fold struct-passed params. See
/// [DESIGN §2/§3] for the option analysis.
library SHRINCSParams {
    // PROFILE_NAME: the canonical suite-qualified profile string. It is
    // the sole source of this profile's identity: PROFILE_ID hashes it,
    // and the public-key commitment binds it as the tag suffix
    // "shrincs-public-key/<PROFILE_NAME>" ([DESIGN §4] rider Q2), so the
    // two can never drift.
    string internal constant PROFILE_NAME = "shrincs-256s-keccak";
    // PROFILE_ID: stable identifier for this compiled profile. Consumed
    // by the profile-identity test/CI guard ([DESIGN §3.5]) to catch a
    // wrong-profile or remappings.txt-shadowed build.
    bytes32 internal constant PROFILE_ID = keccak256(bytes(PROFILE_NAME));

    // Encoded stateful public key layout:
    // 32-byte pkSeed || 32-byte root || 4-byte maxSignatures.
    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES = 68;
    // Stateful WOTS-C uses 64 chains.
    uint16 internal constant WOTS_CHAINS_STATEFUL = 64;
    // Stateful WOTS-C uses base-16 digits for message expansion.
    uint16 internal constant WOTS_BASE_STATEFUL = 16;
    // WOTS_TARGET_SUM_STATEFUL: the WOTS-C constant digit-sum target
    // = len * (w - 1) / 2
    // -> WOTS_CHAINS_STATEFUL * (WOTS_BASE_STATEFUL - 1) / 2
    //    = 64 * (16 - 1) / 2 = 480
    // Python: 64 * (16 - 1) // 2
    uint32 internal constant WOTS_TARGET_SUM_STATEFUL = 480;
    // STATELESS_SIGNATURE_LIMIT: the stateless-signature budget for this
    // profile = 2^20
    // -> 1 << 20 = 1048576
    // Python: 2 ** 20
    uint64 internal constant STATELESS_SIGNATURE_LIMIT = 1_048_576;
    // HASH_LEN: the SPHINCS/WOTS `n` security parameter [FIPS205 §11] —
    // hash output length in bytes.
    uint16 internal constant HASH_LEN = 32;
    // HASH_MASK: high-aligned truncation mask applied at every hash-
    // producing site ([DESIGN §2(b)/§3.3]). Keeps the top HASH_LEN bytes
    // of a 32-byte hash slot and zeroes the low (32 - HASH_LEN), so a
    // truncated profile emits high-aligned, zero-padded node values in
    // a bytes32. For 256s (HASH_LEN = 32) this is all-ones and folds to
    // a no-op under via-ir (measured, [DESIGN §2(b)]).
    // = ((1 << (8*HASH_LEN)) - 1) << (8*(32 - HASH_LEN))
    // -> (2^256 - 1) << 0 = 2^256 - 1
    // Python: (((1 << (8*32)) - 1) << (8*(32-32))) & (2**256 - 1)
    bytes32 internal constant HASH_MASK = bytes32(type(uint256).max);
    // HYPERTREE_HEIGHT: the FIPS205 `h` parameter [FIPS205 §7] — total
    // hypertree height (sum of all subtree heights).
    uint8 internal constant HYPERTREE_HEIGHT = 64;
    // NUM_HYPERTREE_LAYERS: the FIPS205 `d` parameter [FIPS205 §7] —
    // number of hypertree layers.
    uint8 internal constant NUM_HYPERTREE_LAYERS = 8;
    // FORS_TREE_HEIGHT: the SPHINCSPLUS `a` parameter [SPHINCSPLUS §5.5]
    // — FORS tree height (each FORS tree has 2^a leaves).
    uint8 internal constant FORS_TREE_HEIGHT = 14;
    // NUM_FORS_TREES: the SPHINCSPLUS `k` parameter [SPHINCSPLUS §5.5] —
    // number of FORS trees per FORS signature.
    uint8 internal constant NUM_FORS_TREES = 22;
    // WOTS_CHAIN_LEN: the WOTSPLUS `w` (Winternitz) parameter
    // [WOTSPLUS §3] — hash-chain length and digit base.
    uint16 internal constant WOTS_CHAIN_LEN = 16;
    // NUM_WOTS_CHAINS: the WOTSPLUS `len` parameter [WOTSPLUS §3] —
    // number of hash chains per WOTS signature.
    uint16 internal constant NUM_WOTS_CHAINS = 64;
    // WOTS_TARGET_SUM_STATELESS: the WOTS-C constant digit-sum target
    // for the stateless hypertree WOTS chains (Hypertree.verifyWotsC32)
    // = len * (w - 1) / 2
    // -> NUM_WOTS_CHAINS * (WOTS_CHAIN_LEN - 1) / 2
    //    = 64 * (16 - 1) / 2 = 480
    // Python: 64 * (16 - 1) // 2
    uint32 internal constant WOTS_TARGET_SUM_STATELESS = 480;
}
