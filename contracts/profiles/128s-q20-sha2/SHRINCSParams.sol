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

/// @title SHRINCSParams (128s-q20-sha2 profile)
/// @notice Compile-time SHRINCS/SPHINCS parameter tuple for the
/// 128s-q20-sha2 profile: the SHA-256 twin of the 128s-q20 profile.
/// Every crypto constant is IDENTICAL to
/// contracts/profiles/128s-q20/SHRINCSParams.sol; only PROFILE_NAME
/// (and PROFILE_ID) carries the suite-qualified "-sha2" suffix.
/// Selected by the `shrincs-profile/` remapping paired with the sha2
/// `shrincs-hash/` remapping (foundry.toml [profile.128s-q20-sha2]).
/// @dev This directory is a deliberate duplicate of the 128s-q20
/// params, mirroring the 256s/256s-sha2 pair. The suite-identity
/// design keeps a single-literal PROFILE_NAME per profile so the
/// commitment binding stays byte- and gas-neutral (no runtime
/// composition); the cost is this copy. The duplication is guarded:
/// the profile-identity test (SHRINCSProfileInvariants) pins every
/// non-identity constant here to the documented 128s-q20 values under
/// the 128s-q20-sha2 profile (which CI runs), so a divergence on any
/// crypto constant fails CI. q20 fixes STATELESS_SIGNATURE_LIMIT =
/// 2^20; it shares every other constant with the q18 sibling. Node
/// values are truncated to HASH_LEN = 16 bytes, high-aligned in a
/// 32-byte slot (HASH_MASK, [DESIGN §2(b)]). Stateful side follows n
/// (32 chains, target sum 240; maintainer decision Q6). See [DESIGN].
library SHRINCSParams {
    // PROFILE_NAME: the canonical suite-qualified profile string. It is
    // the sole source of this profile's identity: PROFILE_ID hashes it,
    // and the public-key commitment binds it as the tag suffix
    // "shrincs-public-key/<PROFILE_NAME>" ([DESIGN §4] rider Q2), so the
    // two can never drift. The "-sha2" suffix domain-separates this
    // profile's commitments from the keccak
    // "shrincs-128s-q20-keccak" twin.
    string internal constant PROFILE_NAME = "shrincs-128s-q20-sha2";
    // PROFILE_ID: stable identifier for this compiled profile. Consumed
    // by the profile-identity test/CI guard ([DESIGN §3.5]).
    bytes32 internal constant PROFILE_ID = keccak256(bytes(PROFILE_NAME));

    // Encoded stateful public key layout (kept 68 bytes across all
    // profiles, [DESIGN §3.2]):
    // 32-byte pkSeed || 32-byte root || 4-byte maxSignatures.
    uint16 internal constant STATEFUL_PUBLIC_KEY_BYTES = 68;
    // Stateful WOTS-C follows n: 2n = 32 chains (maintainer decision Q6).
    uint16 internal constant WOTS_CHAINS_STATEFUL = 32;
    // Stateful WOTS-C uses base-16 digits for message expansion.
    uint16 internal constant WOTS_BASE_STATEFUL = 16;
    // WOTS_TARGET_SUM_STATEFUL: the WOTS-C constant digit-sum target
    // = len * (w - 1) / 2
    // -> WOTS_CHAINS_STATEFUL * (WOTS_BASE_STATEFUL - 1) / 2
    //    = 32 * (16 - 1) / 2 = 240
    // Python: 32 * (16 - 1) // 2
    uint32 internal constant WOTS_TARGET_SUM_STATEFUL = 240;
    // STATELESS_SIGNATURE_LIMIT: the stateless-signature budget for this
    // profile = 2^20 (~4 FORS reuses per h = 18 hypertree leaf on
    // average). NOTE: the q20 budget wants profile security-analysis
    // backing before production use (maintainer decision Q1,
    // 2026-07-10); q18 is the conservative sibling with the same
    // (a, k, h) constants.
    // -> 1 << 20 = 1048576
    // Python: 2 ** 20
    uint64 internal constant STATELESS_SIGNATURE_LIMIT = 1_048_576;
    // HASH_LEN: the SPHINCS/WOTS `n` security parameter [FIPS205 §11] —
    // hash output length in bytes.
    uint16 internal constant HASH_LEN = 16;
    // HASH_MASK: high-aligned truncation mask ([DESIGN §2(b)/§3.3]).
    // Keeps the top HASH_LEN bytes of a 32-byte hash slot and zeroes the
    // low (32 - HASH_LEN), so node values are high-aligned, zero-padded.
    // = ((1 << (8*HASH_LEN)) - 1) << (8*(32 - HASH_LEN))
    // -> (2^128 - 1) << 128  (high 16 bytes set)
    // Python: (((1 << (8*16)) - 1) << (8*(32-16))) & (2**256 - 1)
    bytes32 internal constant HASH_MASK =
        bytes32(uint256(type(uint128).max) << 128);
    // HYPERTREE_HEIGHT: the FIPS205 `h` parameter [FIPS205 §7] — total
    // hypertree height (sum of all subtree heights).
    uint8 internal constant HYPERTREE_HEIGHT = 18;
    // NUM_HYPERTREE_LAYERS: the FIPS205 `d` parameter [FIPS205 §7] —
    // number of hypertree layers. d = 1 ⇒ subtree height h/d = 18 and
    // the tree index is always 0 (treeBits = h - h/d = 0).
    uint8 internal constant NUM_HYPERTREE_LAYERS = 1;
    // FORS_TREE_HEIGHT: the SPHINCSPLUS `a` parameter [SPHINCSPLUS §5.5]
    // — FORS tree height (each FORS tree has 2^a leaves).
    uint8 internal constant FORS_TREE_HEIGHT = 24;
    // NUM_FORS_TREES: the SPHINCSPLUS `k` parameter [SPHINCSPLUS §5.5] —
    // number of FORS trees per FORS signature (FORS-C reveals k - 1 = 5).
    uint8 internal constant NUM_FORS_TREES = 6;
    // WOTS_CHAIN_LEN: the WOTSPLUS `w` (Winternitz) parameter
    // [WOTSPLUS §3] — hash-chain length and digit base.
    uint16 internal constant WOTS_CHAIN_LEN = 16;
    // NUM_WOTS_CHAINS: the WOTSPLUS `len` parameter [WOTSPLUS §3] —
    // number of hash chains per WOTS signature. WOTS-C carries no
    // checksum chains, so len = 2n = 32 for w = 16.
    uint16 internal constant NUM_WOTS_CHAINS = 32;
    // WOTS_TARGET_SUM_STATELESS: the WOTS-C constant digit-sum target
    // for the stateless hypertree WOTS chains (Hypertree.verifyWotsC32)
    // = len * (w - 1) / 2
    // -> NUM_WOTS_CHAINS * (WOTS_CHAIN_LEN - 1) / 2
    //    = 32 * (16 - 1) / 2 = 240
    // Python: 32 * (16 - 1) // 2
    uint32 internal constant WOTS_TARGET_SUM_STATELESS = 240;
}
