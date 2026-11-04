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

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

/// @title StatelessLayout
/// @notice Fixed-layout wire format for SHRINCS stateless signatures, and
/// the calldata word readers the stateless verify path uses.
/// @dev This is the only stateless signature encoding. It replaced the
/// pre-0.4.0 ABI envelope, which carried an offset and a length word for
/// every dynamic field and did not fit the WalletConnect relay payload cap.
/// The fixed form is a
/// flat concatenation of 32-byte words and two big-endian uint32 counters,
/// with every size taken from the compiled SHRINCSParams profile. There are
/// no offsets, so a payload is either exactly PAYLOAD_LEN bytes or rejected.
/// The layout is documented in docs/compact-stateless-encoding.md and
/// mirrored by the SDK encoder.
///
///   payload = PK || PQ
///     PK = statefulPublicKey || publicKeyCommitment || pkSeed ||
///          hypertreeRoot
///     PQ = FORS || hypertree     (the SPHINCSPlusC signature)
///       FORS = randomizer || counter(4) || entry[k-1]
///         entry = secretLeaf || authPath[a]
///       hypertree = layer[d]
///         layer = wotsCPkHash || randomizer || counter(4) ||
///                 chains[len] || authPath[h/d]
///
/// Revert model. Every stateless verify function checks one total length
/// up front, then reads fixed offsets that the length check proves are in
/// bounds. A wrong length or a failed check returns false (0xffffffff at
/// the ERC-7913 boundary). The stateless path never reverts on malformed
/// input; only out-of-gas reverts.
library StatelessLayout {
    // ENCODING_VERSION: version of this fixed layout. The wallet
    // envelope header carries it; verifiers expose it for capability
    // detection. Bump on any change to the offsets below.
    uint8 internal constant ENCODING_VERSION = 1;

    // Public-key section -------------------------------------------------

    // STATEFUL_PUBLIC_KEY_LEN: width of the packed stateful public key,
    // the first PK field -> STATEFUL_PUBLIC_KEY_BYTES. 256s: 68.
    uint256 internal constant STATEFUL_PUBLIC_KEY_LEN =
        SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES;
    // Offsets of the three 32-byte PK words after the stateful key.
    uint256 internal constant COMMITMENT_OFFSET = STATEFUL_PUBLIC_KEY_LEN;
    uint256 internal constant PK_SEED_OFFSET = COMMITMENT_OFFSET + 32;
    uint256 internal constant HYPERTREE_ROOT_OFFSET = PK_SEED_OFFSET + 32;
    // PK_LEN: statefulPublicKey || commitment || pkSeed || hypertreeRoot
    // -> STATEFUL_PUBLIC_KEY_BYTES + 3 * 32. 256s: 68 + 96 = 164.
    // Python: 68 + 3 * 32
    uint256 internal constant PK_LEN = HYPERTREE_ROOT_OFFSET + 32;

    // FORS section (offsets relative to the FORS slice) -----------------

    // FORS_SIGNED_TREES: the SPHINCSPLUS `k` parameter minus one
    // [SPHINCSPLUSC §4] — FORS-C omits the final tree: k - 1
    // -> NUM_FORS_TREES - 1. 256s: 22 - 1 = 21.
    // Python: 22 - 1
    uint256 internal constant FORS_SIGNED_TREES =
        uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
    uint256 internal constant FORS_RANDOMIZER_OFFSET = 0;
    uint256 internal constant FORS_COUNTER_OFFSET = 32;
    uint256 internal constant FORS_ENTRIES_OFFSET = 36;
    // FORS_ENTRY_LEN: secretLeaf || authPath[a], a = FORS_TREE_HEIGHT
    // [SPHINCSPLUS §5.5] -> 32 + FORS_TREE_HEIGHT * 32.
    // 256s: 32 + 14 * 32 = 480.
    // Python: 32 + 14 * 32
    uint256 internal constant FORS_ENTRY_LEN =
        32 + uint256(SHRINCSParams.FORS_TREE_HEIGHT) * 32;
    // FORS_LEN: randomizer || counter || entry[k-1]
    // -> 36 + (k - 1) * FORS_ENTRY_LEN. 256s: 36 + 21 * 480 = 10116.
    // Python: 36 + 21 * (32 + 14 * 32)
    uint256 internal constant FORS_LEN =
        FORS_ENTRIES_OFFSET + FORS_SIGNED_TREES * FORS_ENTRY_LEN;

    // Hypertree section (offsets relative to one layer slice) -----------

    // SUBTREE_HEIGHT: the SPHINCSPLUS `h' = h / d` parameter
    // [SPHINCSPLUS §5] — height of one hypertree subtree
    // -> HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS. 256s: 64 / 8 = 8.
    // Python: 64 // 8
    uint256 internal constant SUBTREE_HEIGHT = uint256(
        SHRINCSParams.HYPERTREE_HEIGHT
    ) / uint256(SHRINCSParams.NUM_HYPERTREE_LAYERS);
    uint256 internal constant LAYER_PK_HASH_OFFSET = 0;
    uint256 internal constant LAYER_RANDOMIZER_OFFSET = 32;
    uint256 internal constant LAYER_COUNTER_OFFSET = 64;
    uint256 internal constant LAYER_CHAINS_OFFSET = 68;
    // LAYER_AUTH_PATH_OFFSET: 68 + len * 32, len = NUM_WOTS_CHAINS
    // [WOTSPLUS §3] -> LAYER_CHAINS_OFFSET + NUM_WOTS_CHAINS * 32.
    // 256s: 68 + 64 * 32 = 2116.
    // Python: 68 + 64 * 32
    uint256 internal constant LAYER_AUTH_PATH_OFFSET =
        LAYER_CHAINS_OFFSET + uint256(SHRINCSParams.NUM_WOTS_CHAINS) * 32;
    // LAYER_LEN: pkHash || randomizer || counter || chains || authPath
    // -> 68 + len * 32 + h' * 32, with h' * 32 written as h * 32 / d so the
    // multiplication precedes the division. 256s: 2116 + 64 * 32 / 8 = 2372.
    // Python: 68 + 64 * 32 + 64 * 32 // 8
    uint256 internal constant LAYER_LEN = LAYER_AUTH_PATH_OFFSET
        + uint256(SHRINCSParams.HYPERTREE_HEIGHT) * 32
        / uint256(SHRINCSParams.NUM_HYPERTREE_LAYERS);
    // HYPERTREE_LEN: d * LAYER_LEN -> NUM_HYPERTREE_LAYERS * LAYER_LEN.
    // 256s: 8 * 2372 = 18976.
    // Python: 8 * (68 + 64 * 32 + 8 * 32)
    uint256 internal constant HYPERTREE_LEN =
        uint256(SHRINCSParams.NUM_HYPERTREE_LAYERS) * LAYER_LEN;

    // Totals -------------------------------------------------------------

    // PQ_LEN: the SPHINCSPlusC signature, FORS || hypertree
    // -> FORS_LEN + HYPERTREE_LEN. 256s: 10116 + 18976 = 29092.
    // Python: 10116 + 18976
    uint256 internal constant PQ_LEN = FORS_LEN + HYPERTREE_LEN;
    // PAYLOAD_LEN: the SHRINCS stateless payload, PK || PQ
    // -> PK_LEN + PQ_LEN. 256s: 164 + 29092 = 29256.
    // Python: 164 + 29092
    uint256 internal constant PAYLOAD_LEN = PK_LEN + PQ_LEN;

    // publicKeyFields: Slice the four public-key fields out of a payload.
    /// @dev Precondition: payload.length >= PK_LEN, proven by the caller's
    /// total-length check. Each field is a calldata slice; nothing is
    /// copied.
    function publicKeyFields(bytes calldata payload)
        internal
        pure
        returns (
            bytes calldata statefulPublicKey,
            bytes calldata commitment,
            bytes calldata pkSeed,
            bytes calldata hypertreeRoot
        )
    {
        statefulPublicKey = payload[0:COMMITMENT_OFFSET];
        commitment = payload[COMMITMENT_OFFSET:PK_SEED_OFFSET];
        pkSeed = payload[PK_SEED_OFFSET:HYPERTREE_ROOT_OFFSET];
        hypertreeRoot = payload[HYPERTREE_ROOT_OFFSET:PK_LEN];
    }

    // readWord: Load the 32-byte word at `offset` inside `data`.
    /// @dev Precondition: offset + 32 <= data.length. Every caller proves
    /// this with its single up-front total-length check against the
    /// constants above; there is no per-read check.
    function readWord(bytes calldata data, uint256 offset)
        internal
        pure
        returns (bytes32 value)
    {
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            value := calldataload(add(data.offset, offset))
        }
    }

    // readUint32: Load the big-endian uint32 at `offset` inside `data`.
    /// @dev Loads a full word starting at `offset` and keeps its top four
    /// bytes. Precondition: offset + 32 <= data.length, as for readWord.
    /// Both counter fields sit at least 32 bytes before the end of their
    /// section, so the extra 28 bytes read the next field and are
    /// discarded.
    function readUint32(bytes calldata data, uint256 offset)
        internal
        pure
        returns (uint32)
    {
        // casting to 'uint32' is safe because bytes4 holds exactly 32
        // bits
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(bytes4(readWord(data, offset)));
    }
}
