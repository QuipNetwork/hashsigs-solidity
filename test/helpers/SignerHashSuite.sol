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

/// @title SignerHashSuite (TEST-ONLY)
/// @notice Suite-aware scheme hash for the in-Solidity test signers. The
/// production HashSuite seam (shrincs-hash/) already routes every
/// VERIFIER-shape scheme hash; the test signers route those through it
/// directly. This sibling covers only the SIGNER-ONLY scheme hashes that have
/// no verifier counterpart -- keygen KDFs, PRF randomizers, per-chain/leaf
/// secrets, and the stateful empty-tail node -- so that under the SHA-256
/// suite they swap to SHA-256 in lockstep with the Rust signer's scheme_hash
/// seam, while the keccak suites stay byte-identical.
/// @dev Dispatch is on HashSuite.HASH_SUITE_ID (1 = keccak-256, 2 = SHA-256),
/// the same id the production suite exports [83d hash-seam design]. Both
/// branches are `pure`: keccak256 is an opcode and sha256() is a pure builtin
/// (the FIPS 180-4 precompile via the compiler intrinsic), so the signer
/// stays `pure` for signer-only shapes and no view-widening propagates from
/// them. HASH_SUITE_ID is a compile-time constant, so the unused branch folds
/// away and the keccak build hashes with keccak256 alone. This library is
/// TEST-ONLY (kept under test/helpers); production contracts never route
/// through it. EVM-domain hashes (the public-key commitment, account
/// action/rotation framing) stay keccak and are NOT routed here.
library SignerHashSuite {
    // schemeHash: suite-selected scheme hash over a packed preimage.
    // Mirrors the Rust signer's scheme_hash / hash_packed seam: keccak-256
    // under the keccak suites, SHA-256 under the 256s-sha2 suite. The caller
    // passes the exact abi.encodePacked(...) preimage; only the hash
    // primitive changes across suites, never the tag string or field layout.
    function schemeHash(bytes memory data) internal pure returns (bytes32) {
        if (HashSuite.HASH_SUITE_ID == 1) {
            return keccak256(data);
        }
        return sha256(data);
    }
}
