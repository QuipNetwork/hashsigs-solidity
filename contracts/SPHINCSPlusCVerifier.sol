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

import {
    IERC7913SignatureVerifier
} from "./interfaces/IERC7913SignatureVerifier.sol";
import {SPHINCSPlusC} from "./SPHINCSPlusC.sol";

/// @title SPHINCSPlusCVerifier
/// @notice ERC-7913 signature verifier for the stateless SPHINCSPlusC
/// scheme: a FORS-C few-time signature carried up a hypertree of WOTS-C
/// layers to a pinned public root.
/// @dev Trustless by construction: no owner, no storage, no constructor, no
/// upgradability. `key` is abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot)
/// (64 bytes); `signature` is the fixed-layout FORS || hypertree signature
/// described in StatelessLayout (StatelessLayout.PQ_LEN bytes). No commitment
/// logic anywhere in it: the caller (or the SHRINCSVerifier delegating here)
/// owns the bundle and commitment binding.
///
/// Revert model. A malformed key (wrong length), a signature of the wrong
/// length, and a well-formed but invalid signature all return 0xffffffff:
/// the single length check proves every fixed-offset read in bounds, so
/// there is no reverting decode. No try/catch anywhere. Out-of-gas reverts
/// to the caller; ERC-7913 permits this. Every word is read from a fixed
/// offset inside the signature, never from adjacent calldata, so the
/// encoding has no framing malleability. Verification runs in-contract
/// through the SPHINCSPlusC library with no external call.
///
/// Caller obligations. The shared SPHINCSPlusC verification stack is `view`
/// because it also compiles with the SHA-256 suite. Its hashing helpers use
/// `staticcall` to precompile 0x02. The adapter verifies signatures without
/// touching persistent state. Budget accounting, nonce and key-version replay
/// scoping, and rotated-key installation belong to the WRAPPER contract.
/// SHRINCSAccountVerifierExample is the reference wrapper. Any future
/// storage-needing helper belongs in a separate wrapper/base contract at the
/// top of the inheritance chain, never in this adapter or its libraries.
///
/// @dev Abstract profile base. The verify logic is profile-agnostic (it
/// takes its parameter tuple from the compile-time-selected SHRINCSParams);
/// each build profile deploys its own concrete subclass
/// (SPHINCSPlusC256sKeccak / SPHINCSPlusC128sQ18Keccak /
/// SPHINCSPlusC128sQ20Keccak), which adds a PROFILE_TAG and is compiled under
/// that profile's constants. This is `abstract` so the unsuffixed,
/// profile-ambiguous artifact can never be deployed.
abstract contract SPHINCSPlusCVerifier is IERC7913SignatureVerifier {
    // Version tag identifying this verifier's key/envelope format family.
    // Shared across profiles: it names the ERC-7913 key/envelope format for
    // the stateless SPHINCSPlusC scheme, not the parameter set. The
    // per-profile parameter identity lives in each subclass's PROFILE_TAG.
    // v4: the signature is the fixed StatelessLayout layout.
    bytes32 public constant VERSION_TAG =
        keccak256("quip.sphincsplusc-verifier.v4");
    // Any non-magic value denotes signature failure.
    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    /// @notice ERC-7913 verification entrypoint for stateless SPHINCSPlusC
    /// signatures.
    /// @dev Decodes the 64-byte key into two calldata seed slices, then
    /// verifies FORS-C plus the hypertree over the 32 hash bytes under the
    /// public seed and root, reading the fixed-layout signature in place.
    /// See the contract-level revert model.
    /// @param key abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot).
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The stateless signature (StatelessLayout.PQ_LEN
    /// bytes).
    /// @return The verify selector on success; 0xffffffff otherwise.
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (bytes calldata pkSeed, bytes calldata hypertreeRoot, bool okKey) =
            SPHINCSPlusC.decodeKey(key);
        if (!okKey) return INVALID_SIGNATURE;
        if (SPHINCSPlusC.verify(pkSeed, hypertreeRoot, hash, signature)) {
            return IERC7913SignatureVerifier.verify.selector;
        }
        return INVALID_SIGNATURE;
    }
}
