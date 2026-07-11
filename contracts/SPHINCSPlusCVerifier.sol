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
import {SHRINCSCodec} from "./SHRINCSCodec.sol";
import {SPHINCSPlusC} from "./SPHINCSPlusC.sol";

/// @title SPHINCSPlusCVerifier
/// @notice ERC-7913 signature verifier for the stateless SPHINCSPlusC
/// scheme: a FORS-C few-time signature carried up a hypertree of WOTS-C
/// layers to a pinned public root.
/// @dev Trustless by construction: no owner, no storage, no constructor, no
/// upgradability. `key` is abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot)
/// (64 bytes); `signature` is the SHRINCSCodec stateless-signature envelope
/// (abi.encode(StatelessSignature)). No commitment logic anywhere in it:
/// the caller (or the SHRINCSVerifier delegating here) owns the bundle and
/// commitment binding.
///
/// Revert model (same as the SHRINCSVerifier). A malformed key or envelope
/// returns 0xffffffff, reached only through SHRINCSCodec's non-reverting
/// structural validation — no try/catch anywhere. Every other failure,
/// including an inner out-of-gas, reverts to the caller; ERC-7913 permits
/// this. verify runs entirely in-contract through the memory-typed
/// SPHINCSPlusC library, with no external call.
///
/// Caller obligations. Every SPHINCSPlusC library is `pure` and this
/// adapter's `verify` is likewise storage-free and `pure` (removing the
/// self-call hop left no external call); it verifies a signature and nothing
/// more. All
/// statefulness — stateless-budget accounting, nonce/keyVersion replay
/// scoping, installing a rotated key — is the WRAPPER contract's job.
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
    bytes32 public constant VERSION_TAG =
        keccak256("quip.sphincsplusc-verifier.v1");
    // Any non-magic value denotes signature failure.
    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    /// @notice ERC-7913 verification entrypoint for stateless SPHINCSPlusC
    /// signatures.
    /// @dev Decodes the 64-byte key into the two stateless seed words and the
    /// stateless-signature envelope through SHRINCSCodec's non-reverting
    /// validators (malformed key or envelope -> 0xffffffff). After validation
    /// abi.decode is infallible, so verify re-materializes the two seed words
    /// as 32-byte `bytes memory` and hands them, with the decoded signature,
    /// straight to the memory-typed SPHINCSPlusC library, which verifies
    /// FORS-C plus the hypertree over exactly the 32 hash bytes under the
    /// public seed and root. No external call, no try/catch: an execution
    /// failure, including out-of-gas, reverts. See the contract-level revert
    /// model.
    /// @param key abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot).
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The SHRINCSCodec stateless-signature envelope.
    /// @return The verify selector on success; 0xffffffff for a
    /// malformed key or envelope, or a well-formed but invalid
    /// signature. Execution failures revert.
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external pure returns (bytes4) {
        (bytes32 pkSeed, bytes32 hypertreeRoot, bool okKey) =
            SHRINCSCodec.decodeStatelessKey(key);
        if (!okKey) return INVALID_SIGNATURE;

        (
            SPHINCSPlusC.StatelessSignature memory signature_,
            bool okEnvelope
        ) = SHRINCSCodec.decodeStatelessSignatureEnvelope(signature);
        if (!okEnvelope) return INVALID_SIGNATURE;

        // The two seed words become 32-byte `bytes memory` for the
        // memory-typed SPHINCSPlusC library call.
        bool valid = SPHINCSPlusC.verify(
            abi.encodePacked(pkSeed),
            abi.encodePacked(hypertreeRoot),
            SHRINCSCodec.toMessage(hash),
            signature_
        );
        if (valid) return IERC7913SignatureVerifier.verify.selector;
        return INVALID_SIGNATURE;
    }
}
