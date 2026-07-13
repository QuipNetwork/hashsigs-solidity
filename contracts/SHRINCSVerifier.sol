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
import {SHRINCS} from "./SHRINCS.sol";

/// @title SHRINCSVerifier
/// @notice ERC-7913 signature verifier for the hybrid SHRINCS scheme:
/// stateful actions via `verify`, stateless actions delegated to a pinned
/// SPHINCSPlusC verifier via `verifyStateless`.
/// @dev Trustless by construction: no owner, no storage, no constructor, no
/// upgradability. `key` is the 32-byte SHRINCS publicKeyCommitment;
/// `signature` is the SHRINCS stateful envelope
/// (abi.encode(PublicKey, SHRINCS.Signature)) for `verify`, or the
/// stateless envelope (abi.encode(PublicKey, SPHINCSPlusC.Signature)) for
/// `verifyStateless`. Verifies signature validity only.
///
/// Revert model (deliberate: replaces the previous try/catch swallow).
/// A malformed key (wrong length) returns 0xffffffff through the length-
/// guarded key decoder. A malformed envelope reverts downstream through
/// solc's calldata member access on the re-tagged struct (the canonicity
/// walk is gone; a short buffer, out-of-range offset or length, or dirty
/// value-type high bits reverts there) — that revert is the rejection
/// channel, and there is no try/catch anywhere. A well-formed but invalid
/// signature returns 0xffffffff. Every other failure, including an inner
/// out-of-gas, reverts to the caller; ERC-7913 permits this (the interface
/// says a verifier SHOULD return 0xffffffff OR revert on an invalid
/// signature). A caller that needs a boolean must treat a revert as its own
/// policy decision. Acceptance is wider than abi.decode's: any framing whose
/// in-place field reads reproduce a valid signature's field values verifies.
/// The reads are bounds-checked against calldatasize, not the envelope
/// slice, so they may read into adjacent calldata such as the outer ABI
/// padding, and under masked-hash profiles a tail-truncated envelope can
/// still verify. This is pure encoding malleability, never a wrong-accept;
/// consumers must key on decoded fields, not envelope bytes.
/// The stateful `verify` path runs entirely in-contract through the
/// calldata-typed SHRINCS library, verifying the re-tagged envelope in place
/// with no external call. The only remaining external call is
/// `verifyStateless`'s delegation to the pinned SPHINCSPlusC sibling; no try
/// surrounds it, so an out-of-gas there propagates as a revert instead of
/// being misreported as an invalid signature.
///
/// Caller obligations. Every SHRINCS library is `pure` and both adapters
/// are storage-free (their entrypoints are `view` or `pure`); they verify a
/// signature and nothing more. All statefulness is the WRAPPER contract's
/// job: single-use tracking of stateful leaves, nonce and keyVersion replay
/// scoping, and installing the commitment a rotation returns.
/// SHRINCSAccountVerifierExample is the reference wrapper. Any future
/// storage-needing helper belongs in a separate wrapper/base contract at the
/// top of the inheritance chain, never in these libraries or adapters.
///
/// @dev Abstract profile base. The verify/decode logic is profile-agnostic
/// (it takes its parameter tuple from the compile-time-selected
/// SHRINCSParams); each build profile deploys its own concrete subclass
/// (SHRINCS256sKeccak / SHRINCS128sQ18Keccak / SHRINCS128sQ20Keccak), which
/// adds a PROFILE_TAG, pins its sibling SPHINCSPlusC verifier address, and is
/// compiled under that profile's constants. This is `abstract` so the
/// unsuffixed, profile-ambiguous artifact can never be deployed. The ABI
/// surface (verify, verifyStateless, VERSION_TAG) is preserved on every
/// concrete subclass.
abstract contract SHRINCSVerifier is IERC7913SignatureVerifier {
    // Version tag identifying this verifier's key/envelope format family.
    // Shared across profiles: it names the ERC-7913 key/envelope format,
    // not the parameter set. The per-profile parameter identity lives in
    // each subclass's PROFILE_TAG. Unchanged by the adapter restructure:
    // the key/envelope format family it names is unchanged.
    bytes32 public constant VERSION_TAG =
        keccak256("quip.shrincs-verifier.v1");
    // Any non-magic value denotes signature failure.
    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    /// @notice ERC-7913 verification entrypoint for stateful signatures.
    /// @dev Decodes the 32-byte key into the installed bundle commitment
    /// (wrong length -> 0xffffffff) and re-tags the stateful envelope in
    /// place (a malformed envelope reverts downstream), then hands the
    /// typed calldata struct pointers straight to the calldata-typed SHRINCS
    /// library, which enforces the commitment-vs-bundle match, bundle shape,
    /// leaf-index bounds, WOTS-C
    /// reconstruction, and the unbalanced-tree root over exactly the 32 hash
    /// bytes. No external call, no try/catch: an execution failure, including
    /// out-of-gas, reverts. See the contract-level revert model.
    /// @param key The 32-byte SHRINCS publicKeyCommitment.
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The SHRINCS stateful envelope.
    /// @return The verify selector on success; 0xffffffff for a malformed key
    /// (wrong length) or a well-formed but invalid signature. A malformed
    /// envelope and other execution failures revert.
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (bytes32 publicKeyCommitment, bool okKey) =
            SHRINCS.decodePublicKeyCommitment(key);
        if (!okKey) return INVALID_SIGNATURE;

        (
            SHRINCS.PublicKey calldata publicKey,
            SHRINCS.Signature calldata statefulSignature
        ) = SHRINCS.statefulEnvelope(signature);

        if (SHRINCS.verify(
                publicKeyCommitment, hash, publicKey, statefulSignature
            )) {
            return IERC7913SignatureVerifier.verify.selector;
        }
        return INVALID_SIGNATURE;
    }

    /// @notice ERC-7913-style verification entrypoint for stateless
    /// signatures, delegated to the pinned SPHINCSPlusC verifier.
    /// @dev Decodes the 32-byte key (the installed commitment; wrong length
    /// -> 0xffffffff), then hands the stateless envelope to
    /// SHRINCS.prepareStatelessDelegation, which re-tags it in place (a
    /// malformed envelope reverts downstream), runs the bundle-vs-commitment
    /// check (commitment first, then shape, mirroring the library stateless
    /// path),
    /// loads the two 32-byte stateless seed words, and returns the delegate
    /// key
    /// (abi.encode(pkSeed, hypertreeRoot)) and stateless signature envelope.
    /// This adapter then delegates the FORS-C + hypertree cryptography to the
    /// pinned SPHINCSPlusC deployment, returning that verifier's selector or
    /// 0xffffffff. No try/catch: a failure in the delegate reverts.
    /// This is a high-level bytes4-returning call, so solc's extcodesize and
    /// return-data-length checks make a call to an undeployed or
    /// short-returning sibling revert, never a false 0xffffffff.
    /// @param key The 32-byte SHRINCS publicKeyCommitment.
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The SHRINCS stateless envelope.
    /// @return The verify selector on success; 0xffffffff for a malformed key
    /// (wrong length) or a well-formed but invalid signature. A malformed
    /// envelope and other execution failures revert.
    function verifyStateless(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (bytes32 publicKeyCommitment, bool okKey) =
            SHRINCS.decodePublicKeyCommitment(key);
        if (!okKey) return INVALID_SIGNATURE;

        (
            bool okDelegation,
            bytes memory delegateKey,
            bytes memory delegateSignature
        ) = SHRINCS.prepareStatelessDelegation(
            publicKeyCommitment, signature
        );
        if (!okDelegation) return INVALID_SIGNATURE;

        return IERC7913SignatureVerifier(_pinnedSphincsPlusC())
            .verify(delegateKey, hash, delegateSignature);
    }

    /// @notice Address of the pinned SPHINCSPlusC verifier this profile
    /// delegates stateless verification to.
    /// @dev The abstract base cannot know the profile, so each concrete
    /// subclass overrides this with a compile-time constant equal to the
    /// CREATE3 address of its SPHINCSPlusC sibling, pinned by a profile-gated
    /// test so C8's deploy scripts cannot drift from it.
    /// @return The pinned SPHINCSPlusC verifier address.
    function _pinnedSphincsPlusC() internal view virtual returns (address);
}
