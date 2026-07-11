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
import {SHRINCSCore} from "./SHRINCSCore.sol";
import {SHRINCSCodec} from "./SHRINCSCodec.sol";
import {SPHINCSPlusCCore} from "./SPHINCSPlusCCore.sol";
import {UXMSS} from "./UXMSS.sol";

/// @title SHRINCS
/// @notice ERC-7913 signature verifier for the hybrid SHRINCS scheme:
/// stateful actions via `verify`, stateless actions delegated to a pinned
/// SPHINCSPlusC verifier via `verifyStateless`.
/// @dev Trustless by construction: no owner, no storage, no constructor, no
/// upgradability. `key` is the 32-byte SHRINCS publicKeyCommitment;
/// `signature` is the SHRINCSCodec stateful envelope
/// (abi.encode(PublicKey, StatefulSignature)) for `verify`, or the
/// stateless envelope (abi.encode(PublicKey, StatelessSignature)) for
/// `verifyStateless`. Verifies signature validity only.
///
/// Revert model (deliberate: replaces the previous try/catch swallow).
/// A malformed key or envelope returns 0xffffffff, reached only through the
/// non-reverting structural validation in SHRINCSCodec — there is no
/// try/catch anywhere. Every other failure, including an inner out-of-gas,
/// reverts to the caller; ERC-7913 permits this (the interface says a
/// verifier SHOULD return 0xffffffff OR revert on an invalid signature).
/// A caller that needs a boolean must treat a revert as its own policy
/// decision. Exactly one self-call hop remains per entrypoint: the
/// memory->calldata re-materialization bridge, since SHRINCSCore takes
/// calldata structs and external functions cannot live in a library. No
/// try surrounds that hop, so an out-of-gas there propagates as a revert
/// instead of being misreported as an invalid signature.
///
/// Caller obligations. Every SHRINCS library is `pure` and both adapters are
/// storage-free `view`; they verify a signature and nothing more. All
/// statefulness is the WRAPPER contract's job: single-use tracking of
/// stateful leaves, nonce and keyVersion replay scoping, and installing the
/// commitment a rotation returns. SHRINCSAccountVerifierExample is the
/// reference wrapper. Any future storage-needing helper belongs in a
/// separate wrapper/base contract at the top of the inheritance chain, never
/// in these libraries or adapters.
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
abstract contract SHRINCS is IERC7913SignatureVerifier {
    // Version tag identifying this verifier's key/envelope format family.
    // Shared across profiles: it names the ERC-7913 key/envelope format,
    // not the parameter set. The per-profile parameter identity lives in
    // each subclass's PROFILE_TAG. Unchanged by the adapter restructure:
    // the key/envelope format family it names is unchanged.
    bytes32 public constant VERSION_TAG =
        keccak256("quip.shrincs-verifier.v1");
    // Any non-magic value denotes signature failure.
    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    /// @notice ERC-7913 verification entrypoint for stateful signatures.
    /// @dev Decodes the 32-byte key into the installed bundle commitment and
    /// the stateful envelope through SHRINCSCodec's non-reverting validators
    /// (malformed key or envelope -> 0xffffffff). After validation abi.decode
    /// is infallible, so verify itself decodes and drives the single
    /// memory->calldata self-call hop. No try/catch: an execution failure,
    /// including out-of-gas, reverts. See the contract-level revert model.
    /// @param key The 32-byte SHRINCS publicKeyCommitment.
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The SHRINCSCodec stateful envelope.
    /// @return The verify selector on success, 0xffffffff on malformed input.
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (bytes32 commitment, bool okKey) = SHRINCSCodec.decodeKey(key);
        if (!okKey) return INVALID_SIGNATURE;

        (
            SHRINCSCore.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature_,
            bool okEnvelope
        ) = SHRINCSCodec.decodeStatefulEnvelope(signature);
        if (!okEnvelope) return INVALID_SIGNATURE;

        if (this.checkStateful(commitment, hash, publicKey, signature_)) {
            return IERC7913SignatureVerifier.verify.selector;
        }
        return INVALID_SIGNATURE;
    }

    /// @notice Self-call hop — calldata re-materialization and stateful
    /// verification. onlySelf.
    /// @dev Receiving the structs through an external call re-encodes the
    /// validated memory structs into calldata (SHRINCSCore takes calldata
    /// structs), then verifies the stateful signature over exactly the 32
    /// hash bytes under the commitment. SHRINCSCore enforces the
    /// commitment-vs-bundle match, bundle shape, leaf-index bounds, WOTS-C
    /// reconstruction, and the unbalanced-tree root; nothing is added here.
    /// No try wraps this call: an out-of-gas propagates as a revert.
    /// @param commitment The installed bundle commitment.
    /// @param hash The 32-byte message hash.
    /// @param publicKey The decoded public-key bundle.
    /// @param signature The decoded stateful signature.
    /// @return True when the stateful signature verifies.
    function checkStateful(
        bytes32 commitment,
        bytes32 hash,
        SHRINCSCore.PublicKey calldata publicKey,
        UXMSS.StatefulSignature calldata signature
    ) external view onlySelf returns (bool) {
        return SHRINCSCore.verifyStatefulUncheckedMessage(
            commitment, publicKey, SHRINCSCodec.toMessage(hash), signature
        );
    }

    /// @notice ERC-7913-style verification entrypoint for stateless
    /// signatures, delegated to the pinned SPHINCSPlusC verifier.
    /// @dev Decodes the 32-byte key (the installed commitment) and the
    /// stateless envelope through SHRINCSCodec's non-reverting validators
    /// (malformed -> 0xffffffff). Runs the bundle-vs-commitment check locally
    /// (commitment first, then shape, mirroring the library stateless path)
    /// through the single memory->calldata self-call hop, then delegates the
    /// FORS-C + hypertree cryptography to the pinned SPHINCSPlusC deployment
    /// with key = abi.encode(pkSeed, hypertreeRoot) and the stateless
    /// signature envelope, returning that verifier's selector or 0xffffffff.
    /// No try/catch: an execution failure in the delegate reverts.
    /// @param key The 32-byte SHRINCS publicKeyCommitment.
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The SHRINCSCodec stateless envelope.
    /// @return The verify selector on success, 0xffffffff on malformed input.
    function verifyStateless(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (bytes32 commitment, bool okKey) = SHRINCSCodec.decodeKey(key);
        if (!okKey) return INVALID_SIGNATURE;

        (
            SHRINCSCore.PublicKey memory publicKey,
            SPHINCSPlusCCore.StatelessSignature memory signature_,
            bool okEnvelope
        ) = SHRINCSCodec.decodeStatelessEnvelope(signature);
        if (!okEnvelope) return INVALID_SIGNATURE;

        (bool okBundle, bytes32 pkSeed, bytes32 hypertreeRoot) =
            this.checkStatelessBundle(commitment, publicKey);
        if (!okBundle) return INVALID_SIGNATURE;

        return IERC7913SignatureVerifier(_pinnedSphincsPlusC())
            .verify(
                SHRINCSCodec.encodeStatelessKey(pkSeed, hypertreeRoot),
                hash,
                SHRINCSCodec.encodeStatelessSignatureEnvelope(signature_)
            );
    }

    /// @notice Self-call hop — bundle-vs-commitment check and stateless
    /// seed extraction. onlySelf.
    /// @dev Re-materializes the validated bundle as calldata to run the
    /// commitment match (commitment first) then the fixed-shape check,
    /// mirroring SHRINCSCore.verifyStatelessUncheckedMessage's ordering, and
    /// loads the two 32-byte stateless seed words the pinned verifier needs.
    /// No cryptography here; the pinned SPHINCSPlusC verifier owns FORS-C and
    /// the hypertree.
    /// @param commitment The installed bundle commitment.
    /// @param publicKey The decoded public-key bundle.
    /// @return ok True when the bundle matches the commitment and shape.
    /// @return pkSeed The stateless public seed word.
    /// @return hypertreeRoot The stateless public root word.
    function checkStatelessBundle(
        bytes32 commitment,
        SHRINCSCore.PublicKey calldata publicKey
    )
        external
        view
        onlySelf
        returns (bool ok, bytes32 pkSeed, bytes32 hypertreeRoot)
    {
        // Commitment first, then shape, mirroring the library stateless path.
        if (!SHRINCSCodec.matchesExpectedPublicKeyCommitment(
                publicKey, commitment
            )) return (false, bytes32(0), bytes32(0));
        if (!SHRINCSCodec.validPublicKey(publicKey)) {
            return (false, bytes32(0), bytes32(0));
        }
        // validPublicKey has proven both fields are exactly 32 bytes.
        bytes calldata seed = publicKey.pkSeed;
        bytes calldata root = publicKey.hypertreeRoot;
        // Memory-safe: reads two calldata words into stack variables; no
        // memory is written.
        assembly ("memory-safe") {
            pkSeed := calldataload(seed.offset)
            hypertreeRoot := calldataload(root.offset)
        }
        return (true, pkSeed, hypertreeRoot);
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
