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

import {SHRINCS} from "./SHRINCS.sol";
import {UXMSS} from "./UXMSS.sol";
import {SPHINCSPlusC} from "./SPHINCSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

/// @notice Byte-format definitions bridging ERC-7913 opaque bytes to typed
/// SHRINCS structs.
/// @dev Single source of truth for the verifier envelope format; tests (and
/// later the SDK) must encode through this library so encoder and decoder
/// cannot drift.
/// @dev Revert model: the envelope decoders abi.decode the calldata
/// directly. A malformed encoding reverts inside abi.decode (short buffer,
/// out-of-range offset or length, or dirty value-type high bits); that revert
/// is the rejection channel, so the envelope decoders no longer report
/// malformed input through the `ok` flag (it is now always true on return).
/// The key/commitment decoders still length-check and report a wrong length
/// through `ok == false` without reverting. Acceptance is the ABI's: any
/// non-canonical framing abi.decode tolerates (non-minimal offsets, gap or
/// trailing bytes, dirty `bytes` tail padding) decodes to the same logical
/// value and verifies, so envelopes are byte-malleable — external consumers
/// must key on decoded field values, never on the envelope bytes.
library SHRINCSCodec {
    /// @notice Decode an ERC-7913 `key` into the SHRINCS installed bundle
    /// commitment.
    /// @dev Requires the key to be exactly one 32-byte commitment word and
    /// loads it from calldata. Never reverts; malformed keys are reported
    /// through the ok flag.
    /// @param key The ERC-7913 key bytes (exactly 32 bytes).
    /// @return commitment The decoded 32-byte publicKeyCommitment. Named
    /// `commitment` here only to avoid shadowing this library's
    /// publicKeyCommitment(...) helper; the SHRINCS facade and the verifiers
    /// carry it in a `publicKeyCommitment` local.
    /// @return ok False when the key length is not 32.
    function decodePublicKeyCommitment(bytes calldata key)
        internal
        pure
        returns (bytes32 commitment, bool ok)
    {
        // The key format is exactly the 32-byte SHRINCS publicKeyCommitment,
        // nothing else.
        if (key.length != 32) return (bytes32(0), false);
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the 32-byte commitment word directly from calldata.
            commitment := calldataload(key.offset)
        }
        return (commitment, true);
    }

    /// @notice Decode the ERC-7913 `signature` envelope into typed SHRINCS
    /// structs.
    /// @dev Envelope layout is abi.encode(PublicKey, SHRINCS.Signature) with
    /// no mode prefix. abi.decode reverts on a malformed encoding (short
    /// buffer, out-of-range offset or length, or dirty value-type high bits);
    /// that revert is the rejection channel. Non-canonical framing abi.decode
    /// tolerates decodes to the same value and is accepted (byte-malleable).
    /// @param envelope The abi-encoded stateful envelope bytes.
    /// @return publicKey The decoded SHRINCS public-key bundle.
    /// @return signature The decoded stateful signature.
    /// @return ok Always true on return; a malformed envelope reverts.
    function decodeStatefulEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature,
            bool ok
        )
    {
        (publicKey, signature) =
            abi.decode(envelope, (SHRINCS.PublicKey, SHRINCS.Signature));
        return (publicKey, signature, true);
    }

    /// @notice Inverse of decodeStatefulEnvelope.
    /// @dev Encodes the bundle and stateful signature with the exact layout
    /// the decoder expects, so tests and off-chain encoders share one format
    /// definition with the verifier.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param signature The stateful signature.
    /// @return envelope The abi-encoded stateful envelope bytes.
    function encodeStatefulEnvelope(
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.Signature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    /// @notice Decode the SHRINCSVerifier stateless envelope into typed
    /// structs.
    /// @dev Envelope layout is abi.encode(PublicKey, SPHINCSPlusC.Signature)
    /// with no mode prefix. abi.decode reverts on a malformed encoding (short
    /// buffer, out-of-range offset or length, or dirty value-type high bits);
    /// that revert is the rejection channel. Non-canonical framing abi.decode
    /// tolerates decodes to the same value and is accepted (byte-malleable).
    /// @param envelope The abi-encoded stateless envelope bytes.
    /// @return publicKey The decoded SHRINCS public-key bundle.
    /// @return signature The decoded stateless signature.
    /// @return ok Always true on return; a malformed envelope reverts.
    function decodeStatelessEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,
            bool ok
        )
    {
        (publicKey, signature) = abi.decode(
            envelope, (SHRINCS.PublicKey, SPHINCSPlusC.Signature)
        );
        return (publicKey, signature, true);
    }

    /// @notice Inverse of decodeStatelessEnvelope.
    /// @dev Shares one format definition with the decoder so the verifier,
    /// tests, and off-chain encoders cannot drift.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param signature The stateless signature.
    /// @return envelope The abi-encoded stateless envelope bytes.
    function encodeStatelessEnvelope(
        SHRINCS.PublicKey memory publicKey,
        SPHINCSPlusC.Signature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    /// @notice Decode the SPHINCSPlusCVerifier key into its two seed words.
    /// @dev Key layout is abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot),
    /// exactly 64 bytes of static words with no framing freedom, so a length
    /// check plus two calldata loads is a complete canonicity check. Never
    /// reverts; malformed keys are reported through the ok flag.
    /// @param key The ERC-7913 key bytes (exactly 64 bytes).
    /// @return pkSeed The stateless SPHINCS-style public seed.
    /// @return hypertreeRoot The stateless SPHINCS-style public root.
    /// @return ok False when the key length is not 64.
    function decodeStatelessKey(bytes calldata key)
        internal
        pure
        returns (bytes32 pkSeed, bytes32 hypertreeRoot, bool ok)
    {
        // Two static bytes32 words abi.encode to exactly 64 bytes.
        if (key.length != 64) return (bytes32(0), bytes32(0), false);
        // Memory-safe: reads two calldata words into stack variables; no
        // memory is written.
        assembly ("memory-safe") {
            pkSeed := calldataload(key.offset)
            hypertreeRoot := calldataload(add(key.offset, 32))
        }
        return (pkSeed, hypertreeRoot, true);
    }

    /// @notice Inverse of decodeStatelessKey.
    /// @dev Builds the SPHINCSPlusCVerifier key the sub-call verify expects.
    /// @param pkSeed The stateless SPHINCS-style public seed.
    /// @param hypertreeRoot The stateless SPHINCS-style public root.
    /// @return key The abi-encoded stateless key bytes (64 bytes).
    function encodeStatelessKey(bytes32 pkSeed, bytes32 hypertreeRoot)
        internal
        pure
        returns (bytes memory key)
    {
        return abi.encode(pkSeed, hypertreeRoot);
    }

    /// @notice Decode the SPHINCSPlusCVerifier envelope into a typed
    /// stateless signature.
    /// @dev Envelope layout is abi.encode(SPHINCSPlusC.Signature) with no
    /// mode prefix. abi.decode reverts on a malformed encoding (short buffer,
    /// out-of-range offset or length, or dirty value-type high bits); that
    /// revert is the rejection channel. Non-canonical framing abi.decode
    /// tolerates decodes to the same value and is accepted (byte-malleable).
    /// @param envelope The abi-encoded stateless-signature envelope bytes.
    /// @return signature The decoded stateless signature.
    /// @return ok Always true on return; a malformed envelope reverts.
    function decodeStatelessSignatureEnvelope(bytes calldata envelope)
        internal
        pure
        returns (SPHINCSPlusC.Signature memory signature, bool ok)
    {
        signature = abi.decode(envelope, (SPHINCSPlusC.Signature));
        return (signature, true);
    }

    /// @notice Inverse of decodeStatelessSignatureEnvelope.
    /// @dev Builds the SPHINCSPlusCVerifier signature envelope the sub-call
    /// verify expects, so the delegation path re-encodes through one format
    /// definition.
    /// @param signature The stateless signature.
    /// @return envelope The abi-encoded stateless-signature envelope bytes.
    function encodeStatelessSignatureEnvelope(
        SPHINCSPlusC.Signature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(signature);
    }

    /// @notice Convert the ERC-7913 32-byte hash into the SHRINCS signed
    /// message bytes.
    /// @dev ERC-7913 hands a bytes32 hash; SHRINCS signs raw message bytes.
    /// The hash IS the message: exactly its 32 bytes, packed.
    /// @param hash The 32-byte ERC-7913 hash.
    /// @return message The message bytes SHRINCS signs (the 32 hash bytes).
    function toMessage(bytes32 hash)
        internal
        pure
        returns (bytes memory message)
    {
        return abi.encodePacked(hash);
    }

    // publicKeyCommitment: Recompute the bundle commitment from a fully
    // encoded public key.
    // 1. Domain-separate the commitment as a SHRINCS public-key bundle hash.
    // 2. Bind the stateful public key, stateless public seed, and hypertree
    // root.
    // 3. Return the installed public-key commitment.
    function publicKeyCommitment(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    // publicKeyCommitmentFromParts: Recompute the bundle commitment from
    // explicit component fields.
    // 1. Domain-separate the commitment as a SHRINCS public-key bundle hash.
    // 2. Bind the stateful public key, stateless public seed, and hypertree
    // root.
    // 3. Return the installed public-key commitment.
    function publicKeyCommitmentFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
    }

    // matchesExpectedPublicKeyCommitment: Check that a bundled public key
    // matches an installed commitment.
    // 1. Load the declared commitment from memory.
    // 2. Check it against the caller-supplied expected commitment.
    // 3. Recompute the bundle commitment and require it to match too.
    function matchesExpectedPublicKeyCommitment(
        SHRINCS.PublicKey memory publicKey,
        bytes32 expectedPublicKeyCommitment
    ) internal pure returns (bool) {
        bytes memory encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 actualCommitment;
        // Memory-safe: reads one memory word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the declared 32-byte commitment from the bytes payload.
            actualCommitment := mload(add(encodedCommitment, 32))
        }
        // First require the declared field to match the expected installed
        // commitment.
        if (actualCommitment != expectedPublicKeyCommitment) return false;
        // Then require the whole public-key bundle to recompute to that same
        // commitment.
        return publicKeyCommitment(publicKey) == expectedPublicKeyCommitment;
    }

    // validPublicKey: Validate public-key byte lengths and confirm its
    // embedded commitment is correct.
    // 1. Check the encoded stateful public-key length.
    // 2. Check the commitment, public-seed, and hypertree-root lengths.
    // 3. Load the embedded commitment from memory.
    // 4. Recompute the bundle commitment and require it to match the embedded
    // field.
    function validPublicKey(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bool)
    {
        // The stateful public key has a fixed packed byte width.
        if (
            publicKey.statefulPublicKey.length
                != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) return false;
        // The embedded commitment field is always one hash output wide.
        if (publicKey.publicKeyCommitment.length != 32) return false;
        // The stateless public seed is always one hash output wide.
        if (publicKey.pkSeed.length != 32) return false;
        // The hypertree root is always one hash output wide.
        if (publicKey.hypertreeRoot.length != 32) return false;
        bytes memory encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 expectedCommitment;
        // Memory-safe: reads one memory word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the embedded 32-byte commitment from the bytes payload.
            expectedCommitment := mload(add(encodedCommitment, 32))
        }
        return publicKeyCommitment(publicKey) == expectedCommitment;
    }

    // decodeStatefulPublicKey: Decode the fixed-width stateful public-key
    // payload into typed fields.
    // 1. Allocate the decoded struct in memory.
    // 2. Copy the public seed, root, and max-signatures fields from memory.
    // 3. Return the decoded struct together with a success flag.
    /// @dev Precondition: callers must supply the validPublicKey-checked
    /// 68-byte encoding; the fixed-offset assembly reads below assume it.
    function decodeStatefulPublicKey(bytes memory encoded)
        internal
        pure
        returns (UXMSS.StatefulPublicKey memory publicKey, bool ok)
    {
        // Decoded StatefulPublicKey layout (0x60 bytes) written at the
        // free-memory pointer:
        //   [0x00..0x20) pkSeed
        //   [0x20..0x40) root
        //   [0x40..0x60) maxSignatures (high 4 bytes of the last input word)
        // The final input word (encoded+0x60) reads the last, word-padded
        // slot of the `encoded` payload: STATEFUL_PUBLIC_KEY_BYTES rounds up
        // to a whole number of words, so this word is allocated and readable;
        // only its high 4 bytes carry maxSignatures and the shr discards the
        // trailing padding.
        // Memory-safe: allocates 0x60 bytes and advances the free-memory
        // pointer past them; reads stay inside the `encoded` buffer.
        assembly ("memory-safe") {
            // Allocate the decoded struct starting at the free-memory
            // pointer.
            publicKey := mload(0x40)
            // Copy the first 32 bytes as the stateful public seed.
            mstore(publicKey, mload(add(encoded, 32)))
            // Copy the next 32 bytes as the stateful root.
            mstore(add(publicKey, 0x20), mload(add(encoded, 64)))
            // Copy the high 4 bytes of the final word as maxSignatures.
            mstore(add(publicKey, 0x40), shr(224, mload(add(encoded, 96))))
            // Bump the free-memory pointer past the decoded struct.
            mstore(0x40, add(publicKey, 0x60))
        }
        return (publicKey, true);
    }
}
