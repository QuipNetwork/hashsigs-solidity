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

import {ShrincsTypes} from "./ShrincsTypes.sol";

/// @notice Byte-format definitions bridging ERC-7913 opaque bytes to typed
/// SHRINCS structs.
/// @dev Single source of truth for the verifier envelope format; tests (and
/// later the SDK) must encode through this library so encoder and decoder
/// cannot drift.
library ShrincsCodec {
    error InvalidEnvelope();

    /// @notice Decode an ERC-7913 `key` into the SHRINCS installed bundle
    /// commitment.
    /// @dev Requires the key to be exactly one 32-byte commitment word and
    /// loads it from calldata. Never reverts; malformed keys are reported
    /// through the ok flag.
    /// @param key The ERC-7913 key bytes (exactly 32 bytes).
    /// @return commitment The decoded 32-byte publicKeyCommitment.
    /// @return ok False when the key length is not 32.
    function decodeKey(bytes calldata key)
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
    /// @dev Envelope layout is abi.encode(PublicKey, StatefulSignature) with
    /// no mode prefix. Reverts on malformed input and on any non-canonical
    /// encoding (re-encoding the decoded structs must reproduce the exact
    /// bytes); callers isolate the revert via a try/self-call hop.
    /// @param envelope The abi-encoded stateful envelope bytes.
    /// @return publicKey The decoded SHRINCS public-key bundle.
    /// @return signature The decoded stateful signature.
    function decodeStatefulEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            ShrincsTypes.StatefulSignature memory signature
        )
    {
        (publicKey, signature) = abi.decode(
            envelope,
            (ShrincsTypes.PublicKey, ShrincsTypes.StatefulSignature)
        );

        if (
            keccak256(envelope)
                != keccak256(abi.encode(publicKey, signature))
        ) {
            revert InvalidEnvelope();
        }

        return (publicKey, signature);
    }

    /// @notice Inverse of decodeStatefulEnvelope.
    /// @dev Encodes the bundle and stateful signature with the exact layout
    /// the decoder expects, so tests and off-chain encoders share one format
    /// definition with the verifier.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param signature The stateful signature.
    /// @return envelope The abi-encoded stateful envelope bytes.
    function encodeStatefulEnvelope(
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.StatefulSignature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
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
    function publicKeyCommitment(ShrincsTypes.PublicKey calldata publicKey)
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
    // 1. Require a nonzero expected installed-key commitment.
    // 2. Require a 32-byte encoded commitment field inside the public key.
    // 3. Load the declared commitment from calldata.
    // 4. Check it against the caller-supplied expected commitment.
    // 5. Recompute the bundle commitment and require it to match too.
    function matchesExpectedPublicKeyCommitment(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 expectedPublicKeyCommitment
    ) internal pure returns (bool) {
        // A missing installed-key commitment is always invalid.
        if (expectedPublicKeyCommitment == bytes32(0)) return false;
        // The encoded commitment field must always be one hash output wide.
        if (publicKey.publicKeyCommitment.length != 32) return false;
        bytes calldata encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 actualCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the declared 32-byte commitment directly from calldata.
            actualCommitment := calldataload(encodedCommitment.offset)
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
    // 3. Load the embedded commitment from calldata.
    // 4. Recompute the bundle commitment and require it to match the embedded
    // field.
    function validPublicKey(ShrincsTypes.PublicKey calldata publicKey)
        internal
        pure
        returns (bool)
    {
        // The stateful public key has a fixed packed byte width.
        if (
            publicKey.statefulPublicKey.length
                != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES
        ) return false;
        // The embedded commitment field is always one hash output wide.
        if (publicKey.publicKeyCommitment.length != 32) return false;
        // The stateless public seed is always one hash output wide.
        if (publicKey.pkSeed.length != 32) return false;
        // The hypertree root is always one hash output wide.
        if (publicKey.hypertreeRoot.length != 32) return false;
        bytes calldata encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 expectedCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the embedded 32-byte commitment directly from calldata.
            expectedCommitment := calldataload(encodedCommitment.offset)
        }
        return publicKeyCommitment(publicKey) == expectedCommitment;
    }

    // decodeStatefulPublicKey: Decode the fixed-width stateful public-key
    // payload into typed fields.
    // 1. Check the exact packed byte width of the encoded stateful public
    // key.
    // 2. Allocate the decoded struct in memory.
    // 3. Copy the public seed, root, and max-signatures fields from calldata.
    // 4. Return the decoded struct together with a success flag.
    function decodeStatefulPublicKey(bytes calldata encoded)
        internal
        pure
        returns (ShrincsTypes.StatefulPublicKey memory publicKey, bool ok)
    {
        if (encoded.length != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES) {
            return (publicKey, false);
        }
        // Decoded StatefulPublicKey layout (0x60 bytes) written at the
        // free-memory pointer:
        //   [0x00..0x20) pkSeed
        //   [0x20..0x40) root
        //   [0x40..0x60) maxSignatures (high 4 bytes of the last input word)
        // Memory-safe: allocates 0x60 bytes and advances the free-memory
        // pointer past them.
        assembly ("memory-safe") {
            // Allocate the decoded struct starting at the free-memory
            // pointer.
            publicKey := mload(0x40)
            // Copy the first 32 bytes as the stateful public seed.
            mstore(publicKey, calldataload(encoded.offset))
            // Copy the next 32 bytes as the stateful root.
            mstore(
                add(publicKey, 0x20),
                calldataload(add(encoded.offset, 32))
            )
            // Copy the high 4 bytes of the final word as maxSignatures.
            mstore(
                add(publicKey, 0x40),
                shr(224, calldataload(add(encoded.offset, 64)))
            )
            // Bump the free-memory pointer past the decoded struct.
            mstore(0x40, add(publicKey, 0x60))
        }
        return (publicKey, true);
    }
}
