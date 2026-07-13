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

import {FORSMinusC} from "./FORSMinusC.sol";
import {Hypertree} from "./Hypertree.sol";

/// @title SPHINCSPlusC
/// @notice Stateless SPHINCS+C-style verification ([SPHINCSPLUSC]): a FORS-C
/// few-time signature carried up a hypertree of WOTS-C layers to the public
/// root. Documented deviations from the paper: keccak-based tag hashes stand
/// in for the SPHINCS+ tweakable hash, and the hypertree coordinates are
/// chained sequentially per layer (the FIPS-205 §8.2 deviation note lives on
/// Hypertree, where the coordinate recurrence is enforced).
/// @dev Knows only the stateless primitives (public seed, public root,
/// FORS-C, hypertree). Commitments, contexts, and the stateful side belong
/// to the hybrid SHRINCS library above it.
library SPHINCSPlusC {
    /// @notice The stateless SPHINCS+C signature.
    /// @dev A SHRINCS stateless signature is a SPHINCSPlusC.Signature:
    /// SHRINCS declares no stateless struct of its own (Solidity cannot alias
    /// structs), so the SHRINCS library handles the stateless path with this
    /// type directly.
    struct Signature {
        // Message-signing few-time signature at the bottom of the stateless
        // path.
        FORSMinusC.ForsSignature fors;
        // Hypertree layers authenticating the FORS root to the public root.
        Hypertree.HypertreeLayerSignature[] hypertree;
    }

    // decodeKey: Facade forward decoding the SPHINCSPlusCVerifier 64-byte key
    // into its two stateless seed slices. Keeps the adapter's only edge
    // pointed at this parent library.
    function decodeKey(bytes calldata key)
        internal
        pure
        returns (
            bytes calldata pkSeed,
            bytes calldata hypertreeRoot,
            bool ok
        )
    {
        return decodeStatelessKey(key);
    }

    // signatureEnvelope: Facade forward re-tagging the SPHINCSPlusCVerifier
    // stateless-signature envelope into a typed calldata Signature pointer
    // in place, with no copy. Keeps the adapter's only import edge pointed
    // here.
    function signatureEnvelope(bytes calldata envelope)
        internal
        pure
        returns (Signature calldata signature)
    {
        return statelessSignatureEnvelope(envelope);
    }

    // verify: Facade verify over a hash and the two seed slices. Wraps
    // the message-bytes verify below by packing the ERC-7913 hash into the
    // signed message bytes; the calldata seed slices are read in place.
    function verify(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes32 hash,
        Signature calldata signature
    ) internal view returns (bool) {
        return verify(pkSeed, hypertreeRoot, toMessage(hash), signature);
    }

    // verify: Verify a stateless signature after the caller has already
    // constructed the exact signed message bytes.
    // 1. Reconstruct the FORS-C root from the signed message bytes and FORS
    // proof.
    // 2. Carry that root up the hypertree and compare it to the public root.
    /// @dev Callers must supply pkSeed and hypertreeRoot as exactly 32
    /// bytes each: in-repo callers are validPublicKey-checked or supplied as
    /// 32-byte key slices, and the calldataload-32 reads below assume it.
    function verify(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes memory message,
        Signature calldata signature
    ) internal view returns (bool) {
        // Reconstruct the FORS root from the message, FORS
        // randomness/counter, and revealed leaves. The FORS digest also
        // yields the layer-0 hypertree coordinates (T6: no longer carried in
        // the signature), returned here to seed hypertree verification.
        (
            bytes32 forsRoot,
            uint64 seedTreeIndex,
            uint32 seedLeafIndex,
            bool ok
        ) = FORSMinusC.verifyForsCAndReturnRoot(
            pkSeed, hypertreeRoot, message, signature.fors
        );
        if (!ok) return false;
        // Carry the reconstructed FORS root up the hypertree until it matches
        // the public root, seeding the layer-0 coordinates from the digest.
        return Hypertree.verifyHypertree(
            pkSeed,
            hypertreeRoot,
            forsRoot,
            seedTreeIndex,
            seedLeafIndex,
            signature.hypertree
        );
    }

    // Encoders and decoders (folded from the dissolved codec library).
    // Stateless key/message/signature-envelope serialization backing
    // the public API above; none reference SHRINCS types, keeping this
    // base library free of any edge to the hybrid SHRINCS layer.

    /// @notice Decode the SPHINCSPlusCVerifier key into its two seed slices.
    /// @dev Key layout is abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot),
    /// exactly 64 bytes of static words with no framing, so the length
    /// check is a complete canonicity check. The two 32-byte seed words are
    /// returned as calldata slices the stateless verify path reads in place,
    /// with no copy. Never reverts; a wrong length is reported through the ok
    /// flag.
    /// @param key The ERC-7913 key bytes (exactly 64 bytes).
    /// @return pkSeed Calldata slice of the stateless public seed word.
    /// @return hypertreeRoot Calldata slice of the stateless root word.
    /// @return ok False when the key length is not 64.
    function decodeStatelessKey(bytes calldata key)
        internal
        pure
        returns (
            bytes calldata pkSeed,
            bytes calldata hypertreeRoot,
            bool ok
        )
    {
        // Two static bytes32 words abi.encode to exactly 64 bytes.
        if (key.length != 64) return (key[0:0], key[0:0], false);
        return (key[0:32], key[32:64], true);
    }

    /// @notice Inverse of the stateless-signature re-tag
    /// (statelessSignatureEnvelope). Reference/off-chain encoder and the
    /// differential oracle for sliceStatelessSignatureEnvelope; the
    /// delegation path builds through the slice-copy below.
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

    /// @notice Zero-copy re-tag of a stateless-signature envelope into a
    /// typed calldata struct pointer.
    /// @dev Envelope layout is abi.encode(SPHINCSPlusC.Signature): a single
    /// dynamic struct, so the head is one offset word. Same safety story as
    /// statefulEnvelope (E1a/E2 revert, E1b lands in {revert, false} via the
    /// downstream Panic backstop plus the KEEP guards, encoding malleability
    /// accepted by design).
    /// @param payload The abi-encoded stateless-signature envelope calldata.
    /// @return signature Calldata pointer to the stateless signature.
    function statelessSignatureEnvelope(bytes calldata payload)
        internal
        pure
        returns (SPHINCSPlusC.Signature calldata signature)
    {
        // Pure calldata re-tag: reads one offset word into one calldata
        // pointer; no memory is read or written.
        assembly ("memory-safe") {
            signature := add(payload.offset, calldataload(payload.offset))
        }
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
}
