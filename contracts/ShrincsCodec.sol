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

/// @notice Byte-format definitions bridging ERC-7913 opaque bytes to typed SHRINCS structs.
/// @dev Single source of truth for the verifier envelope format; tests (and later the SDK)
/// must encode through this library so encoder and decoder cannot drift.
library ShrincsCodec {
    // decodeKey: Decode an ERC-7913 `key` into the SHRINCS installed bundle commitment.
    // 1. Require the key to be exactly one 32-byte commitment word.
    // 2. Load the commitment directly from calldata.
    // 3. Never revert; report malformed keys through the ok flag.
    function decodeKey(bytes calldata key) internal pure returns (bytes32 commitment, bool ok) {
        // The key format is exactly the 32-byte SHRINCS publicKeyCommitment, nothing else.
        if (key.length != 32) return (bytes32(0), false);
        assembly {
            // Load the 32-byte commitment word directly from calldata.
            commitment := calldataload(key.offset)
        }
        return (commitment, true);
    }

    // decodeStatefulEnvelope: Decode the ERC-7913 `signature` envelope into typed SHRINCS structs.
    // 1. Envelope layout is abi.encode(ShrincsTypes.PublicKey, ShrincsTypes.StatefulSignature) — no mode prefix.
    // 2. Reverts on malformed input; callers isolate the revert via a try/self-call hop.
    function decodeStatefulEnvelope(bytes calldata envelope)
        internal
        pure
        returns (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatefulSignature memory signature)
    {
        return abi.decode(envelope, (ShrincsTypes.PublicKey, ShrincsTypes.StatefulSignature));
    }

    // encodeStatefulEnvelope: Inverse of decodeStatefulEnvelope.
    // 1. Encode the key bundle and stateful signature with the exact layout the decoder expects.
    // 2. Exists so tests and off-chain encoders share one format definition with the verifier.
    function encodeStatefulEnvelope(
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.StatefulSignature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    // toMessage: Convert the ERC-7913 32-byte hash into the SHRINCS signed message bytes.
    // 1. ERC-7913 hands us a bytes32 hash; SHRINCS signs raw message bytes.
    // 2. The hash IS the message: exactly its 32 bytes, packed.
    function toMessage(bytes32 hash) internal pure returns (bytes memory message) {
        return abi.encodePacked(hash);
    }
}
