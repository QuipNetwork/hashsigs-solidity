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
import {ShrincsCodec} from "./ShrincsCodec.sol";
import {ShrincsTypes} from "./ShrincsTypes.sol";

/// @title ShrincsVerifier
/// @notice ERC-7913 signature verifier for stateful SHRINCS signatures.
/// @dev Trustless by construction: no owner, no storage, no constructor, no
/// upgradability. `key` is the 32-byte SHRINCS publicKeyCommitment;
/// `signature` is the ShrincsCodec stateful envelope (abi.encode(PublicKey,
/// StatefulSignature)). Verifies signature validity only; callers that
/// require one-time-use of stateful leaves track leaf consumption themselves.
/// @dev Minimum gas: a stateful verification costs roughly 260k gas.
/// verify isolates the check behind a try/catch self-call, so an inner
/// out-of-gas (the 63/64 rule strands the hop while the outer frame keeps
/// 1/64) is caught and returned as 0xffffffff — a valid signature then
/// reports invalid. Callers MUST forward gas comfortably above ~260k so a
/// genuine signature is never misreported as invalid.
contract ShrincsVerifier is IERC7913SignatureVerifier {
    // Version tag identifying this verifier's key/envelope format family.
    bytes32 public constant VERSION_TAG =
        keccak256("quip.shrincs-verifier.v1");
    // Any non-magic value denotes signature failure.
    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    /// @notice ERC-7913 verification entrypoint. Never reverts.
    /// @dev Decodes the 32-byte key into the installed bundle commitment
    /// (bad length -> 0xffffffff), then self-calls decodeAndCheck through
    /// try/catch so an abi.decode revert on a malformed envelope surfaces as
    /// a failure value instead of bubbling up. See the contract-level @dev
    /// for the minimum-gas requirement.
    /// @param key The 32-byte SHRINCS publicKeyCommitment.
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The ShrincsCodec stateful envelope.
    /// @return The verify selector on success, 0xffffffff on any failure.
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (bytes32 commitment, bool ok) = ShrincsCodec.decodeKey(key);
        if (!ok) return INVALID_SIGNATURE;

        try this.decodeAndCheck(commitment, hash, signature) returns (
            bool valid
        ) {
            if (valid) return IERC7913SignatureVerifier.verify.selector;
        } catch {
            return INVALID_SIGNATURE;
        }
        return INVALID_SIGNATURE;
    }

    /// @notice Self-call hop #1 — envelope decoding. onlySelf.
    /// @dev Decodes the envelope into memory structs via ShrincsCodec
    /// (reverts on malformed bytes, which verify catches), then re-enters
    /// through hop #2 so the memory structs are re-materialized as calldata.
    /// @param commitment The installed bundle commitment.
    /// @param hash The 32-byte message hash.
    /// @param envelope The stateful envelope bytes.
    /// @return True when the decoded stateful signature verifies.
    function decodeAndCheck(
        bytes32 commitment,
        bytes32 hash,
        bytes calldata envelope
    ) external view onlySelf returns (bool) {
        (
            ShrincsTypes.PublicKey memory publicKey,
            ShrincsTypes.StatefulSignature memory signature
        ) = ShrincsCodec.decodeStatefulEnvelope(envelope);

        return this.checkDecoded(commitment, hash, publicKey, signature);
    }

    /// @notice Self-call hop #2 — calldata re-materialization and
    /// verification. onlySelf.
    /// @dev Receiving the structs through an external call re-encodes them
    /// into calldata (SHRINCS takes calldata structs), then verifies the
    /// stateful signature over exactly the 32 hash bytes under the
    /// commitment. SHRINCS already enforces commitment-vs-bundle match,
    /// bundle shape, leaf-index bounds, WOTS-C reconstruction, and the
    /// unbalanced-tree root; nothing is added here.
    /// @param commitment The installed bundle commitment.
    /// @param hash The 32-byte message hash.
    /// @param publicKey The decoded public-key bundle.
    /// @param signature The decoded stateful signature.
    /// @return True when the stateful signature verifies.
    function checkDecoded(
        bytes32 commitment,
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature
    ) external view onlySelf returns (bool) {
        return SHRINCS.verifyStatefulUncheckedMessage(
            commitment, publicKey, ShrincsCodec.toMessage(hash), signature
        );
    }
}
