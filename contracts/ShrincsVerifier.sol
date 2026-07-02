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

import {IERC7913SignatureVerifier} from "./interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCS} from "./SHRINCS.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";
import {ShrincsTypes} from "./ShrincsTypes.sol";

/// @notice ERC-7913 signature verifier for stateless SHRINCS signatures.
/// @dev Trustless by construction: no owner, no storage, no constructor, no upgradability.
/// `key` is the 32-byte SHRINCS publicKeyCommitment; `signature` is the ShrincsCodec
/// stateless envelope. Stateful SHRINCS signatures are out of scope (they need on-chain
/// leaf tracking and belong in account wrappers, not a stateless view verifier).
contract ShrincsVerifier is IERC7913SignatureVerifier {
    // Version tag identifying this verifier's key/envelope format family.
    bytes32 public constant VERSION_TAG = keccak256("quip.shrincs-verifier.v1");
    // Any non-magic value denotes signature failure.
    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    // verify: ERC-7913 entrypoint. Never reverts.
    // 1. Decode the 32-byte key into the installed bundle commitment; bad length -> 0xffffffff.
    // 2. Self-call decodeAndCheck through try/catch so abi.decode reverts on malformed
    //    envelopes surface as a failure value instead of bubbling up.
    // 3. Return the ERC-7913 magic value on success or 0xffffffff on any failure.
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (bytes32 commitment, bool ok) = ShrincsCodec.decodeKey(key);
        if (!ok) return INVALID_SIGNATURE;

        try this.decodeAndCheck(commitment, hash, signature) returns (bool valid) {
            if (valid) return IERC7913SignatureVerifier.verify.selector;
        } catch {
            return INVALID_SIGNATURE;
        }
        return INVALID_SIGNATURE;
    }

    // decodeAndCheck: Self-call hop #1 — envelope decoding.
    // 1. Decode the envelope into memory structs via ShrincsCodec (reverts on malformed bytes;
    //    verify(...) catches that revert).
    // 2. Re-enter through hop #2 so the memory structs are re-materialized as calldata structs.
    function decodeAndCheck(bytes32 commitment, bytes32 hash, bytes calldata envelope)
        external
        view
        onlySelf
        returns (bool)
    {
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature) =
            ShrincsCodec.decodeStatelessEnvelope(envelope);

        return this.checkDecoded(commitment, hash, publicKey, signature);
    }

    // checkDecoded: Self-call hop #2 — calldata re-materialization and verification.
    // 1. Receiving the structs through an external call re-encodes them into this call's
    //    calldata — required because SHRINCS takes calldata structs.
    // 2. Verify the stateless signature over exactly the 32 hash bytes under the commitment.
    // 3. SHRINCS already enforces commitment-vs-bundle match, bundle shape, non-empty
    //    hypertree, FORS root reconstruction, and the hypertree walk — nothing is added here.
    function checkDecoded(
        bytes32 commitment,
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature
    ) external view onlySelf returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(commitment, publicKey, ShrincsCodec.toMessage(hash), signature);
    }
}
