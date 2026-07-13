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
} from "../interfaces/IERC7913SignatureVerifier.sol";

/// @title SHRINCSERC7913ConsumerExample
/// @notice Minimal consumer-side example for the generic ERC-7913 verifier
/// interface.
/// @dev This is the "integrator" example: it does not own nonce, keyVersion,
/// leaf tracking, recovery mode, or rotation policy. It simply stores the
/// verifier and key bytes and asks the verifier whether an opaque signature
/// authorizes a supplied hash.
contract SHRINCSERC7913ConsumerExample {
    uint256 internal constant SHRINCS_PUBLIC_KEY_COMMITMENT_BYTES = 32;

    IERC7913SignatureVerifier public immutable verifier;
    bytes public trustedKey;

    /// @notice Check whether `signature` authorizes `hash` under the stored
    /// ERC-7913 key.
    /// @param hash The 32-byte message hash supplied by the integrator.
    /// @param signature The opaque ERC-7913 signature envelope.
    /// @return True when the verifier returns the ERC-7913 success selector.
    function isAuthorized(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        try verifier.verify(trustedKey, hash, signature) returns (
            bytes4 result
        ) {
            return result == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    /// @notice Require the stored key to authorize `hash`.
    /// @dev Reverts when the verifier reports failure or reverts.
    /// @param hash The 32-byte message hash supplied by the integrator.
    /// @param signature The opaque ERC-7913 signature envelope.
    function requireAuthorized(bytes32 hash, bytes calldata signature)
        external
        view
    {
        require(
            verifier.verify(trustedKey, hash, signature)
                == IERC7913SignatureVerifier.verify.selector,
            "invalid signature"
        );
    }

    constructor(address verifier_, bytes memory trustedKey_) {
        require(verifier_ != address(0), "verifier is zero");
        require(
            trustedKey_.length == SHRINCS_PUBLIC_KEY_COMMITMENT_BYTES,
            "trustedKey must be 32 bytes"
        );
        verifier = IERC7913SignatureVerifier(verifier_);
        trustedKey = trustedKey_;
    }
}
