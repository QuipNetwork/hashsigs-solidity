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

import {SHRINCSVerifier} from "../SHRINCSVerifier.sol";
import {
    IERC7913SignatureVerifier
} from "../interfaces/IERC7913SignatureVerifier.sol";

/// @title SHRINCSStatelessConsumerExample
/// @notice Minimal consumer-side example for the explicit SHRINCS stateless
/// verification entrypoint.
/// @dev This example shows the non-generic integration path for callers that
/// want the SHRINCS verifier's dedicated stateless delegate flow. Like the
/// generic ERC-7913 consumer example, it owns no replay, stateful-use, or
/// rotation state.
contract SHRINCSStatelessConsumerExample {
    uint256 internal constant SHRINCS_PUBLIC_KEY_COMMITMENT_BYTES = 32;

    SHRINCSVerifier public immutable verifier;
    bytes public trustedKey;

    /// @notice Check whether `signature` authorizes `hash` under the stored
    /// key through the verifier's stateless path.
    /// @param hash The 32-byte message hash supplied by the integrator.
    /// @param signature The opaque SHRINCS stateless envelope.
    /// @return True when the verifier returns the ERC-7913 success selector.
    function isAuthorizedStateless(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        try verifier.verifyStateless(trustedKey, hash, signature) returns (
            bytes4 result
        ) {
            return result == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    /// @notice Require the stored key to authorize `hash` through the
    /// stateless verifier path.
    /// @dev Reverts when the verifier reports failure or reverts.
    /// @param hash The 32-byte message hash supplied by the integrator.
    /// @param signature The opaque SHRINCS stateless envelope.
    function requireAuthorizedStateless(
        bytes32 hash,
        bytes calldata signature
    ) external view {
        require(
            verifier.verifyStateless(trustedKey, hash, signature)
                == IERC7913SignatureVerifier.verify.selector,
            "invalid stateless signature"
        );
    }

    constructor(address verifier_, bytes memory trustedKey_) {
        require(verifier_ != address(0), "verifier is zero");
        require(
            trustedKey_.length == SHRINCS_PUBLIC_KEY_COMMITMENT_BYTES,
            "trustedKey must be 32 bytes"
        );
        verifier = SHRINCSVerifier(verifier_);
        trustedKey = trustedKey_;
    }
}
