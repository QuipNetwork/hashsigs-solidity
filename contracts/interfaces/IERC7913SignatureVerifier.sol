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

/// @notice Canonical ERC-7913 signature verifier interface.
/// @dev Defined locally because this repo carries no OpenZeppelin dependency.
interface IERC7913SignatureVerifier {
    /// verify: Check whether `signature` is a valid signature over `hash` for
    /// the key material `key`.
    /// 1. `key` is an opaque key encoding whose format is defined by the
    /// implementing verifier.
    /// 2. `signature` is an opaque signature encoding whose format is defined
    /// by the implementing verifier.
    /// 3. MUST return `IERC7913SignatureVerifier.verify.selector`
    /// (0x024ad318) if the signature is valid.
    /// 4. SHOULD return 0xffffffff (or revert) if the signature is invalid or
    /// the key is empty/malformed.
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}
