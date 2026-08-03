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

/// @title ICreateX
/// @notice Minimal interface to pcaversaccio's canonical CreateX factory
/// (github.com/pcaversaccio/createx), the pre-deployed singleton at
/// 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed on every supported chain.
/// Only the two functions the deploy tooling uses are declared.
/// @dev Salt semantics: `deployCreate3` GUARDS the caller-supplied salt
/// before use, branching on the salt's own leading bytes. Every `QUIP:*`
/// salt in this repo takes the PERMISSIONED branch — leading 20 bytes ==
/// `msg.sender`, byte 20 == 0x00 — for which the guard is
/// `guardedSalt = keccak256(abi.encode(msg.sender, salt))`. Only that
/// sender reaches the resulting address; any other caller fails the match
/// and silently falls through to the permissionless branch
/// (`keccak256(abi.encode(salt))`), landing elsewhere WITHOUT reverting.
/// See script/CreateXSalt.sol for the mirror and DeployBase for the
/// broadcaster and salt-shape checks that make that fallback loud.
/// `computeCreate3Address` applies NO guard: pass it the GUARDED salt.
interface ICreateX {
    /// @notice Deploy `initCode` via CREATE3 under the guarded `salt`.
    /// @param salt The raw (unguarded) deployment salt.
    /// @param initCode The child contract creation code.
    /// @return newContract The deployed child address.
    function deployCreate3(bytes32 salt, bytes memory initCode)
        external
        payable
        returns (address newContract);

    /// @notice Predict the CREATE3 child address for a GUARDED salt.
    /// @param salt The guarded salt (see the guard note above).
    /// @return computedAddress The predicted child contract address.
    function computeCreate3Address(bytes32 salt)
        external
        view
        returns (address computedAddress);
}
