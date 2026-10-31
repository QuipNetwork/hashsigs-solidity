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

/// @notice Transaction-scoped attestation registry layered on an ERC-7913
/// verifier: a successful `verifyAndAttest` records the verification in
/// EIP-1153 transient storage so downstream contracts in the same
/// transaction can query it instead of demanding a fresh signature.
/// @dev Shared attestation-slot spec (consumers MUST derive the identical
/// slot):
///   slot  = keccak256(abi.encode(account, keyHash, messageHash))
///   value = 1 on success; never written on failure.
/// where `account` is the address that called `verifyAndAttest`
/// (`msg.sender` at attest time), `keyHash` is `keccak256(key)` over the
/// raw ERC-7913 key bytes, and `messageHash` is the exact `bytes32 hash`
/// that was verified. The address is deliberately the FIRST word of the
/// `abi.encode` input so the slot has the `keccak256(A || X)` shape of
/// ERC-7562 *associated* storage: an ERC-4337 account may write it during
/// the validation phase without violating bundler storage rules.
interface IERC7913TransientAttestation {
    /// @notice Verify `signature` over `hash` for `key` exactly like the
    /// verifier's ERC-7913 `verify`, and on success record the
    /// verification for `msg.sender` in transient storage for the rest of
    /// the transaction.
    /// @dev Verification semantics, return values, and revert behavior are
    /// identical to `verify`; only the transient attestation write is
    /// added, so this function cannot be `view` and reverts if reached
    /// through a `staticcall` with a valid signature (TSTORE is illegal in
    /// a static context). Never wrap it in a `staticcall`.
    /// @param key The verifier-defined opaque key encoding.
    /// @param hash The 32-byte message hash to verify.
    /// @param signature The verifier-defined opaque signature encoding.
    /// @return magicValue The value `verify` would return for the same
    /// input: the ERC-7913 selector on success, 0xffffffff on a
    /// well-formed but invalid input (nothing is attested), and a revert
    /// wherever `verify` reverts.
    function verifyAndAttest(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external returns (bytes4 magicValue);

    /// @notice Whether `verifyAndAttest` succeeded for the exact triple
    /// `(account, keyHash, hash)` earlier in the current transaction.
    /// @dev A positive answer is a transaction-scoped PUBLIC fact: it
    /// proves "`account` had a valid signature by the key hashing to
    /// `keyHash` over `hash` verified this transaction" — nothing more.
    /// Any contract may attest for its own `msg.sender` identity, so
    /// consumers are responsible for trusting `account` and for
    /// domain-separating the hashes they query. Transient storage clears
    /// when the transaction ends; TLOAD is legal in `view`.
    /// @param account The address that called the attesting verification.
    /// @param keyHash `keccak256` of the raw ERC-7913 key bytes.
    /// @param hash The 32-byte message hash that was verified.
    /// @return True when the attestation slot holds 1.
    function wasVerified(address account, bytes32 keyHash, bytes32 hash)
        external
        view
        returns (bool);
}
