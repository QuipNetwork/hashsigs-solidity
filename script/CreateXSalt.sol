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

import {Create3} from "./Create3.sol";

/// @title CreateXSalt
/// @notice The CreateX salt policy for every canonical QUIP deploy: salt
/// construction, the salt guard, and the resulting CREATE3 child address.
/// Deliberately separate from Create3, which is the guard-FREE CREATE2
/// proxy primitive; keeping the two apart is what lets
/// test/CreateXCreate3.t.sol anchor the proxy math to a real on-chain
/// deployment independently of whichever guard mode we use.
/// @dev PERMISSIONED mode. The raw salt embeds DEPLOYER in its leading 20
/// bytes and 0x00 in byte 20, so CreateX guards it to
/// keccak256(abi.encode(msg.sender, salt)) and ONLY DEPLOYER can reach the
/// advertised address. The 0x00 flag keeps block.chainid out of the guard,
/// so a given salt resolves to the same address on every chain. A third
/// party calling deployCreate3 with a published raw salt does not match
/// the embedded sender, so CreateX takes its permissionless branch and
/// lands them somewhere else entirely — that is what closes the squatting
/// surface this repo previously had to detect after the fact.
library CreateXSalt {
    // Canonical CreateX singleton (github.com/pcaversaccio/createx),
    // pre-deployed at this same address on every supported chain. Never
    // compiled here, so no artifact of ours is address-load-bearing.
    address internal constant CREATEX =
        0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    // The canonical deployer. ADDRESS-LOAD-BEARING: every published
    // CREATE3 address is a function of this account, and only this
    // account can deploy at those addresses. Changing it moves all of
    // them; losing its key makes them permanently unreachable on any
    // chain not already deployed to.
    address internal constant DEPLOYER =
        0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26;

    // Byte 20 of a raw salt is CreateX's redeploy-protection flag. 0x00
    // keeps block.chainid out of the guard, so addresses are
    // chain-invariant; 0x01 would scope them per chain.
    bytes1 internal constant FLAG_NO_CHAIN_SCOPE = 0x00;

    /// @notice Compose the raw CreateX salt for a salt label.
    /// @dev Layout is CreateX's own: [20B DEPLOYER][1B flag][11B entropy],
    /// where the entropy is the leading 11 bytes of `labelHash` — so the
    /// human label still determines the salt. NOTE: this is a function
    /// call, which Solidity forbids in a `constant` initializer, so the
    /// deploy scripts spell the same expression out inline. The pin tests
    /// assert the two agree, which keeps that duplication honest.
    /// @param labelHash keccak256 of the salt label, e.g.
    /// keccak256("QUIP:SHRINCS256sKeccak:V4.0").
    /// @return The raw (unguarded) salt to hand to deployCreate3.
    function rawSalt(bytes32 labelHash) internal pure returns (bytes32) {
        // casting to 'bytes11' is safe because truncating to the leading
        // 11 bytes IS the intent: CreateX reserves bytes 0-19 for the
        // sender field and byte 20 for the flag, leaving exactly 11
        // bytes of caller-chosen entropy
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes11 entropy = bytes11(labelHash);
        return bytes32(
            abi.encodePacked(bytes20(DEPLOYER), FLAG_NO_CHAIN_SCOPE, entropy)
        );
    }

    /// @notice CreateX's salt guard, for the one mode we use.
    /// @dev Mirrors ONLY the (sender field == msg.sender, flag == 0x00)
    /// branch, with DEPLOYER hardcoded rather than read from the live
    /// caller. That is deliberate: a mirror keyed on msg.sender/tx.origin
    /// would compute the PERMISSIONLESS address whenever the broadcaster
    /// is wrong, and DeployBase's `deployed == expected` check would then
    /// pass — turning a loud failure into a silent deploy at a squattable
    /// address. Hardcoding also keeps this `pure`, so every prediction in
    /// the scripts and pin tests stays RPC-free.
    /// @param raw The raw salt from `rawSalt`.
    /// @return The guarded salt CreateX derives internally.
    function guardedSalt(bytes32 raw) internal pure returns (bytes32) {
        return keccak256(abi.encode(DEPLOYER, raw));
    }

    /// @notice The CREATE3 child address DEPLOYER reaches with `raw`.
    /// @param raw The raw salt from `rawSalt`.
    /// @return The predicted child address, identical on every chain.
    function addressOf(bytes32 raw) internal pure returns (address) {
        return Create3.addressOf(guardedSalt(raw), CREATEX);
    }

    /// @notice Fail closed on a salt that would take a CreateX branch
    /// other than the one this library mirrors.
    /// @dev Catches the two failures a broadcaster check cannot see: a
    /// stale or mistyped sender field (CreateX applies its permissionless
    /// guard, putting the artifact at a squattable address) and a 0x01
    /// flag byte (chain-scoped guard, which would silently destroy
    /// chain-invariance while every other check still passed). Solc folds
    /// this away entirely when `raw` is a constant.
    /// @param raw The raw salt to check.
    function requireWellFormed(bytes32 raw) internal pure {
        // casting to 'bytes20' is safe because the leading 20 bytes ARE
        // the sender field this check exists to read
        // forge-lint: disable-next-line(unsafe-typecast)
        address senderField = address(bytes20(raw));
        require(
            senderField == DEPLOYER, "CreateXSalt: sender field != DEPLOYER"
        );
        require(
            raw[20] == FLAG_NO_CHAIN_SCOPE, "CreateXSalt: flag byte != 0x00"
        );
    }
}
