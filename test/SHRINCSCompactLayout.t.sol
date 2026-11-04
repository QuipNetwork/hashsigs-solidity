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

import {Test} from "../lib/forge-std/src/Test.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {StatelessLayout} from "../contracts/StatelessLayout.sol";

/// @notice Pins the StatelessLayout wire layout. Under the 256s profiles the
/// sizes must equal the frozen table in docs/compact-stateless-encoding.md;
/// under every profile they must equal the formula over SHRINCSParams, so a
/// params change cannot drift the layout silently.
contract SHRINCSCompactLayoutTest is Test {
    function testLayoutDerivesFromParams() public pure {
        uint256 chains = SHRINCSParams.NUM_WOTS_CHAINS;
        uint256 forsHeight = SHRINCSParams.FORS_TREE_HEIGHT;
        uint256 layers = SHRINCSParams.NUM_HYPERTREE_LAYERS;
        uint256 subtree = uint256(SHRINCSParams.HYPERTREE_HEIGHT) / layers;
        uint256 pk = uint256(SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES) + 96;
        uint256 signedTrees = uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
        uint256 fors = 36 + signedTrees * (32 + forsHeight * 32);
        uint256 layer = 68 + chains * 32 + subtree * 32;
        assertEq(StatelessLayout.PK_LEN, pk, "PK_LEN");
        assertEq(StatelessLayout.FORS_LEN, fors, "FORS_LEN");
        assertEq(StatelessLayout.LAYER_LEN, layer, "LAYER_LEN");
        assertEq(StatelessLayout.HYPERTREE_LEN, layers * layer, "HT_LEN");
        assertEq(StatelessLayout.PQ_LEN, fors + layers * layer, "PQ_LEN");
        assertEq(
            StatelessLayout.PAYLOAD_LEN,
            StatelessLayout.PK_LEN + StatelessLayout.PQ_LEN,
            "PAYLOAD_LEN"
        );
        // The PK words sit back to back after the stateful key.
        assertEq(
            StatelessLayout.COMMITMENT_OFFSET,
            SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        );
        assertEq(
            StatelessLayout.PK_SEED_OFFSET,
            StatelessLayout.COMMITMENT_OFFSET + 32
        );
        assertEq(
            StatelessLayout.HYPERTREE_ROOT_OFFSET,
            StatelessLayout.PK_SEED_OFFSET + 32
        );
        assertEq(StatelessLayout.ENCODING_VERSION, 1);
    }

    /// @dev The frozen 256s table (keccak and sha2 share the sizes).
    function testLayoutMatches256sTable() public pure {
        if (
            SHRINCSParams.NUM_FORS_TREES != 22
                || SHRINCSParams.NUM_HYPERTREE_LAYERS != 8
        ) return;
        assertEq(StatelessLayout.PK_LEN, 164, "PK");
        assertEq(StatelessLayout.FORS_ENTRY_LEN, 480, "FORS entry");
        assertEq(StatelessLayout.FORS_LEN, 10_116, "FORS");
        assertEq(StatelessLayout.LAYER_LEN, 2372, "layer");
        assertEq(StatelessLayout.HYPERTREE_LEN, 18_976, "hypertree");
        assertEq(StatelessLayout.PQ_LEN, 29_092, "PQ");
        assertEq(StatelessLayout.PAYLOAD_LEN, 29_256, "payload");
        // Wallet envelope: 37-byte header + 65-byte ECDSA + payload.
        assertEq(37 + 65 + StatelessLayout.PAYLOAD_LEN, 29_358, "envelope");
    }
}
