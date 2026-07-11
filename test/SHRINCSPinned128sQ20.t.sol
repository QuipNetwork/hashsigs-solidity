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
import {Create3, Create3Factory} from "../script/Create3.sol";
import {SHRINCS128sQ20Keccak} from "../contracts/SHRINCS128sQ20Keccak.sol";

/// @dev Exposes the internal pinned SPHINCSPlusC address of the concrete
/// 128s-q20 deployable so the pin test can compare it to the CREATE3
/// derivation.
contract SHRINCS128sQ20PinHarness is SHRINCS128sQ20Keccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @notice Pins the 128s-q20 SHRINCS verifier's SPHINCSPlusC sibling address
/// to its CREATE3 derivation so C8's deploy scripts cannot drift from the C7
/// constant. Profile-gated (128s-q20) like the deployable itself.
contract SHRINCSPinned128sQ20Test is Test {
    bytes32 internal constant FACTORY_SALT =
        keccak256("QUIP:Create3Factory:V1.0");
    bytes32 internal constant CHILD_SALT =
        keccak256("QUIP:SPHINCSPlusC128sQ20Keccak:V1.0");

    function testPinnedAddressMatchesCreate3Derivation() public {
        address factory = vm.computeCreate2Address(
            FACTORY_SALT,
            keccak256(type(Create3Factory).creationCode),
            CREATE2_FACTORY
        );
        address expected = Create3.addressOf(CHILD_SALT, factory);

        SHRINCS128sQ20PinHarness harness = new SHRINCS128sQ20PinHarness();
        assertEq(
            harness.pinned(),
            expected,
            "pinned SPHINCSPlusC128sQ20Keccak address must match CREATE3"
        );
    }
}
