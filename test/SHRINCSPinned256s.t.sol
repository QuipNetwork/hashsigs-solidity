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
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";

/// @dev Exposes the internal pinned SPHINCSPlusC address of the concrete
/// 256s deployable so the pin test can compare it to the CREATE3 derivation.
contract SHRINCS256sPinHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @notice Pins the 256s SHRINCS verifier's SPHINCSPlusC sibling address to
/// its CREATE3 derivation so C8's deploy scripts cannot drift from the C7
/// constant. Profile-gated (256s) like the deployable itself.
contract SHRINCSPinned256sTest is Test {
    bytes32 internal constant FACTORY_SALT =
        keccak256("QUIP:Create3Factory:V1.0");
    bytes32 internal constant CHILD_SALT =
        keccak256("QUIP:SPHINCSPlusC256sKeccak:V1.0");

    function testPinnedAddressMatchesCreate3Derivation() public {
        address factory = vm.computeCreate2Address(
            FACTORY_SALT,
            keccak256(type(Create3Factory).creationCode),
            CREATE2_FACTORY
        );
        address expected = Create3.addressOf(CHILD_SALT, factory);

        SHRINCS256sPinHarness harness = new SHRINCS256sPinHarness();
        assertEq(
            harness.pinned(),
            expected,
            "pinned SPHINCSPlusC256sKeccak address must match CREATE3"
        );
    }
}
