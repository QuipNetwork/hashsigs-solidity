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

import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {StatelessLayout} from "../contracts/StatelessLayout.sol";
import {SHRINCSCompactFixtures} from "./helpers/SHRINCSCompactFixtures.sol";

contract Issue08ForsShapeHarness {
    function verifyShape(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes calldata fors
    ) external view returns (bool ok) {
        (,,, ok) = FORSMinusC.verifyForsCAndReturnRoot(
            pkSeed, hypertreeRoot, bytes("issue08-shape"), fors
        );
    }

    function verifySigned(
        bytes calldata key,
        bytes32 hash,
        bytes calldata fors
    ) external view returns (bool ok) {
        (bytes calldata pkSeed, bytes calldata hypertreeRoot, bool okKey) =
            SPHINCSPlusC.decodeKey(key);
        require(okKey, "key");
        (,,, ok) = FORSMinusC.verifyForsCAndReturnRoot(
            pkSeed, hypertreeRoot, SPHINCSPlusC.toMessage(hash), fors
        );
    }
}

/// @notice Issue 08: a FORS-C signature of the wrong shape is rejected
/// without reverting. In the fixed StatelessLayout encoding the shape is
/// the single slice length, so every length other than FORS_LEN fails.
contract Issue08ForsShapeValidationTest is SHRINCSCompactFixtures {
    Issue08ForsShapeHarness internal harness;
    bytes internal sphincsKey;
    bytes32 internal rawMessage;
    bytes internal forsSection;

    function setUp() public {
        harness = new Issue08ForsShapeHarness();
        deployVerifiers();
        CompactCase memory valid = loadCase("valid");
        sphincsKey = valid.sphincsKey;
        rawMessage = valid.rawMessage;
        forsSection =
            byteRange(valid.compactSignature, 0, StatelessLayout.FORS_LEN);
    }

    function testAcceptsExactEntries() public view {
        assertTrue(_verifySigned(forsSection));
    }

    function testRejectsShortEntriesWithoutReverting() public view {
        bytes memory valid = forsSection;
        assertFalse(
            _verifySigned(
                byteRange(
                    valid, 0, valid.length - StatelessLayout.FORS_ENTRY_LEN
                )
            ),
            "one entry missing"
        );
        assertFalse(
            _verifySigned(
                byteRange(valid, 0, StatelessLayout.FORS_ENTRIES_OFFSET)
            ),
            "no entries"
        );
    }

    /// @dev Extra entries are never read, so without the length guard this
    /// valid section would still verify.
    function testRejectsLongEntriesWithoutReverting() public view {
        bytes memory valid = forsSection;
        assertFalse(
            _verifySigned(
                bytes.concat(
                    valid,
                    byteRange(
                        valid,
                        StatelessLayout.FORS_ENTRIES_OFFSET,
                        StatelessLayout.FORS_ENTRIES_OFFSET
                            + StatelessLayout.FORS_ENTRY_LEN
                    )
                )
            )
        );
    }

    /// @dev The fixed layout has no randomizer length field: a randomizer of
    /// any other length changes the section's total length.
    function testFuzzRejectsEveryWrongRandomizerLength(uint256 length)
        public
        view
    {
        length = bound(length, 0, 64);
        vm.assume(length != 32);
        bytes memory valid = forsSection;
        bytes memory randomizer = length < 32
            ? byteRange(valid, 0, length)
            : bytes.concat(byteRange(valid, 0, 32), new bytes(length - 32));
        assertFalse(
            _verifySigned(
                bytes.concat(
                    randomizer,
                    byteRange(
                        valid,
                        StatelessLayout.FORS_COUNTER_OFFSET,
                        valid.length
                    )
                )
            )
        );
    }

    function testRejectsShortSliceWithoutReverting() public view {
        assertFalse(_verify(new bytes(StatelessLayout.FORS_LEN - 1)));
    }

    function testRejectsLongSliceWithoutReverting() public view {
        assertFalse(_verify(new bytes(StatelessLayout.FORS_LEN + 1)));
    }

    function testFuzzRejectsEveryWrongLength(bytes calldata fors)
        public
        view
    {
        vm.assume(fors.length != StatelessLayout.FORS_LEN);
        assertFalse(_verify(fors));
    }

    function _verifySigned(bytes memory fors) internal view returns (bool) {
        return harness.verifySigned(sphincsKey, rawMessage, fors);
    }

    function _verify(bytes memory fors) internal view returns (bool) {
        return harness.verifyShape(
            abi.encodePacked(bytes32(uint256(1))),
            abi.encodePacked(bytes32(uint256(2))),
            fors
        );
    }
}
