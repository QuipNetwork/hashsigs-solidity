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

import {Test} from "forge-std/Test.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCSTestCodec} from "./helpers/SHRINCSTestCodec.sol";

contract Issue11SliceAlignmentHarness {
    function sliceThenAllocate(bytes calldata envelope)
        external
        pure
        returns (
            bytes memory sliced,
            uint256 freeAfterSlice,
            uint256 nextAllocation,
            bytes32 paddingBefore,
            bytes32 paddingAfter
        )
    {
        (, SPHINCSPlusC.Signature calldata signature) =
            SHRINCS.statelessEnvelope(envelope);
        sliced = SHRINCS.sliceStatelessSignatureEnvelope(signature);

        uint256 logicalEnd;
        assembly ("memory-safe") {
            freeAfterSlice := mload(0x40)
            logicalEnd := add(add(sliced, 0x20), mload(sliced))
            paddingBefore := mload(logicalEnd)
        }

        bytes memory next = new bytes(32);
        assembly ("memory-safe") {
            nextAllocation := next
            paddingAfter := mload(logicalEnd)
        }
    }
}

contract Issue11SliceAlignmentTest is Test {
    Issue11SliceAlignmentHarness internal harness;

    function setUp() public {
        harness = new Issue11SliceAlignmentHarness();
    }

    // Fuzzes the induced tail shift over every residue mod 32 (0 is the
    // aligned control, matching the canonical unshifted encoding) so each
    // run exercises a different branch of the free-memory rounding in
    // SHRINCS.sliceStatelessSignatureEnvelope. The padding word
    // immediately after the slice is memory the production assembly
    // never writes (only the free-memory pointer is bumped past it), so
    // its value is unspecified; this only asserts allocator-alignment
    // properties the assembly does guarantee, not that the padding holds
    // any particular value.
    function testFuzzTailShiftPreservesAllocatorAlignment(uint256 shift)
        public
        view
    {
        shift = bound(shift, 0, 31);
        bytes memory envelope = _shiftedTailEnvelope(shift);
        (
            bytes memory sliced,
            uint256 freeAfterSlice,
            uint256 nextAllocation,
            bytes32 paddingBefore,
            bytes32 paddingAfter
        ) = harness.sliceThenAllocate(envelope);

        assertEq(
            sliced.length % 32,
            shift,
            "slice length residue must track the induced tail shift"
        );
        assertEq(freeAfterSlice % 32, 0, "free-memory pointer must align");
        assertEq(
            nextAllocation,
            freeAfterSlice,
            "next allocation must start after rounded slice storage"
        );
        // With a 0 shift the slice is already 32-aligned: there is no
        // padding gap between the slice and the free-memory pointer, so
        // `next` legitimately starts writing its own header at
        // `logicalEnd` and this comparison does not apply.
        if (shift != 0) {
            assertEq(
                paddingAfter,
                paddingBefore,
                "next allocation must not overwrite slice padding"
            );
        }
    }

    function _shiftedTailEnvelope(uint256 shift)
        internal
        pure
        returns (bytes memory shifted)
    {
        bytes[] memory authPath = new bytes[](1);
        authPath[0] = hex"01";
        Hypertree.HypertreeLayerSignature[] memory hypertree =
            new Hypertree.HypertreeLayerSignature[](1);
        hypertree[0] = Hypertree.HypertreeLayerSignature({
            wotsCPkHash: hex"02",
            wotsCSignature: WOTSPlusC.WotsCSignature({
                randomizer: hex"03", counter: 0, chains: new bytes[](0)
            }),
            authPath: authPath
        });
        SPHINCSPlusC.Signature memory signature = SPHINCSPlusC.Signature({
            fors: FORSMinusC.ForsSignature({
                randomizer: new bytes(0),
                counter: 0,
                entries: new FORSMinusC.ForsEntry[](0)
            }),
            hypertree: hypertree
        });
        SHRINCS.PublicKey memory publicKey;
        bytes memory canonical =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);

        shifted = new bytes(canonical.length + shift);
        for (uint256 i = 0; i < canonical.length; ++i) {
            shifted[i] = canonical[i];
        }
        _shiftFinalAuthPathTail(shifted, shift);
    }

    function _shiftFinalAuthPathTail(bytes memory envelope, uint256 shift)
        internal
        pure
    {
        assembly ("memory-safe") {
            let base := add(envelope, 0x20)
            let signature := add(base, mload(add(base, 0x20)))
            let hypertree := add(signature, mload(add(signature, 0x20)))
            let layerHead := add(hypertree, 0x20)
            let layer := add(layerHead, mload(layerHead))
            let authPath := add(layer, mload(add(layer, 0x40)))
            let pathHead := add(authPath, 0x20)
            let tailOffsetWord := pathHead
            let tailLength := add(pathHead, mload(tailOffsetWord))

            // Move the final bytes tail `shift` bytes to the right and
            // adjust its relative offset by the same amount. Its data
            // pointer and padded end become `shift` mod 32 while remaining
            // entirely inside the enclosing calldata (the buffer was
            // grown by exactly `shift` bytes above to make room).
            for { let i := 0x40 } gt(i, 0) { i := sub(i, 1) } {
                mstore8(
                    add(tailLength, add(sub(i, 1), shift)),
                    byte(0, mload(add(tailLength, sub(i, 1))))
                )
            }
            mstore(tailOffsetWord, add(mload(tailOffsetWord), shift))
        }
    }
}
