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

    function testNonAlignedTailPreservesAllocatorAndPadding() public view {
        bytes memory envelope = _nonAlignedTailEnvelope();
        (
            bytes memory sliced,
            uint256 freeAfterSlice,
            uint256 nextAllocation,
            bytes32 paddingBefore,
            bytes32 paddingAfter
        ) = harness.sliceThenAllocate(envelope);

        assertEq(sliced.length % 32, 1, "fixture must be non-word-aligned");
        assertEq(freeAfterSlice % 32, 0, "free-memory pointer must align");
        assertEq(
            nextAllocation,
            freeAfterSlice,
            "next allocation must start after rounded slice storage"
        );
        assertEq(paddingBefore, bytes32(0), "slice padding must start zero");
        assertEq(
            paddingAfter,
            bytes32(0),
            "next allocation must not overwrite slice padding"
        );
    }

    function _nonAlignedTailEnvelope()
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

        shifted = new bytes(canonical.length + 1);
        for (uint256 i = 0; i < canonical.length; ++i) {
            shifted[i] = canonical[i];
        }
        _shiftFinalAuthPathTail(shifted);
    }

    function _shiftFinalAuthPathTail(bytes memory envelope) internal pure {
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

            // Move the final bytes tail one byte to the right and adjust its
            // relative offset. Its data pointer and padded end become 1 mod
            // 32 while remaining entirely inside the enclosing calldata.
            for { let i := 0x40 } gt(i, 0) { i := sub(i, 1) } {
                mstore8(
                    add(tailLength, i),
                    byte(0, mload(add(tailLength, sub(i, 1))))
                )
            }
            mstore(tailOffsetWord, add(mload(tailOffsetWord), 1))
        }
    }
}
