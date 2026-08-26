// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";

contract Issue10SliceBoundsHarness {
    function slice(bytes calldata envelope)
        external
        pure
        returns (bytes memory)
    {
        (, SPHINCSPlusC.Signature calldata signature) =
            SHRINCS.statelessEnvelope(envelope);
        return SHRINCS.sliceStatelessSignatureEnvelope(signature);
    }
}

contract Issue10SliceBoundsTest is Test {
    Issue10SliceBoundsHarness internal harness;

    function setUp() public {
        harness = new Issue10SliceBoundsHarness();
    }

    function testRejectsTailBeforeSignatureWithoutExhaustingGas() public {
        bytes memory callData =
            abi.encodeCall(harness.slice, (_backwardTailEnvelope()));

        uint256 gasBefore = gasleft();
        (bool success, bytes memory revertData) =
            address(harness).call{gas: 200_000}(callData);
        uint256 gasUsed = gasBefore - gasleft();

        assertFalse(success, "backward slice must reject");
        assertGe(
            revertData.length, 4, "revert must contain an error selector"
        );
        bytes4 selector;
        assembly ("memory-safe") {
            selector := mload(add(revertData, 0x20))
        }
        assertEq(
            selector,
            SHRINCS.InvalidStatelessSignatureSlice.selector,
            "must reject at the explicit slice bound"
        );
        assertLt(gasUsed, 100_000, "rejection must have bounded gas cost");
    }

    function _backwardTailEnvelope()
        internal
        pure
        returns (bytes memory envelope)
    {
        bytes memory encodedHypertree = abi.encode(_hypertree());
        envelope = new bytes(0x800);
        _copy(encodedHypertree, 0x20, envelope, 0x80);

        assembly ("memory-safe") {
            // The outer signature pointer resolves to envelope + 0x400.
            mstore(add(envelope, 0x40), 0x400)
            // signature.hypertree wraps backward and resolves to the valid
            // encoded hypertree array at envelope + 0x80.
            mstore(add(envelope, 0x440), sub(0, 0x380))
        }
    }

    function _hypertree()
        internal
        pure
        returns (Hypertree.HypertreeLayerSignature[] memory hypertree)
    {
        bytes[] memory authPath = new bytes[](1);
        authPath[0] = hex"01";
        hypertree = new Hypertree.HypertreeLayerSignature[](1);
        hypertree[0] = Hypertree.HypertreeLayerSignature({
            wotsCPkHash: hex"02",
            wotsCSignature: WOTSPlusC.WotsCSignature({
                randomizer: hex"03", counter: 0, chains: new bytes[](0)
            }),
            authPath: authPath
        });
    }

    function _copy(
        bytes memory source,
        uint256 sourceOffset,
        bytes memory target,
        uint256 targetOffset
    ) internal pure {
        for (uint256 i = sourceOffset; i < source.length; ++i) {
            target[targetOffset + i - sourceOffset] = source[i];
        }
    }
}
