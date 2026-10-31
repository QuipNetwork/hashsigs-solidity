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
        // Reads the first word of revertData (top 4 bytes = the
        // selector).
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

    // Reachable forward-overrun: the final (1-byte) auth-path tail's
    // padded end (rounded up to 32) lands past calldatasize when the
    // envelope's own trailing ABI padding for that tail is stripped and
    // the outer `bytes envelope` call-site argument is not itself
    // 32-padded either. Confirms the `bodyEnd > msg.data.length` disjunct
    // in SHRINCS.sliceStatelessSignatureEnvelope
    // [contracts/SHRINCS.sol:680].
    function testRejectsForwardOverrunTailWithoutExhaustingGas() public {
        bytes memory envelope = _envelopeWithoutTailPadding();
        bytes memory callData =
            abi.encodeWithSelector(harness.slice.selector, envelope);
        // abi.encodeWithSelector right-pads the dynamic `envelope` argument
        // to a 32-byte boundary; envelope.length is 1 mod 32 (its own
        // trailing tail padding was already stripped by
        // _envelopeWithoutTailPadding), so strip the call-site padding too.
        // The real calldata then ends exactly at the tail's raw 1-byte
        // content, while the slice's rounded-up bodyEnd still points 31
        // bytes past it, reaching the forward-overrun branch instead of
        // the solc-inserted per-field bounds check.
        uint256 paddingLength = (32 - (envelope.length % 32)) % 32;
        _truncate(callData, callData.length - paddingLength);

        uint256 gasBefore = gasleft();
        (bool success, bytes memory revertData) =
            address(harness).call{gas: 200_000}(callData);
        uint256 gasUsed = gasBefore - gasleft();

        assertFalse(success, "forward-overrun slice must reject");
        assertGe(
            revertData.length, 4, "revert must contain an error selector"
        );
        bytes4 selector;
        // Reads the first word of revertData (top 4 bytes = the
        // selector).
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

    // Shrinks `data` to `newLength` in place. Memory-safe: only rewrites
    // the length word of an existing Solidity-managed allocation; the
    // free-memory pointer is untouched.
    function _truncate(bytes memory data, uint256 newLength) internal pure {
        assembly ("memory-safe") {
            mstore(data, newLength)
        }
    }

    // Builds a canonical stateless envelope whose final (and only)
    // auth-path tail is 1 byte (hex"01"), then drops the 31 zero bytes
    // that abi.encode pads that tail out to a full 32-byte word with.
    // The returned envelope's declared length ends immediately after the
    // tail's one real byte instead of at its rounded-up 32-byte boundary.
    function _envelopeWithoutTailPadding()
        internal
        pure
        returns (bytes memory envelope)
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
        envelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
        // hex"01" is the tail's only real byte; abi.encode always pads a
        // dynamic bytes element's word to 32, so the last 31 bytes of the
        // canonical encoding are always that padding here.
        _truncate(envelope, envelope.length - 31);
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
