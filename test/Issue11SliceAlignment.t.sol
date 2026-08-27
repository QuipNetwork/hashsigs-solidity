// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";

contract Issue11SliceAlignmentHarness {
    function sliceThenAllocate(bytes calldata envelope)
        external
        pure
        returns (
            bytes memory slice,
            uint256 freePointerRemainder,
            bytes32 paddingAfterAllocation
        )
    {
        (, SPHINCSPlusC.Signature calldata signature) =
            SHRINCS.statelessEnvelope(envelope);
        slice = SHRINCS.sliceStatelessSignatureEnvelope(signature);

        uint256 logicalEnd;
        assembly ("memory-safe") {
            logicalEnd := add(add(slice, 0x20), mload(slice))
            freePointerRemainder := mod(mload(0x40), 0x20)
        }

        // The old allocator started this bytes object at logicalEnd. Its
        // length word therefore changed the slice's first padding word to 32.
        bytes memory nextAllocation = new bytes(32);
        nextAllocation[0] = 0xa5;
        assembly ("memory-safe") {
            paddingAfterAllocation := mload(logicalEnd)
        }
    }
}

contract Issue11SliceAlignmentTest is Test {
    Issue11SliceAlignmentHarness internal harness;

    function setUp() public {
        harness = new Issue11SliceAlignmentHarness();
    }

    function testNonWordAlignedFramingKeepsNextAllocationSeparate()
        public
        view
    {
        bytes memory envelope = _nonWordAlignedEnvelope();
        (
            bytes memory slice,
            uint256 freePointerRemainder,
            bytes32 paddingAfterAllocation
        ) = harness.sliceThenAllocate(envelope);

        // The shifted final tail makes the copied signature body 1 mod 32.
        assertEq(slice.length % 32, 1, "fixture must exercise odd body size");
        assertEq(
            freePointerRemainder,
            0,
            "free-memory pointer must remain word-aligned"
        );
        assertEq(
            paddingAfterAllocation,
            bytes32(0),
            "next allocation must not overwrite envelope padding"
        );
    }

    function _nonWordAlignedEnvelope()
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
                randomizer: hex"04",
                counter: 0,
                entries: new FORSMinusC.ForsEntry[](0)
            }),
            hypertree: hypertree
        });
        SHRINCS.PublicKey memory publicKey = SHRINCS.PublicKey({
            statefulPublicKey: hex"05",
            publicKeyCommitment: hex"06",
            pkSeed: hex"07",
            hypertreeRoot: hex"08"
        });

        bytes memory canonical = abi.encode(publicKey, signature);
        envelope = new bytes(canonical.length + 1);
        for (uint256 i = 0; i < canonical.length; ++i) {
            envelope[i] = canonical[i];
        }

        uint256 signatureStart = _word(envelope, 0x20);
        uint256 hypertreeStart =
            signatureStart + _word(envelope, signatureStart + 0x20);
        uint256 arrayHead = hypertreeStart + 0x20;
        uint256 layerStart = arrayHead + _word(envelope, arrayHead);
        uint256 authPathStart =
            layerStart + _word(envelope, layerStart + 0x40);
        uint256 authPathHead = authPathStart + 0x20;
        uint256 tailStart = authPathHead + _word(envelope, authPathHead);

        // Shift the final bytes value (length plus padded data) right by
        // one byte and point the nested array element at the shifted value.
        for (uint256 i = 0x40; i > 0; --i) {
            envelope[tailStart + i] = envelope[tailStart + i - 1];
        }
        _storeWord(envelope, authPathHead, _word(envelope, authPathHead) + 1);
    }

    function _word(bytes memory data, uint256 offset)
        internal
        pure
        returns (uint256 value)
    {
        assembly ("memory-safe") {
            value := mload(add(add(data, 0x20), offset))
        }
    }

    function _storeWord(bytes memory data, uint256 offset, uint256 value)
        internal
        pure
    {
        assembly ("memory-safe") {
            mstore(add(add(data, 0x20), offset), value)
        }
    }
}
