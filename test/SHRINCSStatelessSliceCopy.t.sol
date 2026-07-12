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
import {SHRINCSCodec} from "../contracts/SHRINCSCodec.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract SliceCopySigner is SHRINCSStatelessVectorSigner {}

/// @dev External `bytes calldata` entrypoints that re-tag a stateless
/// envelope exactly as SHRINCS.prepareStatelessDelegation does, then build
/// the delegate signature payload both ways: the slice-copy under test and
/// the abi.encode reference encoder that is its byte-for-byte spec.
contract SliceCopyHarness {
    function sliceVsOracle(bytes calldata envelope)
        external
        pure
        returns (bytes memory slice, bytes memory oracle)
    {
        (, SPHINCSPlusC.Signature calldata sig) =
            SHRINCSCodec.statelessEnvelope(envelope);
        slice = SHRINCSCodec.sliceStatelessSignatureEnvelope(sig);
        oracle = SHRINCSCodec.encodeStatelessSignatureEnvelope(sig);
    }

    /// @dev A masked-profile-legal tail truncation: the envelope view is cut
    /// by `cut` bytes so the re-tag reads the signature's tail out of the
    /// still-present adjacent calldata, exactly the framing the malleability
    /// model documents. The slice-copy must still equal abi.encode.
    function sliceVsOracleTruncated(bytes calldata envelope, uint256 cut)
        external
        pure
        returns (bytes memory slice, bytes memory oracle)
    {
        bytes calldata env = envelope[0:envelope.length - cut];
        (, SPHINCSPlusC.Signature calldata sig) =
            SHRINCSCodec.statelessEnvelope(env);
        slice = SHRINCSCodec.sliceStatelessSignatureEnvelope(sig);
        oracle = SHRINCSCodec.encodeStatelessSignatureEnvelope(sig);
    }

    function buildSlice(bytes calldata envelope)
        external
        view
        returns (uint256 used, bytes memory out)
    {
        (, SPHINCSPlusC.Signature calldata sig) =
            SHRINCSCodec.statelessEnvelope(envelope);
        uint256 g = gasleft();
        out = SHRINCSCodec.sliceStatelessSignatureEnvelope(sig);
        used = g - gasleft();
    }

    function buildEncode(bytes calldata envelope)
        external
        view
        returns (uint256 used, bytes memory out)
    {
        (, SPHINCSPlusC.Signature calldata sig) =
            SHRINCSCodec.statelessEnvelope(envelope);
        uint256 g = gasleft();
        out = SHRINCSCodec.encodeStatelessSignatureEnvelope(sig);
        used = g - gasleft();
    }
}

/// @notice Differential proof that the delegation-path slice-copy
/// (SHRINCSCodec.sliceStatelessSignatureEnvelope) reproduces exactly the
/// bytes abi.encode of the re-tagged stateless signature would produce, over
/// the real 256s vector, a fuzz of well-formed re-encoded envelopes, and a
/// masked-profile-legal tail-truncated frame; plus the gas reduction from
/// dropping the field-by-field memory materialization. Profile-gated (256s).
contract SHRINCSStatelessSliceCopyTest is Test {
    SliceCopyHarness internal harness;
    SliceCopySigner internal signer;

    bytes internal validEnvelope;

    function setUp() public {
        harness = new SliceCopyHarness();
        signer = new SliceCopySigner();
        validEnvelope = this.buildStatelessEnvelope();
    }

    function testSliceEqualsAbiEncodeOnVector() public view {
        (bytes memory slice, bytes memory oracle) =
            harness.sliceVsOracle(validEnvelope);
        assertEq(
            slice, oracle, "slice-copy must equal abi.encode on the vector"
        );
    }

    // Cut 33 bytes: shortens the envelope view into the last authPath
    // element's data word, so the re-tag reads the signature tail from the
    // adjacent (still-present) calldata. The slice-copy spans the struct's
    // own extent, matching abi.encode's re-serialization from the same reads.
    function testSliceEqualsAbiEncodeOnTruncatedFrame() public view {
        (bytes memory slice, bytes memory oracle) =
            harness.sliceVsOracleTruncated(validEnvelope, 33);
        assertEq(
            slice,
            oracle,
            "slice-copy must equal abi.encode on a truncated frame"
        );
    }

    function testSliceUsesLessGasThanAbiEncode() public view {
        (uint256 sliceGas,) = harness.buildSlice(validEnvelope);
        (uint256 encodeGas,) = harness.buildEncode(validEnvelope);
        assertLt(
            sliceGas,
            encodeGas,
            "slice-copy must cost less than the abi.encode build"
        );
    }

    /// @dev Fuzz over well-formed re-encoded signature envelopes: multi-entry
    /// FORS and a non-empty hypertree (1..3 fully populated WOTS-C layers,
    /// each with a non-empty authPath), so the slice-copy is proven against
    /// abi.encode across signature shapes, not just the vector's.
    function testFuzzSliceEqualsAbiEncode(
        bytes calldata randomizer,
        uint32 counter,
        bytes calldata leaf,
        bytes calldata pathElem,
        uint8 entryShape,
        uint8 layerShape,
        uint8 pathShape
    ) public view {
        bytes[] memory authPath = new bytes[](1 + (uint256(pathShape) % 3));
        for (uint256 i = 0; i < authPath.length; i++) {
            authPath[i] = pathElem;
        }
        uint256 entryCount = 1 + (uint256(entryShape) % 4);
        FORSMinusC.ForsEntry[] memory entries =
            new FORSMinusC.ForsEntry[](entryCount);
        for (uint256 i = 0; i < entryCount; i++) {
            entries[i] =
                FORSMinusC.ForsEntry({secretLeaf: leaf, authPath: authPath});
        }
        uint256 layerCount = 1 + (uint256(layerShape) % 3);
        Hypertree.HypertreeLayerSignature[] memory hypertree =
            new Hypertree.HypertreeLayerSignature[](layerCount);
        for (uint256 i = 0; i < layerCount; i++) {
            hypertree[i] = Hypertree.HypertreeLayerSignature({
                treeIndex: 0,
                leafIndex: 0,
                wotsCPkHash: leaf,
                wotsCSignature: WOTSPlusC.WotsCSignature({
                    randomizer: randomizer,
                    counter: counter,
                    chains: authPath
                }),
                authPath: authPath
            });
        }
        SPHINCSPlusC.Signature memory signature = SPHINCSPlusC.Signature({
            fors: FORSMinusC.ForsSignature({
                randomizer: randomizer, counter: counter, entries: entries
            }),
            hypertree: hypertree
        });
        SHRINCS.PublicKey memory publicKey = SHRINCS.PublicKey({
            statefulPublicKey: leaf,
            publicKeyCommitment: leaf,
            pkSeed: leaf,
            hypertreeRoot: leaf
        });
        bytes memory envelope =
            SHRINCSCodec.encodeStatelessEnvelope(publicKey, signature);
        (bytes memory slice, bytes memory oracle) =
            harness.sliceVsOracle(envelope);
        assertEq(
            slice, oracle, "well-formed slice-copy must equal abi.encode"
        );
    }

    /// @dev Builds a real 256s stateless signature and the two-element
    /// stateless envelope the delegation path re-tags. External so it runs in
    /// its own memory frame (the fixture working set is large).
    function buildStatelessEnvelope()
        external
        returns (bytes memory envelope)
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("slice-copy fixture"), 4
        );
        require(ok, "keygen");

        bytes32 hash = keccak256("slice-copy message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        require(beginOk, "begin");
        SPHINCSPlusC.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "complete");

        envelope = SHRINCSCodec.encodeStatelessEnvelope(publicKey, signature);
    }
}
