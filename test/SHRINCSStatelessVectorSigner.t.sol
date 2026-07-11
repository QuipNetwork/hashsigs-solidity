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
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSStatelessVectorSigningFacade
} from "./helpers/SHRINCSStatelessVectorSigningFacade.sol";

contract SHRINCSStatelessVectorSignerHarness is
    SHRINCSStatelessVectorSigner
{
    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusC.Signature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }
}

contract SHRINCSStatelessVectorSignerTest is Test {
    // line-length: allow — fmt cannot wrap a using-for directive
    using SHRINCSStatelessVectorSigningFacade for SHRINCSStatelessVectorSignerHarness;

    SHRINCSStatelessVectorSignerHarness internal signer;

    function setUp() public {
        signer = new SHRINCSStatelessVectorSignerHarness();
    }

    function testStagedStatelessVectorSignerProducesVerifyingSignature()
        public
    {
        bytes memory message =
            abi.encodePacked(keccak256("staged stateless vector message"));
        (bytes32 sessionId, bool ok) = signer.beginSessionFromSeed(
            bytes("staged stateless vector seed"), 4, message
        );
        assertTrue(ok, "session must start");

        (
            bool active,
            bool forsPrepared,
            bool forsFinalized,
            uint32 nextForsTree,
            uint32 nextLayer
        ) = signer.sessionProgress(sessionId);
        assertTrue(active, "session active");
        assertTrue(forsPrepared, "fors prepared");
        assertFalse(forsFinalized, "fors not finalized yet");
        assertEq(nextForsTree, 0, "fors starts at tree zero");
        assertEq(nextLayer, 0, "hypertree starts at layer zero");

        uint32 totalForsProcessed;
        bool forsDone;
        while (!forsDone) {
            (uint32 processedFors, bool stepDone) =
                signer.stepFors(sessionId, 1);
            assertEq(
                processedFors,
                1,
                "one FORS tree should be processed per step"
            );
            totalForsProcessed += processedFors;
            forsDone = stepDone;
        }
        assertEq(
            totalForsProcessed,
            SHRINCSParams.NUM_FORS_TREES - 1,
            "all signed FORS trees must be processed"
        );

        bytes32 forsRoot = signer.finalizeFors(sessionId);
        assertTrue(forsRoot != bytes32(0), "FORS root must finalize");

        uint32 totalLayersProcessed;
        bool hypertreeDone;
        while (!hypertreeDone) {
            (uint32 processedLayers, bool stepDone) =
                signer.stepHypertree(sessionId, 1);
            assertEq(
                processedLayers,
                1,
                "one hypertree layer should be processed per step"
            );
            totalLayersProcessed += processedLayers;
            hypertreeDone = stepDone;
        }
        assertEq(
            totalLayersProcessed,
            SHRINCSParams.NUM_HYPERTREE_LAYERS,
            "all hypertree layers must be processed"
        );

        bytes memory encodedSignature = signer.finalizeSignature(sessionId);
        SPHINCSPlusC.Signature memory signature =
            abi.decode(encodedSignature, (SPHINCSPlusC.Signature));
        SHRINCS.PublicKey memory publicKey =
            signer.sessionPublicKey(sessionId);
        bytes memory signedMessage = signer.sessionMessage(sessionId);

        assertEq(
            signature.fors.entries.length,
            SHRINCSParams.NUM_FORS_TREES - 1,
            "FORS-C entry count"
        );
        assertEq(
            signature.hypertree.length,
            SHRINCSParams.NUM_HYPERTREE_LAYERS,
            "hypertree layer count"
        );

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 expectedPublicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }

        assertTrue(
            signer.verifyUnsafeRaw(
                expectedPublicKeyCommitment,
                publicKey,
                signedMessage,
                signature
            ),
            "staged stateless signer output must verify"
        );
    }

    function testHighLevelStatelessFacadeProducesVerifyingSignature()
        public
    {
        bytes memory message = abi.encodePacked(
            keccak256("high level stateless vector message")
        );
        (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,
            bool ok
        ) = signer.signFromSeed(
            bytes("high level stateless vector seed"), 4, message
        );

        assertTrue(ok, "high-level signing must succeed");
        assertEq(
            signature.fors.entries.length,
            SHRINCSParams.NUM_FORS_TREES - 1,
            "FORS-C entry count"
        );
        assertEq(
            signature.hypertree.length,
            SHRINCSParams.NUM_HYPERTREE_LAYERS,
            "hypertree layer count"
        );

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 expectedPublicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }

        assertTrue(
            signer.verifyUnsafeRaw(
                expectedPublicKeyCommitment, publicKey, message, signature
            ),
            "high-level stateless signer output must verify"
        );
    }

    // Regression coverage for the forsDigestBytes message-copy loop, which
    // copies the message in whole 32-byte words: lengths that are not a
    // multiple of 32 exercise the final partial-word chunk, and lengths
    // above 32 exercise multi-word copies. Guards the copy-loop class
    // (ce0fafc) and the free-memory-pointer overhang fix (F-01).
    function _assertRawStatelessRoundTrip(uint256 messageLen) internal {
        bytes memory message = new bytes(messageLen);
        for (uint256 i = 0; i < messageLen;) {
            message[i] = bytes1(uint8((i % 251) + 1));
            unchecked {
                ++i;
            }
        }
        (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,
            bool ok
        ) = signer.signFromSeed(
            bytes("forsDigestBytes overhang regression seed"), 4, message
        );
        assertTrue(ok, "signing must succeed");

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 expectedPublicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }
        assertTrue(
            signer.verifyUnsafeRaw(
                expectedPublicKeyCommitment, publicKey, message, signature
            ),
            "raw stateless signer output must verify"
        );
    }

    function testStatelessRawMessageLength1() public {
        _assertRawStatelessRoundTrip(1);
    }

    function testStatelessRawMessageLength13() public {
        _assertRawStatelessRoundTrip(13);
    }

    function testStatelessRawMessageLength33() public {
        _assertRawStatelessRoundTrip(33);
    }

    function testStatelessRawMessageLength64() public {
        _assertRawStatelessRoundTrip(64);
    }

    function testStatelessRawMessageLength65() public {
        _assertRawStatelessRoundTrip(65);
    }
}
