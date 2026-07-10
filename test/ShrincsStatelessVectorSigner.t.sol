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
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {
    ShrincsStatelessVectorSigner
} from "./helpers/ShrincsStatelessVectorSigner.sol";
import {
    ShrincsStatelessVectorSigningFacade
} from "./helpers/ShrincsStatelessVectorSigningFacade.sol";

contract ShrincsStatelessVectorSignerHarness is
    ShrincsStatelessVectorSigner
{
    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }
}

contract ShrincsStatelessVectorSignerTest is Test {
    // line-length: allow — fmt cannot wrap a using-for directive
    using ShrincsStatelessVectorSigningFacade for ShrincsStatelessVectorSignerHarness;

    ShrincsStatelessVectorSignerHarness internal signer;

    function setUp() public {
        signer = new ShrincsStatelessVectorSignerHarness();
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
            ShrincsTypes.NUM_FORS_TREES - 1,
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
            ShrincsTypes.NUM_HYPERTREE_LAYERS,
            "all hypertree layers must be processed"
        );

        bytes memory encodedSignature = signer.finalizeSignature(sessionId);
        ShrincsTypes.StatelessSignature memory signature =
            abi.decode(encodedSignature, (ShrincsTypes.StatelessSignature));
        ShrincsTypes.PublicKey memory publicKey =
            signer.sessionPublicKey(sessionId);
        bytes memory signedMessage = signer.sessionMessage(sessionId);

        assertEq(
            signature.fors.entries.length,
            ShrincsTypes.NUM_FORS_TREES - 1,
            "FORS-C entry count"
        );
        assertEq(
            signature.hypertree.length,
            ShrincsTypes.NUM_HYPERTREE_LAYERS,
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
            ShrincsTypes.PublicKey memory publicKey,
            ShrincsTypes.StatelessSignature memory signature,
            bool ok
        ) = signer.signFromSeed(
            bytes("high level stateless vector seed"), 4, message
        );

        assertTrue(ok, "high-level signing must succeed");
        assertEq(
            signature.fors.entries.length,
            ShrincsTypes.NUM_FORS_TREES - 1,
            "FORS-C entry count"
        );
        assertEq(
            signature.hypertree.length,
            ShrincsTypes.NUM_HYPERTREE_LAYERS,
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
}
