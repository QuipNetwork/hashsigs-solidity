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

import {ShrincsStatelessVectorSigner} from "./ShrincsStatelessVectorSigner.sol";
import {ShrincsTypes} from "../../contracts/ShrincsTypes.sol";

/// @notice TEST-ONLY orchestration facade for the staged stateless signer.
/// @dev This library keeps the actual signing work in the storage-backed staged signer,
/// but hides the manual FORS / hypertree loops from tests and vector generators.
library ShrincsStatelessVectorSigningFacade {
    function signFromSeed(
        ShrincsStatelessVectorSigner signer,
        bytes memory seedMaterial,
        uint32 maxStatefulSignatures,
        bytes memory message
    )
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            ShrincsTypes.StatelessSignature memory signature,
            bool ok
        )
    {
        bytes32 sessionId;
        (sessionId, ok) = signer.beginSessionFromSeed(seedMaterial, maxStatefulSignatures, message);
        if (!ok) return (publicKey, signature, false);
        return completeSession(signer, sessionId);
    }

    function completeSession(ShrincsStatelessVectorSigner signer, bytes32 sessionId)
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            ShrincsTypes.StatelessSignature memory signature,
            bool ok
        )
    {
        bool done;
        while (!done) {
            (, done) = signer.stepFors(sessionId, 1);
        }
        signer.finalizeFors(sessionId);

        done = false;
        while (!done) {
            (, done) = signer.stepHypertree(sessionId, 1);
        }

        bytes memory encodedSignature = signer.finalizeSignature(sessionId);
        publicKey = signer.sessionPublicKey(sessionId);
        signature = abi.decode(encodedSignature, (ShrincsTypes.StatelessSignature));
        return (publicKey, signature, true);
    }
}
