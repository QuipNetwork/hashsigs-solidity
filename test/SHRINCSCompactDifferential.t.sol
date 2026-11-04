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

import {
    StatelessSignatureTypes
} from "./helpers/StatelessSignatureTypes.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {StatelessLayout} from "../contracts/StatelessLayout.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestCodec} from "./helpers/SHRINCSTestCodec.sol";
import {SHRINCSCompactFixtures} from "./helpers/SHRINCSCompactFixtures.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract CompactDifferentialSigner is SHRINCSStatelessVectorSigner {}

/// @notice Vector conformance for the fixed-layout stateless path: on every
/// Rust-anchored stateless case, the deployed SHRINCS verifier and its
/// SPHINCSPlusC sibling return exactly the verdict the Rust generator
/// assigned, valid and invalid alike, and an in-Solidity signed fixture
/// verifies end to end. The Rust vectors are produced independently of this
/// repository's Solidity, so they are the reference.
contract SHRINCSCompactDifferentialTest is SHRINCSCompactFixtures {
    function setUp() public {
        deployVerifiers();
    }

    function testEncoderProducesExactLengths() public view {
        CompactCase memory valid = loadCase("valid");
        assertEq(valid.compactPayload.length, StatelessLayout.PAYLOAD_LEN);
        assertEq(valid.compactSignature.length, StatelessLayout.PQ_LEN);
    }

    /// @dev Every Rust-anchored case, under the installed (valid) key and
    /// under the case's own declared commitment, at both layers.
    function testVectorCasesMatchRustVerdicts() public view {
        bytes32 installed = loadCase("valid").commitment;
        string[7] memory names = caseNames();
        for (uint256 i = 0; i < names.length; ++i) {
            CompactCase memory c = loadCase(names[i]);
            assertShrincsVerdict(c, installed, c.callerHash, c.expectedValid);
            assertShrincsVerdict(
                c, c.commitment, c.callerHash, c.expectedValid
            );
            assertSphincsVerdict(c, c.rawMessage, c.expectedSphincsValid);
        }
    }

    function testWrongHashRejected() public view {
        CompactCase memory c = loadCase("valid");
        assertShrincsVerdict(
            c, c.commitment, c.callerHash ^ bytes32(uint256(1)), false
        );
        assertSphincsVerdict(c, c.rawMessage ^ bytes32(uint256(1)), false);
    }

    /// @dev The in-Solidity signed fixture SHRINCSStatelessDelegation uses,
    /// on the profiles where in-process stateless signing is feasible.
    function testInSoliditySignedFixtureVerifies() public {
        if (isStateless128sProfile()) return;
        CompactDifferentialSigner signer = new CompactDifferentialSigner();
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("stateless delegation fixture"), 4
        );
        require(ok, "keygen");
        bytes32 commitment =
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey);
        bytes32 hash = keccak256("stateless delegation message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey,
            publicKey,
            abi.encodePacked(
                SHRINCS.statelessRawMessageHash(commitment, hash)
            )
        );
        require(beginOk, "begin");
        StatelessSignatureTypes.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "complete");

        bytes memory key = abi.encodePacked(commitment);
        bytes memory payload =
            SHRINCSTestCodec.encodeCompactPayload(publicKey, signature);
        assertEq(
            verifier.verifyStateless(key, hash, payload), VERIFY_SELECTOR
        );
        assertEq(
            verifier.verifyStateless(
                key, keccak256("other message"), payload
            ),
            INVALID_SIGNATURE
        );
    }

    function assertShrincsVerdict(
        CompactCase memory c,
        bytes32 installed,
        bytes32 hash,
        bool expectedValid
    ) internal view {
        assertEq(
            verifier.verifyStateless(
                abi.encodePacked(installed), hash, c.compactPayload
            ),
            expectedValid ? VERIFY_SELECTOR : INVALID_SIGNATURE,
            string.concat("SHRINCS verdict differs from Rust: ", c.name)
        );
    }

    function assertSphincsVerdict(
        CompactCase memory c,
        bytes32 message,
        bool expectedValid
    ) internal view {
        assertEq(
            sibling.verify(c.sphincsKey, message, c.compactSignature),
            expectedValid ? VERIFY_SELECTOR : INVALID_SIGNATURE,
            string.concat("SPHINCSPlusC verdict differs from Rust: ", c.name)
        );
    }

    function isStateless128sProfile() internal pure returns (bool) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        return id == PROFILE_128S_Q18 || id == PROFILE_128S_Q20;
    }
}
