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
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {UXMSS} from "../contracts/UXMSS.sol";

contract SHRINCSStatefulActionSignerHarness {
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        external
        pure
        returns (SHRINCS.SigningKey memory, SHRINCS.PublicKey memory, bool)
    {
        return SHRINCSTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function signStatefulAction(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.ActionContext memory context
    )
        external
        pure
        returns (
            SHRINCS.SigningKey memory,
            UXMSS.StatefulSignature memory,
            bool
        )
    {
        return SHRINCSTestSigner.signStatefulAction(
                signingKey, publicKey, context
            );
    }

    function verify(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.ActionContext calldata context,
        UXMSS.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(
            expectedPublicKeyCommitment, publicKey, context, signature
        );
    }
}

contract SHRINCSSignerStatefulActionTest is Test {
    SHRINCSStatefulActionSignerHarness internal harness;

    function setUp() public {
        harness = new SHRINCSStatefulActionSignerHarness();
    }

    function testStatefulActionSignerProducesCanonicalVerifyingSignature()
        public
        view
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = harness.keygen(bytes("solidity stateful action signer seed"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCS.ActionContext memory context =
            SHRINCS.ActionContext({
                domainSeparator: keccak256("domain"),
                nonce: 7,
                keyVersion: 3,
                actionType: keccak256("transfer"),
                payloadHash: keccak256("payload")
            });

        (
            SHRINCS.SigningKey memory nextSigningKey,
            UXMSS.StatefulSignature memory signature,
            bool signOk
        ) = harness.signStatefulAction(signingKey, publicKey, context);

        assertTrue(signOk, "action signing must succeed");
        assertEq(
            nextSigningKey.nextStatefulLeafIndex,
            2,
            "canonical action signing must consume one leaf"
        );

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 expectedPublicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }

        assertTrue(
            harness.verify(
                expectedPublicKeyCommitment, publicKey, context, signature
            ),
            "canonical stateful action signature must verify"
        );
    }

    // line-length: allow — test name is one unbreakable token
    function testStatefulActionSignerRejectsMalformedPublicKeyCommitmentField()
        public
        view
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = harness.keygen(bytes("stateful malformed public key seed"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        publicKey.publicKeyCommitment = hex"1234";

        // forgefmt: disable-next-line
        SHRINCS.ActionContext memory context =
            SHRINCS.ActionContext({
                domainSeparator: keccak256("domain"),
                nonce: 1,
                keyVersion: 1,
                actionType: keccak256("action"),
                payloadHash: keccak256("payload")
            });

        (,, bool signOk) =
            harness.signStatefulAction(signingKey, publicKey, context);
        assertEq(
            signOk, false, "malformed public key commitment must be rejected"
        );
    }
}
