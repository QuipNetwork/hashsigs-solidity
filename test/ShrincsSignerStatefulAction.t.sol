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
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";

contract ShrincsStatefulActionSignerHarness {
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        external
        pure
        returns (
            ShrincsTypes.SigningKey memory,
            ShrincsTypes.PublicKey memory,
            bool
        )
    {
        return ShrincsTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function signStatefulAction(
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.ActionContext memory context
    )
        external
        pure
        returns (
            ShrincsTypes.SigningKey memory,
            ShrincsTypes.StatefulSignature memory,
            bool
        )
    {
        return ShrincsTestSigner.signStatefulAction(
            signingKey, publicKey, context
        );
    }

    function verify(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext calldata context,
        ShrincsTypes.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStateful(
            expectedPublicKeyCommitment, publicKey, context, signature
        );
    }
}

contract ShrincsSignerStatefulActionTest is Test {
    ShrincsStatefulActionSignerHarness internal harness;

    function setUp() public {
        harness = new ShrincsStatefulActionSignerHarness();
    }

    function testStatefulActionSignerProducesCanonicalVerifyingSignature()
        public
        view
    {
        (
            ShrincsTypes.SigningKey memory signingKey,
            ShrincsTypes.PublicKey memory publicKey,
            bool keygenOk
        ) = harness.keygen(bytes("solidity stateful action signer seed"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        // forgefmt: disable-next-line
        ShrincsTypes.ActionContext memory context =
            ShrincsTypes.ActionContext({
                domainSeparator: keccak256("domain"),
                nonce: 7,
                keyVersion: 3,
                actionType: keccak256("transfer"),
                payloadHash: keccak256("payload")
            });

        (
            ShrincsTypes.SigningKey memory nextSigningKey,
            ShrincsTypes.StatefulSignature memory signature,
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
            ShrincsTypes.SigningKey memory signingKey,
            ShrincsTypes.PublicKey memory publicKey,
            bool keygenOk
        ) = harness.keygen(bytes("stateful malformed public key seed"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        publicKey.publicKeyCommitment = hex"1234";

        // forgefmt: disable-next-line
        ShrincsTypes.ActionContext memory context =
            ShrincsTypes.ActionContext({
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
