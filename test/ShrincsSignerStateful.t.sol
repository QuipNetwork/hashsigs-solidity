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
import {UXMSS} from "../contracts/UXMSS.sol";
import {ShrincsParams} from "shrincs-profile/ShrincsParams.sol";

contract ShrincsStatefulSignerHarness {
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        external
        pure
        returns (SHRINCS.SigningKey memory, SHRINCS.PublicKey memory, bool)
    {
        return ShrincsTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function signStatefulRaw(
        SHRINCS.SigningKey memory signingKey,
        bytes memory message
    )
        external
        pure
        returns (
            SHRINCS.SigningKey memory,
            UXMSS.StatefulSignature memory,
            bool
        )
    {
        return ShrincsTestSigner.signStatefulRaw(signingKey, message);
    }

    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        UXMSS.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatefulUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }
}

contract ShrincsSignerStatefulTest is Test {
    ShrincsStatefulSignerHarness internal harness;

    function setUp() public {
        harness = new ShrincsStatefulSignerHarness();
    }

    function testStatefulSignerProducesVerifyingSignatureAndAdvancesLeaf()
        public
        view
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = harness.keygen(bytes("solidity stateful signer seed"), 4);
        assertTrue(keygenOk, "keygen must succeed");

        bytes memory message =
            abi.encodePacked(keccak256("solidity stateful signer message"));
        (
            SHRINCS.SigningKey memory nextSigningKey,
            UXMSS.StatefulSignature memory signature,
            bool signOk
        ) = harness.signStatefulRaw(signingKey, message);

        assertTrue(signOk, "signing must succeed");
        assertEq(
            nextSigningKey.nextStatefulLeafIndex,
            2,
            "stateful leaf must advance"
        );
        assertEq(
            signature.chains.length,
            ShrincsParams.WOTS_CHAINS_STATEFUL,
            "all stateful chains must be present"
        );
        assertEq(
            signature.authPath.length,
            1,
            "leaf one must have a one-node auth path"
        );

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 expectedPublicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }
        assertTrue(
            harness.verifyUnsafeRaw(
                expectedPublicKeyCommitment, publicKey, message, signature
            ),
            "signer output must verify"
        );
    }

    function testStatefulSignerRejectsExhaustedKey() public view {
        (SHRINCS.SigningKey memory signingKey,, bool keygenOk) =
            harness.keygen(bytes("stateful exhaustion seed"), 1);
        assertTrue(keygenOk, "keygen must succeed");

        bytes memory message = abi.encodePacked(
            keccak256("stateful signer exhaustion message")
        );
        (SHRINCS.SigningKey memory usedKey,, bool firstOk) =
            harness.signStatefulRaw(signingKey, message);
        assertTrue(firstOk, "first signature must succeed");

        (,, bool secondOk) = harness.signStatefulRaw(usedKey, message);
        assertEq(secondOk, false, "exhausted key must stop signing");
    }
}
