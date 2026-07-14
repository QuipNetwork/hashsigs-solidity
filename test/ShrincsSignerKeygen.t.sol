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
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";

contract ShrincsSignerHarness {
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        external
        pure
        returns (ShrincsTypes.SigningKey memory, ShrincsTypes.PublicKey memory, bool)
    {
        return ShrincsTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }
}

contract ShrincsSignerKeygenTest is Test {
    ShrincsSignerHarness internal harness;
    bytes32 internal constant EXPECTED_STATEFUL_SK_SEED =
        0xd8016f4be6e7a5c7bcd60e9552d8aa678437377d79258c830d9fc77a06aeaccb;
    bytes32 internal constant EXPECTED_STATEFUL_PRF_SEED =
        0x3a49d4cf20bff4e5a9770e379c7f9a6474fd2d5c1c34f204ced26567b7981aa8;
    bytes32 internal constant EXPECTED_STATEFUL_PK_SEED =
        0xa4a372b30187a5bf20d242a6e0a87206cf281bc0fdbbc44c835b3811f800587e;
    bytes32 internal constant EXPECTED_STATEFUL_ROOT =
        0x59255b6f0e6ee44c1957d1d48bd7edfa936b7a8a073a13a2eb973b3ab87860f6;
    bytes32 internal constant EXPECTED_STATELESS_SK_SEED =
        0x307041ea3217779667ec95a7661acbcaa52cdf46a7902cf61726c38301f0a4fe;
    bytes32 internal constant EXPECTED_STATELESS_PRF_SEED =
        0xa49f5e4c7395acc51737c7095f36715ab351afca3b5ace9dce843fa884acb967;
    bytes32 internal constant EXPECTED_PK_SEED = 0x7f71921f640162143dc08fe0dcc827bb0baf83c5cd9a52830447aed753b58d75;
    bytes32 internal constant EXPECTED_HYPERTREE_ROOT =
        0x51ed6195736b8c640399d7127c2073429879f795645b3fdaa7780bce6fd134b2;

    function setUp() public {
        harness = new ShrincsSignerHarness();
    }

    function testKeygenRejectsZeroStatefulBudget() public view {
        (,, bool ok) = harness.keygen(bytes("seed"), 0);
        assertEq(ok, false, "zero budget must fail");
    }

    function testKeygenRejectsExcessiveStatefulBudget() public view {
        (,, bool ok) = harness.keygen(bytes("seed"), 4097);
        assertEq(ok, false, "excessive budget must fail");
    }

    function testKeygenIsDeterministicForSameSeed() public view {
        (ShrincsTypes.SigningKey memory signingKeyA, ShrincsTypes.PublicKey memory publicKeyA, bool okA) =
            harness.keygen(bytes("solidity keygen seed"), 8);
        (ShrincsTypes.SigningKey memory signingKeyB, ShrincsTypes.PublicKey memory publicKeyB, bool okB) =
            harness.keygen(bytes("solidity keygen seed"), 8);

        assertTrue(okA && okB, "keygen must succeed");
        assertEq(signingKeyA.statefulSkSeed, signingKeyB.statefulSkSeed);
        assertEq(signingKeyA.statefulPrfSeed, signingKeyB.statefulPrfSeed);
        assertEq(signingKeyA.statefulPkSeed, signingKeyB.statefulPkSeed);
        assertEq(signingKeyA.statefulRoot, signingKeyB.statefulRoot);
        assertEq(signingKeyA.maxStatefulSignatures, signingKeyB.maxStatefulSignatures);
        assertEq(signingKeyA.nextStatefulLeafIndex, signingKeyB.nextStatefulLeafIndex);
        assertEq(signingKeyA.statelessSkSeed, signingKeyB.statelessSkSeed);
        assertEq(signingKeyA.statelessPrfSeed, signingKeyB.statelessPrfSeed);
        assertEq(signingKeyA.pkSeed, signingKeyB.pkSeed);
        assertEq(signingKeyA.hypertreeRoot, signingKeyB.hypertreeRoot);
        assertEq(keccak256(publicKeyA.pkSeed), keccak256(publicKeyB.pkSeed));
        assertEq(keccak256(publicKeyA.hypertreeRoot), keccak256(publicKeyB.hypertreeRoot));
    }

    function testKeygenBuildsConsistentPublicKeyBundle() public view {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            harness.keygen(bytes("solidity public key seed"), 4);

        assertTrue(ok, "keygen must succeed");
        assertEq(signingKey.nextStatefulLeafIndex, 1, "legacy fixture cursor starts at leaf 1");
        assertEq(publicKey.pkSeed.length, 32);
        assertEq(publicKey.hypertreeRoot.length, 32);

        assertEq(keccak256(publicKey.pkSeed), keccak256(abi.encodePacked(signingKey.pkSeed)));
        assertEq(keccak256(publicKey.hypertreeRoot), keccak256(abi.encodePacked(signingKey.hypertreeRoot)));
    }

    function testKeygenMatchesRustSignerGoldenOutput() public view {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            harness.keygen(bytes("solidity public key seed"), 4);

        assertTrue(ok, "keygen must succeed");
        assertEq(signingKey.statefulSkSeed, EXPECTED_STATEFUL_SK_SEED);
        assertEq(signingKey.statefulPrfSeed, EXPECTED_STATEFUL_PRF_SEED);
        assertEq(signingKey.statefulPkSeed, EXPECTED_STATEFUL_PK_SEED);
        assertEq(signingKey.statefulRoot, EXPECTED_STATEFUL_ROOT);
        assertEq(signingKey.statelessSkSeed, EXPECTED_STATELESS_SK_SEED);
        assertEq(signingKey.statelessPrfSeed, EXPECTED_STATELESS_PRF_SEED);
        assertEq(signingKey.pkSeed, EXPECTED_PK_SEED);
        assertEq(signingKey.hypertreeRoot, EXPECTED_HYPERTREE_ROOT);
        assertEq(keccak256(publicKey.pkSeed), keccak256(abi.encodePacked(EXPECTED_PK_SEED)));
        assertEq(keccak256(publicKey.hypertreeRoot), keccak256(abi.encodePacked(EXPECTED_HYPERTREE_ROOT)));
    }
}
