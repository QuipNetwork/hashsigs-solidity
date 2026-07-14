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
    function keygen(bytes memory seedMaterial)
        external
        pure
        returns (ShrincsTypes.SigningKey memory, ShrincsTypes.PublicKey memory, bool)
    {
        return ShrincsTestSigner.keygen(seedMaterial);
    }

    function compactSingleLaneKeygen(bytes memory seedMaterial, uint8 q)
        external
        pure
        returns (bytes32 skSeed, bytes32 pkSeed, bytes32 pkRoot, bool ok)
    {
        return ShrincsTestSigner.compactSingleLaneKeygen(seedMaterial, q);
    }
}

contract ShrincsSignerKeygenTest is Test {
    ShrincsSignerHarness internal harness;
    bytes32 internal constant EXPECTED_STATELESS_SK_SEED =
        0x307041ea3217779667ec95a7661acbcaa52cdf46a7902cf61726c38301f0a4fe;
    bytes32 internal constant EXPECTED_STATELESS_PRF_SEED =
        0xa49f5e4c7395acc51737c7095f36715ab351afca3b5ace9dce843fa884acb967;
    bytes32 internal constant EXPECTED_PK_SEED = 0x7f71921f640162143dc08fe0dcc827bb0baf83c5cd9a52830447aed753b58d75;
    bytes32 internal constant EXPECTED_HYPERTREE_ROOT =
        0x51ed6195736b8c640399d7127c2073429879f795645b3fdaa7780bce6fd134b2;
    bytes32 internal constant EXPECTED_COMPACT_SK_SEED =
        0xe47b49bdf6bc7080c4d227b34a4c73bd2254d266416c9ae1e5b6a390f2dbf840;
    bytes32 internal constant EXPECTED_COMPACT_PK_SEED =
        0xaf6b725bd57277bab58cf43159cdb4f62f069d03bd97772edca55800c157b564;
    bytes32 internal constant EXPECTED_COMPACT_PK_ROOT =
        0x2b35541081dcb889a799f10c73718fa568ba4785d0c4e053ab793d0ecfd53d1c;

    function setUp() public {
        harness = new ShrincsSignerHarness();
    }

    function testKeygenIsDeterministicForSameSeed() public view {
        (ShrincsTypes.SigningKey memory signingKeyA, ShrincsTypes.PublicKey memory publicKeyA, bool okA) =
            harness.keygen(bytes("solidity keygen seed"));
        (ShrincsTypes.SigningKey memory signingKeyB, ShrincsTypes.PublicKey memory publicKeyB, bool okB) =
            harness.keygen(bytes("solidity keygen seed"));

        assertTrue(okA && okB, "keygen must succeed");
        assertEq(signingKeyA.statelessSkSeed, signingKeyB.statelessSkSeed);
        assertEq(signingKeyA.statelessPrfSeed, signingKeyB.statelessPrfSeed);
        assertEq(signingKeyA.pkSeed, signingKeyB.pkSeed);
        assertEq(signingKeyA.hypertreeRoot, signingKeyB.hypertreeRoot);
        assertEq(keccak256(publicKeyA.pkSeed), keccak256(publicKeyB.pkSeed));
        assertEq(keccak256(publicKeyA.hypertreeRoot), keccak256(publicKeyB.hypertreeRoot));
    }

    function testKeygenBuildsConsistentPublicKeyBundle() public view {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            harness.keygen(bytes("solidity public key seed"));

        assertTrue(ok, "keygen must succeed");
        assertEq(publicKey.pkSeed.length, 32);
        assertEq(publicKey.hypertreeRoot.length, 32);

        assertEq(keccak256(publicKey.pkSeed), keccak256(abi.encodePacked(signingKey.pkSeed)));
        assertEq(keccak256(publicKey.hypertreeRoot), keccak256(abi.encodePacked(signingKey.hypertreeRoot)));
    }

    function testKeygenMatchesRustSignerGoldenOutput() public view {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            harness.keygen(bytes("solidity public key seed"));

        assertTrue(ok, "keygen must succeed");
        assertEq(signingKey.statelessSkSeed, EXPECTED_STATELESS_SK_SEED);
        assertEq(signingKey.statelessPrfSeed, EXPECTED_STATELESS_PRF_SEED);
        assertEq(signingKey.pkSeed, EXPECTED_PK_SEED);
        assertEq(signingKey.hypertreeRoot, EXPECTED_HYPERTREE_ROOT);
        assertEq(keccak256(publicKey.pkSeed), keccak256(abi.encodePacked(EXPECTED_PK_SEED)));
        assertEq(keccak256(publicKey.hypertreeRoot), keccak256(abi.encodePacked(EXPECTED_HYPERTREE_ROOT)));
    }

    function testCompactKeygenMatchesRustSignerGoldenOutput() public view {
        (bytes32 skSeed, bytes32 pkSeed, bytes32 pkRoot, bool ok) =
            harness.compactSingleLaneKeygen(bytes("solidity public key seed"), 0);

        assertTrue(ok, "compact keygen must succeed");
        assertEq(skSeed, EXPECTED_COMPACT_SK_SEED);
        assertEq(pkSeed, EXPECTED_COMPACT_PK_SEED);
        assertEq(pkRoot, EXPECTED_COMPACT_PK_ROOT);
    }
}
