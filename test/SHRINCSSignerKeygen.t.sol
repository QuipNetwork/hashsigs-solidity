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
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

contract SHRINCSSignerHarness {
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        external
        view
        returns (SHRINCS.SigningKey memory, SHRINCS.PublicKey memory, bool)
    {
        // `view`: the seam-routed signer reaches the production HashSuite,
        // whose sha2 helpers staticcall the 0x02 precompile.
        return SHRINCSTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function decodeStatefulPublicKey(bytes calldata encoded)
        external
        pure
        returns (UXMSS.StatefulPublicKey memory, bool)
    {
        return SHRINCS.decodeStatefulPublicKey(encoded);
    }
}

contract SHRINCSSignerKeygenTest is Test {
    SHRINCSSignerHarness internal harness;
    bytes32 internal constant EXPECTED_STATEFUL_SK_SEED =
        0xd8016f4be6e7a5c7bcd60e9552d8aa678437377d79258c830d9fc77a06aeaccb;
    bytes32 internal constant EXPECTED_STATEFUL_PRF_SEED =
        0x3a49d4cf20bff4e5a9770e379c7f9a6474fd2d5c1c34f204ced26567b7981aa8;
    bytes32 internal constant EXPECTED_STATEFUL_PK_SEED =
        0xa4a372b30187a5bf20d242a6e0a87206cf281bc0fdbbc44c835b3811f800587e;
    bytes32 internal constant EXPECTED_STATELESS_SK_SEED =
        0x307041ea3217779667ec95a7661acbcaa52cdf46a7902cf61726c38301f0a4fe;
    bytes32 internal constant EXPECTED_STATELESS_PRF_SEED =
        0xa49f5e4c7395acc51737c7095f36715ab351afca3b5ace9dce843fa884acb967;
    bytes32 internal constant EXPECTED_PK_SEED =
        0x7f71921f640162143dc08fe0dcc827bb0baf83c5cd9a52830447aed753b58d75;

    // Profile-varying keygen goldens (seed "solidity public key seed",
    // maxStatefulSignatures 4). The seeds above are pure-KDF and identical
    // across all three keccak profiles; these fields change with the F-08
    // stateful chain tag, the profile-bound commitment, and 128s Trunc16
    // (roots high-aligned, zero-padded). Anchored to the Rust signer's T6
    // regeneration. Under 128s the stateful root/public key (q18 and q20
    // share them) come from the feasible stateful subsystem; the 128s
    // stateless hypertree root and commitment are asserted by the
    // vector-backed SHRINCSSphincs128sVectors suite, not recomputed here.
    struct ProfileGoldens {
        bytes32 statefulRoot;
        bytes32 hypertreeRoot;
        bytes statefulPublicKey;
        bytes32 publicKeyCommitment;
    }

    // 256s-keccak.
    bytes32 internal constant G256_STATEFUL_ROOT =
        0x4f26a29da785b7d9c0194e409dff00c4234e3708ad80a5506f40c0bc83d78f4e;
    bytes32 internal constant G256_HYPERTREE_ROOT =
        0x51ed6195736b8c640399d7127c2073429879f795645b3fdaa7780bce6fd134b2;
    bytes32 internal constant G256_COMMITMENT =
        0x38681966d8f8ddcbc3dc966d2cb03feb627182622893a0b9a1580f6440db5654;
    bytes internal constant G256_STATEFUL_PUBLIC_KEY =
    // line-length: allow — one unbreakable test vector literal token
    hex"a4a372b30187a5bf20d242a6e0a87206cf281bc0fdbbc44c835b3811f800587e4f26a29da785b7d9c0194e409dff00c4234e3708ad80a5506f40c0bc83d78f4e00000004";

    // 128s-keccak (q18 and q20 share these; the stateless hypertree root
    // and commitment goldens live in the vector-backed suite instead).
    bytes32 internal constant G128_STATEFUL_ROOT =
        0xb745e962fce45192d99c9f841789953700000000000000000000000000000000;
    bytes internal constant G128_STATEFUL_PUBLIC_KEY =
    // line-length: allow — one unbreakable test vector literal token
    hex"a4a372b30187a5bf20d242a6e0a87206cf281bc0fdbbc44c835b3811f800587eb745e962fce45192d99c9f84178995370000000000000000000000000000000000000004";

    function setUp() public {
        harness = new SHRINCSSignerHarness();
    }

    // expectedProfileGoldens: return the active profile's keygen goldens.
    // 256s vs 128s split on HASH_LEN. Under 128s the stateless-derived
    // fields (hypertreeRoot, publicKeyCommitment) stay zero: only the
    // HASH_LEN == 32 assertions read them; the 128s canonical values are
    // pinned by the vector-backed SHRINCSSphincs128sVectors suite.
    function expectedProfileGoldens()
        internal
        pure
        returns (ProfileGoldens memory g)
    {
        if (SHRINCSParams.HASH_LEN == 32) {
            g.statefulRoot = G256_STATEFUL_ROOT;
            g.hypertreeRoot = G256_HYPERTREE_ROOT;
            g.statefulPublicKey = G256_STATEFUL_PUBLIC_KEY;
            g.publicKeyCommitment = G256_COMMITMENT;
            return g;
        }
        g.statefulRoot = G128_STATEFUL_ROOT;
        g.statefulPublicKey = G128_STATEFUL_PUBLIC_KEY;
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
        (
            SHRINCS.SigningKey memory signingKeyA,
            SHRINCS.PublicKey memory publicKeyA,
            bool okA
        ) = harness.keygen(bytes("solidity keygen seed"), 8);
        (
            SHRINCS.SigningKey memory signingKeyB,
            SHRINCS.PublicKey memory publicKeyB,
            bool okB
        ) = harness.keygen(bytes("solidity keygen seed"), 8);

        assertTrue(okA && okB, "keygen must succeed");
        assertEq(signingKeyA.statefulSkSeed, signingKeyB.statefulSkSeed);
        assertEq(signingKeyA.statefulPrfSeed, signingKeyB.statefulPrfSeed);
        assertEq(signingKeyA.statefulPkSeed, signingKeyB.statefulPkSeed);
        assertEq(signingKeyA.statefulRoot, signingKeyB.statefulRoot);
        assertEq(
            signingKeyA.maxStatefulSignatures,
            signingKeyB.maxStatefulSignatures
        );
        assertEq(
            signingKeyA.nextStatefulLeafIndex,
            signingKeyB.nextStatefulLeafIndex
        );
        assertEq(signingKeyA.statelessSkSeed, signingKeyB.statelessSkSeed);
        assertEq(signingKeyA.statelessPrfSeed, signingKeyB.statelessPrfSeed);
        assertEq(signingKeyA.pkSeed, signingKeyB.pkSeed);
        assertEq(signingKeyA.hypertreeRoot, signingKeyB.hypertreeRoot);
        assertEq(
            keccak256(publicKeyA.statefulPublicKey),
            keccak256(publicKeyB.statefulPublicKey)
        );
        assertEq(
            keccak256(publicKeyA.publicKeyCommitment),
            keccak256(publicKeyB.publicKeyCommitment)
        );
        assertEq(keccak256(publicKeyA.pkSeed), keccak256(publicKeyB.pkSeed));
        assertEq(
            keccak256(publicKeyA.hypertreeRoot),
            keccak256(publicKeyB.hypertreeRoot)
        );
    }

    function testKeygenBuildsConsistentPublicKeyBundle() public view {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = harness.keygen(bytes("solidity public key seed"), 4);

        assertTrue(ok, "keygen must succeed");
        assertEq(
            signingKey.nextStatefulLeafIndex,
            1,
            "stateful path starts at leaf 1"
        );
        assertEq(
            publicKey.statefulPublicKey.length,
            SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        );
        assertEq(publicKey.publicKeyCommitment.length, 32);
        assertEq(publicKey.pkSeed.length, 32);
        assertEq(publicKey.hypertreeRoot.length, 32);

        // line-length: allow — fmt canonical call head exceeds cap
        bytes32 expectedCommitment = SHRINCS.publicKeyCommitmentFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );
        assertEq(
            keccak256(publicKey.publicKeyCommitment),
            keccak256(abi.encodePacked(expectedCommitment))
        );

        (UXMSS.StatefulPublicKey memory decodedStateful, bool decodedOk) =
            harness.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        assertTrue(decodedOk, "stateful public key must decode");
        assertEq(decodedStateful.pkSeed, signingKey.statefulPkSeed);
        assertEq(decodedStateful.root, signingKey.statefulRoot);
        assertEq(
            decodedStateful.maxSignatures, signingKey.maxStatefulSignatures
        );
        assertEq(
            keccak256(publicKey.pkSeed),
            keccak256(abi.encodePacked(signingKey.pkSeed))
        );
        assertEq(
            keccak256(publicKey.hypertreeRoot),
            keccak256(abi.encodePacked(signingKey.hypertreeRoot))
        );
    }

    function testKeygenMatchesRustSignerGoldenOutput() public view {
        // Anchored to the Rust signer's T6 regeneration. The KDF seeds and
        // the stateful goldens (statefulRoot, statefulPublicKey) are
        // Solidity-computable and cross-checked under every keccak profile.
        //
        // The stateless hypertree root — and the public-key commitment that
        // binds it — require the full stateless hypertree keygen, which is
        // computationally infeasible in the Solidity test signer at 128s
        // (2^18 WOTS leaves; the signer intentionally carries the 256s
        // hypertree geometry, so its 128s hypertree root is non-canonical).
        // Those two fields are therefore asserted only at 256s here; the
        // authoritative 128s stateless coverage is the vector-backed
        // SHRINCSSphincs128sVectors suite, which verifies the Rust-anchored
        // 128s stateless signature (and its commitment) through the
        // production verifier.
        ProfileGoldens memory g = expectedProfileGoldens();
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = harness.keygen(bytes("solidity public key seed"), 4);

        assertTrue(ok, "keygen must succeed");
        assertEq(signingKey.statefulSkSeed, EXPECTED_STATEFUL_SK_SEED);
        assertEq(signingKey.statefulPrfSeed, EXPECTED_STATEFUL_PRF_SEED);
        assertEq(signingKey.statefulPkSeed, EXPECTED_STATEFUL_PK_SEED);
        assertEq(signingKey.statefulRoot, g.statefulRoot);
        assertEq(signingKey.statelessSkSeed, EXPECTED_STATELESS_SK_SEED);
        assertEq(signingKey.statelessPrfSeed, EXPECTED_STATELESS_PRF_SEED);
        assertEq(signingKey.pkSeed, EXPECTED_PK_SEED);
        assertEq(
            keccak256(publicKey.statefulPublicKey),
            keccak256(g.statefulPublicKey)
        );
        assertEq(
            keccak256(publicKey.pkSeed),
            keccak256(abi.encodePacked(EXPECTED_PK_SEED))
        );
        if (SHRINCSParams.HASH_LEN == 32) {
            assertEq(signingKey.hypertreeRoot, g.hypertreeRoot);
            assertEq(
                keccak256(publicKey.publicKeyCommitment),
                keccak256(abi.encodePacked(g.publicKeyCommitment))
            );
            assertEq(
                keccak256(publicKey.hypertreeRoot),
                keccak256(abi.encodePacked(g.hypertreeRoot))
            );
        }
    }
}
