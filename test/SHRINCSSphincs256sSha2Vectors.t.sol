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
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";

// Stateless verify core exposed as an external call so tamper cases can be
// wrapped in try/catch and a revert treated as a rejection. Declared `view`
// because the sha2 suite hashes through the 0x02 precompile via staticcall.
contract Stateless256sSha2Harness {
    function verifyUnsafeRaw(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedCommitment, publicKey, message, signature
        );
    }
}

/// @title SHRINCSSphincs256sSha2VectorsTest
/// @notice The vector-backed end-to-end cross-check for the SHA-256 suite. It
/// feeds the Rust-anchored 256s-sha2 stateless vector (identical scheme
/// parameters to 256s keccak, SHA-256 scheme hashes) through the production
/// Solidity verifier, closing the loop the per-helper KATs (HashSuiteKat)
/// leave open. Runs only under the 256s-sha2 profile; HASH_SUITE_ID selects
/// the suite and the JSON together, and the keccak profiles compile-skip this
/// suite (foundry.toml).
contract SHRINCSSphincs256sSha2VectorsTest is Test {
    Stateless256sSha2Harness internal stateless;
    string internal vectors;

    // 256s-sha2 keygen goldens (seed "solidity public key seed", max 4),
    // verbatim from the reviewed Rust round. The SHRINCSSignerKeygen suite
    // cannot reproduce these in-Solidity: its test signer hardcodes keccak256
    // rather than routing through the seam, so under sha2 it would derive a
    // keccak key. They are instead anchored here through the production
    // commitment builder (testKeygenGoldenCommitmentThroughBuilder), which
    // pins the one EVM-domain value and proves the commitment stays keccak
    // over the sha2-qualified profile name.
    bytes32 internal constant GOLD_STATEFUL_PK_SEED =
        0xf494b6c697b228cdd907b2a3715b593add7c70aab70db1665420e18a857a4896;
    bytes32 internal constant GOLD_STATEFUL_ROOT =
        0x987bbbb50688c43f8cb2f721f514c505e6b5628001b30b3ac1bfd70678d47ad8;
    bytes32 internal constant GOLD_PK_SEED =
        0x6fb692d48a54a181431c14c7835f52ac92f430bde760f417abecce0bd006f369;
    bytes32 internal constant GOLD_HYPERTREE_ROOT =
        0x8f1d4397a513eee3323f8a5945b4e4a1ec4ebcf416e772f60ea8009957a80aac;
    bytes32 internal constant GOLD_PUBLIC_KEY_COMMITMENT =
        0x89d7d495077a5966edcc66b91d7a93fb9e2691dc6aa5d2be3cef999f16d95425;
    bytes internal constant GOLD_STATEFUL_PUBLIC_KEY =
    // line-length: allow — one unbreakable test vector literal token
    hex"f494b6c697b228cdd907b2a3715b593add7c70aab70db1665420e18a857a4896987bbbb50688c43f8cb2f721f514c505e6b5628001b30b3ac1bfd70678d47ad800000004";

    struct LegacyPublicKey {
        bytes statefulPublicKey;
        bytes pkSeed;
        bytes hypertreeRoot;
    }

    struct LegacyForsEntry {
        bytes secretLeaf;
        bytes[] authPath;
    }

    struct LegacyForsSignature {
        bytes randomizer;
        uint32 counter;
        LegacyForsEntry[] entries;
    }

    struct LegacyWotsCSignature {
        bytes randomizer;
        uint32 counter;
        bytes[] chains;
    }

    struct LegacyHypertreeLayerSignature {
        bytes wotsCPkHash;
        LegacyWotsCSignature wotsCSignature;
        bytes[] authPath;
    }

    struct LegacyStatelessSignature {
        LegacyForsSignature fors;
        LegacyHypertreeLayerSignature[] hypertree;
    }

    function setUp() public {
        // Skip under any non-sha2 profile: this suite is bound to the
        // 256s-sha2 vector JSON and the SHA-256 hash suite.
        if (HashSuite.HASH_SUITE_ID != 2) return;
        stateless = new Stateless256sSha2Harness();
        vectors = vm.readFile(vectorPath());
    }

    function vectorPath() internal pure returns (string memory) {
        return "test/test_vectors/shrincs_sphincs_256s_sha2.json";
    }

    function testStateless256sSha2ValidVectorVerifies() public {
        vm.skip(HashSuite.HASH_SUITE_ID != 2);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertTrue(
            stateless.verifyUnsafeRaw(
                commitmentWord(publicKey), publicKey, message, signature
            ),
            "256s-sha2 stateless Rust vector must verify through verifier"
        );
    }

    // Records the 256s-sha2 stateless verify gas (an actual, not an equality
    // anchor: sha2 costs more per hash than keccak). Decoding is excluded
    // from the measured window.
    function testMeasureStateless256sSha2VerifyGas() public {
        vm.skip(HashSuite.HASH_SUITE_ID != 2);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 commitment = commitmentWord(publicKey);
        uint256 startGas = gasleft();
        bool ok = stateless.verifyUnsafeRaw(
            commitment, publicKey, message, signature
        );
        uint256 used = startGas - gasleft();
        assertTrue(ok, "256s-sha2 stateless vector must verify");
        emit log_named_uint("stateless.256s_sha2_verify_gas", used);
    }

    function testStateless256sSha2RejectsWrongCommitment() public {
        vm.skip(HashSuite.HASH_SUITE_ID != 2);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertEq(
            stateless.verifyUnsafeRaw(
                bytes32(uint256(1)), publicKey, message, signature
            ),
            false,
            "256s-sha2 stateless wrong commitment must be rejected"
        );
    }

    function testStateless256sSha2RejectsTamperedForsLeaf() public {
        vm.skip(HashSuite.HASH_SUITE_ID != 2);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].secretLeaf =
            abi.encodePacked(keccak256("256s-sha2 tampered fors leaf"));
        assertEq(
            statelessRejected(
                commitmentWord(publicKey), publicKey, message, signature
            ),
            true,
            "256s-sha2 stateless tampered FORS leaf must not wrong-accept"
        );
    }

    function testStateless256sSha2RejectsTamperedHypertreeAuth() public {
        vm.skip(HashSuite.HASH_SUITE_ID != 2);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath[0] =
            abi.encodePacked(keccak256("256s-sha2 tampered hypertree auth"));
        assertEq(
            statelessRejected(
                commitmentWord(publicKey), publicKey, message, signature
            ),
            true,
            "256s-sha2 stateless tampered hypertree auth must not accept"
        );
    }

    // Anchors the reviewed 256s-sha2 keygen goldens through the PRODUCTION
    // commitment builder under the sha2 profile (PROFILE_NAME
    // "shrincs-256s-sha2"): the golden commitment must be exactly the keccak
    // bundle hash over the golden public key. Also pins the golden stateful
    // public key's structure (pkSeed || root || maxSignatures). This is the
    // achievable anchor for a golden key the keccak test signer cannot
    // reproduce; the vector cases above cover a second, distinct key.
    function testKeygenGoldenCommitmentThroughBuilder() public {
        vm.skip(HashSuite.HASH_SUITE_ID != 2);
        assertEq(
            GOLD_STATEFUL_PUBLIC_KEY,
            abi.encodePacked(
                GOLD_STATEFUL_PK_SEED, GOLD_STATEFUL_ROOT, uint32(4)
            ),
            "golden stateful pubkey = pkSeed || root || maxSignatures"
        );
        bytes32 built = SHRINCS.publicKeyCommitmentFromParts(
            GOLD_STATEFUL_PUBLIC_KEY,
            abi.encodePacked(GOLD_PK_SEED),
            abi.encodePacked(GOLD_HYPERTREE_ROOT)
        );
        assertEq(
            built,
            GOLD_PUBLIC_KEY_COMMITMENT,
            "golden commitment must match production keccak bundle hash"
        );
    }

    function statelessRejected(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey memory publicKey,
        bytes memory message,
        SPHINCSPlusC.Signature memory signature
    ) internal view returns (bool) {
        try stateless.verifyUnsafeRaw(
            expectedCommitment, publicKey, message, signature
        ) returns (
            bool ok
        ) {
            return !ok;
        } catch {
            return true;
        }
    }

    function commitmentWord(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32)
    {
        // EVM-domain bundle commitment: keccak256 under every suite (the
        // scheme hash swaps to SHA-256, the commitment does not). Binds the
        // sha2-qualified profile name via SHRINCSParams.PROFILE_NAME.
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    function decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            LegacyPublicKey memory legacyPublicKey,
            bytes memory legacyMessage,
            LegacyStatelessSignature memory legacySignature
        ) = abi.decode(
            args, (LegacyPublicKey, bytes, LegacyStatelessSignature)
        );

        publicKey = SHRINCS.PublicKey({
            statefulPublicKey: legacyPublicKey.statefulPublicKey,
            publicKeyCommitment: vm.parseJsonBytes(
                vectors,
                string.concat(
                    trimCalldataSuffix(vectorKey),
                    ".publicKey.publicKeyCommitment"
                )
            ),
            pkSeed: legacyPublicKey.pkSeed,
            hypertreeRoot: legacyPublicKey.hypertreeRoot
        });

        message = legacyMessage;
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    // line-length: allow — fmt canonical header exceeds cap
    function convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (SPHINCSPlusC.Signature memory signature)
    {
        FORSMinusC.ForsEntry[] memory entries =
            new FORSMinusC.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = FORSMinusC.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf,
                authPath: legacy.fors.entries[i].authPath
            });
        }

        // forgefmt: disable-next-line
        Hypertree.HypertreeLayerSignature[] memory layers =
            new Hypertree.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = Hypertree.HypertreeLayerSignature({
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: WOTSPlusC.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature
                    .randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = SPHINCSPlusC.Signature({
            fors: FORSMinusC.ForsSignature({
                randomizer: legacy.fors.randomizer,
                counter: legacy.fors.counter,
                entries: entries
            }),
            hypertree: layers
        });
    }

    function vectorArgs(string memory vectorKey)
        internal
        returns (bytes memory)
    {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
    }

    function stripSelector(bytes memory input)
        internal
        pure
        returns (bytes memory output)
    {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }

    function trimCalldataSuffix(string memory path)
        internal
        pure
        returns (string memory trimmed)
    {
        bytes memory source = bytes(path);
        bytes memory suffix = bytes(".calldata");
        require(source.length >= suffix.length, "path too short");
        uint256 trimmedLength = source.length - suffix.length;
        bytes memory out = new bytes(trimmedLength);
        for (uint256 i = 0; i < trimmedLength; ++i) {
            out[i] = source[i];
        }
        trimmed = string(out);
    }
}
