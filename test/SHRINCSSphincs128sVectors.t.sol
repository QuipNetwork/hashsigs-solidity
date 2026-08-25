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
// wrapped in try/catch and a revert treated as a rejection.
contract Stateless128sHarness {
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

// SHRINCSSphincs128sVectors: the vector-backed 128s stateless coverage
// deferred to the Solidity side by the T6 Rust regeneration (the Rust 128s
// stateless keygen/verify is compute-infeasible in-process, so the Rust
// goldens are generator output not round-trip-verified). This suite is the
// authoritative 128s cross-check: it feeds the Rust-anchored 128s stateless
// vector (FORS-C + single-layer hypertree, Trunc16 node values) through the
// production Solidity verifier. It runs only under the 128s profiles; the
// active profile's constants and its JSON are selected together.
contract SHRINCSSphincs128sVectorsTest is Test {
    Stateless128sHarness internal stateless;
    string internal vectors;

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
        // Skip under any non-128s profile: this suite is bound to the 128s
        // vector JSON and constants.
        if (SHRINCSParams.HASH_LEN == 32) return;
        stateless = new Stateless128sHarness();
        vectors = vm.readFile(vectorPath());
    }

    function vectorPath() internal pure returns (string memory) {
        // Two axes select the file, and BOTH are load-bearing. q18 and q20
        // share every stateless field except the commitment tag, so the
        // stateless-signature budget picks the params. The scheme hash suite
        // picks the twin: a sha2 profile verifies SHA-256 scheme hashes, so
        // the keccak vectors would fail on it, and selecting on the budget
        // alone would silently hand a sha2 build its keccak twin's file.
        bool isSha2 = HashSuite.HASH_SUITE_ID == 2;
        if (SHRINCSParams.STATELESS_SIGNATURE_LIMIT == 262_144) {
            return isSha2
                ? "test/test_vectors/shrincs_sphincs_128s_q18_sha2.json"
                : "test/test_vectors/shrincs_sphincs_128s_q18_keccak.json";
        }
        return isSha2
            ? "test/test_vectors/shrincs_sphincs_128s_q20_sha2.json"
            : "test/test_vectors/shrincs_sphincs_128s_q20_keccak.json";
    }

    function testStateless128sValidVectorVerifies() public {
        vm.skip(SHRINCSParams.HASH_LEN == 32);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertTrue(
            stateless.verifyUnsafeRaw(
                commitmentWord(publicKey), publicKey, message, signature
            ),
            "128s stateless Rust vector must verify through the verifier"
        );
    }

    // Records the 128s stateless verify gas (sanity bound ~408k; T6
    // intentionally changes calldata/preimages, so this is an actual, not an
    // equality anchor). Decoding is excluded from the measured window.
    function testMeasureStateless128sVerifyGas() public {
        vm.skip(SHRINCSParams.HASH_LEN == 32);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 commitment = commitmentWord(publicKey);
        uint256 before = gasleft();
        bool ok = stateless.verifyUnsafeRaw(
            commitment, publicKey, message, signature
        );
        uint256 used = before - gasleft();
        assertTrue(ok, "128s stateless vector must verify");
        emit log_named_uint("stateless.128s_verify_gas", used);
    }

    function testStateless128sRejectsWrongCommitment() public {
        vm.skip(SHRINCSParams.HASH_LEN == 32);
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
            "128s stateless wrong commitment must be rejected"
        );
    }

    function testStateless128sRejectsTamperedForsLeaf() public {
        vm.skip(SHRINCSParams.HASH_LEN == 32);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].secretLeaf =
            abi.encodePacked(keccak256("128s tampered fors leaf"));
        assertEq(
            statelessRejected(
                commitmentWord(publicKey), publicKey, message, signature
            ),
            true,
            "128s stateless tampered FORS leaf must not wrong-accept"
        );
    }

    function testStateless128sRejectsTamperedHypertreeAuth() public {
        vm.skip(SHRINCSParams.HASH_LEN == 32);
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath[0] =
            abi.encodePacked(keccak256("128s tampered hypertree auth"));
        assertEq(
            statelessRejected(
                commitmentWord(publicKey), publicKey, message, signature
            ),
            true,
            "128s stateless tampered hypertree auth must not wrong-accept"
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
