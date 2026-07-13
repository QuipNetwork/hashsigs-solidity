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
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

// Profile-independent SHRINCS envelope codec coverage, split out of
// SHRINCSEnvelope.t.sol (P4). These tests exercise only the SHRINCS
// encoder/decoder library and SPHINCSPlusC.toMessage over synthetic key
// bundles and signatures (no vector reads, no concrete verifier), so they
// compile and run under every build profile (the chain count is taken from
// SHRINCSParams.WOTS_CHAINS_STATEFUL). The 256s-vector-bound ERC-7913
// integration test stays in SHRINCSEnvelope.t.sol with its keccak skips.

// Exposes the SHRINCS envelope encoders/decoders through external functions
// so tests exercise the real calldata-facing decode paths.
contract SHRINCSEnvelopeHarness {
    function decodePublicKeyCommitment(bytes calldata key)
        external
        pure
        returns (bytes32 commitment, bool ok)
    {
        return SHRINCS.decodePublicKeyCommitment(key);
    }

    function decodeStatefulEnvelope(bytes calldata envelope)
        external
        pure
        returns (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature,
            bool ok
        )
    {
        return SHRINCS.decodeStatefulEnvelope(envelope);
    }

    function encodeStatefulEnvelope(
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.Signature memory signature
    ) external pure returns (bytes memory envelope) {
        return SHRINCS.encodeStatefulEnvelope(publicKey, signature);
    }

    function toMessage(bytes32 hash)
        external
        pure
        returns (bytes memory message)
    {
        return SPHINCSPlusC.toMessage(hash);
    }
}

contract SHRINCSEnvelopeCodecTest is Test {
    SHRINCSEnvelopeHarness internal harness;

    function setUp() public {
        harness = new SHRINCSEnvelopeHarness();
    }

    // buildSamplePublicKey: Construct a fully populated synthetic key bundle
    // for round-trip checks.
    function buildSamplePublicKey()
        internal
        pure
        returns (SHRINCS.PublicKey memory publicKey)
    {
        publicKey = SHRINCS.PublicKey({
            statefulPublicKey: abi.encodePacked(
                keccak256("codec stateful pk seed"),
                keccak256("codec stateful root"),
                uint32(7)
            ),
            publicKeyCommitment: abi.encodePacked(
                keccak256("codec bundle commitment")
            ),
            pkSeed: abi.encodePacked(keccak256("codec pk seed")),
            hypertreeRoot: abi.encodePacked(
                keccak256("codec hypertree root")
            )
        });
    }

    // buildSampleSignature: Construct a fully populated synthetic stateful
    // signature so every field — randomizer, counter, chains, authPath —
    // is exercised by the round-trip.
    function buildSampleSignature()
        internal
        pure
        returns (SHRINCS.Signature memory signature)
    {
        signature.randomizer = keccak256("codec stateful randomizer");
        signature.counter = 42;
        signature.chains = new bytes32[](SHRINCSParams.WOTS_CHAINS_STATEFUL);
        for (uint256 i = 0; i < signature.chains.length; i++) {
            signature.chains[i] =
                keccak256(abi.encode("codec stateful chain", i));
        }
        signature.authPath = new bytes32[](2);
        for (uint256 i = 0; i < signature.authPath.length; i++) {
            signature.authPath[i] =
                keccak256(abi.encode("codec stateful auth", i));
        }
    }

    function testDecodeKeyAcceptsExactly32Bytes() public view {
        bytes32 expected = keccak256("codec key word");
        (bytes32 commitment, bool ok) =
            harness.decodePublicKeyCommitment(abi.encodePacked(expected));
        assertTrue(ok, "32-byte key must decode");
        assertEq(
            commitment,
            expected,
            "decoded commitment must match the key word"
        );
    }

    function testDecodeKeyRejectsWrongLengthsWithoutReverting() public view {
        uint256[5] memory badLengths = [uint256(0), 20, 31, 33, 64];
        for (uint256 i = 0; i < badLengths.length; i++) {
            bytes memory key = new bytes(badLengths[i]);
            for (uint256 j = 0; j < key.length; j++) {
                key[j] = 0xab;
            }
            (bytes32 commitment, bool ok) =
                harness.decodePublicKeyCommitment(key);
            assertFalse(ok, "wrong-length key must not decode");
            assertEq(
                commitment,
                bytes32(0),
                "rejected key must return a zero commitment"
            );
        }
    }

    function testStatefulEnvelopeRoundTripPreservesEveryField() public view {
        SHRINCS.PublicKey memory publicKey = buildSamplePublicKey();
        SHRINCS.Signature memory signature = buildSampleSignature();

        bytes memory envelope =
            harness.encodeStatefulEnvelope(publicKey, signature);
        (
            SHRINCS.PublicKey memory decodedKey,
            SHRINCS.Signature memory decodedSig,
            bool ok
        ) = harness.decodeStatefulEnvelope(envelope);
        assertTrue(ok, "canonical envelope must decode");

        // The envelope layout is exactly abi.encode(PublicKey,
        // StatefulSignature).
        assertEq(
            envelope,
            abi.encode(publicKey, signature),
            "envelope must be plain abi.encode of both structs"
        );

        assertEq(
            decodedKey.statefulPublicKey,
            publicKey.statefulPublicKey,
            "statefulPublicKey"
        );
        assertEq(
            decodedKey.publicKeyCommitment,
            publicKey.publicKeyCommitment,
            "publicKeyCommitment"
        );
        assertEq(decodedKey.pkSeed, publicKey.pkSeed, "pkSeed");
        assertEq(
            decodedKey.hypertreeRoot,
            publicKey.hypertreeRoot,
            "hypertreeRoot"
        );

        assertEq(decodedSig.randomizer, signature.randomizer, "randomizer");
        assertEq(decodedSig.counter, signature.counter, "counter");
        assertEq(
            decodedSig.chains.length, signature.chains.length, "chain count"
        );
        for (uint256 i = 0; i < signature.chains.length; i++) {
            assertEq(
                decodedSig.chains[i], signature.chains[i], "chain value"
            );
        }
        assertEq(
            decodedSig.authPath.length,
            signature.authPath.length,
            "authPath length"
        );
        for (uint256 i = 0; i < signature.authPath.length; i++) {
            assertEq(
                decodedSig.authPath[i],
                signature.authPath[i],
                "authPath node"
            );
        }
    }

    // Revert model: the canonicity walk is gone, so the decoder is plain
    // abi.decode. A dynamic offset pointing out of range reverts inside
    // abi.decode. (Non-canonical framing abi.decode tolerates — trailing or
    // gap bytes, aliased/out-of-order offsets, oversized in-range arrays —
    // decodes to the same value and is accepted; those malleability
    // rejections went away with the walk.)
    function testDecodeStatefulEnvelopeRevertsOnMalformedDynamicOffset()
        public
    {
        bytes memory malformed =
            overwriteSignatureChainsOffset(validEnvelope(), 0x81);
        vm.expectRevert();
        harness.decodeStatefulEnvelope(malformed);
    }

    // A huge claimed auth-path length reads past the buffer and reverts
    // inside abi.decode.
    function testDecodeStatefulEnvelopeRevertsOnHugeAuthPathLength() public {
        bytes memory malformed =
            overwriteSignatureAuthPathLength(validEnvelope(), 10_000);
        vm.expectRevert();
        harness.decodeStatefulEnvelope(malformed);
    }

    function testToMessageIsThePackedHash() public view {
        bytes32 hash = keccak256("codec message hash");
        bytes memory message = harness.toMessage(hash);
        assertEq(message.length, 32, "message must be exactly 32 bytes");
        assertEq(
            message,
            abi.encodePacked(hash),
            "message must be the packed hash bytes"
        );
    }

    function testFuzzToMessageMatchesPackedHash(bytes32 hash) public view {
        assertEq(
            harness.toMessage(hash),
            abi.encodePacked(hash),
            "message must always be the packed hash bytes"
        );
    }

    function validEnvelope() internal view returns (bytes memory) {
        return harness.encodeStatefulEnvelope(
            buildSamplePublicKey(), buildSampleSignature()
        );
    }

    function overwriteSignatureChainsOffset(
        bytes memory source,
        uint256 newOffset
    ) internal pure returns (bytes memory out) {
        out = cloneBytes(source);
        uint256 signatureOffset = wordAt(out, 32);
        writeWord(out, signatureOffset + 64, bytes32(newOffset));
    }

    function overwriteSignatureAuthPathLength(
        bytes memory source,
        uint256 newLength
    ) internal pure returns (bytes memory out) {
        out = cloneBytes(source);
        uint256 signatureOffset = wordAt(out, 32);
        uint256 authPathOffset = wordAt(out, signatureOffset + 96);
        writeWord(out, signatureOffset + authPathOffset, bytes32(newLength));
    }

    function cloneBytes(bytes memory source)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(source.length);
        for (uint256 i = 0; i < source.length; ++i) {
            out[i] = source[i];
        }
    }

    function wordAt(bytes memory data, uint256 offset)
        internal
        pure
        returns (uint256 value)
    {
        assembly {
            value := mload(add(add(data, 32), offset))
        }
    }

    function writeWord(bytes memory data, uint256 offset, bytes32 value)
        internal
        pure
    {
        assembly {
            mstore(add(add(data, 32), offset), value)
        }
    }
}
