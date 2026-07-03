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
import {ShrincsCodec} from "../contracts/ShrincsCodec.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";

// Exposes the internal codec library through external functions so tests exercise
// the real calldata-facing decode paths.
contract ShrincsCodecHarness {
    function decodeKey(bytes calldata key) external pure returns (bytes32 commitment, bool ok) {
        return ShrincsCodec.decodeKey(key);
    }

    function decodeStatefulEnvelope(bytes calldata envelope)
        external
        pure
        returns (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatefulSignature memory signature)
    {
        return ShrincsCodec.decodeStatefulEnvelope(envelope);
    }

    function encodeStatefulEnvelope(
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.StatefulSignature memory signature
    ) external pure returns (bytes memory envelope) {
        return ShrincsCodec.encodeStatefulEnvelope(publicKey, signature);
    }

    function toMessage(bytes32 hash) external pure returns (bytes memory message) {
        return ShrincsCodec.toMessage(hash);
    }
}

contract ShrincsCodecTest is Test {
    ShrincsCodecHarness internal codec;

    function setUp() public {
        codec = new ShrincsCodecHarness();
    }

    // buildSamplePublicKey: Construct a fully populated synthetic key bundle for round-trip checks.
    function buildSamplePublicKey() internal pure returns (ShrincsTypes.PublicKey memory publicKey) {
        publicKey = ShrincsTypes.PublicKey({
            statefulPublicKey: abi.encodePacked(
                keccak256("codec stateful pk seed"), keccak256("codec stateful root"), uint32(7)
            ),
            publicKeyCommitment: abi.encodePacked(keccak256("codec bundle commitment")),
            pkSeed: abi.encodePacked(keccak256("codec pk seed")),
            hypertreeRoot: abi.encodePacked(keccak256("codec hypertree root"))
        });
    }

    // buildSampleSignature: Construct a fully populated synthetic stateful signature so
    // every field — randomizer, counter, chains, authPath — is exercised by the round-trip.
    function buildSampleSignature() internal pure returns (ShrincsTypes.StatefulSignature memory signature) {
        signature.randomizer = keccak256("codec stateful randomizer");
        signature.counter = 42;
        signature.chains = new bytes32[](3);
        for (uint256 i = 0; i < signature.chains.length; i++) {
            signature.chains[i] = keccak256(abi.encode("codec stateful chain", i));
        }
        signature.authPath = new bytes32[](2);
        for (uint256 i = 0; i < signature.authPath.length; i++) {
            signature.authPath[i] = keccak256(abi.encode("codec stateful auth", i));
        }
    }

    function testDecodeKeyAcceptsExactly32Bytes() public view {
        bytes32 expected = keccak256("codec key word");
        (bytes32 commitment, bool ok) = codec.decodeKey(abi.encodePacked(expected));
        assertTrue(ok, "32-byte key must decode");
        assertEq(commitment, expected, "decoded commitment must match the key word");
    }

    function testDecodeKeyRejectsWrongLengthsWithoutReverting() public view {
        uint256[5] memory badLengths = [uint256(0), 20, 31, 33, 64];
        for (uint256 i = 0; i < badLengths.length; i++) {
            bytes memory key = new bytes(badLengths[i]);
            for (uint256 j = 0; j < key.length; j++) {
                key[j] = 0xab;
            }
            (bytes32 commitment, bool ok) = codec.decodeKey(key);
            assertFalse(ok, "wrong-length key must not decode");
            assertEq(commitment, bytes32(0), "rejected key must return a zero commitment");
        }
    }

    function testStatefulEnvelopeRoundTripPreservesEveryField() public view {
        ShrincsTypes.PublicKey memory publicKey = buildSamplePublicKey();
        ShrincsTypes.StatefulSignature memory signature = buildSampleSignature();

        bytes memory envelope = codec.encodeStatefulEnvelope(publicKey, signature);
        (ShrincsTypes.PublicKey memory decodedKey, ShrincsTypes.StatefulSignature memory decodedSig) =
            codec.decodeStatefulEnvelope(envelope);

        // The envelope layout is exactly abi.encode(PublicKey, StatefulSignature).
        assertEq(envelope, abi.encode(publicKey, signature), "envelope must be plain abi.encode of both structs");

        assertEq(decodedKey.statefulPublicKey, publicKey.statefulPublicKey, "statefulPublicKey");
        assertEq(decodedKey.publicKeyCommitment, publicKey.publicKeyCommitment, "publicKeyCommitment");
        assertEq(decodedKey.pkSeed, publicKey.pkSeed, "pkSeed");
        assertEq(decodedKey.hypertreeRoot, publicKey.hypertreeRoot, "hypertreeRoot");

        assertEq(decodedSig.randomizer, signature.randomizer, "randomizer");
        assertEq(decodedSig.counter, signature.counter, "counter");
        assertEq(decodedSig.chains.length, signature.chains.length, "chain count");
        for (uint256 i = 0; i < signature.chains.length; i++) {
            assertEq(decodedSig.chains[i], signature.chains[i], "chain value");
        }
        assertEq(decodedSig.authPath.length, signature.authPath.length, "authPath length");
        for (uint256 i = 0; i < signature.authPath.length; i++) {
            assertEq(decodedSig.authPath[i], signature.authPath[i], "authPath node");
        }
    }

    function testToMessageIsThePackedHash() public view {
        bytes32 hash = keccak256("codec message hash");
        bytes memory message = codec.toMessage(hash);
        assertEq(message.length, 32, "message must be exactly 32 bytes");
        assertEq(message, abi.encodePacked(hash), "message must be the packed hash bytes");
    }

    function testFuzzToMessageMatchesPackedHash(bytes32 hash) public view {
        assertEq(codec.toMessage(hash), abi.encodePacked(hash), "message must always be the packed hash bytes");
    }
}
