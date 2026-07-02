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

    function decodeStatelessEnvelope(bytes calldata envelope)
        external
        pure
        returns (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature)
    {
        return ShrincsCodec.decodeStatelessEnvelope(envelope);
    }

    function encodeStatelessEnvelope(
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.StatelessSignature memory signature
    ) external pure returns (bytes memory envelope) {
        return ShrincsCodec.encodeStatelessEnvelope(publicKey, signature);
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

    // buildSampleSignature: Construct a fully populated synthetic stateless signature with
    // multiple FORS entries and hypertree layers so nested members are exercised.
    function buildSampleSignature() internal pure returns (ShrincsTypes.StatelessSignature memory signature) {
        signature.fors.randomizer = abi.encodePacked(keccak256("codec fors randomizer"));
        signature.fors.counter = 42;
        signature.fors.entries = new ShrincsTypes.ForsEntry[](2);
        for (uint256 i = 0; i < 2; i++) {
            signature.fors.entries[i].secretLeaf = abi.encodePacked(keccak256(abi.encode("codec fors leaf", i)));
            signature.fors.entries[i].authPath = new bytes[](3);
            for (uint256 j = 0; j < 3; j++) {
                signature.fors.entries[i].authPath[j] = abi.encodePacked(keccak256(abi.encode("codec fors auth", i, j)));
            }
        }

        signature.hypertree = new ShrincsTypes.HypertreeLayerSignature[](2);
        for (uint256 i = 0; i < 2; i++) {
            ShrincsTypes.HypertreeLayerSignature memory layer = signature.hypertree[i];
            layer.treeIndex = uint64(1000 + i);
            layer.leafIndex = uint32(20 + i);
            layer.wotsCPkHash = abi.encodePacked(keccak256(abi.encode("codec wots pk hash", i)));
            layer.wotsCSignature.randomizer = abi.encodePacked(keccak256(abi.encode("codec wots randomizer", i)));
            layer.wotsCSignature.counter = uint32(300 + i);
            layer.wotsCSignature.chains = new bytes[](2);
            layer.wotsCSignature.chains[0] = abi.encodePacked(keccak256(abi.encode("codec wots chain a", i)));
            layer.wotsCSignature.chains[1] = abi.encodePacked(keccak256(abi.encode("codec wots chain b", i)));
            layer.authPath = new bytes[](2);
            layer.authPath[0] = abi.encodePacked(keccak256(abi.encode("codec layer auth a", i)));
            layer.authPath[1] = abi.encodePacked(keccak256(abi.encode("codec layer auth b", i)));
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

    function testStatelessEnvelopeRoundTripPreservesEveryField() public view {
        ShrincsTypes.PublicKey memory publicKey = buildSamplePublicKey();
        ShrincsTypes.StatelessSignature memory signature = buildSampleSignature();

        bytes memory envelope = codec.encodeStatelessEnvelope(publicKey, signature);
        (ShrincsTypes.PublicKey memory decodedKey, ShrincsTypes.StatelessSignature memory decodedSig) =
            codec.decodeStatelessEnvelope(envelope);

        // The envelope layout is exactly abi.encode(PublicKey, StatelessSignature).
        assertEq(envelope, abi.encode(publicKey, signature), "envelope must be plain abi.encode of both structs");

        assertEq(decodedKey.statefulPublicKey, publicKey.statefulPublicKey, "statefulPublicKey");
        assertEq(decodedKey.publicKeyCommitment, publicKey.publicKeyCommitment, "publicKeyCommitment");
        assertEq(decodedKey.pkSeed, publicKey.pkSeed, "pkSeed");
        assertEq(decodedKey.hypertreeRoot, publicKey.hypertreeRoot, "hypertreeRoot");

        assertEq(decodedSig.fors.randomizer, signature.fors.randomizer, "fors randomizer");
        assertEq(decodedSig.fors.counter, signature.fors.counter, "fors counter");
        assertEq(decodedSig.fors.entries.length, signature.fors.entries.length, "fors entry count");
        for (uint256 i = 0; i < signature.fors.entries.length; i++) {
            assertEq(decodedSig.fors.entries[i].secretLeaf, signature.fors.entries[i].secretLeaf, "fors secretLeaf");
            assertEq(
                decodedSig.fors.entries[i].authPath.length,
                signature.fors.entries[i].authPath.length,
                "fors authPath length"
            );
            for (uint256 j = 0; j < signature.fors.entries[i].authPath.length; j++) {
                assertEq(
                    decodedSig.fors.entries[i].authPath[j], signature.fors.entries[i].authPath[j], "fors authPath node"
                );
            }
        }

        assertEq(decodedSig.hypertree.length, signature.hypertree.length, "hypertree layer count");
        for (uint256 i = 0; i < signature.hypertree.length; i++) {
            ShrincsTypes.HypertreeLayerSignature memory expected = signature.hypertree[i];
            ShrincsTypes.HypertreeLayerSignature memory actual = decodedSig.hypertree[i];
            assertEq(actual.treeIndex, expected.treeIndex, "layer treeIndex");
            assertEq(actual.leafIndex, expected.leafIndex, "layer leafIndex");
            assertEq(actual.wotsCPkHash, expected.wotsCPkHash, "layer wotsCPkHash");
            assertEq(actual.wotsCSignature.randomizer, expected.wotsCSignature.randomizer, "layer wots randomizer");
            assertEq(actual.wotsCSignature.counter, expected.wotsCSignature.counter, "layer wots counter");
            assertEq(actual.wotsCSignature.chains.length, expected.wotsCSignature.chains.length, "layer chain count");
            for (uint256 j = 0; j < expected.wotsCSignature.chains.length; j++) {
                assertEq(actual.wotsCSignature.chains[j], expected.wotsCSignature.chains[j], "layer chain value");
            }
            assertEq(actual.authPath.length, expected.authPath.length, "layer authPath length");
            for (uint256 j = 0; j < expected.authPath.length; j++) {
                assertEq(actual.authPath[j], expected.authPath[j], "layer authPath node");
            }
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
