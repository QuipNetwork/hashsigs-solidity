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
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

contract CodecERC7913ConsumerHarness {
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    function isValidSignatureNow(
        bytes calldata signer,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bool) {
        if (signer.length < 20) return false;

        address verifierAddress = verifierFromSigner(signer);
        if (signer.length == 20) {
            if (verifierAddress.code.length > 0) {
                // line-length: allow — fmt canonical tuple head exceeds cap
                (bool ok, bytes memory returnData) = verifierAddress.staticcall(
                    abi.encodeWithSignature(
                        "isValidSignature(bytes32,bytes)", hash, signature
                    )
                );
                return ok && returnData.length >= 32
                    && returnedBytes4(returnData) == ERC1271_MAGIC_VALUE;
            }
            return ecdsaRecoverMatches(verifierAddress, hash, signature);
        }

        if (verifierAddress.code.length == 0) return false;

        try IERC7913SignatureVerifier(verifierAddress)
            .verify(signer[20:], hash, signature) returns (
            bytes4 magic
        ) {
            return magic == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    function verifierFromSigner(bytes calldata signer)
        internal
        pure
        returns (address verifierAddress)
    {
        assembly {
            verifierAddress := shr(96, calldataload(signer.offset))
        }
    }

    function returnedBytes4(bytes memory returnData)
        internal
        pure
        returns (bytes4 value)
    {
        assembly {
            value := mload(add(returnData, 32))
        }
    }

    function ecdsaRecoverMatches(
        address expected,
        bytes32 hash,
        bytes calldata signature
    ) internal pure returns (bool) {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        address recovered = ecrecover(hash, v, r, s);
        return recovered != address(0) && recovered == expected;
    }
}

contract CodecMockERC1271Signer {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    bytes32 internal immutable validHash;
    bytes32 internal immutable validSignatureHash;

    constructor(bytes32 hash, bytes memory signature) {
        validHash = hash;
        validSignatureHash = keccak256(signature);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (hash == validHash && keccak256(signature) == validSignatureHash)
        {
            return MAGIC_VALUE;
        }
        return INVALID_SIGNATURE;
    }
}

contract CodecNonMagicERC7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0xffffffff;
    }
}

// Minimal concrete instance of the abstract profile base for the codec
// integration test (the real per-profile subclasses are empty too). The
// pinned SPHINCSPlusC address is unused on the stateful path exercised
// here, so it returns the zero address.
contract CodecSHRINCSVerifierHarness is SHRINCSVerifier {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

// Exposes the internal codec library through external functions so tests
// exercise the real calldata-facing decode paths.
contract SHRINCSCodecHarness {
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

contract SHRINCSCodecTest is Test {
    SHRINCSCodecHarness internal codec;

    function setUp() public {
        codec = new SHRINCSCodecHarness();
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
            codec.decodePublicKeyCommitment(abi.encodePacked(expected));
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
                codec.decodePublicKeyCommitment(key);
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
            codec.encodeStatefulEnvelope(publicKey, signature);
        (
            SHRINCS.PublicKey memory decodedKey,
            SHRINCS.Signature memory decodedSig,
            bool ok
        ) = codec.decodeStatefulEnvelope(envelope);
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
        codec.decodeStatefulEnvelope(malformed);
    }

    // A huge claimed auth-path length reads past the buffer and reverts
    // inside abi.decode.
    function testDecodeStatefulEnvelopeRevertsOnHugeAuthPathLength() public {
        bytes memory malformed =
            overwriteSignatureAuthPathLength(validEnvelope(), 10_000);
        vm.expectRevert();
        codec.decodeStatefulEnvelope(malformed);
    }

    function testToMessageIsThePackedHash() public view {
        bytes32 hash = keccak256("codec message hash");
        bytes memory message = codec.toMessage(hash);
        assertEq(message.length, 32, "message must be exactly 32 bytes");
        assertEq(
            message,
            abi.encodePacked(hash),
            "message must be the packed hash bytes"
        );
    }

    function testFuzzToMessageMatchesPackedHash(bytes32 hash) public view {
        assertEq(
            codec.toMessage(hash),
            abi.encodePacked(hash),
            "message must always be the packed hash bytes"
        );
    }

    function validEnvelope() internal view returns (bytes memory) {
        return codec.encodeStatefulEnvelope(
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

contract SHRINCSCodecERC7913IntegrationTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    string internal constant VECTOR_PATH =
        "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    SHRINCSVerifier internal verifier;
    CodecERC7913ConsumerHarness internal consumer;
    CodecMockERC1271Signer internal erc1271Signer;
    CodecNonMagicERC7913Verifier internal nonMagicVerifier;
    string internal vectors;

    struct LegacyStatefulPublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    struct LegacyStatefulSignature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[64] chains;
        bytes32[] authPath;
    }

    bytes32 internal signedHash;
    bytes internal validKey;
    bytes internal validEnvelope;

    function setUp() public {
        verifier = new CodecSHRINCSVerifierHarness();
        consumer = new CodecERC7913ConsumerHarness();
        nonMagicVerifier = new CodecNonMagicERC7913Verifier();
        vectors = vm.readFile(VECTOR_PATH);

        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(
            bytes("shrincs erc7913 stateful verifier seed"), 4
        );
        assertTrue(keygenOk, "in-test keygen must succeed");

        signedHash = keccak256("shrincs erc7913 stateful verifier vector");
        bytes memory message = abi.encodePacked(signedHash);

        (SHRINCS.Signature memory signature, bool signOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        assertTrue(signOk, "leaf-1 signing must succeed");

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 commitmentWord;
        assembly {
            commitmentWord := mload(add(commitmentBytes, 32))
        }

        validKey = abi.encodePacked(commitmentWord);
        validEnvelope = SHRINCS.encodeStatefulEnvelope(publicKey, signature);
        erc1271Signer = new CodecMockERC1271Signer(signedHash, validEnvelope);
    }

    // Checks that a stateful signature made by the Rust code works through
    // ERC-7913.
    function testVerifyRustGeneratedStatefulVectorReturnsMagicValue()
        public
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes32 hash,
            SHRINCS.Signature memory signature
        ) = decodeRustStatefulVector();
        bytes memory envelope =
            SHRINCS.encodeStatefulEnvelope(publicKey, signature);

        assertEq(
            verifier.verify(publicKey.publicKeyCommitment, hash, envelope),
            IERC7913SignatureVerifier.verify.selector,
            // line-length: allow — one unbreakable string literal token
            "Rust-generated stateful vector must verify through the ERC-7913 envelope"
        );
    }

    // Checks that a 32-byte key of all zeros is rejected.
    function testRejectsZeroCommitmentKey() public view {
        assertEq(
            verifier.verify(
                abi.encodePacked(bytes32(0)), signedHash, validEnvelope
            ),
            INVALID_SIGNATURE,
            "zero commitment key must be rejected"
        );
    }

    // Checks that a caller can verify signer = verifier address followed by
    // key bytes.
    function testConsumerAcceptsVerifierKeySigner() public view {
        bytes memory signer = abi.encodePacked(address(verifier), validKey);
        assertTrue(
            consumer.isValidSignatureNow(signer, signedHash, validEnvelope),
            "verifier || key signer must verify"
        );
    }

    // Checks that a signer value shorter than an address is rejected.
    function testConsumerRejectsSignerShorterThanAddress() public view {
        bytes memory signer = new bytes(19);
        assertFalse(
            consumer.isValidSignatureNow(signer, signedHash, validEnvelope),
            "signer shorter than one address must fail"
        );
    }

    // Checks that a 20-byte signer uses ERC-1271, not ERC-7913 with an empty
    // key.
    function testConsumerUsesERC1271FallbackForEmptyKey() public view {
        bytes memory signer = abi.encodePacked(address(erc1271Signer));
        assertTrue(
            consumer.isValidSignatureNow(signer, signedHash, validEnvelope),
            "20-byte signer must use ERC-1271 fallback"
        );
        assertFalse(
            consumer.isValidSignatureNow(
                abi.encodePacked(address(verifier)),
                signedHash,
                validEnvelope
            ),
            // line-length: allow — one unbreakable string literal token
            "20-byte ERC-7913 verifier address must not be called with an empty key"
        );
    }

    // Checks that verification fails if the verifier does not return the
    // ERC-7913 success value.
    function testConsumerRejectsNonMagicVerifierReturn() public view {
        bytes memory signer =
            abi.encodePacked(address(nonMagicVerifier), validKey);
        assertFalse(
            consumer.isValidSignatureNow(signer, signedHash, validEnvelope),
            "non-magic ERC-7913 return value must fail"
        );
    }

    // Checks that a consumer rejects verifier addresses that have no contract
    // code.
    function testConsumerRejectsVerifierAddressWithNoCode() public view {
        address noCodeVerifier =
            address(0x1234567890123456789012345678901234567890);
        assertEq(
            noCodeVerifier.code.length, 0, "test address must have no code"
        );

        bytes memory signer = abi.encodePacked(noCodeVerifier, validKey);
        assertFalse(
            consumer.isValidSignatureNow(signer, signedHash, validEnvelope),
            "no-code ERC-7913 verifier address must fail"
        );
    }

    // Checks that a good key and signature fail if the signer points at the
    // wrong contract.
    function testConsumerRejectsValidSignatureWithWrongVerifierAddress()
        public
        view
    {
        bytes memory signer =
            abi.encodePacked(address(erc1271Signer), validKey);
        assertFalse(
            consumer.isValidSignatureNow(signer, signedHash, validEnvelope),
            "wrong verifier address must fail even with a good signature"
        );
    }

    function decodeRustStatefulVector()
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes32 hash,
            SHRINCS.Signature memory signature
        )
    {
        bytes memory args = vectorArgs(".stateful.cases.valid.calldata");
        (
            LegacyStatefulPublicKey memory legacyKey,
            bytes memory message,
            LegacyStatefulSignature memory legacySignature
        ) = abi.decode(
            args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature)
        );

        assertEq(
            message.length,
            32,
            "ERC-7913 vector message must be exactly one bytes32"
        );
        assembly {
            hash := mload(add(message, 32))
        }

        bytes memory pkSeed = vm.parseJsonBytes(
            vectors, ".stateless.cases.valid.publicKey.pkSeed"
        );
        bytes memory hypertreeRoot = vm.parseJsonBytes(
            vectors, ".stateless.cases.valid.publicKey.hypertreeRoot"
        );
        bytes memory statefulPublicKey = abi.encodePacked(
            legacyKey.pkSeed, legacyKey.root, bytes4(legacyKey.maxSignatures)
        );

        publicKey =
            publicKeyFromParts(statefulPublicKey, pkSeed, hypertreeRoot);
        signature = SHRINCS.Signature({
            randomizer: legacySignature.randomizer,
            counter: legacySignature.counter,
            chains: fixedToDynamicChains(legacySignature.chains),
            authPath: legacySignature.authPath
        });
    }

    function publicKeyFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (SHRINCS.PublicKey memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return SHRINCS.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment),
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
    }

    function fixedToDynamicChains(bytes32[64] memory fixedChains)
        internal
        pure
        returns (bytes32[] memory chains)
    {
        chains = new bytes32[](64);
        for (uint256 i = 0; i < 64; ++i) {
            chains[i] = fixedChains[i];
        }
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
}
