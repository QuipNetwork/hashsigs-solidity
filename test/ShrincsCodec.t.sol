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
import {ShrincsCodec} from "../contracts/ShrincsCodec.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsVerifier} from "../contracts/ShrincsVerifier.sol";
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";

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

// Exposes the internal codec library through external functions so tests
// exercise the real calldata-facing decode paths.
contract ShrincsCodecHarness {
    function decodeKey(bytes calldata key)
        external
        pure
        returns (bytes32 commitment, bool ok)
    {
        return ShrincsCodec.decodeKey(key);
    }

    function decodeStatefulEnvelope(bytes calldata envelope)
        external
        pure
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            ShrincsTypes.StatefulSignature memory signature
        )
    {
        return ShrincsCodec.decodeStatefulEnvelope(envelope);
    }

    function encodeStatefulEnvelope(
        ShrincsTypes.PublicKey memory publicKey,
        ShrincsTypes.StatefulSignature memory signature
    ) external pure returns (bytes memory envelope) {
        return ShrincsCodec.encodeStatefulEnvelope(publicKey, signature);
    }

    function toMessage(bytes32 hash)
        external
        pure
        returns (bytes memory message)
    {
        return ShrincsCodec.toMessage(hash);
    }
}

contract ShrincsCodecTest is Test {
    ShrincsCodecHarness internal codec;

    function setUp() public {
        codec = new ShrincsCodecHarness();
    }

    // buildSamplePublicKey: Construct a fully populated synthetic key bundle
    // for round-trip checks.
    function buildSamplePublicKey()
        internal
        pure
        returns (ShrincsTypes.PublicKey memory publicKey)
    {
        publicKey = ShrincsTypes.PublicKey({
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
        returns (ShrincsTypes.StatefulSignature memory signature)
    {
        signature.randomizer = keccak256("codec stateful randomizer");
        signature.counter = 42;
        signature.chains = new bytes32[](ShrincsTypes.WOTS_CHAINS_STATEFUL);
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
            codec.decodeKey(abi.encodePacked(expected));
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
            (bytes32 commitment, bool ok) = codec.decodeKey(key);
            assertFalse(ok, "wrong-length key must not decode");
            assertEq(
                commitment,
                bytes32(0),
                "rejected key must return a zero commitment"
            );
        }
    }

    function testStatefulEnvelopeRoundTripPreservesEveryField() public view {
        ShrincsTypes.PublicKey memory publicKey = buildSamplePublicKey();
        ShrincsTypes.StatefulSignature memory signature =
            buildSampleSignature();

        bytes memory envelope =
            codec.encodeStatefulEnvelope(publicKey, signature);
        (
            ShrincsTypes.PublicKey memory decodedKey,
            ShrincsTypes.StatefulSignature memory decodedSig
        ) = codec.decodeStatefulEnvelope(envelope);

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

    // Checks that extra bytes at the end of the envelope are rejected.
    function testDecodeStatefulEnvelopeRejectsTrailingBytes() public {
        bytes memory envelope = validEnvelope();
        bytes memory malformed = bytes.concat(envelope, hex"00");

        vm.expectRevert(ShrincsCodec.InvalidEnvelope.selector);
        codec.decodeStatefulEnvelope(malformed);
    }

    // Checks that unused bytes inside the public key part are rejected.
    // line-length: allow — test name is one unbreakable token
    function testDecodeStatefulEnvelopeRejectsNestedTrailingBytesInsidePublicKey()
        public
    {
        bytes memory malformed =
            insertGapBeforePublicKeyCommitment(validEnvelope());

        vm.expectRevert(ShrincsCodec.InvalidEnvelope.selector);
        codec.decodeStatefulEnvelope(malformed);
    }

    // Checks that a bad pointer inside the encoded signature is rejected.
    function testDecodeStatefulEnvelopeRejectsMalformedDynamicOffset()
        public
    {
        bytes memory malformed =
            overwriteSignatureChainsOffset(validEnvelope(), 0x81);

        vm.expectRevert();
        codec.decodeStatefulEnvelope(malformed);
    }

    // Checks that reused pointers inside the encoded public key are rejected.
    function testDecodeStatefulEnvelopeRejectsDuplicatedInternalOffsets()
        public
    {
        bytes memory malformed =
            duplicatePublicKeyCommitmentOffset(validEnvelope());

        vm.expectRevert(ShrincsCodec.InvalidEnvelope.selector);
        codec.decodeStatefulEnvelope(malformed);
    }

    // Checks that out-of-order ABI pointers are rejected even if abi.decode
    // could read them.
    // line-length: allow — test name is one unbreakable token
    function testDecodeStatefulEnvelopeRejectsOutOfOrderOffsetsThatStillDecode()
        public
    {
        bytes memory malformed =
            reorderPublicKeyStatefulAndCommitmentData(validEnvelope());

        vm.expectRevert(ShrincsCodec.InvalidEnvelope.selector);
        codec.decodeStatefulEnvelope(malformed);
    }

    // Checks that a stateful signature must have exactly 64 WOTS-C chain
    // values.
    function testDecodeStatefulEnvelopeRejectsOversizedDeclaredChainArray()
        public
    {
        bytes memory malformed =
            overwriteSignatureChainsLength(validEnvelope(), 65);

        vm.expectRevert();
        codec.decodeStatefulEnvelope(malformed);
    }

    // Checks that a huge claimed auth path length is rejected before the
    // decoded value is accepted.
    function testDecodeStatefulEnvelopeRejectsHugeAuthPathLength() public {
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

    function duplicatePublicKeyCommitmentOffset(bytes memory source)
        internal
        pure
        returns (bytes memory out)
    {
        out = cloneBytes(source);
        uint256 publicKeyOffset = wordAt(out, 0);
        bytes32 statefulPublicKeyOffset =
            bytes32(wordAt(out, publicKeyOffset));
        writeWord(out, publicKeyOffset + 32, statefulPublicKeyOffset);
    }

    function insertGapBeforePublicKeyCommitment(bytes memory source)
        internal
        pure
        returns (bytes memory out)
    {
        uint256 publicKeyOffset = wordAt(source, 0);
        uint256 oldSignatureOffset = wordAt(source, 32);
        uint256 gapOffset =
            publicKeyOffset + wordAt(source, publicKeyOffset + 32);

        out = insertZeroWordAt(source, gapOffset);
        writeWord(out, 32, bytes32(oldSignatureOffset + 32));
        writeWord(
            out,
            publicKeyOffset + 32,
            bytes32(wordAt(source, publicKeyOffset + 32) + 32)
        );
        writeWord(
            out,
            publicKeyOffset + 64,
            bytes32(wordAt(source, publicKeyOffset + 64) + 32)
        );
        writeWord(
            out,
            publicKeyOffset + 96,
            bytes32(wordAt(source, publicKeyOffset + 96) + 32)
        );
    }

    function reorderPublicKeyStatefulAndCommitmentData(bytes memory source)
        internal
        pure
        returns (bytes memory out)
    {
        out = cloneBytes(source);

        uint256 publicKeyOffset = wordAt(source, 0);
        uint256 statefulOffset = wordAt(source, publicKeyOffset);
        uint256 commitmentOffset = wordAt(source, publicKeyOffset + 32);
        uint256 statefulSize = dynamicBytesSegmentSize(
            source, publicKeyOffset + statefulOffset
        );
        uint256 commitmentSize = dynamicBytesSegmentSize(
            source, publicKeyOffset + commitmentOffset
        );

        writeWord(
            out, publicKeyOffset, bytes32(statefulOffset + commitmentSize)
        );
        writeWord(out, publicKeyOffset + 32, bytes32(statefulOffset));

        copyBytesRange(
            out,
            publicKeyOffset + statefulOffset,
            source,
            publicKeyOffset + commitmentOffset,
            commitmentSize
        );
        copyBytesRange(
            out,
            publicKeyOffset + statefulOffset + commitmentSize,
            source,
            publicKeyOffset + statefulOffset,
            statefulSize
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

    function overwriteSignatureChainsLength(
        bytes memory source,
        uint256 newLength
    ) internal pure returns (bytes memory out) {
        out = cloneBytes(source);
        uint256 signatureOffset = wordAt(out, 32);
        uint256 chainsOffset = wordAt(out, signatureOffset + 64);
        writeWord(out, signatureOffset + chainsOffset, bytes32(newLength));
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

    function insertZeroWordAt(bytes memory source, uint256 offset)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(source.length + 32);
        for (uint256 i = 0; i < offset; ++i) {
            out[i] = source[i];
        }
        for (uint256 i = offset; i < source.length; ++i) {
            out[i + 32] = source[i];
        }
    }

    function dynamicBytesSegmentSize(bytes memory source, uint256 offset)
        internal
        pure
        returns (uint256)
    {
        uint256 byteLength = wordAt(source, offset);
        return 32 + ((byteLength + 31) / 32) * 32;
    }

    function copyBytesRange(
        bytes memory target,
        uint256 targetOffset,
        bytes memory source,
        uint256 sourceOffset,
        uint256 length
    ) internal pure {
        for (uint256 i = 0; i < length; ++i) {
            target[targetOffset + i] = source[sourceOffset + i];
        }
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

contract ShrincsCodecERC7913IntegrationTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    string internal constant VECTOR_PATH =
        "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    ShrincsVerifier internal verifier;
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
        verifier = new ShrincsVerifier();
        consumer = new CodecERC7913ConsumerHarness();
        nonMagicVerifier = new CodecNonMagicERC7913Verifier();
        vectors = vm.readFile(VECTOR_PATH);

        (
            ShrincsTypes.SigningKey memory signingKey,
            ShrincsTypes.PublicKey memory publicKey,
            bool keygenOk
        ) = ShrincsTestSigner.keygen(
            bytes("shrincs erc7913 stateful verifier seed"), 4
        );
        assertTrue(keygenOk, "in-test keygen must succeed");

        signedHash = keccak256("shrincs erc7913 stateful verifier vector");
        bytes memory message = abi.encodePacked(signedHash);

        (ShrincsTypes.StatefulSignature memory signature, bool signOk) =
            ShrincsTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        assertTrue(signOk, "leaf-1 signing must succeed");

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 commitmentWord;
        assembly {
            commitmentWord := mload(add(commitmentBytes, 32))
        }

        validKey = abi.encodePacked(commitmentWord);
        validEnvelope =
            ShrincsCodec.encodeStatefulEnvelope(publicKey, signature);
        erc1271Signer = new CodecMockERC1271Signer(signedHash, validEnvelope);
    }

    // Checks that a stateful signature made by the Rust code works through
    // ERC-7913.
    function testVerifyRustGeneratedStatefulVectorReturnsMagicValue()
        public
    {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 hash,
            ShrincsTypes.StatefulSignature memory signature
        ) = decodeRustStatefulVector();
        bytes memory envelope =
            ShrincsCodec.encodeStatefulEnvelope(publicKey, signature);

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
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 hash,
            ShrincsTypes.StatefulSignature memory signature
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
        signature = ShrincsTypes.StatefulSignature({
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
    ) internal pure returns (ShrincsTypes.PublicKey memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return ShrincsTypes.PublicKey({
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
