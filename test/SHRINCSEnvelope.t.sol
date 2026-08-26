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

import {SHRINCSTestCodec} from "./helpers/SHRINCSTestCodec.sol";

import {Test} from "../lib/forge-std/src/Test.sol";
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

contract EnvelopeERC7913ConsumerHarness {
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

contract EnvelopeMockERC1271Signer {
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

contract EnvelopeNonMagicERC7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0xffffffff;
    }
}

// Minimal concrete instance of the abstract profile base for the envelope
// integration test (the real per-profile subclasses are empty too). The
// pinned SPHINCSPlusC address is unused on the stateful path exercised
// here, so it returns the zero address.
contract EnvelopeSHRINCSVerifierHarness is SHRINCSVerifier {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

contract SHRINCSEnvelopeERC7913IntegrationTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    string internal constant VECTOR_PATH =
        "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    SHRINCSVerifier internal verifier;
    EnvelopeERC7913ConsumerHarness internal consumer;
    EnvelopeMockERC1271Signer internal erc1271Signer;
    EnvelopeNonMagicERC7913Verifier internal nonMagicVerifier;
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
        verifier = new EnvelopeSHRINCSVerifierHarness();
        consumer = new EnvelopeERC7913ConsumerHarness();
        nonMagicVerifier = new EnvelopeNonMagicERC7913Verifier();
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

        // line-length: allow — fmt canonical tuple head exceeds cap
        (SHRINCS.Signature memory signature, bool signOk) = SHRINCSTestSigner.signStatefulAdapterAtLeaf(
            signingKey, publicKey, 1, signedHash
        );
        assertTrue(signOk, "leaf-1 signing must succeed");

        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 commitmentWord;
        assembly {
            commitmentWord := mload(add(commitmentBytes, 32))
        }

        validKey = abi.encodePacked(commitmentWord);
        validEnvelope =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
        erc1271Signer =
            new EnvelopeMockERC1271Signer(signedHash, validEnvelope);
    }

    // The committed crypto-level vector signs its message directly and is a
    // V3 raw-adapter fixture. V4 must reject it because it does not bind the
    // complete commitment in the signed digest.
    function testRejectsLegacyRustGeneratedStatefulVector() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes32 hash,
            SHRINCS.Signature memory signature
        ) = decodeRustStatefulVector();
        bytes memory envelope =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);

        assertEq(
            verifier.verify(publicKey.publicKeyCommitment, hash, envelope),
            INVALID_SIGNATURE,
            "V3 raw-hash vector must not verify through the V4 adapter"
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
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
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
