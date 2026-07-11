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
import {SHRINCSCore} from "../contracts/SHRINCSCore.sol";
import {SHRINCSCodec} from "../contracts/SHRINCSCodec.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    ShrincsAccountSigningFacade
} from "./helpers/ShrincsAccountSigningFacade.sol";
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";

/// @dev Concrete instance of the abstract profile base for the raw path.
/// The pinned SPHINCSPlusC address is unused on the stateful path, so it
/// returns the zero address.
contract MutationVerifierHarness is SHRINCS {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

/// @title ShrincsMutationFuzzTest
/// @notice Mutation-malleability fuzz (security-testing plan P4). Starting
/// from a valid signature produced in setUp, any single bit/byte mutation of
/// the wrapper's canonical ERC-1271 envelope is rejected, and any mutation of
/// the raw stateful signature material fails verification. The pristine
/// inputs always verify (guards against test-vector rot).
/// @dev The ERC-1271 path enforces re-encode canonicity, so a byte flip
/// that decodes to the same fields still fails the canonicity check: no
/// second encoding is accepted. The raw ERC-7913 path checks signature
/// only, so it is fuzzed by perturbing the cryptographic fields (chains,
/// counter), which always breaks WOTS-C reconstruction.
contract ShrincsMutationFuzzTest is Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    SHRINCSAccountVerifierExample internal account;
    MutationVerifierHarness internal rawVerifier;

    // Valid ERC-1271 stateful-action envelope and the hash it authorizes.
    bytes internal wrapperEnvelope;
    bytes32 internal wrapperHash;

    // Valid raw ERC-7913 stateful envelope, its key, and its signed hash.
    bytes internal rawEnvelope;
    bytes internal rawKey;
    bytes32 internal rawHash;

    function setUp() public {
        rawVerifier = new MutationVerifierHarness();
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = ShrincsTestSigner.keygen(bytes("shrincs mutation fuzz seed"), 4);
        assertTrue(keygenOk, "keygen");

        bytes32 commitment =
            ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey);
        account = new SHRINCSAccountVerifierExample(commitment);

        _buildWrapperEnvelope(signingKey, publicKey);
        _buildRawEnvelope(signingKey, publicKey, commitment);
    }

    function testValidInputsVerify() public view {
        assertEq(
            account.isValidSignature(wrapperHash, wrapperEnvelope),
            MAGIC_VALUE,
            "pristine 1271 must verify"
        );
        assertEq(
            rawVerifier.verify(rawKey, rawHash, rawEnvelope),
            IERC7913SignatureVerifier.verify.selector,
            "pristine raw must verify"
        );
    }

    // Any single-byte change to the canonical 1271 envelope is rejected: the
    // wrapper's re-encode canonicity check, hash binding, or signature check
    // fails. No second encoding is accepted.
    function testFuzz_wrapper1271ByteFlipRejected(
        uint256 byteSelector,
        uint8 xorValue
    ) public view {
        uint256 index = bound(byteSelector, 0, wrapperEnvelope.length - 1);
        uint8 delta = xorValue == 0 ? 1 : xorValue;
        bytes memory mutated = _clone(wrapperEnvelope);
        mutated[index] = bytes1(uint8(mutated[index]) ^ delta);
        assertEq(
            account.isValidSignature(wrapperHash, mutated),
            INVALID_SIGNATURE,
            "byte-flipped 1271 envelope accepted"
        );
    }

    // Same property at bit granularity.
    function testFuzz_wrapper1271BitFlipRejected(uint256 bitSelector)
        public
        view
    {
        uint256 bitIndex =
            bound(bitSelector, 0, wrapperEnvelope.length * 8 - 1);
        bytes memory mutated = _clone(wrapperEnvelope);
        uint256 byteIndex = bitIndex >> 3;
        uint8 mask = uint8(1) << uint8(7 - (bitIndex & 7));
        mutated[byteIndex] = bytes1(uint8(mutated[byteIndex]) ^ mask);
        assertEq(
            account.isValidSignature(wrapperHash, mutated),
            INVALID_SIGNATURE,
            "bit-flipped 1271 envelope accepted"
        );
    }

    // Mutating any WOTS-C chain value breaks the raw stateful verification.
    function testFuzz_rawChainMutationRejected(
        uint256 chainSelector,
        bytes32 flip
    ) public view {
        (
            SHRINCSCore.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature
        ) = abi.decode(
            rawEnvelope, (SHRINCSCore.PublicKey, UXMSS.StatefulSignature)
        );
        uint256 index = bound(chainSelector, 0, signature.chains.length - 1);
        signature.chains[index] =
            bytes32(uint256(signature.chains[index]) ^ (uint256(flip) | 1));
        bytes memory mutated =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            rawVerifier.verify(rawKey, rawHash, mutated),
            INVALID_SIGNATURE,
            "mutated chain accepted"
        );
    }

    // Perturbing the WOTS-C grind counter breaks the target-sum digest.
    function testFuzz_rawCounterMutationRejected(uint32 delta) public view {
        (
            SHRINCSCore.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature
        ) = abi.decode(
            rawEnvelope, (SHRINCSCore.PublicKey, UXMSS.StatefulSignature)
        );
        uint32 bump = delta == 0 ? 1 : delta;
        // XOR flips at least one counter bit without overflowing uint32.
        signature.counter = signature.counter ^ bump;
        bytes memory mutated =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            rawVerifier.verify(rawKey, rawHash, mutated),
            INVALID_SIGNATURE,
            "mutated counter accepted"
        );
    }

    // _buildWrapperEnvelope: sign the first stateful action against the fresh
    // wrapper and encode the canonical mode-1 ERC-1271 envelope.
    function _buildWrapperEnvelope(
        SHRINCSCore.SigningKey memory signingKey,
        SHRINCSCore.PublicKey memory publicKey
    ) internal {
        bytes32 actionType = keccak256("shrincs-mutation-action");
        bytes32 payloadHash = keccak256("shrincs-mutation-payload");
        (
            ,
            SHRINCSCore.ActionContext memory context,
            UXMSS.StatefulSignature memory signature,
            bool ok
        ) = ShrincsAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );
        assertTrue(ok, "wrapper sign");
        wrapperHash = SHRINCSCore.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        wrapperEnvelope =
            ShrincsAccountSigningFacade.encodeStateful1271Envelope(
                    publicKey, actionType, payloadHash, signature
                );
    }

    // _buildRawEnvelope: sign the fixed hash at leaf 1 and encode the raw
    // ERC-7913 stateful envelope.
    function _buildRawEnvelope(
        SHRINCSCore.SigningKey memory signingKey,
        SHRINCSCore.PublicKey memory publicKey,
        bytes32 commitment
    ) internal {
        rawHash = keccak256("shrincs mutation raw vector");
        UXMSS.StatefulSignature memory signature;
        bool ok;
        (signature, ok) = ShrincsTestSigner.signStatefulRawAtLeaf(
            signingKey, 1, abi.encodePacked(rawHash)
        );
        assertTrue(ok, "raw sign");
        rawKey = abi.encodePacked(commitment);
        rawEnvelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
    }

    function _clone(bytes memory input)
        internal
        pure
        returns (bytes memory copy)
    {
        copy = new bytes(input.length);
        for (uint256 i = 0; i < input.length; i++) {
            copy[i] = input[i];
        }
    }
}
