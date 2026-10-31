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
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

/// @dev Concrete instance of the abstract profile base for the raw path.
/// The pinned SPHINCSPlusC address is unused on the stateful path, so it
/// returns the zero address.
contract MutationVerifierHarness is SHRINCSVerifier {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

/// @title SHRINCSMutationFuzzTest
/// @notice Mutation fuzz (security-testing plan P4). The pristine wrapper
/// ERC-1271 envelope and raw ERC-7913 signature both verify (guards against
/// test-vector rot), and any mutation of the raw stateful signature's
/// cryptographic material fails verification.
/// @dev The raw ERC-7913 path checks the signature only, so it is fuzzed by
/// perturbing the cryptographic fields (chains, counter), which always breaks
/// WOTS-C reconstruction. The wrapper envelope's byte/bit-flip mutation tests
/// were removed with the canonicity walk: a framing mutation now reverts
/// inside abi.decode and a `bytes` tail-padding mutation decodes to the same
/// signature and still verifies (byte-malleable), so a single-mutation
/// "always rejected" property no longer holds. Adversarial wrapper/verifier
/// input coverage lives in SHRINCSGuardPinning's never-wrong-accept suite.
contract SHRINCSMutationFuzzTest is Test {
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
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(bytes("shrincs mutation fuzz seed"), 4);
        assertTrue(keygenOk, "keygen");

        bytes32 commitment =
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey);
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

    // Mutating any WOTS-C chain value breaks the raw stateful verification.
    function testFuzz_rawChainMutationRejected(
        uint256 chainSelector,
        bytes32 flip
    ) public view {
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = abi.decode(rawEnvelope, (SHRINCS.PublicKey, SHRINCS.Signature));
        uint256 index = bound(chainSelector, 0, signature.chains.length - 1);
        signature.chains[index] =
            bytes32(uint256(signature.chains[index]) ^ (uint256(flip) | 1));
        bytes memory mutated =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            rawVerifier.verify(rawKey, rawHash, mutated),
            INVALID_SIGNATURE,
            "mutated chain accepted"
        );
    }

    // Mutating the per-signature randomizer breaks the committed stateful
    // message digest (the randomizer is bound into the digest the leaf's
    // WOTS-C signature is over).
    function testFuzz_rawRandomizerMutationRejected(bytes32 flip)
        public
        view
    {
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = abi.decode(rawEnvelope, (SHRINCS.PublicKey, SHRINCS.Signature));
        // `| 1` guarantees a non-no-op flip regardless of the fuzzed value.
        signature.randomizer =
            bytes32(uint256(signature.randomizer) ^ (uint256(flip) | 1));
        bytes memory mutated =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            rawVerifier.verify(rawKey, rawHash, mutated),
            INVALID_SIGNATURE,
            "mutated randomizer accepted"
        );
    }

    // Perturbing the WOTS-C grind counter breaks the target-sum digest.
    function testFuzz_rawCounterMutationRejected(uint32 delta) public view {
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = abi.decode(rawEnvelope, (SHRINCS.PublicKey, SHRINCS.Signature));
        uint32 bump = delta == 0 ? 1 : delta;
        // XOR flips at least one counter bit without overflowing uint32.
        signature.counter = signature.counter ^ bump;
        bytes memory mutated =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            rawVerifier.verify(rawKey, rawHash, mutated),
            INVALID_SIGNATURE,
            "mutated counter accepted"
        );
    }

    // _buildWrapperEnvelope: sign the first stateful action against the fresh
    // wrapper and encode the canonical mode-1 ERC-1271 envelope.
    function _buildWrapperEnvelope(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey
    ) internal {
        bytes32 actionType = keccak256("shrincs-mutation-action");
        bytes32 payloadHash = keccak256("shrincs-mutation-payload");
        (
            ,
            SHRINCS.ActionContext memory context,
            SHRINCS.Signature memory signature,
            bool ok
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, actionType, payloadHash
        );
        assertTrue(ok, "wrapper sign");
        wrapperHash = SHRINCS.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        wrapperEnvelope =
            SHRINCSAccountSigningFacade.encodeStateful1271Envelope(
                    publicKey, actionType, payloadHash, signature
                );
    }

    // _buildRawEnvelope: sign the fixed hash at leaf 1 and encode the raw
    // ERC-7913 stateful envelope.
    function _buildRawEnvelope(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes32 commitment
    ) internal {
        rawHash = keccak256("shrincs mutation raw vector");
        SHRINCS.Signature memory signature;
        bool ok;
        (signature, ok) = SHRINCSTestSigner.signStatefulAdapterAtLeaf(
            signingKey, publicKey, 1, rawHash
        );
        assertTrue(ok, "raw sign");
        rawKey = abi.encodePacked(commitment);
        rawEnvelope =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
    }
}
