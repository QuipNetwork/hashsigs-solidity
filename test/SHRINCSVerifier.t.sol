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
import {SHRINCSCodec} from "../contracts/SHRINCSCodec.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

/// @dev Minimal concrete instance of the abstract profile base, used to
/// exercise the profile-agnostic stateful verify/decode logic under
/// whichever profile the suite runs. Mirrors the empty concrete subclasses
/// (SHRINCS256sKeccak / SHRINCS128sQ18Keccak / SHRINCS128sQ20Keccak)
/// without pinning the test to any one of them. The pinned SPHINCSPlusC
/// address is irrelevant here (the stateful path never reads it), so it
/// returns the zero address; verifyStateless delegation is covered by the
/// profile-gated SHRINCSStatelessDelegation suite against a real deployable.
contract SHRINCSVerifierHarness is SHRINCSVerifier {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

contract SHRINCSVerifierTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    SHRINCSVerifier internal verifier;

    // One stateful key is generated in setUp; signatures at two in-budget
    // leaves are shared across the happy-path and mutation tests.
    bytes32 internal signedHash;
    bytes32 internal keyCommitment;
    bytes internal validKey;
    bytes internal validEnvelope;
    bytes internal secondLeafEnvelope;

    function setUp() public {
        verifier = new SHRINCSVerifierHarness();

        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(
            bytes("shrincs erc7913 stateful verifier seed"), 4
        );
        assertTrue(keygenOk, "in-test keygen must succeed");

        // The ERC-7913 hash IS the signed message: sign exactly its 32 packed
        // bytes.
        signedHash = keccak256("shrincs erc7913 stateful verifier vector");
        bytes memory message = abi.encodePacked(signedHash);

        (SHRINCS.Signature memory leafOneSignature, bool leafOneOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        assertTrue(leafOneOk, "leaf-1 signing must succeed");
        (SHRINCS.Signature memory leafTwoSignature, bool leafTwoOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 2, message);
        assertTrue(leafTwoOk, "leaf-2 signing must succeed");

        // The ERC-7913 key is the 32-byte bundle commitment word.
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 commitmentWord;
        assembly {
            commitmentWord := mload(add(commitmentBytes, 32))
        }
        keyCommitment = commitmentWord;
        validKey = abi.encodePacked(keyCommitment);

        // Encode through the codec so the tests pin the same format
        // definition the verifier decodes.
        validEnvelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, leafOneSignature);
        secondLeafEnvelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, leafTwoSignature);
    }

    // decodeStoredEnvelope: Reload the shared valid envelope as mutable
    // memory structs.
    function decodeStoredEnvelope()
        internal
        view
        returns (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        )
    {
        return abi.decode(
            validEnvelope, (SHRINCS.PublicKey, SHRINCS.Signature)
        );
    }

    function testVerifyValidSignatureReturnsMagicValue() public view {
        bytes4 result = verifier.verify(validKey, signedHash, validEnvelope);
        assertEq(
            result,
            IERC7913SignatureVerifier.verify.selector,
            "must return the interface selector"
        );
        assertEq(
            result,
            bytes4(0x024ad318),
            "selector must be the ERC-7913 magic value"
        );
    }

    function testVerifyValidSecondLeafSignatureReturnsMagicValue()
        public
        view
    {
        // The verifier checks signature validity only; any in-budget leaf
        // verifies.
        assertEq(
            verifier.verify(validKey, signedHash, secondLeafEnvelope),
            IERC7913SignatureVerifier.verify.selector,
            "a second in-budget leaf must also verify"
        );
    }

    function testVersionTag() public view {
        assertEq(
            verifier.VERSION_TAG(),
            keccak256("quip.shrincs-verifier.v1"),
            "version tag"
        );
    }

    function testRejectsBadKeyLengths() public view {
        uint256[5] memory badLengths = [uint256(0), 20, 31, 33, 64];
        for (uint256 i = 0; i < badLengths.length; i++) {
            bytes memory key = new bytes(badLengths[i]);
            for (uint256 j = 0; j < key.length; j++) {
                key[j] = validKey[j % 32];
            }
            assertEq(
                verifier.verify(key, signedHash, validEnvelope),
                INVALID_SIGNATURE,
                "bad key length must be rejected"
            );
        }
    }

    function testRejectsWrongCommitment() public view {
        bytes memory wrongKey =
            abi.encodePacked(keccak256("some other installed commitment"));
        assertEq(
            verifier.verify(wrongKey, signedHash, validEnvelope),
            INVALID_SIGNATURE,
            "wrong commitment must be rejected"
        );
    }

    function testRejectsTamperedHash() public view {
        bytes32 otherHash = keccak256("a different message hash");
        assertEq(
            verifier.verify(validKey, otherHash, validEnvelope),
            INVALID_SIGNATURE,
            "tampered hash must be rejected"
        );
    }

    function testRejectsTamperedChainValue() public view {
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = decodeStoredEnvelope();
        signature.chains[0] = bytes32(uint256(signature.chains[0]) ^ 1);
        bytes memory envelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            verifier.verify(validKey, signedHash, envelope),
            INVALID_SIGNATURE,
            "tampered WOTS chain must fail"
        );
    }

    function testRejectsTamperedAuthPath() public view {
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = decodeStoredEnvelope();
        signature.authPath[0] = bytes32(uint256(signature.authPath[0]) ^ 1);
        bytes memory envelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            verifier.verify(validKey, signedHash, envelope),
            INVALID_SIGNATURE,
            "tampered auth path must fail"
        );
    }

    // Re-tag model: removing a whole 32-byte word makes the last auth-path
    // array's length word overcommit the calldata (it claims one more word
    // than remains within calldatasize), so solc's calldata tail access
    // reverts; the malformed envelope stays in {revert, false}. Removing a
    // full word (not 1 to 16 bytes) is deliberate: a short tail strip is
    // pure encoding malleability under a masked-hash profile. solc
    // bounds-checks the re-tagged reads against calldatasize, not the
    // envelope slice, so the stripped tail is read back from the outer ABI
    // zero-padding; masking already zeroes those low bytes, so the final
    // node is bit-identical and still verifies (pinned by
    // testTailTruncationAcceptedUnderMaskedProfile).
    function testRejectsTruncatedEnvelope() public {
        bytes memory truncated = validEnvelope;
        assembly {
            // Shrink the in-memory copy of the envelope by one 32-byte word.
            mstore(truncated, sub(mload(truncated), 32))
        }
        vm.expectRevert();
        verifier.verify(validKey, signedHash, truncated);
    }

    // M1 pinning: under masked-hash (128s) profiles a valid envelope with a
    // 1-to-16-byte tail truncation still verifies. solc bounds-checks the
    // re-tagged calldata reads against calldatasize (the whole tx calldata),
    // not the envelope slice, so the final auth-path node's stripped tail is
    // read back from the outer ABI zero-padding. Under 128s maskHash already
    // zeroes those low bytes, so the read-back node is bit-identical and the
    // signature verifies; this is pure encoding malleability, never a
    // wrong-accept. Under 256s (unmasked) the corrupted node yields
    // 0xffffffff without reverting: the bounds check never fires for a tail
    // truncation, so rejection there is purely cryptographic.
    // NUM_HYPERTREE_LAYERS == 1 distinguishes 128s from 256s (d == 8).
    function testTailTruncationAcceptedUnderMaskedProfile() public view {
        bytes4 expected = SHRINCSParams.NUM_HYPERTREE_LAYERS == 1
            ? IERC7913SignatureVerifier.verify.selector
            : INVALID_SIGNATURE;

        bytes memory oneByte = validEnvelope;
        assembly {
            mstore(oneByte, sub(mload(oneByte), 1))
        }
        assertEq(
            verifier.verify(validKey, signedHash, oneByte),
            expected,
            "1-byte tail truncation outcome must match the profile"
        );

        bytes memory sixteenByte = validEnvelope;
        assembly {
            mstore(sixteenByte, sub(mload(sixteenByte), 16))
        }
        assertEq(
            verifier.verify(validKey, signedHash, sixteenByte),
            expected,
            "16-byte tail truncation outcome must match the profile"
        );
    }

    function testRejectsEmptyEnvelope() public {
        vm.expectRevert();
        verifier.verify(validKey, signedHash, bytes(""));
    }

    function testRejectsGarbageEnvelope() public {
        bytes memory garbage = abi.encodePacked(
            keccak256("garbage word one"),
            keccak256("garbage word two"),
            keccak256("garbage word three"),
            uint8(0x99)
        );
        vm.expectRevert();
        verifier.verify(validKey, signedHash, garbage);
    }

    function testRejectsMismatchedBundleCommitment() public view {
        // Distinct from the wrong-key case: here the declared commitment
        // field DOES match the key, but the bundle no longer recomputes to
        // that commitment.
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = decodeStoredEnvelope();
        bytes32 fakeCommitment = keccak256("mismatched bundle commitment");
        publicKey.publicKeyCommitment = abi.encodePacked(fakeCommitment);
        bytes memory envelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            verifier.verify(
                abi.encodePacked(fakeCommitment), signedHash, envelope
            ),
            INVALID_SIGNATURE,
            "bundle that does not recompute to the key commitment must fail"
        );
    }

    // The stateful `verify` path no longer makes any external call (the
    // memory->calldata self-call hops and their onlySelf modifier were
    // removed when SHRINCS became memory-typed), so there is no inner hop to
    // strand here. The equivalent out-of-gas revert-model property now lives
    // on the one remaining external call — verifyStateless's delegation to
    // the pinned SPHINCSPlusC sibling — and is exercised against a real
    // deployed sibling by SHRINCSStatelessDelegationTest's
    // testVerifyStatelessRevertsWhenDelegationStrandedOnValidSig.

    function testFuzzVerifyNeverWrongAccepts(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) public view {
        // Under the revert-on-malformed model a random input either returns
        // the failure value or reverts inside abi.decode; it must never yield
        // the success selector (no wrong-accept).
        try verifier.verify(key, hash, signature) returns (bytes4 result) {
            assertTrue(
                result != IERC7913SignatureVerifier.verify.selector,
                "random inputs must never wrong-accept"
            );
        } catch {
            // A revert on a malformed envelope is a safe rejection.
        }
    }

    function testGasSnapshotHappyPathVerify() public {
        uint256 gasBefore = gasleft();
        bytes4 result = verifier.verify(validKey, signedHash, validEnvelope);
        uint256 gasUsed = gasBefore - gasleft();
        assertEq(
            result,
            IERC7913SignatureVerifier.verify.selector,
            "snapshot call must succeed"
        );
        // Recorded happy-path verify gas (see test logs with -vv for the
        // current number).
        emit log_named_uint("happy-path verify gas", gasUsed);
    }
}
