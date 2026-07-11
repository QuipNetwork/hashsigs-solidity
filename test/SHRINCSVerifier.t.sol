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
import {UXMSS} from "../contracts/UXMSS.sol";
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
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

        (UXMSS.StatefulSignature memory leafOneSignature, bool leafOneOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        assertTrue(leafOneOk, "leaf-1 signing must succeed");
        (UXMSS.StatefulSignature memory leafTwoSignature, bool leafTwoOk) =
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
            UXMSS.StatefulSignature memory signature
        )
    {
        return abi.decode(
            validEnvelope, (SHRINCS.PublicKey, UXMSS.StatefulSignature)
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
            UXMSS.StatefulSignature memory signature
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
            UXMSS.StatefulSignature memory signature
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

    function testRejectsTruncatedEnvelope() public view {
        bytes memory truncated = validEnvelope;
        assembly {
            // Shrink the in-memory copy of the envelope by one byte.
            mstore(truncated, sub(mload(truncated), 1))
        }
        assertEq(
            verifier.verify(validKey, signedHash, truncated),
            INVALID_SIGNATURE,
            "truncated envelope must be rejected"
        );
    }

    function testRejectsEmptyEnvelope() public view {
        assertEq(
            verifier.verify(validKey, signedHash, bytes("")),
            INVALID_SIGNATURE,
            "empty envelope must be rejected"
        );
    }

    function testRejectsGarbageEnvelope() public view {
        bytes memory garbage = abi.encodePacked(
            keccak256("garbage word one"),
            keccak256("garbage word two"),
            keccak256("garbage word three"),
            uint8(0x99)
        );
        assertEq(
            verifier.verify(validKey, signedHash, garbage),
            INVALID_SIGNATURE,
            "garbage envelope must be rejected"
        );
    }

    function testRejectsMismatchedBundleCommitment() public view {
        // Distinct from the wrong-key case: here the declared commitment
        // field DOES match the key, but the bundle no longer recomputes to
        // that commitment.
        (
            SHRINCS.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature
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

    function testCheckStatefulRejectsNonSelfCaller() public {
        (
            SHRINCS.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature
        ) = decodeStoredEnvelope();
        vm.expectRevert(bytes("only self"));
        verifier.checkStateful(
            keyCommitment, signedHash, publicKey, signature
        );
    }

    function testCheckStatelessBundleRejectsNonSelfCaller() public {
        (SHRINCS.PublicKey memory publicKey,) = decodeStoredEnvelope();
        vm.expectRevert(bytes("only self"));
        verifier.checkStatelessBundle(keyCommitment, publicKey);
    }

    /// @dev The deliberate revert-model change: with the try/catch removed,
    /// an inner out-of-gas is no longer swallowed to 0xffffffff. Stranding
    /// the single self-call hop under the 63/64 rule on a VALID signature
    /// makes the outer verify REVERT, so a genuine signature can never be
    /// misreported as invalid because of a gas shortfall.
    function testVerifyRevertsWhenInnerHopStrandedOnValidSig() public {
        // Full gas: the valid signature verifies.
        assertEq(
            verifier.verify(validKey, signedHash, validEnvelope),
            IERC7913SignatureVerifier.verify.selector,
            "control: valid signature verifies with ample gas"
        );

        // Measure the happy-path cost, then forward a fraction that lets the
        // key/envelope decode complete but strands the ~260k stateful hop
        // (which is the bulk of the work) under the 63/64 forwarding rule.
        uint256 gasBefore = gasleft();
        verifier.verify(validKey, signedHash, validEnvelope);
        uint256 happyGas = gasBefore - gasleft();

        (bool success, bytes memory ret) = address(verifier)
        .call{gas: happyGas * 3 / 4}(
            abi.encodeWithSelector(
                SHRINCSVerifier.verify.selector,
                validKey,
                signedHash,
                validEnvelope
            )
        );
        assertFalse(
            success,
            "stranded inner hop must revert, not swallow to 0xffffffff"
        );
        assertEq(
            ret.length, 0, "an out-of-gas revert carries no return data"
        );
    }

    function testFuzzVerifyNeverReverts(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) public view {
        // Any random input must produce a clean failure value, never a
        // revert.
        bytes4 result = verifier.verify(key, hash, signature);
        assertEq(
            result,
            INVALID_SIGNATURE,
            "random inputs must yield the failure value"
        );
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
