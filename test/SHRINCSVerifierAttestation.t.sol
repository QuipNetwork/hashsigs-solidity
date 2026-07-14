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
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

/// @dev Minimal concrete instance of the abstract profile base, mirroring
/// SHRINCSVerifier.t.sol's harness: the attestation paths are
/// profile-agnostic and never read the pinned SPHINCSPlusC address.
contract SHRINCSAttestationHarness is SHRINCSVerifier {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

/// @notice Tests for the IERC7913TransientAttestation surface of
/// SHRINCSVerifier: `verifyAndAttest` writes the shared-spec transient
/// slot only on a successful verification, `wasVerified` reads it, and
/// the plain `verify` never attests.
contract SHRINCSVerifierAttestationTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    bytes4 internal constant MAGIC =
        IERC7913SignatureVerifier.verify.selector;

    SHRINCSVerifier internal verifier;

    // One stateful key is generated in setUp; the leaf-1 signature is
    // shared across the attestation tests.
    bytes32 internal signedHash;
    bytes32 internal validKeyHash;
    bytes internal validKey;
    bytes internal validEnvelope;

    function setUp() public {
        verifier = new SHRINCSAttestationHarness();

        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(
            bytes("shrincs erc7913 transient attestation seed"), 4
        );
        assertTrue(keygenOk, "in-test keygen must succeed");

        // The ERC-7913 hash IS the signed message: sign exactly its 32
        // packed bytes.
        signedHash = keccak256("shrincs erc7913 transient attestation");
        bytes memory message = abi.encodePacked(signedHash);
        (SHRINCS.Signature memory leafOneSignature, bool leafOneOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        assertTrue(leafOneOk, "leaf-1 signing must succeed");

        // The ERC-7913 key is the 32-byte bundle commitment word; the
        // attestation keyHash is keccak256 over those raw key bytes.
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 commitmentWord;
        assembly {
            commitmentWord := mload(add(commitmentBytes, 32))
        }
        validKey = abi.encodePacked(commitmentWord);
        validKeyHash = keccak256(validKey);
        validEnvelope =
            SHRINCS.encodeStatefulEnvelope(publicKey, leafOneSignature);

        // Attest here so testAttestationClearedInNextTransaction can
        // assert the transient slot is gone: Foundry runs setUp and each
        // test as separate transactions, clearing EIP-1153 state between
        // them.
        assertEq(
            verifier.verifyAndAttest(validKey, signedHash, validEnvelope),
            MAGIC,
            "setUp attestation call must verify"
        );
    }

    function testVerifyAndAttestValidSignatureAttestsForCaller() public {
        assertEq(
            verifier.verifyAndAttest(validKey, signedHash, validEnvelope),
            MAGIC,
            "verifyAndAttest must return the ERC-7913 magic value"
        );
        assertTrue(
            verifier.wasVerified(address(this), validKeyHash, signedHash),
            "the exact (caller, keyHash, hash) triple must be attested"
        );
    }

    function testAttestationClearedInNextTransaction() public view {
        // setUp attested this exact triple, but setUp is a previous
        // transaction: EIP-1153 transient storage must have been cleared.
        assertFalse(
            verifier.wasVerified(address(this), validKeyHash, signedHash),
            "attestation must not survive into the next transaction"
        );
    }

    function testAttestationIsBoundToTheExactTriple() public {
        verifier.verifyAndAttest(validKey, signedHash, validEnvelope);

        assertFalse(
            verifier.wasVerified(address(0xBEEF), validKeyHash, signedHash),
            "wrong account must not read as attested"
        );
        assertFalse(
            verifier.wasVerified(
                address(this), keccak256("other key"), signedHash
            ),
            "wrong keyHash must not read as attested"
        );
        assertFalse(
            verifier.wasVerified(
                address(this), validKeyHash, keccak256("other hash")
            ),
            "wrong hash must not read as attested"
        );
    }

    function testAttestationIsBoundToMsgSender() public {
        address smartWallet = makeAddr("smartWallet");
        vm.prank(smartWallet);
        assertEq(
            verifier.verifyAndAttest(validKey, signedHash, validEnvelope),
            MAGIC,
            "pranked attestation call must verify"
        );
        assertTrue(
            verifier.wasVerified(smartWallet, validKeyHash, signedHash),
            "the attestation must be recorded for the calling account"
        );
        assertFalse(
            verifier.wasVerified(address(this), validKeyHash, signedHash),
            "no attestation may exist for a non-calling account"
        );
    }

    function testInvalidSignatureReturnsFailureAndDoesNotAttest() public {
        // Well-formed but invalid: the key names a different installed
        // commitment, mirroring verify's wrong-commitment rejection.
        bytes memory wrongKey =
            abi.encodePacked(keccak256("some other installed commitment"));
        assertEq(
            verifier.verifyAndAttest(wrongKey, signedHash, validEnvelope),
            INVALID_SIGNATURE,
            "failure value must match verify's"
        );
        assertFalse(
            verifier.wasVerified(
                address(this), keccak256(wrongKey), signedHash
            ),
            "a failed verification must attest nothing"
        );
    }

    function testTamperedHashReturnsFailureAndDoesNotAttest() public {
        bytes32 otherHash = keccak256("a different message hash");
        assertEq(
            verifier.verifyAndAttest(validKey, otherHash, validEnvelope),
            INVALID_SIGNATURE,
            "failure value must match verify's"
        );
        assertFalse(
            verifier.wasVerified(address(this), validKeyHash, otherHash),
            "a failed verification must attest nothing"
        );
    }

    // Revert-model parity with verify: a malformed (word-truncated)
    // envelope reverts through the same re-tagged calldata access (see
    // SHRINCSVerifier.t.sol testRevertsOnTruncatedEnvelope).
    function testMalformedEnvelopeRevertsLikeVerify() public {
        bytes memory truncated = validEnvelope;
        assembly {
            // Shrink the in-memory copy of the envelope by one 32-byte
            // word.
            mstore(truncated, sub(mload(truncated), 32))
        }
        vm.expectRevert();
        verifier.verifyAndAttest(validKey, signedHash, truncated);
    }

    function testViewVerifyNeverAttests() public {
        assertEq(
            verifier.verify(validKey, signedHash, validEnvelope),
            MAGIC,
            "plain verify must succeed"
        );
        assertFalse(
            verifier.wasVerified(address(this), validKeyHash, signedHash),
            "the view verify must never write an attestation"
        );
    }

    // Integrators must not reach verifyAndAttest through a staticcall:
    // the success-path TSTORE is illegal in a static context, so a valid
    // signature reverts there instead of attesting.
    function testVerifyAndAttestRevertsUnderStaticcall() public {
        bytes memory callData = abi.encodeCall(
            verifier.verifyAndAttest, (validKey, signedHash, validEnvelope)
        );
        (bool ok,) = address(verifier).staticcall(callData);
        assertFalse(
            ok, "verifyAndAttest under staticcall must revert on a valid sig"
        );
    }

    function testFuzzWasVerifiedFalseUnlessExactTripleAttested(
        address account,
        bytes32 keyHash,
        bytes32 hash
    ) public {
        verifier.verifyAndAttest(validKey, signedHash, validEnvelope);
        bool attested = account == address(this) && keyHash == validKeyHash
            && hash == signedHash;
        assertEq(
            verifier.wasVerified(account, keyHash, hash),
            attested,
            "only the attested triple may read as verified"
        );
    }

    function testGasSnapshotVerifyAndAttestVsVerify() public {
        // Untimed warm-up call: the transaction's first call into the
        // large verifier pays one-time cold account/code access costs
        // that would otherwise be booked entirely to whichever entrypoint
        // is measured first.
        verifier.verify(validKey, signedHash, validEnvelope);

        uint256 gasBefore = gasleft();
        bytes4 viewResult =
            verifier.verify(validKey, signedHash, validEnvelope);
        uint256 verifyGas = gasBefore - gasleft();

        gasBefore = gasleft();
        bytes4 attestResult =
            verifier.verifyAndAttest(validKey, signedHash, validEnvelope);
        uint256 attestGas = gasBefore - gasleft();

        assertEq(viewResult, MAGIC, "snapshot verify call must succeed");
        assertEq(attestResult, MAGIC, "snapshot attest call must succeed");
        assertGe(
            attestGas,
            verifyGas,
            "attesting must not be cheaper than the shared verify path"
        );
        // Recorded happy-path gas (see test logs with -vv for the current
        // numbers).
        emit log_named_uint("happy-path verify gas", verifyGas);
        emit log_named_uint("happy-path verifyAndAttest gas", attestGas);
        emit log_named_uint(
            "attestation overhead gas", attestGas - verifyGas
        );
    }
}
