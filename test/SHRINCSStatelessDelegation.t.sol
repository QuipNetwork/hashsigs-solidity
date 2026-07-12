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
import {Hypertree} from "../contracts/Hypertree.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract DelegationSigner is SHRINCSStatelessVectorSigner {}

/// @dev Exposes the internal pinned SPHINCSPlusC address so the test can
/// deploy the sibling verifier exactly where verifyStateless delegates.
contract SHRINCS256sDelegationHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @notice Exercises the SHRINCSVerifier's verifyStateless delegation to a
/// locally deployed SPHINCSPlusC sibling at the pinned CREATE3 address.
/// Profile-gated (256s); the stateless signature is produced in-Solidity.
contract SHRINCSStatelessDelegationTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    SHRINCS256sDelegationHarness internal verifier;
    DelegationSigner internal signer;

    bytes32 internal signedHash;
    bytes internal validKey;
    bytes internal validEnvelope;

    function setUp() public {
        signer = new DelegationSigner();
        // Build the valid stateless fixture first (in a dedicated frame) so
        // its ~90 KB working set does not stack under later allocations.
        (validKey, validEnvelope, signedHash) = this.buildStatelessFixture();

        verifier = new SHRINCS256sDelegationHarness();
        // Deploy the SPHINCSPlusC 256s sibling exactly where the verifier
        // delegates, so verifyStateless reaches real verification code.
        deployCodeTo(
            "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak",
            "",
            verifier.pinned()
        );
    }

    function testVerifyStatelessValidSignatureReturnsSelector() public view {
        assertEq(
            verifier.verifyStateless(validKey, signedHash, validEnvelope),
            IERC7913SignatureVerifier.verify.selector,
            "valid stateless signature must delegate and verify"
        );
    }

    function testVerifyStatelessRejectsWrongCommitment() public view {
        bytes memory wrongKey =
            abi.encodePacked(keccak256("some other commitment"));
        assertEq(
            verifier.verifyStateless(wrongKey, signedHash, validEnvelope),
            INVALID_SIGNATURE,
            "wrong commitment must be rejected before delegation"
        );
    }

    function testVerifyStatelessRejectsBadKeyLength() public view {
        bytes memory badKey = hex"1234";
        assertEq(
            verifier.verifyStateless(badKey, signedHash, validEnvelope),
            INVALID_SIGNATURE,
            "malformed key must be rejected"
        );
    }

    // Re-tag model: a one-byte truncation leaves every re-tagged offset and
    // length in bounds, so the bundle check passes and the delegate signature
    // is rebuilt with a corrupted last node. This 256s fixture is unmasked,
    // so the sibling's FORS-C plus hypertree reconstruction fails and
    // verifyStateless returns 0xffffffff without reverting (a malformed case
    // moving within {revert, false}). Under a masked-hash profile the same
    // truncation would instead verify as pure encoding malleability, pinned
    // by testTailTruncationAcceptedUnderMaskedProfile in the SHRINCSVerifier
    // suite.
    function testVerifyStatelessRejectsTruncatedEnvelope() public view {
        bytes memory truncated = validEnvelope;
        assembly {
            mstore(truncated, sub(mload(truncated), 1))
        }
        assertEq(
            verifier.verifyStateless(validKey, signedHash, truncated),
            INVALID_SIGNATURE,
            "truncated stateless envelope must be rejected"
        );
    }

    // Pins the delegation slice-build behavior change (epic Z5). The
    // signature's public-key bundle is the valid fixture's, so the commitment
    // and validPublicKey checks pass and prepareStatelessDelegation reaches
    // SHRINCS.sliceStatelessSignatureEnvelope. That build indexes the
    // last hypertree layer's last authPath element; on an empty last-layer
    // authPath (or an empty hypertree) the index reads Panic. verifyStateless
    // wraps the delegation build in no try/catch, so the Panic propagates and
    // the call lands in {revert, false} — never a wrong-accept. The prior
    // canonicity walk rejected these at a sibling-side length check; nothing
    // else pins the new revert. Panic-revert is the expected arm here.
    function testVerifyStatelessSliceBuildRevertsOnMalformedAuthPath()
        public
    {
        (bytes memory emptyAuthPath, bytes memory emptyHypertree) =
            this.buildMalformedEnvelopes();
        assertTrue(
            verifyStatelessRejected(emptyAuthPath),
            "empty last-layer authPath must not wrong-accept"
        );
        assertTrue(
            verifyStatelessRejected(emptyHypertree),
            "empty hypertree must not wrong-accept"
        );
    }

    function testVerifyStatelessRejectsTamperedHash() public view {
        assertEq(
            verifier.verifyStateless(
                validKey, keccak256("other hash"), validEnvelope
            ),
            INVALID_SIGNATURE,
            "a hash the signature does not authorize must fail"
        );
    }

    /// @dev The deliberate revert-model property, on the one external call
    /// the memory restructure left in the verifier surface. With no try/catch
    /// around the stateless delegation, an out-of-gas in the pinned
    /// SPHINCSPlusC sibling is not swallowed to 0xffffffff: stranding that
    /// delegation hop under the 63/64 rule on a VALID signature makes the
    /// outer verifyStateless REVERT, so a genuine signature can never be
    /// misreported as invalid because of a gas shortfall. (The stateful
    /// verify path no longer makes any external call, so it has no equivalent
    /// hop to strand.)
    function testVerifyStatelessRevertsWhenDelegationStrandedOnValidSig()
        public
    {
        // Full gas: the valid stateless signature delegates and verifies.
        assertEq(
            verifier.verifyStateless(validKey, signedHash, validEnvelope),
            IERC7913SignatureVerifier.verify.selector,
            "control: valid stateless signature verifies with ample gas"
        );

        // Measure the happy-path cost, then forward a fraction that lets the
        // key/envelope decode and bundle check complete but strands the
        // delegation into the pinned sibling (the bulk of the work) under the
        // 63/64 forwarding rule.
        uint256 gasBefore = gasleft();
        verifier.verifyStateless(validKey, signedHash, validEnvelope);
        uint256 happyGas = gasBefore - gasleft();

        (bool success, bytes memory ret) = address(verifier)
        .call{gas: happyGas * 3 / 4}(
            abi.encodeCall(
                verifier.verifyStateless,
                (validKey, signedHash, validEnvelope)
            )
        );
        assertFalse(
            success,
            "stranded delegation hop must revert, not swallow to 0xffffffff"
        );
        assertEq(
            ret.length, 0, "an out-of-gas revert carries no return data"
        );
    }

    /// @dev Builds a stateless signature over the raw 32-byte hash message
    /// (exactly what verifyStateless passes to the pinned verifier) and the
    /// matching ERC-7913 key (the 32-byte bundle commitment). External so it
    /// runs in its own memory frame.
    function buildStatelessFixture()
        external
        returns (bytes memory key, bytes memory envelope, bytes32 hash)
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("stateless delegation fixture"), 4
        );
        require(ok, "keygen");

        hash = keccak256("stateless delegation message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        require(beginOk, "begin");
        SPHINCSPlusC.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "complete");

        key = abi.encodePacked(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        envelope = SHRINCS.encodeStatelessEnvelope(publicKey, signature);
    }

    /// @dev Outcome-only rejection check for the slice-build pin: a revert
    /// (Panic) and a `0xffffffff` return are the same safe outcome. Returns
    /// true iff verifyStateless did NOT wrong-accept.
    function verifyStatelessRejected(bytes memory envelope)
        internal
        view
        returns (bool)
    {
        try verifier.verifyStateless(
            validKey, signedHash, envelope
        ) returns (
            bytes4 selector
        ) {
            return selector == INVALID_SIGNATURE;
        } catch {
            return true;
        }
    }

    /// @dev Builds two envelopes whose public-key bundle is the valid
    /// fixture's (same keygen seed, so the installed-commitment and
    /// validPublicKey checks pass) but whose stateless signature is malformed
    /// so the delegation slice-build Panics: one with an empty last-layer
    /// authPath, one with an empty hypertree. External so the large fixture
    /// working set runs in its own memory frame.
    function buildMalformedEnvelopes()
        external
        returns (bytes memory emptyAuthPath, bytes memory emptyHypertree)
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("stateless delegation fixture"), 4
        );
        require(ok, "keygen");

        bytes32 hash = keccak256("stateless delegation message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        require(beginOk, "begin");
        SPHINCSPlusC.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "complete");

        // Empty the last layer's authPath: slice-build's authPath[last] index
        // read Panics; the bundle is untouched so it reaches the slice build.
        uint256 last = signature.hypertree.length - 1;
        signature.hypertree[last].authPath = new bytes[](0);
        emptyAuthPath = SHRINCS.encodeStatelessEnvelope(publicKey, signature);

        // Empty the whole hypertree: slice-build's hypertree[last] index read
        // Panics.
        signature.hypertree = new Hypertree.HypertreeLayerSignature[](0);
        emptyHypertree =
            SHRINCS.encodeStatelessEnvelope(publicKey, signature);
    }
}
