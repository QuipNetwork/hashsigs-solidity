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
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSStatelessVectorSigningFacade
} from "./helpers/SHRINCSStatelessVectorSigningFacade.sol";

/// @dev Exposes the staged signer internals this mutation suite drives: the
/// stateless verify entry point and the hypertree public root, which the
/// WOTS_PK case must recompute under the signer's omission switch.
contract SHRINCSAddressTweakSignerHarness is SHRINCSStatelessVectorSigner {
    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }

    function hypertreeRootFor(bytes32 statelessSkSeed, bytes32 pkSeed)
        external
        view
        returns (bytes32)
    {
        return hypertreePublicRoot(statelessSkSeed, pkSeed);
    }
}

/// @title SHRINCSAddressTweakMutationTest
/// @notice Mutation coverage (§8) for the address-tweak binding added in
/// oak-04: the compressed WOTS-C public-key hash binds the WOTS_PK ADRS word
/// (contracts/Hypertree.sol, offset 41 of the "wots-c-pk" preimage) and the
/// compressed FORS root binds the FORS_ROOTS ADRS word
/// (contracts/FORSMinusC.sol, offset 39 of the "fors-pk" preimage), both
/// [FIPS205 §4.2].
/// @dev The existing suites only prove the positive direction: signer and
/// verifier agree when both include the ADRS word. These tests drive the
/// signer with the ADRS word omitted end to end, key generation included, so
/// the signer stays self-consistent, and require the verifier to reject.
/// Delete the ADRS `mstore` from either production preimage and the matching
/// test fails, because signer and verifier then agree on the omitted layout.
contract SHRINCSAddressTweakMutationTest is Test {
    // line-length: allow — fmt cannot wrap a using-for directive
    using SHRINCSStatelessVectorSigningFacade for SHRINCSAddressTweakSignerHarness;

    // Stateful capacity for the throwaway keys; irrelevant to the stateless
    // paths under test, but keygen rejects zero.
    uint32 internal constant MAX_STATEFUL_SIGNATURES = 4;

    SHRINCSAddressTweakSignerHarness internal signer;

    function setUp() public {
        signer = new SHRINCSAddressTweakSignerHarness();
    }

    /// @notice A signature whose WOTS-C public-key compression omits the
    /// WOTS_PK ADRS word must not verify.
    function testWotsCPkAddressWordOmissionIsRejected() public {
        bytes memory seedMaterial = bytes("oak-04 wots-c-pk adrs mutation");
        bytes memory message =
            abi.encodePacked(keccak256("wots-c-pk adrs mutation message"));

        SHRINCS.SigningKey memory signingKey;
        SHRINCS.PublicKey memory publicKey;
        bool ok;
        (signingKey, publicKey, ok) =
            SHRINCSTestSigner.keygen(seedMaterial, MAX_STATEFUL_SIGNATURES);
        assertTrue(ok, "keygen must succeed");

        // Control: with the switch off the staged signer reproduces the
        // library keygen root, so the patched key below differs from the
        // honest one only in the omitted ADRS word.
        bytes32 controlRoot = signer.hypertreeRootFor(
            signingKey.statelessSkSeed, signingKey.pkSeed
        );
        assertEq(
            controlRoot,
            signingKey.hypertreeRoot,
            "staged signer must reproduce the keygen hypertree root"
        );

        signer.setAddressWordOmission(true, false);
        bytes32 omittedRoot = signer.hypertreeRootFor(
            signingKey.statelessSkSeed, signingKey.pkSeed
        );
        assertTrue(
            omittedRoot != controlRoot,
            "omitting the WOTS_PK ADRS must change the hypertree root"
        );

        bytes32 commitment;
        (signingKey, publicKey, commitment) =
            _rebindHypertreeRoot(signingKey, publicKey, omittedRoot);

        SPHINCSPlusC.Signature memory signature;
        (publicKey, signature) = _signWithKey(signingKey, publicKey, message);

        assertFalse(
            signer.verifyUnsafeRaw(
                commitment, publicKey, message, signature
            ),
            "signature built without the WOTS_PK ADRS must be rejected"
        );
    }

    /// @notice A signature whose FORS root compression omits the FORS_ROOTS
    /// ADRS word must not verify.
    function testForsRootsAddressWordOmissionIsRejected() public {
        bytes memory seedMaterial = bytes("oak-04 fors-pk adrs mutation");
        bytes memory message =
            abi.encodePacked(keccak256("fors-pk adrs mutation message"));

        // The FORS root is not committed in the public key, so an honest
        // key generation is enough here; only the signed root diverges.
        signer.setAddressWordOmission(false, true);
        bytes32 sessionId;
        bool ok;
        (sessionId, ok) = signer.beginSessionFromSeed(
            seedMaterial, MAX_STATEFUL_SIGNATURES, message
        );
        assertTrue(ok, "session must start");

        SHRINCS.PublicKey memory publicKey;
        SPHINCSPlusC.Signature memory signature;
        (publicKey, signature, ok) = signer.completeSession(sessionId);
        assertTrue(ok, "signing must complete");

        assertFalse(
            signer.verifyUnsafeRaw(
                _commitmentOf(publicKey), publicKey, message, signature
            ),
            "signature built without the FORS_ROOTS ADRS must be rejected"
        );
    }

    /// @dev Replace the hypertree root in a freshly generated key pair and
    /// recompute the bundle commitment, so the signer and the verifier agree
    /// on every field except the tweaked compression.
    function _rebindHypertreeRoot(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes32 hypertreeRoot
    )
        internal
        pure
        returns (
            SHRINCS.SigningKey memory,
            SHRINCS.PublicKey memory,
            bytes32 commitment
        )
    {
        signingKey.hypertreeRoot = hypertreeRoot;
        publicKey.hypertreeRoot = abi.encodePacked(hypertreeRoot);
        commitment = SHRINCS.publicKeyCommitmentFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );
        publicKey.publicKeyCommitment = abi.encodePacked(commitment);
        return (signingKey, publicKey, commitment);
    }

    /// @dev Run one staged stateless signing session against a caller-built
    /// key pair.
    function _signWithKey(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes memory message
    )
        internal
        returns (SHRINCS.PublicKey memory, SPHINCSPlusC.Signature memory)
    {
        (bytes32 sessionId, bool ok) =
            signer.beginSession(signingKey, publicKey, message);
        assertTrue(ok, "session must start");
        SPHINCSPlusC.Signature memory signature;
        (publicKey, signature, ok) = signer.completeSession(sessionId);
        assertTrue(ok, "signing must complete");
        return (publicKey, signature);
    }

    function _commitmentOf(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 commitment)
    {
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        // Memory-safe: reads the first word of the commitment bytes value
        // (length word + 32); no memory is written.
        assembly ("memory-safe") {
            commitment := mload(add(commitmentBytes, 32))
        }
    }
}
