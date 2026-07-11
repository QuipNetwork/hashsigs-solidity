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
import {SHRINCSCore} from "../contracts/SHRINCSCore.sol";
import {SPHINCSPlusCCore} from "../contracts/SPHINCSPlusCCore.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
import {
    ShrincsAccountSigningFacade
} from "./helpers/ShrincsAccountSigningFacade.sol";
import {
    ShrincsStatelessVectorSigner
} from "./helpers/ShrincsStatelessVectorSigner.sol";

contract DelegationSigner is ShrincsStatelessVectorSigner {}

/// @dev Exposes the internal pinned SPHINCSPlusC address so the test can
/// deploy the sibling verifier exactly where verifyStateless delegates.
contract SHRINCS256sDelegationHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @notice Exercises the SHRINCS adapter's verifyStateless delegation to a
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

    function testVerifyStatelessRejectsTruncatedEnvelope() public view {
        bytes memory truncated = validEnvelope;
        assembly {
            mstore(truncated, sub(mload(truncated), 1))
        }
        assertEq(
            verifier.verifyStateless(validKey, signedHash, truncated),
            INVALID_SIGNATURE,
            "malformed envelope must be rejected before delegation"
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

    /// @dev Builds a stateless signature over the raw 32-byte hash message
    /// (exactly what verifyStateless passes to the pinned verifier) and the
    /// matching ERC-7913 key (the 32-byte bundle commitment). External so it
    /// runs in its own memory frame.
    function buildStatelessFixture()
        external
        returns (bytes memory key, bytes memory envelope, bytes32 hash)
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool ok
        ) = ShrincsAccountSigningFacade.keygen(
            bytes("stateless delegation fixture"), 4
        );
        require(ok, "keygen");

        hash = keccak256("stateless delegation message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        require(beginOk, "begin");
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = ShrincsAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        require(completeOk, "complete");

        key = abi.encodePacked(
            ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        envelope = SHRINCSCodec.encodeStatelessEnvelope(publicKey, signature);
    }
}
