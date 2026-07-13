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
import {SHRINCS256sSha2} from "../contracts/SHRINCS256sSha2.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract GuardAccountSigningHarnessSha2 is SHRINCSStatelessVectorSigner {}

/// @dev Exposes the pinned SPHINCSPlusC sibling address so the guard can
/// deploy the delegate the stateless verify staticcalls into.
contract GuardDelegationHarnessSha2 is SHRINCS256sSha2 {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @title HashSuiteStatelessGuardSha2Test
/// @notice The SHA-256 twin of HashSuiteStatelessGuardTest. It is the guard
/// that actually matters: under the sha2 suite every scheme-hash helper is
/// `view` and reaches SHA-256 through the 0x02 precompile via `staticcall`,
/// so the whole verify stack widened from `pure` to `view` and the compiler
/// no longer forbids storage access. This drives a full stateless verify
/// under vm.record and asserts the verifier reads and writes zero storage
/// slots, so an accidental SLOAD/SSTORE in the widened stack fails here
/// instead of silently shipping. The keccak twin keeps the concrete keccak
/// verifier and runs under the keccak profiles; this file compiles only under
/// the sha2 profile (the concrete sha2 verifier is skipped elsewhere) and is
/// itself skip-listed out of the keccak profiles in foundry.toml.
contract HashSuiteStatelessGuardSha2Test is Test {
    GuardAccountSigningHarnessSha2 internal accountSigner;

    function setUp() public {
        accountSigner = new GuardAccountSigningHarnessSha2();
    }

    function test_statelessVerifyTouchesNoStorage() public {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("hashsuite stateless guard seed"), 4
        );
        assertTrue(ok, "guard keygen must succeed");

        bytes32 hash = keccak256("hashsuite stateless guard message");
        bytes32 sessionId;
        (sessionId, ok) = accountSigner.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        assertTrue(ok, "guard session must begin");
        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory signature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "guard signing must complete");

        GuardDelegationHarnessSha2 verifier =
            new GuardDelegationHarnessSha2();
        deployCodeTo(
            "SPHINCSPlusC256sSha2.sol:SPHINCSPlusC256sSha2",
            "",
            verifier.pinned()
        );
        bytes memory key =
            abi.encodePacked(publicKeyCommitmentWord(publicKey));
        bytes memory envelope =
            SHRINCS.encodeStatelessEnvelope(publicKey, signature);

        vm.record();
        bytes4 magic = verifier.verifyStateless(key, hash, envelope);
        (bytes32[] memory reads, bytes32[] memory writes) =
            vm.accesses(address(verifier));

        assertEq(
            magic,
            IERC7913SignatureVerifier.verify.selector,
            "guard stateless verify must accept"
        );
        assertEq(reads.length, 0, "verify must read no storage");
        assertEq(writes.length, 0, "verify must write no storage");
    }

    function publicKeyCommitmentWord(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 out)
    {
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            out := mload(add(commitmentBytes, 32))
        }
    }
}
