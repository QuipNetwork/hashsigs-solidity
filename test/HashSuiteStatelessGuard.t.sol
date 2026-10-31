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
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

contract GuardAccountSigningHarness is SHRINCSStatelessVectorSigner {}

/// @dev Exposes the pinned SPHINCSPlusC sibling address so the guard can
/// deploy the delegate the stateless verify staticcalls into.
contract GuardDelegationHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @title HashSuiteStatelessGuardTest
/// @notice Statelessness guard for the HashSuite seam. The keccak suite keeps
/// every scheme-hash helper `pure`, so the whole verify stack stays `pure`
/// and the compiler already forbids storage access. This test is the
/// insurance the maintainer asked for against a future widening (the SHA-256
/// suite declares its helpers `view`): it drives a full stateless verify
/// under vm.record and asserts the verifier reads and writes zero storage
/// slots, so an accidental SLOAD/SSTORE introduced when the stack widens to
/// `view` fails here instead of silently shipping.
contract HashSuiteStatelessGuardTest is Test {
    GuardAccountSigningHarness internal accountSigner;

    function setUp() public {
        accountSigner = new GuardAccountSigningHarness();
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
            signingKey,
            publicKey,
            abi.encodePacked(
                SHRINCS.statelessRawMessageHash(
                    SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                        publicKey
                    ),
                    hash
                )
            )
        );
        assertTrue(ok, "guard session must begin");
        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory signature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "guard signing must complete");

        GuardDelegationHarness verifier = new GuardDelegationHarness();
        deployCodeTo(
            "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak",
            "",
            verifier.pinned()
        );
        bytes memory key =
            abi.encodePacked(publicKeyCommitmentWord(publicKey));
        bytes memory envelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);

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

    function test_statefulVerifyTouchesNoStorage() public {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSTestSigner.keygen(
            bytes("hashsuite stateful guard seed"), 4
        );
        assertTrue(ok, "guard keygen must succeed");

        bytes32 hash = keccak256("hashsuite stateful guard message");
        SHRINCS.Signature memory signature;
        bool signed;
        (signature, signed) = SHRINCSTestSigner.signStatefulAdapterAtLeaf(
            signingKey, publicKey, 1, hash
        );
        assertTrue(signed, "guard signing must succeed");

        GuardDelegationHarness verifier = new GuardDelegationHarness();
        bytes memory key =
            abi.encodePacked(publicKeyCommitmentWord(publicKey));
        bytes memory envelope =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);

        vm.record();
        bytes4 magic = verifier.verify(key, hash, envelope);
        (bytes32[] memory reads, bytes32[] memory writes) =
            vm.accesses(address(verifier));

        assertEq(
            magic,
            IERC7913SignatureVerifier.verify.selector,
            "guard stateful verify must accept"
        );
        assertEq(reads.length, 0, "verify must read no storage");
        assertEq(writes.length, 0, "verify must write no storage");
    }

    function test_sphincsPlusCVerifyTouchesNoStorage() public {
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
            signingKey,
            publicKey,
            abi.encodePacked(
                SHRINCS.statelessRawMessageHash(
                    SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                        publicKey
                    ),
                    hash
                )
            )
        );
        assertTrue(ok, "guard session must begin");
        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory signature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "guard signing must complete");

        GuardDelegationHarness verifier = new GuardDelegationHarness();
        deployCodeTo(
            "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak",
            "",
            verifier.pinned()
        );
        IERC7913SignatureVerifier sphincs =
            IERC7913SignatureVerifier(verifier.pinned());
        bytes memory sphincsKey = SHRINCS.encodeStatelessKey(
            signingKey.pkSeed, signingKey.hypertreeRoot
        );
        bytes memory sphincsEnvelope =
            SPHINCSPlusC.encodeStatelessSignatureEnvelope(signature);
        bytes32 signedHash = SHRINCS.statelessRawMessageHash(
            publicKeyCommitmentWord(publicKey), hash
        );

        vm.record();
        bytes4 magic =
            sphincs.verify(sphincsKey, signedHash, sphincsEnvelope);
        (bytes32[] memory reads, bytes32[] memory writes) =
            vm.accesses(address(sphincs));

        assertEq(
            magic,
            IERC7913SignatureVerifier.verify.selector,
            "guard sphincsplusc verify must accept"
        );
        assertEq(reads.length, 0, "verify must read no storage");
        assertEq(writes.length, 0, "verify must write no storage");
    }

    function test_verifyEntrypointsAreView() public view {
        _assertVerifyEntrypointsAreView(
            "out/SHRINCS256sKeccak.sol/SHRINCS256sKeccak.json"
        );
        _assertVerifyEntrypointsAreView(
            "out/SPHINCSPlusC256sKeccak.sol/SPHINCSPlusC256sKeccak.json"
        );
    }

    function _assertVerifyEntrypointsAreView(string memory path)
        internal
        view
    {
        string memory json = vm.readFile(path);
        uint256 found;
        for (uint256 i = 0; i < 64; ++i) {
            string memory typeKey =
                string.concat(".abi[", vm.toString(i), "].type");
            if (!vm.keyExistsJson(json, typeKey)) break;
            string memory abiType = vm.parseJsonString(json, typeKey);
            if (keccak256(bytes(abiType)) != keccak256("function")) {
                continue;
            }
            string memory name = vm.parseJsonString(
                json, string.concat(".abi[", vm.toString(i), "].name")
            );
            if (!_hasVerifyPrefix(name)) continue;
            string memory mutability = vm.parseJsonString(
                json,
                string.concat(".abi[", vm.toString(i), "].stateMutability")
            );
            if (keccak256(bytes(name)) == keccak256("verifyAndAttest")) {
                assertEq(
                    mutability,
                    "nonpayable",
                    "verifyAndAttest must be nonpayable"
                );
            } else {
                assertEq(mutability, "view", "verify* must be view");
            }
            ++found;
        }
        assertGt(found, 0, "artifact must declare verify*");
    }

    function _hasVerifyPrefix(string memory name)
        internal
        pure
        returns (bool)
    {
        bytes memory raw = bytes(name);
        if (raw.length < 6) return false;
        return raw[0] == "v" && raw[1] == "e" && raw[2] == "r"
            && raw[3] == "i" && raw[4] == "f" && raw[5] == "y";
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
