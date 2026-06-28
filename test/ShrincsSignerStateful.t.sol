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
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "../contracts/ShrincsUtils.sol";

contract ShrincsStatefulSignerHarness {
    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        external
        pure
        returns (ShrincsTypes.SigningKey memory, ShrincsTypes.PublicKey memory, bool)
    {
        return ShrincsTestSigner.keygen(seedMaterial, maxStatefulSignatures);
    }

    function signStatefulRaw(ShrincsTypes.SigningKey memory signingKey, bytes memory message)
        external
        pure
        returns (ShrincsTypes.SigningKey memory, ShrincsTypes.StatefulSignature memory, bool)
    {
        return ShrincsTestSigner.signStatefulRaw(signingKey, message);
    }

    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatefulUncheckedMessage(expectedPublicKeyCommitment, publicKey, message, signature);
    }
}

contract ShrincsSignerStatefulTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    struct EncodedStatefulPublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    ShrincsStatefulSignerHarness internal harness;
    string internal vectors;

    function setUp() public {
        harness = new ShrincsStatefulSignerHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testStatefulSignerProducesVerifyingSignatureAndAdvancesLeaf() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = decodeRustStatefulVector(".stateful.cases.valid.calldata");

        assertEq(signature.q, 0, "first compact-path slot must be q=0");
        assertEq(signature.forsEntries.length, ShrincsTypes.STATEFUL_FORS_K_OPEN, "opened FORS tree count");
        assertEq(signature.authPath.length, ShrincsTypes.STATEFUL_MERKLE_HEIGHT, "balanced Merkle path length");
        assertTrue(
            harness.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature),
            "Rust-generated compact signature must verify in Solidity"
        );
    }

    function testStatefulSignerRejectsExhaustedKey() public {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        ) = decodeRustStatefulVector(".stateful.cases.valid.calldata");

        publicKey.statefulPublicKey = encodeStatefulPublicKey(publicKey.statefulPublicKey, uint32(signature.q));
        publicKey.publicKeyCommitment =
            abi.encodePacked(
                ShrincsUtils.publicKeyCommitmentFromParts(
                    publicKey.statefulPublicKey,
                    publicKey.pkSeed,
                    publicKey.hypertreeRoot
                )
            );

        assertFalse(
            harness.verifyUnsafeRaw(compositePublicKeyWord(publicKey), publicKey, message, signature),
            "q must be rejected once the key budget is exhausted"
        );
    }

    function decodeRustStatefulVector(string memory vectorKey)
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatefulSignature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (publicKey, message, signature) = abi.decode(args, (ShrincsTypes.PublicKey, bytes, ShrincsTypes.StatefulSignature));
    }

    function encodeStatefulPublicKey(bytes memory encoded, uint32 maxSignatures)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 pkSeed;
        bytes32 root;
        assembly {
            pkSeed := mload(add(encoded, 32))
            root := mload(add(encoded, 64))
        }
        return abi.encodePacked(pkSeed, root, bytes4(maxSignatures));
    }

    function compositePublicKeyWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 word) {
        require(publicKey.publicKeyCommitment.length == 32, "bad commitment length");
        bytes memory encoded = publicKey.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }

    function vectorArgs(string memory vectorKey) internal returns (bytes memory) {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
    }

    function stripSelector(bytes memory input) internal pure returns (bytes memory output) {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length;) {
            output[i - 4] = input[i];
            unchecked {
                ++i;
            }
        }
    }
}
