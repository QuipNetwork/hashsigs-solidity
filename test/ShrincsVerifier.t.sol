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
import {IERC7913SignatureVerifier} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {ShrincsCodec} from "../contracts/ShrincsCodec.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsVerifier} from "../contracts/ShrincsVerifier.sol";
import {ShrincsStatelessVectorSigner} from "./helpers/ShrincsStatelessVectorSigner.sol";
import {ShrincsStatelessVectorSigningFacade} from "./helpers/ShrincsStatelessVectorSigningFacade.sol";

contract ShrincsVerifierTest is Test {
    using ShrincsStatelessVectorSigningFacade for ShrincsStatelessVectorSigner;

    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    ShrincsVerifier internal verifier;

    // One real stateless signature is generated once in setUp and shared across the
    // happy-path and mutation tests because staged signing sessions are heavy.
    bytes32 internal signedHash;
    bytes32 internal keyCommitment;
    bytes internal validKey;
    bytes internal validEnvelope;

    function setUp() public {
        verifier = new ShrincsVerifier();
        ShrincsStatelessVectorSigner signer = new ShrincsStatelessVectorSigner();

        // The ERC-7913 hash IS the signed message: sign exactly its 32 packed bytes.
        signedHash = keccak256("shrincs erc7913 verifier vector");
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature, bool ok) =
            signer.signFromSeed(bytes("shrincs erc7913 verifier seed"), 4, abi.encodePacked(signedHash));
        assertTrue(ok, "in-test stateless signing must succeed");

        // The ERC-7913 key is the 32-byte bundle commitment word.
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        bytes32 commitmentWord;
        assembly {
            commitmentWord := mload(add(commitmentBytes, 32))
        }
        keyCommitment = commitmentWord;
        validKey = abi.encodePacked(keyCommitment);

        // Encode through the codec so the tests pin the same format definition the verifier decodes.
        validEnvelope = ShrincsCodec.encodeStatelessEnvelope(publicKey, signature);
    }

    // decodeStoredEnvelope: Reload the shared valid envelope as mutable memory structs.
    function decodeStoredEnvelope()
        internal
        view
        returns (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature)
    {
        return abi.decode(validEnvelope, (ShrincsTypes.PublicKey, ShrincsTypes.StatelessSignature));
    }

    // flipByte: Flip one bit inside a dynamic bytes field.
    function flipByte(bytes memory data, uint256 index) internal pure {
        data[index] = bytes1(uint8(data[index]) ^ 0x01);
    }

    function testVerifyValidSignatureReturnsMagicValue() public view {
        bytes4 result = verifier.verify(validKey, signedHash, validEnvelope);
        assertEq(result, IERC7913SignatureVerifier.verify.selector, "must return the interface selector");
        assertEq(result, bytes4(0x024ad318), "selector must be the ERC-7913 magic value");
    }

    function testVersionTag() public view {
        assertEq(verifier.VERSION_TAG(), keccak256("quip.shrincs-verifier.v1"), "version tag");
    }

    function testRejectsBadKeyLengths() public view {
        uint256[4] memory badLengths = [uint256(0), 20, 31, 33];
        for (uint256 i = 0; i < badLengths.length; i++) {
            bytes memory key = new bytes(badLengths[i]);
            for (uint256 j = 0; j < key.length; j++) {
                key[j] = validKey[j % 32];
            }
            assertEq(
                verifier.verify(key, signedHash, validEnvelope), INVALID_SIGNATURE, "bad key length must be rejected"
            );
        }
    }

    function testRejectsWrongCommitment() public view {
        bytes memory wrongKey = abi.encodePacked(keccak256("some other installed commitment"));
        assertEq(
            verifier.verify(wrongKey, signedHash, validEnvelope), INVALID_SIGNATURE, "wrong commitment must be rejected"
        );
    }

    function testRejectsTamperedHash() public view {
        bytes32 otherHash = keccak256("a different message hash");
        assertEq(
            verifier.verify(validKey, otherHash, validEnvelope), INVALID_SIGNATURE, "tampered hash must be rejected"
        );
    }

    function testRejectsTamperedHypertreeRoot() public view {
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature) =
            decodeStoredEnvelope();
        flipByte(publicKey.hypertreeRoot, 0);
        bytes memory envelope = ShrincsCodec.encodeStatelessEnvelope(publicKey, signature);
        assertEq(
            verifier.verify(validKey, signedHash, envelope), INVALID_SIGNATURE, "tampered hypertree root must fail"
        );
    }

    function testRejectsTamperedForsEntry() public view {
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature) =
            decodeStoredEnvelope();
        flipByte(signature.fors.entries[0].secretLeaf, 0);
        bytes memory envelope = ShrincsCodec.encodeStatelessEnvelope(publicKey, signature);
        assertEq(verifier.verify(validKey, signedHash, envelope), INVALID_SIGNATURE, "tampered FORS entry must fail");
    }

    function testRejectsTamperedHypertreeChainValue() public view {
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature) =
            decodeStoredEnvelope();
        flipByte(signature.hypertree[0].wotsCSignature.chains[0], 0);
        bytes memory envelope = ShrincsCodec.encodeStatelessEnvelope(publicKey, signature);
        assertEq(
            verifier.verify(validKey, signedHash, envelope), INVALID_SIGNATURE, "tampered hypertree chain must fail"
        );
    }

    function testRejectsTruncatedEnvelope() public view {
        bytes memory truncated = validEnvelope;
        assembly {
            // Shrink the in-memory copy of the envelope by one byte.
            mstore(truncated, sub(mload(truncated), 1))
        }
        assertEq(
            verifier.verify(validKey, signedHash, truncated), INVALID_SIGNATURE, "truncated envelope must be rejected"
        );
    }

    function testRejectsEmptyEnvelope() public view {
        assertEq(verifier.verify(validKey, signedHash, bytes("")), INVALID_SIGNATURE, "empty envelope must be rejected");
    }

    function testRejectsGarbageEnvelope() public view {
        bytes memory garbage = abi.encodePacked(
            keccak256("garbage word one"), keccak256("garbage word two"), keccak256("garbage word three"), uint8(0x99)
        );
        assertEq(verifier.verify(validKey, signedHash, garbage), INVALID_SIGNATURE, "garbage envelope must be rejected");
    }

    function testRejectsMismatchedBundleCommitment() public view {
        // Distinct from the wrong-key case: here the declared commitment field DOES match
        // the key, but the bundle no longer recomputes to that commitment.
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature) =
            decodeStoredEnvelope();
        bytes32 fakeCommitment = keccak256("mismatched bundle commitment");
        publicKey.publicKeyCommitment = abi.encodePacked(fakeCommitment);
        bytes memory envelope = ShrincsCodec.encodeStatelessEnvelope(publicKey, signature);
        assertEq(
            verifier.verify(abi.encodePacked(fakeCommitment), signedHash, envelope),
            INVALID_SIGNATURE,
            "bundle that does not recompute to the key commitment must fail"
        );
    }

    function testDecodeAndCheckRejectsNonSelfCaller() public {
        vm.expectRevert(bytes("only self"));
        verifier.decodeAndCheck(keyCommitment, signedHash, validEnvelope);
    }

    function testCheckDecodedRejectsNonSelfCaller() public {
        (ShrincsTypes.PublicKey memory publicKey, ShrincsTypes.StatelessSignature memory signature) =
            decodeStoredEnvelope();
        vm.expectRevert(bytes("only self"));
        verifier.checkDecoded(keyCommitment, signedHash, publicKey, signature);
    }

    function testFuzzVerifyNeverReverts(bytes calldata key, bytes32 hash, bytes calldata signature) public view {
        // Any random input must produce a clean failure value, never a revert.
        bytes4 result = verifier.verify(key, hash, signature);
        assertEq(result, INVALID_SIGNATURE, "random inputs must yield the failure value");
    }

    function testGasSnapshotHappyPathVerify() public {
        uint256 gasBefore = gasleft();
        bytes4 result = verifier.verify(validKey, signedHash, validEnvelope);
        uint256 gasUsed = gasBefore - gasleft();
        assertEq(result, IERC7913SignatureVerifier.verify.selector, "snapshot call must succeed");
        // Recorded happy-path verify gas (see test logs with -vv for the current number).
        emit log_named_uint("happy-path verify gas", gasUsed);
    }
}
