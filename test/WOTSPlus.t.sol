// Copyright (C) 2024 quip.network
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
import {WOTSPlus} from "../contracts/WOTSPlus.sol";
import {console2 as console} from "../lib/forge-std/src/console2.sol";
import {Vm} from "../lib/forge-std/src/Vm.sol";

contract WOTSPlusTest is Test {
    uint256 constant NUM_SIGNATURE_CHUNKS = 67; // WOTS+ standard number of signature chunks
    // Number of meaningful randomization elements: function key (index 0) + the
    // w-1 shared bitmasks. Equals WOTSPlus.ChainLen.
    uint256 constant NUM_RANDOMIZATION_ELEMENTS = 16;
    
    function testGenerateKeyPair() public pure {
        bytes32 privateSeed = bytes32(uint256(1)); // Example seed
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
               
        require(publicKey.publicKeyHash != 0, "Public key is zero");
        require(publicKey.publicSeed != 0, "Public seed is zero");
        // Verify private key is not zero
        assertTrue(uint256(privateKey) != 0);
    }

    function testSignAndVerifyEmptySignature() public {
        vm.pauseGasMetering();

        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);

        require(publicKey.publicKeyHash != 0, "Public key is zero");
        require(publicKey.publicSeed != 0, "Public seed is zero");
        require(uint256(privateKey) != 0, "Private key is zero");
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        WOTSPlus.WinternitzMessage memory messageData = WOTSPlus.WinternitzMessage({
            messageHash: bytes32(abi.encodePacked(message))
        });
        
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureArray;
        WOTSPlus.WinternitzElements memory signatureArrayElements = WOTSPlus.WinternitzElements({
            elements: signatureArray
        });
        vm.resumeGasMetering();

        bool isValid = WOTSPlus.verify(publicKey, messageData, signatureArrayElements);

        assertFalse(isValid, "Signature verification should have failed");
    }

    function testVerifyValidSignature() public {
        vm.pauseGasMetering();
        bytes32 privateSeed = bytes32(uint256(1));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        WOTSPlus.WinternitzMessage memory messageData = WOTSPlus.WinternitzMessage({
            messageHash: bytes32(abi.encodePacked(message))
        });
        
        // Sign the message
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, messageData);
        WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
            elements: signatureFixed
        });
       
        vm.resumeGasMetering();

        // Verify the signature
        bool isValid = WOTSPlus.verify(publicKey, messageData, signature);

        assertTrue(isValid, "Signature verification failed");
    }

    function testVerifyValidSignatureRandomizationElements() public {
        vm.pauseGasMetering();
        bytes32 privateSeed = bytes32(uint256(1));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        WOTSPlus.WinternitzMessage memory messageData = WOTSPlus.WinternitzMessage({
            messageHash: bytes32(abi.encodePacked(message))
        });
        
        // Sign the message
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, messageData);
        WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
            elements: signatureFixed
        });

        WOTSPlus.WinternitzElements memory randomizationElements = WOTSPlus.generateRandomizationElements(publicKey.publicSeed);
        
        vm.resumeGasMetering();

        // Verify the signature
        bool isValid = WOTSPlus.verifyWithRandomizationElements(publicKey, messageData, signature, randomizationElements);

        assertTrue(isValid, "Signature verification failed");
    }
    
    function testVerifyMany() public {
        for (uint i = 1; i < 200; i++) {
            vm.pauseGasMetering();
            bytes32 privateSeed = bytes32(uint256(i));
            (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: keccak256(abi.encodePacked("Hello World", i))});
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
                elements: signatureFixed
            });
            vm.resumeGasMetering();
            bool isValid = WOTSPlus.verify(publicKey, message, signature);
            assertTrue(isValid, "Signature verification failed");
        }
    }    

    function testVerifyManyWithRandomizationElements() public {
        for (uint i = 1; i < 200; i++) {
            vm.pauseGasMetering();
            bytes32 privateSeed = bytes32(uint256(i));
            (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: keccak256(abi.encodePacked("Hello World", i))});
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
                elements: signatureFixed
            });
            WOTSPlus.WinternitzElements memory randomizationElements = WOTSPlus.generateRandomizationElements(publicKey.publicSeed);
            vm.resumeGasMetering();
            bool isValid = WOTSPlus.verifyWithRandomizationElements(publicKey, message, signature, randomizationElements);
            assertTrue(isValid, "Signature verification failed");
        }
    }

    /*//////////////////////////////////////////////////////////////
                       ADVERSARIAL / NEGATIVE TESTS
    //////////////////////////////////////////////////////////////*/

    // Helper: deterministic (key, message, signature) triple for a given seed/messageHash.
    function _keyMsgSig(bytes32 seed, bytes32 messageHash)
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        )
    {
        bytes32 privateKey;
        (publicKey, privateKey) = WOTSPlus.generateKeyPair(seed);
        message = WOTSPlus.WinternitzMessage({messageHash: messageHash});
        signature = WOTSPlus.WinternitzElements({elements: WOTSPlus.sign(privateKey, message)});
    }

    function test_Verify_TamperedSignatureFails() public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(bytes32(uint256(1)), keccak256("hello"));

        assertTrue(WOTSPlus.verify(publicKey, message, signature), "control should verify");

        // Flip a single bit in one signature element.
        signature.elements[5] = bytes32(uint256(signature.elements[5]) ^ 1);
        assertFalse(WOTSPlus.verify(publicKey, message, signature), "tampered signature must not verify");
    }

    function test_Verify_WrongPublicSeedFails() public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(bytes32(uint256(1)), keccak256("hello"));

        publicKey.publicSeed = bytes32(uint256(publicKey.publicSeed) ^ 1);
        assertFalse(WOTSPlus.verify(publicKey, message, signature), "wrong public seed must not verify");
    }

    function test_Verify_WrongMessageFails() public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            ,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(bytes32(uint256(1)), keccak256("hello"));

        WOTSPlus.WinternitzMessage memory other = WOTSPlus.WinternitzMessage({messageHash: keccak256("goodbye")});
        assertFalse(WOTSPlus.verify(publicKey, other, signature), "signature must not verify a different message");
    }

    function test_VerifyOrRevert_PassesOnValid() public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(bytes32(uint256(7)), keccak256("ok"));

        // Must not revert.
        WOTSPlus.verifyOrRevert(publicKey, message, signature);
    }

    function test_VerifyOrRevert_RevertsOnInvalid() public {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(bytes32(uint256(7)), keccak256("ok"));

        signature.elements[0] = bytes32(uint256(signature.elements[0]) ^ 1);
        vm.expectRevert(WOTSPlus.WOTSPlus__InvalidSignature.selector);
        WOTSPlus.verifyOrRevert(publicKey, message, signature);
    }

    function test_VerifyWithRandomizationElements_MismatchedREFails() public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(bytes32(uint256(1)), keccak256("hello"));

        // Randomization elements derived from an unrelated seed must reject a valid signature.
        WOTSPlus.WinternitzElements memory wrongRE = WOTSPlus.generateRandomizationElements(keccak256("unrelated"));
        assertFalse(
            WOTSPlus.verifyWithRandomizationElements(publicKey, message, signature, wrongRE),
            "mismatched randomization elements must not verify"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                  FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SignVerifyRoundtrip(bytes32 seed, bytes32 messageHash) public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(seed, messageHash);
        assertTrue(WOTSPlus.verify(publicKey, message, signature), "valid signature must verify");
    }

    function testFuzz_VerifyWithRandomizationElementsMatchesVerify(bytes32 seed, bytes32 messageHash) public pure {
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(seed, messageHash);
        WOTSPlus.WinternitzElements memory re = WOTSPlus.generateRandomizationElements(publicKey.publicSeed);
        assertEq(
            WOTSPlus.verify(publicKey, message, signature),
            WOTSPlus.verifyWithRandomizationElements(publicKey, message, signature, re),
            "both verify paths must agree"
        );
    }

    function testFuzz_WrongMessageNeverVerifies(bytes32 seed, bytes32 m1, bytes32 m2) public pure {
        vm.assume(m1 != m2);
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            ,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(seed, m1);
        WOTSPlus.WinternitzMessage memory other = WOTSPlus.WinternitzMessage({messageHash: m2});
        assertFalse(
            WOTSPlus.verify(publicKey, other, signature),
            "a signature must never verify a different message"
        );
    }

    function testFuzz_TamperedElementNeverVerifies(bytes32 seed, uint8 idx, bytes32 delta) public pure {
        vm.assume(delta != bytes32(0));
        (
            WOTSPlus.WinternitzAddress memory publicKey,
            WOTSPlus.WinternitzMessage memory message,
            WOTSPlus.WinternitzElements memory signature
        ) = _keyMsgSig(seed, keccak256("fuzz"));
        uint256 i = uint256(idx) % NUM_SIGNATURE_CHUNKS;
        signature.elements[i] = bytes32(uint256(signature.elements[i]) ^ uint256(delta));
        assertFalse(WOTSPlus.verify(publicKey, message, signature), "tampered signature must not verify");
    }

    struct TestVector {
        bytes32 privateKey;
        bytes32 publicSeed;
        bytes32[NUM_SIGNATURE_CHUNKS] publicKeySegments;
        bytes32[NUM_RANDOMIZATION_ELEMENTS] randomizationElements;
        bytes32 publicKey;
        bytes32 message;
        bytes32[NUM_SIGNATURE_CHUNKS] signature;
    }

    function testVectors() public {
        vm.pauseGasMetering();
        string memory vectorPath = "test/test_vectors/wotsplus_keccak256.json";
        uint256 numVectors = 5;
        TestVector[] memory vectors = new TestVector[](numVectors);
        
        // First, generate all vectors
        for (uint i = 0; i < numVectors; i++) {
            // Generate deterministic test data
            bytes32 privateSeed = keccak256(abi.encodePacked("seed", i));
            bytes memory message = new bytes(WOTSPlus.MessageLen);
            for (uint j = 0; j < WOTSPlus.MessageLen; j++) {
                message[j] = bytes1(uint8((i * j) % 256)); // Deterministic message
            }
            WOTSPlus.WinternitzMessage memory messageData = WOTSPlus.WinternitzMessage({
                messageHash: bytes32(abi.encodePacked(message))
            });
            
            // Generate key pair and signature
            (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            
            WOTSPlus.WinternitzElements memory randomizationElements = WOTSPlus.generateRandomizationElements(publicKey.publicSeed);
            WOTSPlus.WinternitzElements memory publicKeySegments;
            bytes32 functionKey = randomizationElements.elements[0];
            for (uint16 j = 0; j < NUM_SIGNATURE_CHUNKS; j++) {
                bytes32 secretKeySegment = WOTSPlus.Hash(abi.encodePacked(functionKey, WOTSPlus.prf(privateKey, j + 1)));
                publicKeySegments.elements[j] = WOTSPlus.chain(secretKeySegment, randomizationElements, 0, WOTSPlus.ChainLen - 1);
            }
            
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, messageData);
            WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
                elements: signatureFixed
            });

            // Only the first NUM_RANDOMIZATION_ELEMENTS entries are meaningful; the rest
            // of the WinternitzElements struct is unused and stays zero.
            bytes32[NUM_RANDOMIZATION_ELEMENTS] memory reTruncated;
            for (uint j = 0; j < NUM_RANDOMIZATION_ELEMENTS; j++) {
                reTruncated[j] = randomizationElements.elements[j];
            }

            vectors[i] = TestVector({
                privateKey: privateKey,
                publicSeed: publicKey.publicSeed,
                publicKeySegments: publicKeySegments.elements,
                randomizationElements: reTruncated,
                publicKey: publicKey.publicKeyHash,
                message: messageData.messageHash,
                signature: signature.elements
            });
            
            // Verify generated signature
            vm.resumeGasMetering();
            bool isValid = WOTSPlus.verify(publicKey, messageData, signature);
            vm.pauseGasMetering();
            assertTrue(isValid, string.concat("Generated vector ", vm.toString(i), " signature invalid"));
        }
        vm.pauseGasMetering();
        // Try to read existing file and verify
        try vm.readFile(vectorPath) {
            // Format the existing JSON using jq to ensure consistent formatting
            string[] memory command = new string[](3);
            command[0] = "jq";
            command[1] = ".";
            command[2] = vectorPath;
            string memory formattedExisting = string(vm.ffi(command));
            
            // Generate new vectors and format them the same way
            string memory newJson = generateVectorJson(vectors);
            string memory testFilePath = "test/test_vectors/tmp.json";
            vm.writeFile(testFilePath, newJson);
            command[2] = testFilePath;
            string memory formattedNew = string(vm.ffi(command));
            
            assertEq(formattedExisting, formattedNew, "Test vector JSON mismatch");
        } catch {
            // Generate and write new vectors as before
            string memory newJson = generateVectorJson(vectors);
            vm.writeJson(newJson, vectorPath);
            
            // Format using jq
            string[] memory command = new string[](3);
            command[0] = "jq";
            command[1] = ".";
            command[2] = vectorPath;
            bytes memory formattedJson = vm.ffi(command);
            vm.writeFile(vectorPath, string(formattedJson));
            
            emit log_string("WARNING: Test vectors file not found or unreadable. New vectors were generated.");
            emit log_string("Please commit the new test vectors file and verify its contents.");
            assertTrue(false, "Test failed: vectors file needs to be generated");
        }
    }

    function generateVectorJson(TestVector[] memory vectors) internal pure returns (string memory) {
        string memory completeJson = "{";
        for (uint i = 0; i < vectors.length; i++) {
            if (i > 0) completeJson = string.concat(completeJson, ",");
            string memory vectorName = string.concat('"vector', vm.toString(i), '":');
            string memory vectorJson = "{";
            
            vectorJson = string.concat(vectorJson, '"privateKey":"', vm.toString(vectors[i].privateKey), '"');
            vectorJson = string.concat(vectorJson, ',"publicSeed":"', vm.toString(vectors[i].publicSeed), '"');
            
            string memory segmentsJson = "[";
            for (uint j = 0; j < vectors[i].publicKeySegments.length; j++) {
                if (j > 0) segmentsJson = string.concat(segmentsJson, ",");
                segmentsJson = string.concat(segmentsJson, '"', vm.toString(vectors[i].publicKeySegments[j]), '"');
            }
            segmentsJson = string.concat(segmentsJson, "]");
            vectorJson = string.concat(vectorJson, ',"publicKeySegments":', segmentsJson);

            segmentsJson = "[";
            for (uint j = 0; j < vectors[i].randomizationElements.length; j++) {
                if (j > 0) segmentsJson = string.concat(segmentsJson, ",");
                segmentsJson = string.concat(segmentsJson, '"', vm.toString(vectors[i].randomizationElements[j]), '"');
            }
            segmentsJson = string.concat(segmentsJson, "]");
            vectorJson = string.concat(vectorJson, ',"randomizationElements":', segmentsJson);

            vectorJson = string.concat(vectorJson, ',"publicKey":"', vm.toString(vectors[i].publicKey), '"');
            vectorJson = string.concat(vectorJson, ',"message":"', vm.toString(vectors[i].message), '"');
            
            segmentsJson = "[";
            for (uint j = 0; j < vectors[i].signature.length; j++) {
                if (j > 0) segmentsJson = string.concat(segmentsJson, ",");
                segmentsJson = string.concat(segmentsJson, '"', vm.toString(vectors[i].signature[j]), '"');
            }
            segmentsJson = string.concat(segmentsJson, "]");
            vectorJson = string.concat(vectorJson, ',"signature":', segmentsJson);
            
            vectorJson = string.concat(vectorJson, "}");
            completeJson = string.concat(completeJson, vectorName, vectorJson);
        }
        return string.concat(completeJson, "}");
    }
}
