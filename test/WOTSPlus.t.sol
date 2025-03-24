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
    // Add the constant here in the test contract
    uint8 constant NUM_SIGNATURE_CHUNKS = 67; // 64 + 3 (NumMessageChunks + NumChecksumChunks)

    function setUp() public {
        // Setup code if needed
    }

    function testGenerateKeyPair() public pure {
        bytes32 privateSeed = bytes32(uint256(1)); // Example seed
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
               
        // Verify private key is not zero
        assertTrue(uint256(privateKey) != 0);
    }

    function testSignAndVerifyEmptySignature() public pure {
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
        
        bool isValid = WOTSPlus.verify(publicKey, messageData, signatureArrayElements);

        assertFalse(isValid, "Signature verification should have failed");
    }

    function testVerifyValidSignature() public pure {
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
       
        // Verify the signature
        bool isValid = WOTSPlus.verify(publicKey, messageData, signature);

        assertTrue(isValid, "Signature verification failed");
    }

    function testVerifyValidSignatureRandomizationElements() public pure {
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
        
        
        // Verify the signature
        bool isValid = WOTSPlus.verifyWithRandomizationElements(publicKey, messageData, signature, randomizationElements);

        assertTrue(isValid, "Signature verification failed");
    }
    
    function testVerifyMany() public pure {
        for (uint i = 1; i < 200; i++) {
            bytes32 privateSeed = bytes32(uint256(i));
            (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: keccak256(abi.encodePacked("Hello World", i))});
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
                elements: signatureFixed
            });
            bool isValid = WOTSPlus.verify(publicKey, message, signature);
            assertTrue(isValid, "Signature verification failed");
        }
    }    

    function testVerifyManyWithRandomizationElements() public pure {
        for (uint i = 1; i < 200; i++) {
            bytes32 privateSeed = bytes32(uint256(i));
            (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: keccak256(abi.encodePacked("Hello World", i))});
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
                elements: signatureFixed
            });
            WOTSPlus.WinternitzElements memory randomizationElements = WOTSPlus.generateRandomizationElements(publicKey.publicSeed);
            bool isValid = WOTSPlus.verifyWithRandomizationElements(publicKey, message, signature, randomizationElements);
            assertTrue(isValid, "Signature verification failed");
        }
    }

    struct TestVector {
        bytes32 privateKey;
        bytes32 publicSeed;
        bytes32[NUM_SIGNATURE_CHUNKS] publicKeySegments;
        bytes32[NUM_SIGNATURE_CHUNKS] randomizationElements;
        bytes32 publicKey;
        bytes32 message;
        bytes32[NUM_SIGNATURE_CHUNKS] signature;
    }

    function testVectors() public {
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
            for (uint j = 0; j < NUM_SIGNATURE_CHUNKS; j++) {
                publicKeySegments.elements[j] = randomizationElements.elements[j];
            }
            
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, messageData);
            WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({
                elements: signatureFixed
            });
            
            vectors[i] = TestVector({
                privateKey: privateKey,
                publicSeed: publicKey.publicSeed,
                publicKeySegments: publicKeySegments.elements,
                randomizationElements: randomizationElements.elements,
                publicKey: publicKey.publicKeyHash,
                message: messageData.messageHash,
                signature: signature.elements
            });
            
            // Verify generated signature
            bool isValid = WOTSPlus.verify(publicKey, messageData, signature);
            assertTrue(isValid, string.concat("Generated vector ", vm.toString(i), " signature invalid"));
        }
        
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
