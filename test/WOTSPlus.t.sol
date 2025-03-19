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
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Verify public key length
        assertEq(publicKey.length, WOTSPlus.PublicKeySize);
        
        // Verify private key is not zero
        assertTrue(uint256(privateKey) != 0);
    }

    function testSignAndVerifyEmptySignature() public pure {
        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);

        require(publicKey.length == WOTSPlus.PublicKeySize, "Public key length is incorrect");
        require(uint256(privateKey) != 0, "Private key is zero");
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        bytes32[] memory signatureArray = new bytes32[](NUM_SIGNATURE_CHUNKS);
        
        bool isValid = WOTSPlus.verify(publicKey, message, signatureArray);

        assertFalse(isValid, "Signature verification should have failed");
    }

    function testVerifyValidSignature() public pure {
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Sign the message
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
        
        // Convert fixed array to dynamic array
        bytes32[] memory signature = new bytes32[](NUM_SIGNATURE_CHUNKS);
        for (uint i = 0; i < NUM_SIGNATURE_CHUNKS; i++) {
            signature[i] = signatureFixed[i];
        }
        
        // Verify the signature
        bool isValid = WOTSPlus.verify(publicKey, message, signature);

        assertTrue(isValid, "Signature verification failed");
    }

    function testVerifyValidSignatureRandomizationElements() public pure {
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Sign the message
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);

        bytes32 publicSeed;
        assembly {
            publicSeed := mload(add(publicKey, 32))  
        }
        bytes32 publicKeyHash;
        assembly {
            publicKeyHash := mload(add(publicKey, 64))
        }

        bytes32[] memory randomizationElements = WOTSPlus.generateRandomizationElements(publicSeed);
        
        // Convert fixed array to dynamic array
        bytes32[] memory signature = new bytes32[](NUM_SIGNATURE_CHUNKS);
        for (uint i = 0; i < NUM_SIGNATURE_CHUNKS; i++) {
            signature[i] = signatureFixed[i];
        }
        
        // Verify the signature
        bool isValid = WOTSPlus.verifyWithRandomizationElements(publicKeyHash, message, signature, randomizationElements);

        assertTrue(isValid, "Signature verification failed");
    }
    
    function testVerifyMany() public pure {
        for (uint i = 1; i < 200; i++) {
            bytes32 privateSeed = bytes32(uint256(i));
            (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            bytes memory message = bytes.concat(keccak256(abi.encodePacked("Hello World", i)));
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            bytes32[] memory signature = new bytes32[](NUM_SIGNATURE_CHUNKS);
            for (uint j = 0; j < NUM_SIGNATURE_CHUNKS; j++) {
                signature[j] = signatureFixed[j];
            }
            bool isValid = WOTSPlus.verify(publicKey, message, signature);
            assertTrue(isValid, "Signature verification failed");
        }
    }    

    function testVerifyManyWithRandomizationElements() public pure {
        for (uint i = 1; i < 200; i++) {
            bytes32 privateSeed = bytes32(uint256(i));
            (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            bytes memory message = bytes.concat(keccak256(abi.encodePacked("Hello World", i)));
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            bytes32[] memory signature = new bytes32[](NUM_SIGNATURE_CHUNKS);
            for (uint j = 0; j < NUM_SIGNATURE_CHUNKS; j++) {
                signature[j] = signatureFixed[j];
            }
            bytes32 publicSeed;
            assembly {
                publicSeed := mload(add(publicKey, 32))  
            }
            bytes32 publicKeyHash;
            assembly {
                publicKeyHash := mload(add(publicKey, 64))
            }
            bytes32[] memory randomizationElements = WOTSPlus.generateRandomizationElements(publicSeed);
            bool isValid = WOTSPlus.verifyWithRandomizationElements(publicKeyHash, message, signature, randomizationElements);
            assertTrue(isValid, "Signature verification failed");
        }
    }

    struct TestVector {
        bytes32 privateKey;
        bytes32 publicSeed;
        bytes32[] publicKeySegments;
        bytes32[] randomizationElements;
        bytes publicKey;
        bytes message;
        bytes32[] signature;
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
            
            // Generate key pair and signature
            (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            
            bytes32 publicSeed;
            assembly {
                publicSeed := mload(add(publicKey, 32))
            }
            
            bytes32[] memory randomizationElements = WOTSPlus.generateRandomizationElements(publicSeed);
            bytes32[] memory publicKeySegments = new bytes32[](NUM_SIGNATURE_CHUNKS);
            for (uint j = 0; j < NUM_SIGNATURE_CHUNKS; j++) {
                publicKeySegments[j] = randomizationElements[j];
            }
            
            bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
            bytes32[] memory signature = new bytes32[](NUM_SIGNATURE_CHUNKS);
            for (uint j = 0; j < NUM_SIGNATURE_CHUNKS; j++) {
                signature[j] = signatureFixed[j];
            }
            
            vectors[i] = TestVector({
                privateKey: privateKey,
                publicSeed: publicSeed,
                publicKeySegments: publicKeySegments,
                randomizationElements: randomizationElements,
                publicKey: publicKey,
                message: message,
                signature: signature
            });
            
            // Verify generated signature
            bool isValid = WOTSPlus.verify(publicKey, message, signature);
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
