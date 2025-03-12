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

}
