// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "../lib/forge-std/src/Test.sol";
import {WOTSPlus} from "../contracts/WOTSPlus.sol";
import "../lib/forge-std/src/console2.sol";

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

    function testSignAndVerify() public pure {
        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Sign the message
        bytes32[NUM_SIGNATURE_CHUNKS] memory signature = WOTSPlus.sign(privateKey, message);

        bytes32[] memory signatureArray = new bytes32[](NUM_SIGNATURE_CHUNKS);

        for (uint i = 0; i < NUM_SIGNATURE_CHUNKS; i++) {
            signatureArray[i] = signature[i];
            assertTrue(uint256(signature[i]) != 0, "Signature segment is zero");
        }
        
        // Remove this check as it's redundant for fixed-size arrays
        // require(signature.length == NUM_SIGNATURE_CHUNKS, "Invalid signature length");
                
        // Verify the signature - pass the signature array directly
        bool isValid = WOTSPlus.verify(publicKey, message, signatureArray);
        assertTrue(isValid, "Signature verification failed");
    }

    function testVerifyInvalidSignature() public pure {
        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Create an invalid signature (all zeros)
        bytes32[] memory invalidSignature;
        
        // Verify should return false
        bool isValid = WOTSPlus.verify(publicKey, message, invalidSignature);
        assertFalse(isValid, "Invalid signature was incorrectly verified");
    }

    function testVerifyValidSignature() public {
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
}
