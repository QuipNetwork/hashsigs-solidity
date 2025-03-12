// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WOTSPlus} from "../contracts/WOTSPlus.sol";

contract WOTSPlusTest is Test {
    function setUp() public {
        // Setup code if needed
    }

    function testGenerateKeyPair() public {
        bytes32 privateSeed = bytes32(uint256(1)); // Example seed
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Verify public key length
        assertEq(publicKey.length, WOTSPlus.PublicKeySize);
        
        // Verify private key is not zero
        assertTrue(uint256(privateKey) != 0);
    }

    function testSignAndVerify() public {
        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Sign the message
        bytes memory signatureBytes = WOTSPlus.sign(privateKey, message);
        
        // Convert signature bytes to the expected array format
        bytes32[WOTSPlus.NumSignatureChunks] memory signature;
        for (uint i = 0; i < WOTSPlus.NumSignatureChunks; i++) {
            bytes32 chunk;
            assembly {
                chunk := mload(add(add(signatureBytes, 32), mul(i, 32)))
            }
            signature[i] = chunk;
        }
        
        // Verify the signature
        bool isValid = WOTSPlus.verify(publicKey, message, signature);
        assertTrue(isValid, "Signature verification failed");
    }

    function testVerifyInvalidSignature() public {
        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Create an invalid signature (all zeros)
        bytes32[WOTSPlus.NumSignatureChunks] memory invalidSignature;
        
        // Verify should return false
        bool isValid = WOTSPlus.verify(publicKey, message, invalidSignature);
        assertFalse(isValid, "Invalid signature was incorrectly verified");
    }
}