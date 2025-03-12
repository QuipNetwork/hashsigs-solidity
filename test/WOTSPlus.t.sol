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

    function testSignAndVerifyEmptySignature() public {
        // Generate a key pair
        bytes32 privateSeed = bytes32(uint256(1));
        vm.startSnapshotGas("WOTS+ KeyGen");
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        uint256 keyGenGas = vm.stopSnapshotGas("WOTS+ KeyGen");
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        bytes32[] memory signatureArray = new bytes32[](NUM_SIGNATURE_CHUNKS);
        
        vm.startSnapshotGas("WOTS+ Verify");
        bool isValid = WOTSPlus.verify(publicKey, message, signatureArray);
        uint256 verifyGas = vm.stopSnapshotGas("WOTS+ Verify");

        assertFalse(isValid, "Signature verification should have failed");

        console.log("Gas used for key generation:", keyGenGas);
        console.log("Gas used for verification:", verifyGas);
    }

    function testVerifyValidSignature() public {
        bytes32 privateSeed = bytes32(uint256(1));
        vm.startSnapshotGas("WOTS+ KeyGen");
        (bytes memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        uint256 keyGenGas = vm.stopSnapshotGas("WOTS+ KeyGen");
        
        // Create a test message
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint i = 0; i < WOTSPlus.MessageLen; i++) {
            message[i] = bytes1(uint8(i));
        }
        
        // Sign the message
        vm.startSnapshotGas("WOTS+ Sign");
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureFixed = WOTSPlus.sign(privateKey, message);
        uint256 signGas = vm.stopSnapshotGas("WOTS+ Sign");
        
        // Convert fixed array to dynamic array
        bytes32[] memory signature = new bytes32[](NUM_SIGNATURE_CHUNKS);
        for (uint i = 0; i < NUM_SIGNATURE_CHUNKS; i++) {
            signature[i] = signatureFixed[i];
        }
        
        // Verify the signature
        vm.startSnapshotGas("WOTS+ Verify");
        bool isValid = WOTSPlus.verify(publicKey, message, signature);
        uint256 verifyGas = vm.stopSnapshotGas("WOTS+ Verify");

        assertTrue(isValid, "Signature verification failed");

        console.log("Gas used for key generation:", keyGenGas);
        console.log("Gas used for signing:", signGas);
        console.log("Gas used for verification:", verifyGas);
    }
}
