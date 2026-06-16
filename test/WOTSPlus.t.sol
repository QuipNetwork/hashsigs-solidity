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
import {WOTSPlus} from "../contracts/WOTSPlus.sol";

contract WOTSPlusTest is Test {
    uint256 internal constant NUM_SIGNATURE_CHUNKS = 67;

    bytes32 internal constant VECTOR0_PRIVATE_KEY = 0xaaa862dd9e978918cefd61c9705aba23b3bb95722a74ce409904377e7d278321;
    bytes32 internal constant VECTOR0_PUBLIC_SEED = 0xc1e0c4e470a9f985dc82a3122312170ccbdb378d5b3eecc4984d0475c844bf8b;
    bytes32 internal constant VECTOR0_PUBLIC_KEY_HASH =
        0xe77faa33a9707ad51be4fb1c7815afe98cc93c63f59a9909b82cb6c8bda2ee78;
    bytes32 internal constant VECTOR0_MESSAGE = bytes32(0);
    bytes32 internal constant VECTOR0_SIGNATURE0 = 0x07c0b9bce7aecf40134e967e1b9a78d8643ffaf55abdedf75b2cb97ab64cbb66;

    function testGenerateKeyPairMatchesKnownVector0() public pure {
        bytes32 privateSeed = keccak256(abi.encodePacked("seed", uint256(0)));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);

        assertEq(privateKey, VECTOR0_PRIVATE_KEY);
        assertEq(publicKey.publicSeed, VECTOR0_PUBLIC_SEED);
        assertEq(publicKey.publicKeyHash, VECTOR0_PUBLIC_KEY_HASH);
    }

    function testVerifyRejectsEmptySignature() public {
        vm.pauseGasMetering();
        bytes32 privateSeed = bytes32(uint256(1));
        (WOTSPlus.WinternitzAddress memory publicKey,) = WOTSPlus.generateKeyPair(privateSeed);
        WOTSPlus.WinternitzMessage memory messageData =
            WOTSPlus.WinternitzMessage({messageHash: _messageHashFromSequence()});
        WOTSPlus.WinternitzElements memory emptySignature;
        vm.resumeGasMetering();

        bool isValid = WOTSPlus.verify(publicKey, messageData, emptySignature);
        assertTrue(!isValid, "empty signature should not verify");
    }

    function testVerifyValidSignature() public {
        vm.pauseGasMetering();
        bytes32 privateSeed = bytes32(uint256(1));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        WOTSPlus.WinternitzMessage memory messageData =
            WOTSPlus.WinternitzMessage({messageHash: _messageHashFromSequence()});
        WOTSPlus.WinternitzElements memory signature =
            WOTSPlus.WinternitzElements({elements: WOTSPlus.sign(privateKey, messageData)});
        vm.resumeGasMetering();

        bool isValid = WOTSPlus.verify(publicKey, messageData, signature);
        assertTrue(isValid, "signature verification failed");
    }

    function testVerifyValidSignatureWithRandomizationElements() public {
        vm.pauseGasMetering();
        bytes32 privateSeed = bytes32(uint256(1));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        WOTSPlus.WinternitzMessage memory messageData =
            WOTSPlus.WinternitzMessage({messageHash: _messageHashFromSequence()});
        WOTSPlus.WinternitzElements memory signature =
            WOTSPlus.WinternitzElements({elements: WOTSPlus.sign(privateKey, messageData)});
        WOTSPlus.WinternitzElements memory randomizationElements =
            WOTSPlus.generateRandomizationElements(publicKey.publicSeed);
        vm.resumeGasMetering();

        bool isValid =
            WOTSPlus.verifyWithRandomizationElements(publicKey, messageData, signature, randomizationElements);
        assertTrue(isValid, "signature verification with randomization elements failed");
    }

    function testVerifyManyDeterministicSignatures() public {
        for (uint256 i = 1; i < 50; ++i) {
            vm.pauseGasMetering();
            bytes32 privateSeed = bytes32(i);
            (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
            WOTSPlus.WinternitzMessage memory message =
                WOTSPlus.WinternitzMessage({messageHash: keccak256(abi.encodePacked("Hello World", i))});
            WOTSPlus.WinternitzElements memory signature =
                WOTSPlus.WinternitzElements({elements: WOTSPlus.sign(privateKey, message)});
            vm.resumeGasMetering();

            bool isValid = WOTSPlus.verify(publicKey, message, signature);
            assertTrue(isValid, "deterministic signature verification failed");
        }
    }

    function testKnownVector0SignaturePrefixAndVerification() public {
        vm.pauseGasMetering();
        bytes32 privateSeed = keccak256(abi.encodePacked("seed", uint256(0)));
        (WOTSPlus.WinternitzAddress memory publicKey, bytes32 privateKey) = WOTSPlus.generateKeyPair(privateSeed);
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: VECTOR0_MESSAGE});
        bytes32[NUM_SIGNATURE_CHUNKS] memory signatureArray = WOTSPlus.sign(privateKey, message);
        vm.resumeGasMetering();

        assertEq(signatureArray[0], VECTOR0_SIGNATURE0);

        WOTSPlus.WinternitzElements memory signature = WOTSPlus.WinternitzElements({elements: signatureArray});
        bool isValid = WOTSPlus.verify(publicKey, message, signature);
        assertTrue(isValid, "known vector signature should verify");
    }

    function _messageHashFromSequence() internal pure returns (bytes32 out) {
        bytes memory message = new bytes(WOTSPlus.MessageLen);
        for (uint256 i = 0; i < WOTSPlus.MessageLen; ++i) {
            // casting to 'uint8' is safe because i ranges from 0 to MessageLen - 1, and MessageLen is 32
            // forge-lint: disable-next-line(unsafe-typecast)
            message[i] = bytes1(uint8(i));
        }
        out = bytes32(abi.encodePacked(message));
    }
}
