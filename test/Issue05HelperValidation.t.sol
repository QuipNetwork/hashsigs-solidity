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

import {Test} from "forge-std/Test.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {UXMSS} from "../contracts/UXMSS.sol";

contract Issue05HelperHarness {
    function decodeStatefulPublicKey(bytes calldata encoded)
        external
        pure
        returns (UXMSS.StatefulPublicKey memory, bool)
    {
        return SHRINCS.decodeStatefulPublicKey(encoded);
    }

    function hypertreeRootFromPath32(
        uint32 height,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes32 leaf,
        bytes[] calldata authPath
    ) external view returns (bytes32, bool) {
        return Hypertree.hypertreeRootFromPath32(
                height, pkSeed, layer, treeIndex, leafIndex, leaf, authPath
            );
    }

    function rootFromUnbalancedPath(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] calldata authPath
    ) external view returns (bytes32, bool) {
        return UXMSS.rootFromUnbalancedPath(
            pkSeed, leafIndex, leaf, authPath
        );
    }
}

contract Issue05HelperValidationTest is Test {
    Issue05HelperHarness internal harness;

    function setUp() public {
        harness = new Issue05HelperHarness();
    }

    function testDecodeStatefulPublicKeyAcceptsExactEncoding() public view {
        bytes32 pkSeed = keccak256("issue05-pk-seed");
        bytes32 root = keccak256("issue05-root");
        uint32 maxSignatures = 0x01020304;
        bytes memory encoded = abi.encodePacked(pkSeed, root, maxSignatures);
        assertEq(encoded.length, SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES);

        (UXMSS.StatefulPublicKey memory decoded, bool ok) =
            harness.decodeStatefulPublicKey(encoded);
        assertTrue(ok);
        assertEq(decoded.pkSeed, pkSeed);
        assertEq(decoded.root, root);
        assertEq(decoded.maxSignatures, maxSignatures);
    }

    // line-length: allow — forge fmt keeps the descriptive name
    function testFuzzDecodeStatefulPublicKeyRejectsEveryWrongLength(bytes calldata encoded)
        public
        view
    {
        vm.assume(encoded.length != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES);
        (UXMSS.StatefulPublicKey memory decoded, bool ok) =
            harness.decodeStatefulPublicKey(encoded);
        assertFalse(ok);
        assertEq(decoded.pkSeed, bytes32(0));
        assertEq(decoded.root, bytes32(0));
        assertEq(decoded.maxSignatures, 0);
    }

    function testHypertreeRootRejectsShortAuthPathWithoutReverting()
        public
        view
    {
        bytes[] memory authPath = new bytes[](0);
        (bytes32 root, bool ok) = harness.hypertreeRootFromPath32(
            1,
            abi.encodePacked(bytes32(uint256(1))),
            0,
            0,
            0,
            bytes32(uint256(2)),
            authPath
        );
        assertFalse(ok);
        assertEq(root, bytes32(0));
    }

    function testHypertreeRootRejectsLongAuthPathWithoutReverting()
        public
        view
    {
        bytes[] memory authPath = new bytes[](1);
        authPath[0] = abi.encodePacked(bytes32(uint256(3)));
        (bytes32 root, bool ok) = harness.hypertreeRootFromPath32(
            0,
            abi.encodePacked(bytes32(uint256(1))),
            0,
            0,
            0,
            bytes32(uint256(2)),
            authPath
        );
        assertFalse(ok);
        assertEq(root, bytes32(0));
    }

    function testHypertreeRootAcceptsExactHeightPath() public view {
        bytes[] memory authPath = new bytes[](1);
        authPath[0] = abi.encodePacked(bytes32(uint256(3)));
        (, bool ok) = harness.hypertreeRootFromPath32(
            1,
            abi.encodePacked(bytes32(uint256(1))),
            0,
            0,
            0,
            bytes32(uint256(2)),
            authPath
        );
        assertTrue(ok);
    }

    // Height 0 empty path is a legal single-leaf subtree; 1-node fails.
    function testHypertreeRootAcceptsHeightZeroEmptyPathAsLeaf()
        public
        view
    {
        bytes[] memory authPath = new bytes[](0);
        (bytes32 root, bool ok) = harness.hypertreeRootFromPath32(
            0,
            abi.encodePacked(bytes32(uint256(1))),
            0,
            0,
            0,
            bytes32(uint256(2)),
            authPath
        );
        assertTrue(ok);
        assertEq(root, bytes32(uint256(2)));

        authPath = new bytes[](1);
        authPath[0] = abi.encodePacked(bytes32(uint256(3)));
        (root, ok) = harness.hypertreeRootFromPath32(
            0,
            abi.encodePacked(bytes32(uint256(1))),
            0,
            0,
            0,
            bytes32(uint256(2)),
            authPath
        );
        assertFalse(ok);
        assertEq(root, bytes32(0));
    }

    function testUnbalancedRootRejectsEmptyPathWithoutReverting()
        public
        view
    {
        bytes32[] memory authPath = new bytes32[](0);
        (bytes32 root, bool ok) = harness.rootFromUnbalancedPath(
            bytes32(uint256(1)), 0, bytes32(uint256(2)), authPath
        );
        assertFalse(ok);
        assertEq(root, bytes32(0));
    }

    function testUnbalancedRootAcceptsNonEmptyPath() public view {
        bytes32[] memory authPath = new bytes32[](1);
        authPath[0] = bytes32(uint256(3));
        (, bool ok) = harness.rootFromUnbalancedPath(
            bytes32(uint256(1)), 1, bytes32(uint256(2)), authPath
        );
        assertTrue(ok);
    }
}
