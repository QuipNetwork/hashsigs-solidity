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

import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {StatelessLayout} from "../contracts/StatelessLayout.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {SHRINCSCompactFixtures} from "./helpers/SHRINCSCompactFixtures.sol";

contract Issue05HelperHarness {
    function decodeStatefulPublicKey(bytes calldata encoded)
        external
        pure
        returns (UXMSS.StatefulPublicKey memory, bool)
    {
        return SHRINCS.decodeStatefulPublicKey(encoded);
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

    /// @dev Calls Hypertree.verifyHypertree directly, because
    /// SPHINCSPlusC.verify's PQ_LEN check otherwise stops every wrong-length
    /// hypertree before it reaches the guard under test. The FORS section
    /// supplies the real root and layer-0 coordinates.
    function verifyHypertree(
        bytes calldata key,
        bytes32 hash,
        bytes calldata fors,
        bytes calldata hypertree
    ) external view returns (bool) {
        (bytes calldata pkSeed, bytes calldata hypertreeRoot, bool okKey) =
            SPHINCSPlusC.decodeKey(key);
        require(okKey, "key");
        (
            bytes32 forsRoot,
            uint64 treeIndex,
            uint32 leafIndex,
            bool okFors
        ) = FORSMinusC.verifyForsCAndReturnRoot(
            pkSeed, hypertreeRoot, SPHINCSPlusC.toMessage(hash), fors
        );
        require(okFors, "fors");
        return Hypertree.verifyHypertree(
            pkSeed, hypertreeRoot, forsRoot, treeIndex, leafIndex, hypertree
        );
    }
}

contract Issue05HelperValidationTest is SHRINCSCompactFixtures {
    Issue05HelperHarness internal harness;
    bytes internal sphincsKey;
    bytes32 internal rawMessage;
    bytes internal forsSection;
    bytes internal hypertreeSection;

    function setUp() public {
        harness = new Issue05HelperHarness();
        deployVerifiers();
        CompactCase memory valid = loadCase("valid");
        sphincsKey = valid.sphincsKey;
        rawMessage = valid.rawMessage;
        bytes memory signature = valid.compactSignature;
        forsSection = byteRange(signature, 0, StatelessLayout.FORS_LEN);
        hypertreeSection = byteRange(
            signature, StatelessLayout.FORS_LEN, StatelessLayout.PQ_LEN
        );
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

    // Hypertree auth paths. Hypertree._hypertreeRootFromPath32 is private and
    // takes a flat slice, so its auth-path length rejection now lives in the
    // verifyHypertree length guard. These tests keep the original
    // hypertreeRootFromPath32 behaviours pinned at that boundary, using a
    // valid signature so that only the guard can reject the long cases: a
    // layer never reads bytes past its own end.

    function testHypertreeRootRejectsShortAuthPathWithoutReverting()
        public
        view
    {
        bytes memory valid = hypertreeSection;
        assertFalse(
            verifyHypertree(byteRange(valid, 0, valid.length - 32)),
            "last layer missing one auth node"
        );
        assertFalse(
            verifyHypertree(
                bytes.concat(
                    byteRange(
                        valid, 0, StatelessLayout.LAYER_AUTH_PATH_OFFSET
                    ),
                    byteRange(
                        valid,
                        StatelessLayout.LAYER_AUTH_PATH_OFFSET + 32,
                        valid.length
                    )
                )
            ),
            "layer 0 missing one auth node"
        );
        assertFalse(
            verifyHypertree(
                byteRange(
                    valid,
                    0,
                    valid.length - StatelessLayout.SUBTREE_HEIGHT * 32
                )
            ),
            "last layer auth path empty"
        );
    }

    function testHypertreeRootRejectsLongAuthPathWithoutReverting()
        public
        view
    {
        bytes memory valid = hypertreeSection;
        assertFalse(
            verifyHypertree(bytes.concat(valid, bytes32(uint256(3)))),
            "last layer has one extra auth node"
        );
        assertFalse(
            verifyHypertree(
                bytes.concat(
                    byteRange(valid, 0, StatelessLayout.LAYER_LEN),
                    bytes32(uint256(3)),
                    byteRange(valid, StatelessLayout.LAYER_LEN, valid.length)
                )
            ),
            "layer 0 has one extra auth node"
        );
    }

    function testHypertreeRootAcceptsExactHeightPath() public view {
        assertEq(
            StatelessLayout.LAYER_AUTH_PATH_OFFSET
                + StatelessLayout.SUBTREE_HEIGHT * 32,
            StatelessLayout.LAYER_LEN,
            "auth path fills the layer"
        );
        assertTrue(verifyHypertree(hypertreeSection), "exact height");
    }

    /// @dev Replaces testHypertreeRootAcceptsHeightZeroEmptyPathAsLeaf. The
    /// height is now the profile constant, so the helper cannot be reached
    /// with height zero or tested at it. This pins that no profile can make
    /// that case reachable.
    function testHypertreeSubtreeHeightIsNeverZero() public pure {
        assertGt(StatelessLayout.SUBTREE_HEIGHT, 0);
    }

    function testHypertreeRejectsWrongSliceLengthsWithoutReverting()
        public
        view
    {
        bytes memory valid = hypertreeSection;
        assertFalse(
            verifyHypertree(bytes.concat(valid, bytes1(0))), "one byte long"
        );
        assertFalse(
            verifyHypertree(byteRange(valid, 0, valid.length - 1)),
            "one byte short"
        );
        assertFalse(
            verifyHypertree(
                bytes.concat(valid, new bytes(StatelessLayout.LAYER_LEN))
            ),
            "one extra layer"
        );
        assertFalse(
            verifyHypertree(
                byteRange(valid, 0, valid.length - StatelessLayout.LAYER_LEN)
            ),
            "one layer short"
        );
        assertFalse(verifyHypertree(""), "empty");
    }

    function testFuzzHypertreeRejectsEveryWrongLength(uint256 length)
        public
        view
    {
        bytes memory valid = hypertreeSection;
        length = bound(length, 0, 2 * valid.length);
        vm.assume(length != valid.length);
        // Keep the valid bytes as the prefix, zero-padding any extension.
        assertFalse(
            verifyHypertree(
                length < valid.length
                    ? byteRange(valid, 0, length)
                    : bytes.concat(valid, new bytes(length - valid.length))
            )
        );
    }

    function verifyHypertree(bytes memory hypertree)
        internal
        view
        returns (bool)
    {
        return harness.verifyHypertree(
            sphincsKey, rawMessage, forsSection, hypertree
        );
    }
}
