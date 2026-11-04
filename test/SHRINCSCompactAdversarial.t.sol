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

import {StatelessLayout} from "../contracts/StatelessLayout.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    ICompactPinnedVerifier,
    ICompactSibling,
    SHRINCSCompactFixtures
} from "./helpers/SHRINCSCompactFixtures.sol";

/// @notice Adversarial coverage for the compact stateless path: any
/// single-byte mutation of a valid payload is rejected, and malformed
/// shapes (truncated, extended, empty, zeroed, bad key) never revert and
/// always return 0xffffffff. Every call is a staticcall, so a state write
/// would also fail the test.
contract SHRINCSCompactAdversarialTest is SHRINCSCompactFixtures {
    bytes internal key;
    bytes32 internal hash;
    bytes internal payload;
    bytes internal sphincsKey;
    bytes32 internal rawMessage;
    bytes internal pq;

    function setUp() public {
        deployVerifiers();
        CompactCase memory valid = loadCase("valid");
        key = abi.encodePacked(valid.commitment);
        hash = valid.callerHash;
        payload = valid.compactPayload;
        sphincsKey = valid.sphincsKey;
        rawMessage = valid.rawMessage;
        pq = valid.compactSignature;
    }

    function testPristinePayloadVerifies() public view {
        assertEq(shrincs(key, payload), VERIFY_SELECTOR);
        assertEq(sphincs(sphincsKey, pq), VERIFY_SELECTOR);
    }

    /// @dev One flip in every field class: PK fields, FORS randomizer,
    /// counter, leaf, and auth node, and every hypertree layer's pkHash,
    /// randomizer, counter, chain, and auth node.
    function testFieldSweepRejected() public view {
        uint256[] memory offsets = sweepOffsets();
        for (uint256 i = 0; i < offsets.length; ++i) {
            assertEq(
                shrincs(key, flip(payload, offsets[i], 0x01)),
                INVALID_SIGNATURE,
                string.concat("payload offset ", vm.toString(offsets[i]))
            );
            if (offsets[i] >= StatelessLayout.PK_LEN) {
                uint256 pqOffset = offsets[i] - StatelessLayout.PK_LEN;
                assertEq(
                    sphincs(sphincsKey, flip(pq, pqOffset, 0x80)),
                    INVALID_SIGNATURE,
                    string.concat("pq offset ", vm.toString(pqOffset))
                );
            }
        }
    }

    function testDeclaredCommitmentFlipRejected() public view {
        for (uint256 i = 0; i < 32; ++i) {
            assertEq(
                shrincs(
                    key,
                    flip(
                        payload, StatelessLayout.COMMITMENT_OFFSET + i, 0xff
                    )
                ),
                INVALID_SIGNATURE
            );
        }
    }

    function testFuzz_singleByteMutationRejected(uint256 index, uint8 mask)
        public
        view
    {
        index = bound(index, 0, payload.length - 1);
        vm.assume(mask != 0);
        assertEq(shrincs(key, flip(payload, index, mask)), INVALID_SIGNATURE);
    }

    function testFuzz_truncationRejected(uint256 cut) public view {
        cut = bound(cut, 1, payload.length);
        assertEq(
            shrincs(key, slice(payload, payload.length - cut)),
            INVALID_SIGNATURE
        );
        cut = bound(cut, 1, pq.length);
        assertEq(
            sphincs(sphincsKey, slice(pq, pq.length - cut)),
            INVALID_SIGNATURE
        );
    }

    function testFuzz_trailingBytesRejected(bytes memory tail) public view {
        vm.assume(tail.length > 0);
        assertEq(
            shrincs(key, bytes.concat(payload, tail)), INVALID_SIGNATURE
        );
        assertEq(
            sphincs(sphincsKey, bytes.concat(pq, tail)), INVALID_SIGNATURE
        );
    }

    function testFuzz_badKeyLengthRejected(bytes memory badKey) public view {
        vm.assume(badKey.length != 32);
        assertEq(shrincs(badKey, payload), INVALID_SIGNATURE);
        vm.assume(badKey.length != 64);
        assertEq(sphincs(badKey, pq), INVALID_SIGNATURE);
    }

    function testFuzz_arbitraryPayloadRejected(bytes memory junk)
        public
        view
    {
        assertEq(shrincs(key, junk), INVALID_SIGNATURE);
        assertEq(sphincs(sphincsKey, junk), INVALID_SIGNATURE);
    }

    function testEmptyAndZeroedRejected() public view {
        assertEq(shrincs(key, ""), INVALID_SIGNATURE);
        assertEq(sphincs(sphincsKey, ""), INVALID_SIGNATURE);
        assertEq(
            shrincs(key, new bytes(StatelessLayout.PAYLOAD_LEN)),
            INVALID_SIGNATURE
        );
        assertEq(
            sphincs(sphincsKey, new bytes(StatelessLayout.PQ_LEN)),
            INVALID_SIGNATURE
        );
        // Zeroed PQ under a valid PK section clears the bundle checks and
        // must fail in the cryptography, not revert.
        bytes memory zeroedPq = slice(payload, StatelessLayout.PK_LEN);
        assertEq(
            shrincs(key, bytes.concat(zeroedPq, new bytes(pq.length))),
            INVALID_SIGNATURE
        );
        assertEq(shrincs("", payload), INVALID_SIGNATURE);
        assertEq(sphincs("", pq), INVALID_SIGNATURE);
    }

    function testAbiEnvelopeRejectedByCompactEntry() public view {
        CompactCase memory valid = loadCase("valid");
        assertEq(shrincs(key, valid.abiEnvelope), INVALID_SIGNATURE);
        assertEq(
            sphincs(sphincsKey, abi.encode(valid.abiEnvelope)),
            INVALID_SIGNATURE
        );
    }

    function sweepOffsets() internal pure returns (uint256[] memory out) {
        uint256 layers = SHRINCSParams.NUM_HYPERTREE_LAYERS;
        out = new uint256[](10 + 4 + layers * 7);
        uint256 n;
        uint256 pk = StatelessLayout.PK_LEN;
        out[n++] = 0;
        out[n++] = 40; // stateful root
        out[n++] = StatelessLayout.STATEFUL_PUBLIC_KEY_LEN - 1;
        out[n++] = StatelessLayout.COMMITMENT_OFFSET + 31;
        out[n++] = StatelessLayout.PK_SEED_OFFSET;
        out[n++] = StatelessLayout.PK_SEED_OFFSET + 31;
        out[n++] = StatelessLayout.HYPERTREE_ROOT_OFFSET;
        out[n++] = StatelessLayout.HYPERTREE_ROOT_OFFSET + 31;
        out[n++] = pk + StatelessLayout.FORS_RANDOMIZER_OFFSET;
        out[n++] = pk + StatelessLayout.FORS_RANDOMIZER_OFFSET + 31;
        out[n++] = pk + StatelessLayout.FORS_COUNTER_OFFSET;
        out[n++] = pk + StatelessLayout.FORS_COUNTER_OFFSET + 3;
        uint256 entries = pk + StatelessLayout.FORS_ENTRIES_OFFSET;
        out[n++] = entries; // first secret leaf
        out[n++] = pk + StatelessLayout.FORS_LEN - 1; // last auth node
        uint256 hypertree = pk + StatelessLayout.FORS_LEN;
        for (uint256 j = 0; j < layers; ++j) {
            uint256 base = hypertree + j * StatelessLayout.LAYER_LEN;
            out[n++] = base + StatelessLayout.LAYER_PK_HASH_OFFSET;
            out[n++] = base + StatelessLayout.LAYER_RANDOMIZER_OFFSET + 7;
            out[n++] = base + StatelessLayout.LAYER_COUNTER_OFFSET + 3;
            out[n++] = base + StatelessLayout.LAYER_CHAINS_OFFSET;
            out[n++] = base + StatelessLayout.LAYER_AUTH_PATH_OFFSET - 1;
            out[n++] = base + StatelessLayout.LAYER_AUTH_PATH_OFFSET;
            out[n++] = base + StatelessLayout.LAYER_LEN - 1;
        }
    }

    function shrincs(bytes memory key_, bytes memory signature)
        internal
        view
        returns (bytes4)
    {
        (bool ok, bytes memory ret) = address(verifier)
            .staticcall(
                abi.encodeCall(
                    ICompactPinnedVerifier.verifyStateless,
                    (key_, hash, signature)
                )
            );
        assertTrue(ok, "verifyStateless reverted");
        return abi.decode(ret, (bytes4));
    }

    function sphincs(bytes memory key_, bytes memory signature)
        internal
        view
        returns (bytes4)
    {
        (bool ok, bytes memory ret) = address(sibling)
            .staticcall(
                abi.encodeCall(
                    ICompactSibling.verify, (key_, rawMessage, signature)
                )
            );
        assertTrue(ok, "sibling verify reverted");
        return abi.decode(ret, (bytes4));
    }

    function flip(bytes memory data, uint256 index, uint8 mask)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(data);
        out[index] = out[index] ^ bytes1(mask);
    }

    function slice(bytes memory data, uint256 len)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = data[i];
        }
    }
}
