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
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";

/// @dev Calldata/(ptr,len) entry points into HashSuite so the KATs can drive
/// every helper shape. The finalizers copy the buffer to memory and pass its
/// (ptr, len); the calldata helpers take `bytes calldata` exactly as the
/// verifier modules do.
contract HashSuiteHarness {
    function wotsCChain(
        bytes32 tag,
        uint256 tagLen,
        bytes32 pkSeed,
        bytes32 addressWord,
        bytes32 segment
    ) external view returns (bytes32) {
        return HashSuite.hashWotsCChainNoMask32(
            tag, tagLen, pkSeed, addressWord, segment
        );
    }

    function forsLeaf(
        bytes calldata pkSeed,
        bytes32 addressWord,
        bytes calldata sk
    ) external view returns (bytes32) {
        return HashSuite.hashForsLeaf32(pkSeed, addressWord, sk);
    }

    function forsNode(
        bytes calldata pkSeed,
        bytes32 addressWord,
        bytes32 left,
        bytes32 right
    ) external view returns (bytes32) {
        return HashSuite.hashForsNode32(pkSeed, addressWord, left, right);
    }

    function wotsDigest(
        bytes32 pkSeed,
        bytes32 expectedPkHash,
        bytes32 randomizer,
        uint32 counter,
        bytes32 message
    ) external view returns (bytes32) {
        return HashSuite.wotsDigest32(
            pkSeed, expectedPkHash, randomizer, counter, message
        );
    }

    function hypertreeNode(
        bytes32 pkSeed,
        bytes32 addressWord,
        bytes32 left,
        bytes32 right
    ) external view returns (bytes32) {
        return HashSuite.hashHypertreeNode32(
            pkSeed, addressWord, left, right
        );
    }

    function statefulParent(
        bytes32 pkSeed,
        uint32 leftLeafIndex,
        bytes32 left,
        bytes32 right
    ) external view returns (bytes32) {
        return HashSuite.statefulParentHash32(
            pkSeed, leftLeafIndex, left, right
        );
    }

    function forsPk(bytes memory buffer) external view returns (bytes32) {
        (uint256 ptr, uint256 len) = _coords(buffer);
        return HashSuite.hashForsPk32(ptr, len);
    }

    function wotsCPk(bytes memory buffer) external view returns (bytes32) {
        (uint256 ptr, uint256 len) = _coords(buffer);
        return HashSuite.hashWotsCPk32(ptr, len);
    }

    function forsDigestBlock(bytes memory buffer)
        external
        view
        returns (bytes32)
    {
        (uint256 ptr, uint256 len) = _coords(buffer);
        return HashSuite.hashForsDigestBlock32(ptr, len);
    }

    function uxmssDigits(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 randomizer,
        uint32 counter,
        bytes memory message
    ) external pure returns (bytes32) {
        return HashSuite.uxmssWotsDigits32(
            pkSeed, leafIndex, randomizer, counter, message
        );
    }

    function uxmssPk(bytes32 pkSeed, uint32 leafIndex, bytes memory segments)
        external
        pure
        returns (bytes32)
    {
        return HashSuite.uxmssWotsPk32(pkSeed, leafIndex, segments);
    }

    function _coords(bytes memory buffer)
        private
        pure
        returns (uint256 ptr, uint256 len)
    {
        assembly {
            ptr := add(buffer, 32)
        }
        len = buffer.length;
    }
}

/// @title HashSuiteKatTest
/// @notice Per-helper known-answer tests for the active hash suite. Each KAT
/// pins one helper's tag and preimage layout against a readable
/// abi.encodePacked reference plus the suite primitive (keccak256 under the
/// keccak suite, SHA-256 under the sha2 suite), applying the profile
/// HASH_MASK exactly where the helper masks. This is the suite-divergence
/// guard: both suites reuse these layouts, so any drift in a helper's offsets
/// or tag fails its KAT under that suite. The masking is profile-
/// parameterized and the reference primitive is suite-parameterized
/// (_suiteHash), so the same KATs run under every profile.
contract HashSuiteKatTest is Test {
    HashSuiteHarness internal h;

    // Deterministic-but-arbitrary KAT inputs.
    bytes32 internal constant PK_SEED = keccak256("hashsuite-kat.pkSeed");
    bytes32 internal constant ADDR = keccak256("hashsuite-kat.addressWord");
    bytes32 internal constant LEFT = keccak256("hashsuite-kat.left");
    bytes32 internal constant RIGHT = keccak256("hashsuite-kat.right");
    bytes32 internal constant SK = keccak256("hashsuite-kat.sk");
    bytes32 internal constant SEGMENT = keccak256("hashsuite-kat.segment");
    bytes32 internal constant RANDOMIZER =
        keccak256("hashsuite-kat.randomizer");
    bytes32 internal constant EXPECTED_PK =
        keccak256("hashsuite-kat.expectedPkHash");
    bytes32 internal constant MESSAGE = keccak256("hashsuite-kat.message");
    uint32 internal constant COUNTER = 0x01020304;
    uint32 internal constant LEAF_INDEX = 0x0000002a;
    // Nonzero ADRS coordinates for the compression KATs: a zero triple
    // would hide a dropped address word behind an all-zero preimage
    // field, which is exactly the layout drift these KATs must catch.
    uint32 internal constant ADDR_LAYER = 5;
    uint64 internal constant ADDR_TREE = 0x0102030405060708;
    uint32 internal constant ADDR_KEYPAIR = 0x0000002b;

    function setUp() public {
        h = new HashSuiteHarness();
    }

    function _mask(bytes32 value) internal pure returns (bytes32) {
        return value & SHRINCSParams.HASH_MASK;
    }

    // Suite-aware reference primitive: the KAT's independent derivation must
    // use the SAME hash as the active suite. HASH_SUITE_ID is a compile-time
    // constant, so the inactive branch folds away and the keccak reference
    // is byte-for-byte unchanged under the keccak suite.
    function _suiteHash(bytes memory preimage)
        internal
        pure
        returns (bytes32)
    {
        if (HashSuite.HASH_SUITE_ID == 2) {
            return sha256(preimage);
        }
        return keccak256(preimage);
    }

    function test_kat_wotsCChain() public view {
        bytes32 got = h.wotsCChain(
            WOTSPlusC.WOTS_C_CHAIN_TAG,
            WOTSPlusC.WOTS_C_CHAIN_TAG_LEN,
            PK_SEED,
            ADDR,
            SEGMENT
        );
        bytes32 want = _mask(
            _suiteHash(
                abi.encodePacked("wots-c-chain", PK_SEED, ADDR, SEGMENT)
            )
        );
        assertEq(got, want, "wots-c-chain KAT");
    }

    // F-08 negative pin: the stateful chain step uses the "uxmss-wots-chain"
    // tag (16 bytes, 112-byte preimage). Its output must both match the
    // raw-ASCII reference AND diverge from the stateless "wots-c-chain" step
    // for identical inputs, so a chain finished under the pre-T6 shared tag
    // reconstructs a different WOTS-C public-key hash and fails verify.
    function test_kat_uxmssWotsCChain() public view {
        bytes32 got = h.wotsCChain(
            UXMSS.UXMSS_WOTS_CHAIN_TAG,
            UXMSS.UXMSS_WOTS_CHAIN_TAG_LEN,
            PK_SEED,
            ADDR,
            SEGMENT
        );
        bytes32 want = _mask(
            _suiteHash(
                abi.encodePacked("uxmss-wots-chain", PK_SEED, ADDR, SEGMENT)
            )
        );
        assertEq(got, want, "uxmss-wots-chain KAT");

        bytes32 statelessStep = h.wotsCChain(
            WOTSPlusC.WOTS_C_CHAIN_TAG,
            WOTSPlusC.WOTS_C_CHAIN_TAG_LEN,
            PK_SEED,
            ADDR,
            SEGMENT
        );
        assertTrue(
            got != statelessStep,
            "F-08: stateful and stateless chain steps must diverge"
        );
    }

    function test_kat_forsLeaf() public view {
        bytes32 got = h.forsLeaf(
            abi.encodePacked(PK_SEED), ADDR, abi.encodePacked(SK)
        );
        bytes32 want = _mask(
            _suiteHash(abi.encodePacked("fors-leaf", PK_SEED, ADDR, SK))
        );
        assertEq(got, want, "fors-leaf KAT");
    }

    function test_kat_forsNode() public view {
        bytes32 got =
            h.forsNode(abi.encodePacked(PK_SEED), ADDR, LEFT, RIGHT);
        bytes32 want = _mask(
            _suiteHash(
                abi.encodePacked("fors-node", PK_SEED, ADDR, LEFT, RIGHT)
            )
        );
        assertEq(got, want, "fors-node KAT");
    }

    function test_kat_wotsDigest() public view {
        bytes32 got =
            h.wotsDigest(PK_SEED, EXPECTED_PK, RANDOMIZER, COUNTER, MESSAGE);
        // Unmasked: the caller reads base-16 digits out of the full word.
        bytes32 want = _suiteHash(
            abi.encodePacked(
                "wots-c-msg",
                PK_SEED,
                EXPECTED_PK,
                RANDOMIZER,
                COUNTER,
                MESSAGE
            )
        );
        assertEq(got, want, "wots-c-msg KAT");
    }

    function test_kat_hypertreeNode() public view {
        bytes32 got = h.hypertreeNode(PK_SEED, ADDR, LEFT, RIGHT);
        bytes32 want = _mask(
            _suiteHash(
                abi.encodePacked(
                    "hypertree-node", PK_SEED, ADDR, LEFT, RIGHT
                )
            )
        );
        assertEq(got, want, "hypertree-node KAT");
    }

    function test_kat_statefulParent() public view {
        bytes32 got = h.statefulParent(PK_SEED, LEAF_INDEX, LEFT, RIGHT);
        bytes32 want = _mask(
            _suiteHash(
                abi.encodePacked(
                    "uxmss-node", PK_SEED, LEAF_INDEX, LEFT, RIGHT
                )
            )
        );
        assertEq(got, want, "uxmss-node KAT");
    }

    // Production "fors-pk" preimage (FORSMinusC.verifyForsCAndReturnRoot):
    //   [0..7)   "fors-pk"
    //   [7..39)  pkSeed
    //   [39..71) FORS_ROOTS address (type 4) [FIPS205 §4.2]
    //   [71..)   reconstructed per-tree roots
    // The second assertion swaps in a zero word at this fixed offset;
    // any two distinct preimages hash differently, so it only pins the
    // preimage LAYOUT (the ADRS word's offset), not the verifier's
    // binding to it — SHRINCSAddressTweakMutation.t.sol proves binding.
    function test_kat_forsPk() public view {
        bytes32 addressWord = _forsRootsAddressWord();
        bytes memory buffer =
            abi.encodePacked("fors-pk", PK_SEED, addressWord, LEFT, RIGHT);
        assertEq(buffer.length, 71 + 64, "fors-pk roots start at 71");
        bytes32 got = h.forsPk(buffer);
        bytes32 want = _mask(_suiteHash(buffer));
        assertEq(got, want, "fors-pk KAT");

        bytes memory omitted =
            abi.encodePacked("fors-pk", PK_SEED, bytes32(0), LEFT, RIGHT);
        assertTrue(
            got != h.forsPk(omitted),
            "fors-pk preimage layout pins the ADRS word's offset"
        );
    }

    // Production "wots-c-pk" preimage (Hypertree.verifyWotsC32):
    //   [0..9)   "wots-c-pk"
    //   [9..41)  pkSeed
    //   [41..73) WOTS_PK address (type 1) [FIPS205 §4.2]
    //   [73..)   reconstructed chain endpoints
    // The second assertion swaps in a zero word at this fixed offset;
    // any two distinct preimages hash differently, so it only pins the
    // preimage LAYOUT (the ADRS word's offset), not the verifier's
    // binding to it — SHRINCSAddressTweakMutation.t.sol proves binding.
    function test_kat_wotsCPk() public view {
        bytes32 addressWord = _wotsPkAddressWord();
        bytes memory buffer = abi.encodePacked(
            "wots-c-pk", PK_SEED, addressWord, SEGMENT, SEGMENT
        );
        assertEq(buffer.length, 73 + 64, "wots-c-pk endpoints start at 73");
        bytes32 got = h.wotsCPk(buffer);
        bytes32 want = _mask(_suiteHash(buffer));
        assertEq(got, want, "wots-c-pk KAT");

        bytes memory omitted = abi.encodePacked(
            "wots-c-pk", PK_SEED, bytes32(0), SEGMENT, SEGMENT
        );
        assertTrue(
            got != h.wotsCPk(omitted),
            "wots-c-pk preimage layout pins the ADRS word's offset"
        );
    }

    function test_kat_forsDigestBlock() public view {
        bytes memory buffer = abi.encodePacked(
            "fors-digest", PK_SEED, LEFT, RANDOMIZER, COUNTER, MESSAGE
        );
        bytes32 got = h.forsDigestBlock(buffer);
        // Unmasked raw digest block.
        bytes32 want = _suiteHash(buffer);
        assertEq(got, want, "fors-digest KAT");
    }

    function test_kat_uxmssDigits() public view {
        bytes memory message = abi.encodePacked(MESSAGE);
        bytes32 got =
            h.uxmssDigits(PK_SEED, LEAF_INDEX, RANDOMIZER, COUNTER, message);
        // Unmasked stateful WOTS-C message digest.
        bytes32 want = _suiteHash(
            abi.encodePacked(
                "uxmss-wots-digits",
                PK_SEED,
                LEAF_INDEX,
                RANDOMIZER,
                COUNTER,
                message
            )
        );
        assertEq(got, want, "uxmss-wots-digits KAT");
    }

    function test_kat_uxmssPk() public view {
        bytes memory segments = abi.encodePacked(SEGMENT, SEGMENT);
        bytes32 got = h.uxmssPk(PK_SEED, LEAF_INDEX, segments);
        bytes32 want = _mask(
            _suiteHash(
                abi.encodePacked(
                    "uxmss-wots-pk", PK_SEED, LEAF_INDEX, segments
                )
            )
        );
        assertEq(got, want, "uxmss-wots-pk KAT");
    }

    // ADRS word packing shared with the production compressions: the layer
    // sits at bit 224, the tree at 128, the type at 96, and the keypair or
    // leaf at 64 [FIPS205 §4.2]. FORS is below hypertree layer zero, so its
    // layer field stays zero.
    function _forsRootsAddressWord() internal pure returns (bytes32) {
        return bytes32(
            (uint256(ADDR_TREE) << 128)
                | (uint256(FORSMinusC.AddressTypeForsRoots) << 96)
                | (uint256(ADDR_KEYPAIR) << 64)
        );
    }

    function _wotsPkAddressWord() internal pure returns (bytes32) {
        return bytes32(
            (uint256(ADDR_LAYER) << 224) | (uint256(ADDR_TREE) << 128)
                | (uint256(Hypertree.AddressTypeWotsPk) << 96)
                | (uint256(ADDR_KEYPAIR) << 64)
        );
    }
}
