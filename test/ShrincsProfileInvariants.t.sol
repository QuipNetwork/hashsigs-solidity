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
import {Hypertree} from "../contracts/Hypertree.sol";
import {ShrincsParams} from "shrincs-profile/ShrincsParams.sol";

/// @title ShrincsProfileInvariants
/// @notice Profile-agnostic structural invariants plus the profile
/// identity guard ([DESIGN §3.5]). Compiled and run under every build
/// profile.
/// @dev The identity test cross-checks the FOUNDRY_PROFILE name against
/// the compiled-in ShrincsParams tuple, so it fails closed if a
/// top-level remappings.txt shadows the per-profile TOML remapping and
/// silently compiles one profile's name with another's constants
/// (verified hazard, [DESIGN §2(d′)]). CI additionally rejects any
/// remappings.txt at the shell level.
contract ShrincsProfileInvariantsTest is Test {
    // Expected parameter tuple for one profile, keyed by profile name.
    struct ProfileExpectation {
        bytes32 profileId;
        uint256 hashLen;
        uint256 hypertreeHeight;
        uint256 numHypertreeLayers;
        uint256 forsTreeHeight;
        uint256 numForsTrees;
        uint256 numWotsChains;
        uint256 statelessLimit;
        uint256 wotsChainsStateful;
        uint256 wotsTargetSumStateful;
    }

    // Resolve the expected tuple for a FOUNDRY_PROFILE name. The default
    // developer profile, the empty (unset) value, the security-gate
    // profiles (ci, nightly — 256s params plus fuzz tuning), and the
    // canonical production build all select 256s. Reverts on an unknown
    // name so a mis-set profile fails closed rather than skipping the
    // check.
    function expectedFor(string memory profile)
        internal
        pure
        returns (ProfileExpectation memory)
    {
        bytes32 nameHash = keccak256(bytes(profile));
        if (
            nameHash == keccak256("") || nameHash == keccak256("default")
                || nameHash == keccak256("production")
                || nameHash == keccak256("ci")
                || nameHash == keccak256("nightly")
        ) {
            return ProfileExpectation({
                profileId: keccak256("shrincs-256s"),
                hashLen: 32,
                hypertreeHeight: 64,
                numHypertreeLayers: 8,
                forsTreeHeight: 14,
                numForsTrees: 22,
                numWotsChains: 64,
                statelessLimit: 1 << 20,
                wotsChainsStateful: 64,
                wotsTargetSumStateful: 480
            });
        }
        if (
            nameHash == keccak256("128s-q18")
                || nameHash == keccak256("production-128s-q18")
        ) {
            return ProfileExpectation({
                profileId: keccak256("shrincs-128s-q18"),
                hashLen: 16,
                hypertreeHeight: 18,
                numHypertreeLayers: 1,
                forsTreeHeight: 24,
                numForsTrees: 6,
                numWotsChains: 32,
                statelessLimit: 1 << 18,
                wotsChainsStateful: 32,
                wotsTargetSumStateful: 240
            });
        }
        if (
            nameHash == keccak256("128s-q20")
                || nameHash == keccak256("production-128s-q20")
        ) {
            return ProfileExpectation({
                profileId: keccak256("shrincs-128s-q20"),
                hashLen: 16,
                hypertreeHeight: 18,
                numHypertreeLayers: 1,
                forsTreeHeight: 24,
                numForsTrees: 6,
                numWotsChains: 32,
                statelessLimit: 1 << 20,
                wotsChainsStateful: 32,
                wotsTargetSumStateful: 240
            });
        }
        revert("unknown FOUNDRY_PROFILE for profile identity test");
    }

    // Identity guard: the compiled constants must match the tuple the
    // FOUNDRY_PROFILE name promises. Catches a wrong-profile build and
    // the remappings.txt-shadow hazard ([DESIGN §2(d′)/§3.5]).
    function testProfileIdentityMatchesCompiledConstants() public view {
        string memory profile = vm.envOr("FOUNDRY_PROFILE", string(""));
        ProfileExpectation memory want = expectedFor(profile);
        assertEq(ShrincsParams.PROFILE_ID, want.profileId, "PROFILE_ID");
        assertEq(uint256(ShrincsParams.HASH_LEN), want.hashLen, "n");
        assertEq(
            uint256(ShrincsParams.HYPERTREE_HEIGHT),
            want.hypertreeHeight,
            "h"
        );
        assertEq(
            uint256(ShrincsParams.NUM_HYPERTREE_LAYERS),
            want.numHypertreeLayers,
            "d"
        );
        assertEq(
            uint256(ShrincsParams.FORS_TREE_HEIGHT), want.forsTreeHeight, "a"
        );
        assertEq(
            uint256(ShrincsParams.NUM_FORS_TREES), want.numForsTrees, "k"
        );
        assertEq(
            uint256(ShrincsParams.NUM_WOTS_CHAINS), want.numWotsChains, "len"
        );
        assertEq(
            uint256(ShrincsParams.STATELESS_SIGNATURE_LIMIT),
            want.statelessLimit,
            "limit"
        );
        assertEq(
            uint256(ShrincsParams.WOTS_CHAINS_STATEFUL),
            want.wotsChainsStateful,
            "chains_stateful"
        );
        assertEq(
            uint256(ShrincsParams.WOTS_TARGET_SUM_STATEFUL),
            want.wotsTargetSumStateful,
            "target_sum"
        );
    }

    // The hypertree must split into whole balanced subtrees: h % d == 0.
    function testHypertreeHeightDividesByLayers() public pure {
        assertEq(
            uint256(ShrincsParams.HYPERTREE_HEIGHT)
                % uint256(ShrincsParams.NUM_HYPERTREE_LAYERS),
            0,
            "h % d"
        );
    }

    // WOTS-C carries no checksum chains, so len == 2n for w = 16.
    function testWotsChainCountIsTwiceHashLen() public pure {
        assertEq(
            uint256(ShrincsParams.NUM_WOTS_CHAINS),
            2 * uint256(ShrincsParams.HASH_LEN),
            "len == 2n"
        );
    }

    // WOTS-C target sum equals len * (w - 1) / 2 on the stateful side.
    function testWotsTargetSumMatchesChainCount() public pure {
        uint256 base = uint256(ShrincsParams.WOTS_BASE_STATEFUL);
        assertEq(
            uint256(ShrincsParams.WOTS_TARGET_SUM_STATEFUL),
            uint256(ShrincsParams.WOTS_CHAINS_STATEFUL) * (base - 1) / 2,
            "target_sum == len*(w-1)/2"
        );
    }

    // The WOTS digest must fit one 32-byte word (baseW16Digit32 reads
    // from the first len/2 bytes of a single digest word).
    function testWotsDigestFitsOneWord() public pure {
        assertLe(Hypertree.wotsDigestBytes(), 32, "digest <= 32B");
    }

    // Every digest bit-read stays within its reader's width: FORS tree
    // height a and the subtree height use readBits32 (<= 32); the tree
    // index uses readBits64 (<= 64).
    function testDigestBitReadsWithinReaderWidths() public pure {
        uint256 height = uint256(ShrincsParams.HYPERTREE_HEIGHT);
        uint256 layers = uint256(ShrincsParams.NUM_HYPERTREE_LAYERS);
        uint256 subtreeHeight = height / layers;
        uint256 treeBits = height - subtreeHeight;
        assertLe(uint256(ShrincsParams.FORS_TREE_HEIGHT), 32, "a <= 32");
        assertLe(subtreeHeight, 32, "h/d <= 32");
        assertLe(treeBits, 64, "treeBits <= 64");
    }

    // The FORS digest stream (k*a + h bits, byte-rounded) must be
    // nonempty and small enough that forsDigestBytes + 32 slack stays a
    // sane allocation.
    function testForsDigestByteCountSane() public pure {
        uint256 forsBits = uint256(ShrincsParams.NUM_FORS_TREES)
            * uint256(ShrincsParams.FORS_TREE_HEIGHT);
        uint256 digestBytes =
            (forsBits + uint256(ShrincsParams.HYPERTREE_HEIGHT) + 7) / 8;
        assertGe(digestBytes, 1, "digestBytes >= 1");
        assertLt(digestBytes, 1024, "digestBytes < 1024");
    }

    // The FORS low-index address field (forsTreeIndex << a + leaf) must
    // fit the 32-bit low-index slot: (k << a) bounds it.
    function testForsLowIndexFits32Bits() public pure {
        uint256 bound = uint256(ShrincsParams.NUM_FORS_TREES)
            << uint256(ShrincsParams.FORS_TREE_HEIGHT);
        assertLt(bound, uint256(type(uint32).max), "k<<a < 2^32");
    }

    // HASH_MASK must be exactly the high HASH_LEN bytes of ones (the
    // high-aligned truncation mask, [DESIGN §3.3]).
    function testHashMaskIsHighAlignedOnes() public pure {
        uint256 hashLen = uint256(ShrincsParams.HASH_LEN);
        uint256 hashBits = 8 * hashLen;
        uint256 lowOnes = hashBits >= 256
            ? type(uint256).max
            : (uint256(1) << hashBits) - 1;
        uint256 shiftUp = 8 * (32 - hashLen);
        uint256 expectedMask = shiftUp >= 256 ? 0 : lowOnes << shiftUp;
        assertEq(ShrincsParams.HASH_MASK, bytes32(expectedMask), "HASH_MASK");
    }
}
