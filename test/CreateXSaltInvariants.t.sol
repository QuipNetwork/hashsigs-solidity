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
import {Create3} from "../script/Create3.sol";
import {CreateXSalt} from "../script/CreateXSalt.sol";

/// @notice Pins the permissioned CreateX salt scheme: every canonical salt
/// is laid out the way CreateX's sender-scoped branch requires, every
/// advertised address matches DEPLOYMENTS.md, and — the point of the whole
/// scheme — a third party using a published raw salt lands somewhere else.
/// @dev Profile-independent: the salts are pure math over their label
/// strings, so this file imports nothing profile-gated and is in no `skip`
/// list. It therefore runs under all four ci-matrix profiles.
contract CreateXSaltInvariantsTest is Test {
    // Every canonical salt label. Order is the DEPLOYMENTS.md table order.
    function _labels() internal pure returns (string[8] memory) {
        return [
            "QUIP:SPHINCSPlusC256sKeccak:V3.0",
            "QUIP:SPHINCSPlusC128sQ18Keccak:V3.0",
            "QUIP:SPHINCSPlusC128sQ20Keccak:V3.0",
            "QUIP:SPHINCSPlusC256sSha2:V3.0",
            "QUIP:SHRINCS256sKeccak:V4.0",
            "QUIP:SHRINCS128sQ18Keccak:V4.0",
            "QUIP:SHRINCS128sQ20Keccak:V4.0",
            "QUIP:SHRINCS256sSha2:V4.0"
        ];
    }

    // The published addresses, in the same order. This is the
    // DEPLOYMENTS.md <-> code regression lock: it fails loudly if anyone
    // edits a label, the deployer, the flag byte, or the entropy width.
    function _addresses() internal pure returns (address[8] memory) {
        return [
            0xe52707C5D76E2F7c3314cF3dcc340eB9BbAE3864,
            0x23cc6a3b31A3f6734530FCddB19eabE31F9a3037,
            0xf6e309c6795447584110404FbaE112E4236d40AD,
            0x55346bdc46Cf36C844c0f708041C916c0B65718f,
            0xF2f9E6D692da41b089c3c261c41509669eEc5567,
            0x695BA9d92FB431B4d446EEcb40b9874c9E43cc91,
            0xa301C72c150d735ED741F3Fd980691d1a77F7c52,
            0x10eE478959bD9cd9E99573cf208D217d704C2FF5
        ];
    }

    // The three slice reads below are truncating by design: reading
    // exactly those byte ranges IS what these tests assert. Routed
    // through helpers so each cast carries one lint waiver rather than
    // scattering directives across every assertion.

    function _senderField(bytes32 raw) internal pure returns (address) {
        // casting to 'bytes20' is safe: bytes 0-19 are the sender field
        // forge-lint: disable-next-line(unsafe-typecast)
        return address(bytes20(raw));
    }

    function _entropy(bytes32 raw) internal pure returns (bytes11) {
        // casting to 'bytes11' is safe: bytes 21-31 are the entropy
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes11(raw << 168);
    }

    function _labelPrefix(bytes32 h) internal pure returns (bytes11) {
        // casting to 'bytes11' is safe: the leading 11 bytes of the label
        // hash are exactly what rawSalt embeds
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes11(h);
    }

    // External wrapper so vm.expectRevert can intercept the library's
    // inlined `require` (internal library calls are not a CALL).
    function requireWellFormedExternal(bytes32 raw) external pure {
        CreateXSalt.requireWellFormed(raw);
    }

    /// @notice Every salt is laid out as CreateX's sender-scoped branch
    /// requires: [20B DEPLOYER][0x00][11B of the label hash].
    /// @dev A wrong sender field silently routes CreateX to its
    /// permissionless branch (squattable address); a 0x01 flag byte
    /// silently routes it to the chain-scoped branch, giving a different
    /// address per chain. Neither reverts inside CreateX, so this is the
    /// check that catches them.
    function testEverySaltIsWellFormed() public pure {
        string[8] memory labels = _labels();
        for (uint256 i = 0; i < labels.length; i++) {
            bytes32 labelHash = keccak256(bytes(labels[i]));
            bytes32 raw = CreateXSalt.rawSalt(labelHash);

            assertEq(
                _senderField(raw),
                CreateXSalt.DEPLOYER,
                "salt bytes 0-19 must be the canonical deployer"
            );
            assertEq(raw[20], bytes1(0x00), "salt byte 20 must be 0x00");
            assertEq(
                _entropy(raw),
                _labelPrefix(labelHash),
                "salt bytes 21-31 must be the label hash prefix"
            );
            // The library and the deploy scripts' inline composition must
            // agree; requireWellFormed is what _deploy calls at runtime.
            CreateXSalt.requireWellFormed(raw);
        }
    }

    /// @notice The layout holds for any label, not just the nine.
    function testFuzzSaltLayout(bytes32 labelHash) public pure {
        bytes32 raw = CreateXSalt.rawSalt(labelHash);
        assertEq(_senderField(raw), CreateXSalt.DEPLOYER, "sender");
        assertEq(raw[20], bytes1(0x00), "flag");
        assertEq(_entropy(raw), _labelPrefix(labelHash), "entropy");
        CreateXSalt.requireWellFormed(raw);
    }

    /// @notice requireWellFormed reverts when the sender field is not
    /// the canonical deployer. CreateX would otherwise take its
    /// permissionless branch and land at a squattable address.
    function testRequireWellFormedRevertsOnWrongSender() public {
        bytes32 labelHash = keccak256("QUIP:test:bad-sender");
        bytes32 bad = bytes32(
            abi.encodePacked(
                bytes20(address(0xBAD)),
                CreateXSalt.FLAG_NO_CHAIN_SCOPE,
                _labelPrefix(labelHash)
            )
        );
        vm.expectRevert(bytes("CreateXSalt: sender field != DEPLOYER"));
        this.requireWellFormedExternal(bad);
    }

    /// @notice requireWellFormed reverts on CreateX's 0x01 chain-scope
    /// flag. That flag would silently destroy chain-invariance.
    function testRequireWellFormedRevertsOnChainScopedFlag() public {
        bytes32 labelHash = keccak256("QUIP:test:bad-flag");
        // 0x01 is CreateX's chain-scope flag (byte 20); the library
        // mirrors only the 0x00 / no-chain-scope branch.
        bytes32 bad = bytes32(
            abi.encodePacked(
                bytes20(CreateXSalt.DEPLOYER),
                bytes1(0x01),
                _labelPrefix(labelHash)
            )
        );
        vm.expectRevert(bytes("CreateXSalt: flag byte != 0x00"));
        this.requireWellFormedExternal(bad);
    }

    /// @notice Distinct labels give distinct salts and addresses.
    function testFuzzDistinctLabelsGiveDistinctSalts(
        bytes32 labelA,
        bytes32 labelB
    ) public pure {
        vm.assume(_labelPrefix(labelA) != _labelPrefix(labelB));
        bytes32 rawA = CreateXSalt.rawSalt(labelA);
        bytes32 rawB = CreateXSalt.rawSalt(labelB);
        assertTrue(rawA != rawB, "distinct entropy -> distinct salt");
        assertTrue(
            CreateXSalt.addressOf(rawA) != CreateXSalt.addressOf(rawB),
            "distinct salt -> distinct address"
        );
    }

    /// @notice Truncating the label hash to 11 entropy bytes is an
    /// explicit reviewed property: two hashes that share a prefix
    /// produce the same salt (and therefore the same address).
    function testSharedPrefixGivesEqualSalts() public pure {
        bytes32 labelA = keccak256("QUIP:test:truncation-a");
        // Flip the last bit, which sits outside the leading 11 bytes
        // (88 bits), so the prefix is unchanged and the full hashes
        // differ.
        bytes32 labelB = labelA ^ bytes32(uint256(1));
        assertTrue(labelA != labelB, "full hashes differ");
        assertEq(
            _labelPrefix(labelA),
            _labelPrefix(labelB),
            "leading 11 bytes match"
        );
        assertEq(
            CreateXSalt.rawSalt(labelA),
            CreateXSalt.rawSalt(labelB),
            "shared prefix -> equal salt"
        );
        assertEq(
            CreateXSalt.addressOf(CreateXSalt.rawSalt(labelA)),
            CreateXSalt.addressOf(CreateXSalt.rawSalt(labelB)),
            "shared prefix -> equal address"
        );
    }

    /// @notice THE point of the permissioned scheme: publishing a raw salt
    /// does not hand anyone the advertised address.
    /// @dev A third party calling deployCreate3 with our published raw
    /// salt does not match the embedded sender field, so CreateX applies
    /// its permissionless guard, keccak256(abi.encode(raw)), and lands
    /// them at a completely different address. Under the previous scheme
    /// those two were the same address, which is exactly the hazard
    /// test/CreateXCreate3.t.sol's Create3SquatTest still documents.
    function testSquatSurfaceIsClosed() public pure {
        string[8] memory labels = _labels();
        for (uint256 i = 0; i < labels.length; i++) {
            bytes32 raw = CreateXSalt.rawSalt(keccak256(bytes(labels[i])));

            address ours = CreateXSalt.addressOf(raw);
            address theirs = Create3.addressOf(
                keccak256(abi.encode(raw)), CreateXSalt.CREATEX
            );

            assertTrue(
                ours != theirs,
                "permissionless branch must not reach our address"
            );
        }
    }

    /// @notice The nine advertised addresses match DEPLOYMENTS.md.
    function testAdvertisedAddressesMatchRegistry() public pure {
        string[8] memory labels = _labels();
        address[8] memory expected = _addresses();
        for (uint256 i = 0; i < labels.length; i++) {
            bytes32 raw = CreateXSalt.rawSalt(keccak256(bytes(labels[i])));
            assertEq(
                CreateXSalt.addressOf(raw),
                expected[i],
                "derived address must match the published registry"
            );
        }
    }

    /// @notice No two artifacts share an address.
    function testAdvertisedAddressesAreDistinct() public pure {
        address[8] memory addrs = _addresses();
        for (uint256 i = 0; i < addrs.length; i++) {
            for (uint256 j = i + 1; j < addrs.length; j++) {
                assertTrue(addrs[i] != addrs[j], "addresses must differ");
            }
        }
    }
}
