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
import {DeployWOTSPlus} from "../script/DeployWOTSPlus.s.sol";

/// @dev Exposes the WOTS+ deploy script's internal SALT so the inline
/// composition the scripts must write (CreateXSalt.rawSalt is a function
/// call, which Solidity forbids in a `constant` initializer) can be
/// asserted against the library. WOTS+ is the only deploy script no
/// profile skips, so this probe compiles everywhere; the four pin tests
/// cover the profile-gated scripts the same way.
contract DeployWOTSPlusProbe is DeployWOTSPlus {
    function salt() external pure returns (bytes32) {
        return SALT;
    }
}

/// @notice Pins the permissioned CreateX salt scheme: every canonical salt
/// is laid out the way CreateX's sender-scoped branch requires, every
/// advertised address matches DEPLOYMENTS.md, and — the point of the whole
/// scheme — a third party using a published raw salt lands somewhere else.
/// @dev Profile-independent: the salts are pure math over their label
/// strings, so this file imports nothing profile-gated and is in no `skip`
/// list. It therefore runs under all four ci-matrix profiles.
contract CreateXSaltInvariantsTest is Test {
    // Every canonical salt label. Order is the DEPLOYMENTS.md table order.
    function _labels() internal pure returns (string[9] memory) {
        return [
            "QUIP:SPHINCSPlusC256sKeccak:V1.0",
            "QUIP:SPHINCSPlusC128sQ18Keccak:V1.0",
            "QUIP:SPHINCSPlusC128sQ20Keccak:V1.0",
            "QUIP:SPHINCSPlusC256sSha2:V1.0",
            "QUIP:SHRINCS256sKeccak:V1.0",
            "QUIP:SHRINCS128sQ18Keccak:V1.0",
            "QUIP:SHRINCS128sQ20Keccak:V1.0",
            "QUIP:SHRINCS256sSha2:V1.0",
            "QUIP:WOTSPlus:V1.0"
        ];
    }

    // The published addresses, in the same order. This is the
    // DEPLOYMENTS.md <-> code regression lock: it fails loudly if anyone
    // edits a label, the deployer, the flag byte, or the entropy width.
    function _addresses() internal pure returns (address[9] memory) {
        return [
            0x97B3726F44e3B7521199CE4e0fC160A32A597d31,
            0xF4f47272350af70D9735FDBf42d398D17470c2f0,
            0x0A218Bf4A264B00c89883b2A780478627a0C7E08,
            0x8F477848aC34523095F68f60C5d5eFa21a491fCA,
            0xE6F2970bA30d59e8288b7007bA755828372457c3,
            0xDA52530D9027bea659d8458e1128a566B43C8c69,
            0x4f78F04b9C496749972afcb0ad5C114326De5086,
            0x31F7262Db25b5F16ddfA4A995FfB298386BB57D8,
            0xef0CbdEC1ed6Db29F44030Bc22e4BD1D19898208
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

    /// @notice Every salt is laid out as CreateX's sender-scoped branch
    /// requires: [20B DEPLOYER][0x00][11B of the label hash].
    /// @dev A wrong sender field silently routes CreateX to its
    /// permissionless branch (squattable address); a 0x01 flag byte
    /// silently routes it to the chain-scoped branch, giving a different
    /// address per chain. Neither reverts inside CreateX, so this is the
    /// check that catches them.
    function testEverySaltIsWellFormed() public pure {
        string[9] memory labels = _labels();
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

    /// @notice THE point of the permissioned scheme: publishing a raw salt
    /// does not hand anyone the advertised address.
    /// @dev A third party calling deployCreate3 with our published raw
    /// salt does not match the embedded sender field, so CreateX applies
    /// its permissionless guard, keccak256(abi.encode(raw)), and lands
    /// them at a completely different address. Under the previous scheme
    /// those two were the same address, which is exactly the hazard
    /// test/CreateXCreate3.t.sol's Create3SquatTest still documents.
    function testSquatSurfaceIsClosed() public pure {
        string[9] memory labels = _labels();
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
        string[9] memory labels = _labels();
        address[9] memory expected = _addresses();
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
        address[9] memory addrs = _addresses();
        for (uint256 i = 0; i < addrs.length; i++) {
            for (uint256 j = i + 1; j < addrs.length; j++) {
                assertTrue(addrs[i] != addrs[j], "addresses must differ");
            }
        }
    }

    /// @notice The WOTS+ script's inline salt matches the library.
    /// @dev The scripts cannot call CreateXSalt.rawSalt in a `constant`
    /// initializer, so they duplicate the composition. This asserts the
    /// duplicate is faithful — the four pin tests do the same for the
    /// profile-gated scripts.
    function testDeployScriptSaltMatchesLibrary() public {
        DeployWOTSPlusProbe probe = new DeployWOTSPlusProbe();
        assertEq(
            probe.salt(),
            CreateXSalt.rawSalt(keccak256("QUIP:WOTSPlus:V1.0")),
            "DeployWOTSPlus SALT must match CreateXSalt.rawSalt"
        );
    }
}
