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
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCS256sSha2} from "../contracts/SHRINCS256sSha2.sol";
import {SPHINCSPlusC256sSha2} from "../contracts/SPHINCSPlusC256sSha2.sol";
import {DeploySHRINCS256sSha2} from "../script/DeploySHRINCS256sSha2.s.sol";

/// @dev Exposes the internal pinned SPHINCSPlusC address of the concrete
/// 256s-sha2 deployable so the pin test can compare it to the CREATE3
/// derivation.
contract SHRINCS256sSha2PinHarness is SHRINCS256sSha2 {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @dev Exposes the deploy script's SPHINCSPlusC sibling salt/address
/// constants (both internal) so the pin test can assert they match the
/// CREATE3 derivation. The script validates these only at deploy time, so
/// a typo would otherwise reach production; this makes it fail CI.
contract DeploySHRINCS256sSha2Probe is DeploySHRINCS256sSha2 {
    function siblingSalt() external pure returns (bytes32) {
        return SPHINCS_PLUS_C_SALT;
    }

    function siblingAddr() external pure returns (address) {
        return SPHINCS_PLUS_C;
    }
}

/// @notice Pins the 256s-sha2 SHRINCS verifier's SPHINCSPlusC sibling address
/// to its CREATE3 derivation so the deploy scripts cannot drift from the
/// pinned constant. The derivation goes through the pre-deployed CreateX
/// singleton, so it is suite-independent pure math — no compiled factory
/// artifact is involved. Profile-gated (256s-sha2) like the deployable
/// itself.
contract SHRINCSPinned256sSha2Test is Test {
    // Canonical CreateX singleton; mirrors DeployBase.s.sol CREATEX.
    address internal constant CREATEX =
        0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    bytes32 internal constant CHILD_SALT =
        keccak256("QUIP:SPHINCSPlusC256sSha2:V1.0");

    function testPinnedAddressMatchesCreate3Derivation() public {
        // CreateX guards a plain (non-sender-prefixed) salt to
        // keccak256(abi.encode(salt)) before its CREATE3 deploy.
        address expected =
            Create3.addressOf(keccak256(abi.encode(CHILD_SALT)), CREATEX);

        SHRINCS256sSha2PinHarness harness = new SHRINCS256sSha2PinHarness();
        assertEq(
            harness.pinned(),
            expected,
            "pinned SPHINCSPlusC256sSha2 address must match CREATE3"
        );

        // Mirror the deploy script's sibling constants against the same
        // derivation so a typo in the script fails CI, not just deploy.
        DeploySHRINCS256sSha2Probe probe = new DeploySHRINCS256sSha2Probe();
        assertEq(
            probe.siblingSalt(),
            CHILD_SALT,
            "deploy script SPHINCS_PLUS_C_SALT must match pin test"
        );
        assertEq(
            probe.siblingAddr(),
            expected,
            "deploy script SPHINCS_PLUS_C must match CREATE3 derivation"
        );
    }

    /// @notice Both 256s-sha2 deployables tag their compiled parameter set
    /// with the profile's PROFILE_ID (suite-qualified shrincs-256s-sha2).
    function testProfileTagMatchesProfileId() public {
        assertEq(
            new SHRINCS256sSha2().PROFILE_TAG(),
            SHRINCSParams.PROFILE_ID,
            "SHRINCS256sSha2 PROFILE_TAG"
        );
        assertEq(
            new SPHINCSPlusC256sSha2().PROFILE_TAG(),
            SHRINCSParams.PROFILE_ID,
            "SPHINCSPlusC256sSha2 PROFILE_TAG"
        );
    }
}
