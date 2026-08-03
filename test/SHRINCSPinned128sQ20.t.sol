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
import {CreateXSalt} from "../script/CreateXSalt.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCS128sQ20Keccak} from "../contracts/SHRINCS128sQ20Keccak.sol";
import {
    SPHINCSPlusC128sQ20Keccak
} from "../contracts/SPHINCSPlusC128sQ20Keccak.sol";
import {
    DeploySHRINCS128sQ20Keccak
} from "../script/DeploySHRINCS128sQ20Keccak.s.sol";
import {
    DeploySPHINCSPlusC128sQ20Keccak
} from "../script/DeploySPHINCSPlusC128sQ20Keccak.s.sol";

/// @dev Exposes the internal pinned SPHINCSPlusC address of the concrete
/// 128s-q20 deployable so the pin test can compare it to the CREATE3
/// derivation.
contract SHRINCS128sQ20PinHarness is SHRINCS128sQ20Keccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @dev Exposes the deploy script's SPHINCSPlusC sibling salt/address
/// constants (both internal) so the pin test can assert they match the
/// CREATE3 derivation. The script validates these only at deploy time, so
/// a typo would otherwise reach production; this makes it fail CI.
contract DeploySHRINCS128sQ20Probe is DeploySHRINCS128sQ20Keccak {
    function siblingSalt() external pure returns (bytes32) {
        return SPHINCS_PLUS_C_SALT;
    }

    function siblingAddr() external pure returns (address) {
        return SPHINCS_PLUS_C;
    }
}

/// @dev Exposes the SPHINCSPlusC deploy script's internal SALT so
/// the pin test can assert that script's inline salt composition
/// matches the library derivation. The scripts must duplicate the
/// composition (Solidity forbids a function call in a `constant`
/// initializer), so this is what keeps the duplicate honest.
contract DeploySPHINCSPlusC128sQ20Probe is DeploySPHINCSPlusC128sQ20Keccak {
    function salt() external pure returns (bytes32) {
        return SALT;
    }
}

/// @notice Pins the 128s-q20 SHRINCS verifier's SPHINCSPlusC sibling address
/// to its CREATE3 derivation so the deploy scripts cannot drift from the
/// pinned constant. Profile-gated (128s-q20) like the deployable itself.
contract SHRINCSPinned128sQ20Test is Test {
    // Canonical CreateX singleton; mirrors DeployBase.s.sol CREATEX. The
    // derivation needs no compiled artifact: CreateX is pre-deployed, so
    // the child address is pure math over (CREATEX, guarded salt) and is
    // identical under every build profile.
    address internal constant CREATEX =
        0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    bytes32 internal constant CHILD_LABEL =
        keccak256("QUIP:SPHINCSPlusC128sQ20Keccak:V1.0");

    function testPinnedAddressMatchesCreate3Derivation() public {
        // CreateX guards our sender-prefixed salt to
        // keccak256(abi.encode(DEPLOYER, salt)) before its CREATE3
        // deploy, so only the canonical deployer can reach this
        // address. CREATEX is asserted against the library below.
        assertEq(
            CREATEX,
            CreateXSalt.CREATEX,
            "pin test CREATEX must match the deploy library"
        );
        bytes32 childSalt = CreateXSalt.rawSalt(CHILD_LABEL);
        address expected = CreateXSalt.addressOf(childSalt);

        SHRINCS128sQ20PinHarness harness = new SHRINCS128sQ20PinHarness();
        assertEq(
            harness.pinned(),
            expected,
            "pinned SPHINCSPlusC128sQ20Keccak address must match CREATE3"
        );

        // Mirror the deploy script's sibling constants against the same
        // derivation so a typo in the script fails CI, not just deploy.
        DeploySHRINCS128sQ20Probe probe = new DeploySHRINCS128sQ20Probe();
        assertEq(
            probe.siblingSalt(),
            childSalt,
            "deploy script SPHINCS_PLUS_C_SALT must match pin test"
        );
        assertEq(
            probe.siblingAddr(),
            expected,
            "deploy script SPHINCS_PLUS_C must match CREATE3 derivation"
        );

        DeploySPHINCSPlusC128sQ20Probe childProbe =
            new DeploySPHINCSPlusC128sQ20Probe();
        assertEq(
            childProbe.salt(),
            childSalt,
            "SPHINCSPlusC deploy script SALT must match derivation"
        );
    }

    /// @notice Both 128s-q20 deployables tag their compiled parameter set
    /// with the profile's PROFILE_ID (shrincs-128s-q20-keccak).
    function testProfileTagMatchesProfileId() public {
        assertEq(
            new SHRINCS128sQ20Keccak().PROFILE_TAG(),
            SHRINCSParams.PROFILE_ID,
            "SHRINCS128sQ20Keccak PROFILE_TAG"
        );
        assertEq(
            new SPHINCSPlusC128sQ20Keccak().PROFILE_TAG(),
            SHRINCSParams.PROFILE_ID,
            "SPHINCSPlusC128sQ20Keccak PROFILE_TAG"
        );
    }
}
