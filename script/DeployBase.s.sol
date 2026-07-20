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

import {Script, console} from "../lib/forge-std/src/Script.sol";
import {Create3} from "./Create3.sol";
import {ICreateX} from "./ICreateX.sol";

/// @title CreateXDeployer
/// @notice Shared CREATE3 deploy logic for the SHRINCS verifiers and the
/// WOTS+ library (maintainer decision Q5: CREATE3 for all deploys). Each
/// concrete script pins its own salt and required build profile.
/// @dev All deploys go through the canonical CreateX singleton
/// (0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed, pre-deployed at the same
/// address on every supported chain), so a child address is a function of
/// (CREATEX, salt) ONLY — chain-invariant, independent of the child's
/// init code, and independent of anything this repo compiles. Nothing in
/// the address derivation depends on compiler settings; the pinned
/// runtime codehashes still do (metadata stripping in foundry.toml keeps
/// them chain-invariant). SHRINCS is testnet-only; see DEPLOYMENTS.md
/// for the historical own-factory CREATE3, CREATE2 (verifier), and
/// Hardhat-Ignition (WOTS+) mechanisms this replaces.
abstract contract CreateXDeployer is Script {
    // Canonical CreateX factory (github.com/pcaversaccio/createx). Same
    // address on every chain (presigned deployment transactions; an
    // OP-stack genesis preinstall). Unlike the historical own factory it
    // is never compiled here, so no init-code pin exists or is needed.
    address internal constant CREATEX =
        0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    // HARD REQUIREMENT (F-17): the canonical deploy MUST run under the
    // expected build profile, or the wrong parameter set / bytecode is
    // deployed. Fail closed rather than publish a mislabeled artifact.
    function _requireProfile(string memory expected) internal view {
        string memory profile = vm.envOr("FOUNDRY_PROFILE", string(""));
        require(
            keccak256(bytes(profile)) == keccak256(bytes(expected)),
            "deploy: wrong FOUNDRY_PROFILE"
        );
    }

    // CreateX cannot be bootstrapped by this tooling: it deploys only
    // through its published presigned transactions (see DEPLOYMENTS.md),
    // so its absence fails the run instead.
    function _requireCreateX() internal view {
        require(
            CREATEX.code.length != 0,
            "deploy: CreateX not deployed on this chain"
        );
    }

    // CreateX's permissionless-mode salt guard: a salt whose first 20
    // bytes are neither msg.sender nor zero (every QUIP:* salt) is
    // guarded to keccak256(abi.encode(salt)) before the CREATE3 deploy.
    function _guardedSalt(bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(salt));
    }

    // Predict the CreateX CREATE3 child for a raw salt with local math
    // (Create3.addressOf mirrors CreateX's derivation: same canonical
    // CREATE3 proxy init code). Pure, so predictions and the pin tests
    // need no RPC; _deploy cross-checks it against CreateX's own
    // computeCreate3Address before broadcasting.
    function _addressOf(bytes32 salt) internal pure returns (address) {
        return Create3.addressOf(_guardedSalt(salt), CREATEX);
    }

    // A SHRINCS verifier delegates stateless verification to its pinned
    // SPHINCSPlusC sibling. CREATE3 fixes the sibling address regardless
    // of deploy order, but verifyStateless reverts on empty code, so the
    // sibling MUST be deployed (its own script) FIRST. Assert both before
    // the verifier deploys: `siblingSalt` derives to exactly the pinned
    // constant (drift guard vs the deploy-script salt), and the sibling
    // already has code. Call from each SHRINCS script's run().
    function _requireSibling(bytes32 siblingSalt, address pinned)
        internal
        view
    {
        address derived = _addressOf(siblingSalt);
        require(derived == pinned, "deploy: SPHINCSPlusC sibling drift");
        require(
            derived.code.length != 0,
            "deploy: SPHINCSPlusC sibling not deployed"
        );
    }

    // Deploy `initCode` under `salt` through CreateX's CREATE3, after
    // asserting the build profile. Idempotent on our own prior deploy;
    // fails closed on any other occupant.
    //
    // `expectedCodehash` is the pinned runtime codehash of the artifact
    // (each concrete script pins it; regenerate per DEPLOYMENTS.md).
    // CREATE3 child addresses are a function of (CREATEX, salt) ONLY —
    // CreateX's permissionless mode ignores init code and sender, so a
    // third party can pre-deploy arbitrary code at a documented salt and
    // permanently capture the advertised address. The occupied-address
    // branch therefore cannot assume the code is ours: it logs the
    // on-chain codehash, then reverts unless it equals the pin. A
    // squatted salt or a stale pin aborts the deploy instead of passing
    // silently as "already deployed" (fail closed, F-17). A genuine
    // re-run (our own prior deploy) matches the pin and skips.
    function _deploy(
        string memory label,
        string memory expectedProfile,
        bytes32 salt,
        bytes32 expectedCodehash,
        bytes memory initCode
    ) internal {
        _requireProfile(expectedProfile);
        _requireCreateX();

        // Local prediction, cross-checked against CreateX's own view
        // (computeCreate3Address takes the GUARDED salt). A mismatch
        // means the guard or derivation assumptions broke — fail before
        // broadcasting anything.
        address expected = _addressOf(salt);
        require(
            ICreateX(CREATEX).computeCreate3Address(_guardedSalt(salt))
                == expected,
            "deploy: CreateX address derivation drift"
        );

        console.log("CreateX factory:  ", CREATEX);
        console.log(label);
        console.log("  expected addr:  ", expected);

        if (expected.code.length != 0) {
            // Log the on-chain codehash BEFORE asserting (pin regeneration
            // reads this value), then fail closed unless it matches the
            // pinned artifact hash. A mismatch is a squatted salt or a
            // stale pin, never a safe skip.
            console.log("  already occupied; runtime codehash:");
            console.logBytes32(expected.codehash);
            require(
                expected.codehash == expectedCodehash,
                "deploy: address occupied by unexpected code: "
                "squatted or stale pin"
            );
            console.log("  matches pinned codehash. Skipping.");
            return;
        }

        vm.broadcast();
        address deployed = ICreateX(CREATEX).deployCreate3(salt, initCode);
        require(deployed == expected, "deploy: address mismatch");

        console.log("  deployed at:    ", deployed);
        // The registry value; consumers pin (address, codehash) from
        // DEPLOYMENTS.md, never from a local rebuild. Log it BEFORE the pin
        // assert so a first deploy still prints the value to record even
        // when the pin is a placeholder, then fail closed if the freshly
        // deployed code drifts from the pin.
        console.log("  runtime codehash (record in DEPLOYMENTS.md):");
        console.logBytes32(deployed.codehash);
        require(
            deployed.codehash == expectedCodehash,
            "deploy: deployed codehash != pinned artifact"
        );
    }
}
