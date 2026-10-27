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
import {CreateXSalt} from "./CreateXSalt.sol";
import {ICreateX} from "./ICreateX.sol";

/// @title CreateXDeployer
/// @notice Shared CREATE3 deploy logic for the SHRINCS verifiers and the
/// WOTS+ library (maintainer decision Q5: CREATE3 for all deploys). Each
/// concrete script pins its own salt and required build profile.
/// @dev All deploys go through the canonical CreateX singleton
/// (0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed, pre-deployed at the same
/// address on every supported chain) in CreateX's PERMISSIONED mode, so a
/// child address is a function of (CREATEX, DEPLOYER, salt) — still
/// chain-invariant and still independent of the child's init code and of
/// anything this repo compiles, but now reachable only by the canonical
/// deployer (see CreateXSalt). Nothing in the address derivation depends
/// on compiler settings; the pinned runtime codehashes still do (metadata
/// stripping in foundry.toml keeps them chain-invariant). See
/// DEPLOYMENTS.md for the superseded permissionless-salt deploys and for
/// the historical own-factory CREATE3, CREATE2 (verifier), and
/// Hardhat-Ignition (WOTS+) mechanisms this replaces.
abstract contract CreateXDeployer is Script {
    // Canonical CreateX factory (github.com/pcaversaccio/createx). Same
    // address on every chain (presigned deployment transactions; an
    // OP-stack genesis preinstall). Unlike the historical own factory it
    // is never compiled here, so no init-code pin exists or is needed.
    address internal constant CREATEX = CreateXSalt.CREATEX;

    // The one account that can deploy at any advertised address.
    address internal constant DEPLOYER = CreateXSalt.DEPLOYER;

    // Byte 20 of every raw salt. Re-exported so each concrete script can
    // spell its salt out inline (Solidity forbids function calls in a
    // `constant` initializer, so CreateXSalt.rawSalt cannot be used
    // there); the pin tests assert the inline form matches the library.
    bytes1 internal constant SALT_FLAG = CreateXSalt.FLAG_NO_CHAIN_SCOPE;

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

    // CreateX's permissioned-mode salt guard. Every QUIP:* salt embeds
    // DEPLOYER in its leading 20 bytes with a 0x00 flag byte, so CreateX
    // guards it to keccak256(abi.encode(DEPLOYER, salt)) and no other
    // account can reach the resulting address. See CreateXSalt for why
    // the deployer is hardcoded rather than read from the live caller.
    function _guardedSalt(bytes32 salt) internal pure returns (bytes32) {
        return CreateXSalt.guardedSalt(salt);
    }

    // Predict the CreateX CREATE3 child for a raw salt with local math
    // (Create3.addressOf mirrors CreateX's derivation: same canonical
    // CREATE3 proxy init code). Pure, so predictions and the pin tests
    // need no RPC; _deploy cross-checks it against CreateX's own
    // computeCreate3Address before broadcasting.
    function _addressOf(bytes32 salt) internal pure returns (address) {
        return CreateXSalt.addressOf(salt);
    }

    // HARD REQUIREMENT: the canonical deploy MUST be broadcast by
    // DEPLOYER. CreateX's guard keys on msg.sender, and a mismatch does
    // NOT revert there — it silently falls through to the permissionless
    // branch and deploys at a DIFFERENT (squattable) address. Forge
    // resolves one sender for the run and pranks it into both the call
    // caller and tx.origin for the broadcast, so this fires during
    // simulation, before anything is signed. Always pass an explicit
    // --sender alongside --private-key, and never --resume or
    // --skip-simulation: both bypass this check.
    function _requireBroadcaster() internal view {
        require(tx.origin == DEPLOYER, "deploy: wrong broadcaster");
    }

    // A SHRINCS verifier delegates stateless verification to its pinned
    // SPHINCSPlusC sibling. CREATE3 fixes the sibling address regardless
    // of deploy order, but verifyStateless reverts on empty code, so the
    // sibling MUST be deployed (its own script) FIRST. Assert all before
    // the verifier deploys: `siblingSalt` is well-formed (sender field
    // and chain-scope flag), it derives to exactly the pinned constant
    // (drift guard vs the deploy-script salt), the sibling already has
    // code, and its runtime codehash matches `siblingCodehash` — this
    // last check catches our own earlier deploy of a different
    // SPHINCSPlusC build at the same permissioned address, which would
    // otherwise pin a sibling whose bytecode differs from
    // DEPLOYMENTS.md. Call from each SHRINCS script's run().
    function _requireSibling(
        bytes32 siblingSalt,
        address pinned,
        bytes32 siblingCodehash
    ) internal view {
        CreateXSalt.requireWellFormed(siblingSalt);
        address derived = _addressOf(siblingSalt);
        require(derived == pinned, "deploy: SPHINCSPlusC sibling drift");
        require(
            derived.code.length != 0,
            "deploy: SPHINCSPlusC sibling not deployed"
        );
        require(
            derived.codehash == siblingCodehash,
            "deploy: sibling codehash drift"
        );
    }

    // Deploy `initCode` under `salt` through CreateX's CREATE3, after
    // asserting the build profile. Idempotent on our own prior deploy;
    // fails closed on any other occupant.
    //
    // `expectedCodehash` is the pinned runtime codehash of the artifact
    // (each concrete script pins it; regenerate per DEPLOYMENTS.md).
    // Under permissioned salts only DEPLOYER can reach the advertised
    // address, so squatting is prevented rather than merely detected and
    // the codehash pin is now defense in depth rather than the primary
    // guard. It still earns its keep: it catches a stale pin, a drifted
    // artifact, and the residual case of code we did not put there. The
    // occupied-address branch logs the on-chain codehash, then reverts
    // unless it equals the pin, instead of passing silently as "already
    // deployed" (fail closed, F-17). A genuine re-run (our own prior
    // deploy) matches the pin and skips.
    function _deploy(
        string memory label,
        string memory expectedProfile,
        bytes32 salt,
        bytes32 expectedCodehash,
        bytes memory initCode
    ) internal {
        _requireProfile(expectedProfile);
        _requireBroadcaster();
        // Structural check on the salt itself: catches a stale or
        // mistyped sender field and a chain-scoping flag byte, neither of
        // which the broadcaster check above can see.
        CreateXSalt.requireWellFormed(salt);
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
        console.log("broadcaster:      ", tx.origin);
        console.log(label);
        console.log("  expected addr:  ", expected);

        if (expected.code.length != 0) {
            // Log the on-chain codehash BEFORE asserting (pin regeneration
            // reads this value), then fail closed unless it matches the
            // pinned artifact hash. With permissioned salts the likely
            // cause is a stale pin or a drifted artifact rather than a
            // squatter, but either way it is never a safe skip.
            console.log("  already occupied; runtime codehash:");
            console.logBytes32(expected.codehash);
            require(
                expected.codehash == expectedCodehash,
                "deploy: address occupied by unexpected code: "
                "stale pin or drifted artifact"
            );
            console.log("  matches pinned codehash. Skipping.");
            return;
        }

        vm.broadcast();
        address deployed = ICreateX(CREATEX).deployCreate3(salt, initCode);
        // Backstop for the permissioned guard: if CreateX took any branch
        // other than the sender-scoped one we mirror, the child lands
        // elsewhere and this aborts the run. _requireBroadcaster above
        // should already have caught the usual cause.
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
