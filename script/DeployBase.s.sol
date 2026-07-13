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
import {Create3Factory} from "./Create3.sol";

/// @title Create3Deployer
/// @notice Shared CREATE3 deploy logic for the SHRINCS verifiers and the
/// WOTS+ library (maintainer decision Q5: CREATE3 for all deploys). Each
/// concrete script pins its own salt and required build profile.
/// @dev CREATE3 addresses depend only on (factory, salt), so a child's
/// address is chain-invariant and independent of its init code (unlike
/// CREATE2, where a recompile moved the address). The factory itself is
/// a fixed-bytecode contract deployed once per chain at a deterministic
/// address through the canonical CREATE2 proxy, so it is chain-invariant
/// too. SHRINCS is testnet-only; see DEPLOYMENTS.md for the historical
/// CREATE2 (verifier) and Hardhat-Ignition (WOTS+) mechanisms this
/// replaces.
abstract contract Create3Deployer is Script {
    // Salt for the shared CREATE3 factory. Its address (and thus every
    // child address) is a function of this salt and the factory
    // creation-code hash; bump only for a deliberate factory
    // replacement.
    bytes32 internal constant FACTORY_SALT =
        keccak256("QUIP:Create3Factory:V1.0");

    // Pinned keccak256 of the Create3Factory creation code under a
    // PRODUCTION profile. The factory address is
    //   CREATE2(CREATE2_FACTORY, FACTORY_SALT, FACTORY_INITCODE_HASH)
    //   = 0xcE8dAc13593a359d961F91c35F8694cb2A03D005
    // and every deployable is a CREATE3 child of it. foundry.toml strips
    // solc metadata (bytecode_hash="none", cbor_metadata=false), so this
    // hash is identical across all three production profiles (256s /
    // 128s-q18 / 128s-q20): ONE factory serves every suite. It is NOT
    // the test-profile value — test profiles optimize for 200 runs, the
    // production profiles for 1,000,000, so their factory creation code
    // (and hash) differ. The production hash is what actually deploys and
    // is therefore the canonical pinned value; the profile-gated pin
    // tests (test/SHRINCSPinned*.t.sol) mirror it to derive the
    // production factory address without a production build. Regenerate
    // by running any deploy script under a production profile and reading
    // the logged factory init-code hash.
    bytes32 internal constant FACTORY_INITCODE_HASH =
        0xbe6eb1cac061b12187ed962ba44e19142929386dd027feee67ed5ea587777f05;

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

    // Return the chain's CREATE3 factory, deploying it deterministically
    // through the canonical CREATE2 proxy on first use.
    function _factory() internal returns (Create3Factory factory) {
        // The canonical deploy runs under a production profile, whose
        // metadata-free factory creation code hashes to
        // FACTORY_INITCODE_HASH. Log the computed hash (this is the value
        // the pin-regeneration procedure above reads) BEFORE asserting it,
        // so the hash is printed even when the drift check reverts. The
        // assert makes a Create3.sol change (which would move the factory
        // and every child address) fail the deploy instead of silently
        // landing at a different address.
        bytes32 initCodeHash = keccak256(type(Create3Factory).creationCode);
        console.log("Create3Factory init-code hash:");
        console.logBytes32(initCodeHash);
        require(
            initCodeHash == FACTORY_INITCODE_HASH,
            "deploy: factory init-code drift"
        );
        address predicted = vm.computeCreate2Address(
            FACTORY_SALT, FACTORY_INITCODE_HASH, CREATE2_FACTORY
        );
        if (predicted.code.length == 0) {
            vm.broadcast();
            Create3Factory deployed =
                new Create3Factory{salt: FACTORY_SALT}();
            require(
                address(deployed) == predicted,
                "deploy: factory address mismatch"
            );
            return deployed;
        }
        return Create3Factory(predicted);
    }

    // A SHRINCS verifier delegates stateless verification to its pinned
    // SPHINCSPlusC sibling. CREATE3 fixes the sibling address regardless
    // of deploy order, but verifyStateless reverts on empty code, so the
    // sibling MUST be deployed (its own script) FIRST. Assert both before
    // the verifier deploys: `siblingSalt` derives to exactly the pinned
    // constant (drift guard vs the deploy-script salt), and the sibling
    // already has code. Call from each SHRINCS script's run().
    function _requireSibling(bytes32 siblingSalt, address pinned) internal {
        address derived = _factory().addressOf(siblingSalt);
        require(derived == pinned, "deploy: SPHINCSPlusC sibling drift");
        require(
            derived.code.length != 0,
            "deploy: SPHINCSPlusC sibling not deployed"
        );
    }

    // Deploy `initCode` under `salt` via CREATE3, after asserting the
    // build profile. Idempotent on our own prior deploy; fails closed on
    // any other occupant.
    //
    // `expectedCodehash` is the pinned runtime codehash of the artifact
    // (each concrete script pins it and regenerates it the way
    // FACTORY_INITCODE_HASH above is regenerated; see DEPLOYMENTS.md).
    // CREATE3 child addresses are a function of (factory, salt) ONLY — the
    // factory is permissionless and ignores init code (Create3Factory
    // NatSpec), so a third party can pre-deploy arbitrary code at a
    // documented salt and permanently capture the advertised address. The
    // occupied-address branch therefore cannot assume the code is ours: it
    // logs the on-chain codehash, then reverts unless it equals the pin. A
    // squatted salt or a stale pin aborts the deploy instead of passing
    // silently as "already deployed" (fail closed, F-17). A genuine re-run
    // (our own prior deploy) matches the pin and skips.
    function _deploy(
        string memory label,
        string memory expectedProfile,
        bytes32 salt,
        bytes32 expectedCodehash,
        bytes memory initCode
    ) internal {
        _requireProfile(expectedProfile);
        Create3Factory factory = _factory();
        address expected = factory.addressOf(salt);

        console.log("CREATE3 factory:  ", address(factory));
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
        address deployed = factory.deploy(salt, initCode);
        require(deployed == expected, "deploy: address mismatch");

        console.log("  deployed at:    ", deployed);
        // The registry value; consumers pin (address, codehash) from
        // DEPLOYMENTS.md, never from a local rebuild. Log it BEFORE the pin
        // assert so a first deploy still prints the value to record even
        // when the pin is a placeholder (same log-before-assert flow as
        // FACTORY_INITCODE_HASH), then fail closed if the freshly deployed
        // code drifts from the pin.
        console.log("  runtime codehash (record in DEPLOYMENTS.md):");
        console.logBytes32(deployed.codehash);
        require(
            deployed.codehash == expectedCodehash,
            "deploy: deployed codehash != pinned artifact"
        );
    }
}
