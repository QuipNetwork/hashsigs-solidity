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

import {SHRINCSCore} from "../../contracts/SHRINCSCore.sol";
import {UXMSS} from "../../contracts/UXMSS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSAccountVerifierExample
} from "../../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {SHRINCSTestSigner} from "../helpers/SHRINCSTestSigner.sol";

/// @notice Medusa-compatible wrapper subclass exposing the internal state
/// helpers the harness drives. Mirrors the forge invariant harness.
contract MedusaAccountHarness is SHRINCSAccountVerifierExample {
    constructor(bytes32 initialSHRINCSPublicKey)
        SHRINCSAccountVerifierExample(initialSHRINCSPublicKey)
    {}

    function verifyStatefulUncheckedForTest(
        SHRINCSCore.PublicKey calldata publicKey,
        bytes calldata message,
        UXMSS.StatefulSignature calldata signature
    ) external returns (bool) {
        return verifyStatefulUncheckedMessage(publicKey, message, signature);
    }

    function setStatelessSignaturesUsedForTest(uint64 value) external {
        statelessSignaturesUsed = value;
    }

    function applyFullRotationForTest(bytes32 nextKey) external {
        consumeStatelessRotationUse(nextKey, true);
        installFreshFullKey(nextKey);
    }
}

/// @title SHRINCSMedusaHarness
/// @notice Property-mode harness for the nightly Medusa campaign
/// (security-testing plan Task 5). It re-runs the wrapper state-machine
/// properties under Medusa's coverage-guided fuzzer using only plain asserts
/// and property_ functions (no forge cheatcodes). It self-initializes one
/// key in the constructor — Medusa deploys the target and cannot split the
/// 256s keygen across frames as the forge harness does, so one key is used;
/// simulated full rotations reinstall the same commitment, which still
/// advances the key epoch and resets the budget.
/// @dev property_* functions must always return true; a false return or a
/// revert is a Medusa finding. State-mutating act* functions supply the
/// coverage. This complements the per-MR forge invariant suite
/// (SHRINCSAccountInvariants) with longer randomized campaigns.
contract SHRINCSMedusaHarness {
    bytes32 internal constant FIXED_MESSAGE =
        keccak256("shrincs-invariant-fixed-stateful-message");
    uint32 internal constant MAX_LEAF = 4;

    MedusaAccountHarness internal account;
    SHRINCSCore.PublicKey internal publicKey;
    mapping(uint32 => UXMSS.StatefulSignature) internal signatureOf;

    bool internal purityViolated;
    bool internal mutationAccepted;
    bool internal resetViolated;
    uint256 internal prevKeyVersion;
    bool internal keyVersionDecreased;

    constructor() {
        SHRINCSCore.SigningKey memory signingKey;
        bool keygenOk;
        (signingKey, publicKey, keygenOk) =
            SHRINCSTestSigner.keygen(bytes("shrincs-medusa-key"), MAX_LEAF);
        require(keygenOk, "medusa keygen");
        for (uint32 leaf = 1; leaf <= MAX_LEAF; leaf++) {
            UXMSS.StatefulSignature memory signature;
            bool signOk;
            (signature, signOk) = SHRINCSTestSigner.signStatefulRawAtLeaf(
                signingKey, leaf, abi.encodePacked(FIXED_MESSAGE)
            );
            require(signOk, "medusa sign");
            signatureOf[leaf] = signature;
        }
        account = new MedusaAccountHarness(_commitmentWord(publicKey));
        prevKeyVersion = account.keyVersion();
    }

    function actValidStatefulAction() external {
        if (
            account.statefulPolicy()
                != SHRINCSAccountVerifierExample.StatefulPolicy
                .MonotonicIndex
        ) return;
        uint32 leaf = account.nextStatefulLeafIndex();
        if (leaf == 0 || leaf > MAX_LEAF) return;
        bytes32 digestBefore = _stateDigest();
        bool ok = account.verifyStatefulUncheckedForTest(
            publicKey, abi.encodePacked(FIXED_MESSAGE), signatureOf[leaf]
        );
        if (!ok && _stateDigest() != digestBefore) purityViolated = true;
        _afterOp();
    }

    function actGarbageStateful(uint256 leafSelector, bytes32 flip)
        external
    {
        // leafSelector % MAX_LEAF is < MAX_LEAF, so the cast cannot truncate
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 leaf = uint32(1 + (leafSelector % MAX_LEAF));
        UXMSS.StatefulSignature memory signature = signatureOf[leaf];
        signature.chains[0] =
            bytes32(uint256(signature.chains[0]) ^ (uint256(flip) | 1));
        bytes32 digestBefore = _stateDigest();
        bool ok = account.verifyStatefulUncheckedForTest(
            publicKey, abi.encodePacked(FIXED_MESSAGE), signature
        );
        if (ok) mutationAccepted = true;
        else if (_stateDigest() != digestBefore) purityViolated = true;
        _afterOp();
    }

    function actConsumeBudget(uint256 amount) external {
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        // amount is reduced mod (limit + 1) <= uint64 max, so the cast is
        // exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 target = uint64(amount % (uint256(limit) + 1));
        account.setStatelessSignaturesUsedForTest(target);
        _afterOp();
    }

    function actSimulateFullRotation() external {
        if (
            account.statelessSignaturesUsed()
                >= SHRINCSParams.STATELESS_SIGNATURE_LIMIT
        ) return;
        account.applyFullRotationForTest(_commitmentWord(publicKey));
        if (account.statelessSignaturesUsed() != 0) resetViolated = true;
        _afterOp();
    }

    function property_budgetWithinLimit() external view returns (bool) {
        return account.statelessSignaturesUsed()
            <= SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
    }

    function property_budgetResetOnFullRotation()
        external
        view
        returns (bool)
    {
        return !resetViolated;
    }

    function property_keyVersionMonotone() external view returns (bool) {
        return !keyVersionDecreased;
    }

    function property_failClosedPurity() external view returns (bool) {
        return !purityViolated && !mutationAccepted;
    }

    function _afterOp() internal {
        uint256 current = account.keyVersion();
        if (current < prevKeyVersion) keyVersionDecreased = true;
        prevKeyVersion = current;
    }

    function _stateDigest() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                account.nonce(),
                account.keyVersion(),
                account.statelessSignaturesUsed(),
                uint8(account.statefulPolicy()),
                account.statefulPolicyFrozen(),
                account.nextStatefulLeafIndex(),
                account.recoveryMode(),
                account.currentSHRINCSPublicKey()
            )
        );
    }

    function _commitmentWord(SHRINCSCore.PublicKey memory key)
        internal
        pure
        returns (bytes32 word)
    {
        bytes memory encoded = key.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }
}
