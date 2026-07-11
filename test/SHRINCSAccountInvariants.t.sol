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
import {SHRINCSCore} from "../contracts/SHRINCSCore.sol";
import {SPHINCSPlusCCore} from "../contracts/SPHINCSPlusCCore.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";

/// @notice Minimal wrapper subclass exposing the internal state-transition
/// helpers the invariant handler drives directly. Stateful actions run
/// through the raw unchecked-message path so a signature signed once (in
/// setUp) replays across the whole campaign; the rotation helpers apply the
/// same internal installFreshStatefulKey/installFreshFullKey the canonical
/// rotate paths call after a valid recovery signature, so the budget-reset
/// and key-epoch transitions are exercised without an in-loop stateless sign
/// (infeasible at 256s).
contract InvariantAccountHarness is SHRINCSAccountVerifierExample {
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

    function applyStatefulRotationForTest(bytes32 nextKey) external {
        consumeStatelessRotationUse(nextKey, false);
        installFreshStatefulKey(nextKey);
    }

    function applyFullRotationForTest(bytes32 nextKey) external {
        consumeStatelessRotationUse(nextKey, true);
        installFreshFullKey(nextKey);
    }
}

/// @notice Fuzz-driven handler for the wrapper state machine. Each external
/// act* function is a fuzz-selected operation mixing valid stateful actions
/// (replayed from setUp-signed material), adversarial/garbage calls, owner
/// policy changes, and simulated rotations. Ghost booleans latch any
/// violation of invariants I1-I7 for the invariant contract to assert.
contract SHRINCSAccountHandler is Test {
    // Fixed 32-byte message signed once per (key, leaf) in setUp and replayed
    // through the raw stateful path for the whole campaign.
    bytes32 internal constant FIXED_MESSAGE =
        keccak256("shrincs-invariant-fixed-stateful-message");
    // Two pre-generated keys let simulated rotations install a fresh epoch
    // whose stateful signatures the handler still holds.
    uint256 internal constant KEY_COUNT = 2;
    // Leaves 1..MAX_LEAF are pre-signed per key.
    uint32 internal constant MAX_LEAF = 4;

    InvariantAccountHarness public account;

    // Pre-signed material, keyed by [keyIndex][leafIndex].
    mapping(uint256 => SHRINCSCore.PublicKey) internal publicKeyOf;
    mapping(uint256 => bytes32) internal commitmentOf;
    mapping(uint256 => mapping(uint32 => UXMSS.StatefulSignature)) internal
        signatureOf;

    // Monotonicity high-water marks and latched violations (I1, I2). The
    // *Stuck flags catch a rotation that failed to advance nonce/keyVersion,
    // which pure "never decreases" checks cannot see.
    uint256 public ghostPrevNonce;
    uint256 public ghostPrevKeyVersion;
    bool public ghostNonceDecreased;
    bool public ghostKeyVersionDecreased;
    bool public ghostNonceStuck;
    bool public ghostKeyVersionStuck;
    // I5: whether a stateful leaf has been consumed in the current epoch,
    // tracked independently of the wrapper's own freeze flag so removing that
    // flag is caught.
    bool public ghostLeafConsumedThisEpoch;
    // I3: a full rotation must zero the stateless budget; a stateful-only
    // rotation must preserve it.
    bool public ghostResetViolated;
    // I4: bitmap leaves observed used under the current key epoch.
    uint256 public ghostBitmapKeyVersion;
    uint32[] internal ghostUsedLeaves;
    // I5: an owner policy change succeeded after the epoch froze.
    bool public ghostFrozenPolicyChanged;
    // I6: a rotate path returned true without an armed recovery signature.
    bool public ghostRotateGatingViolated;
    // I7: a false-returning call mutated observable state, or a mutated
    // signature was accepted.
    bool public ghostPurityViolated;
    bool public ghostMutationAccepted;

    // prepareKey: keygen one key and pre-sign leaves 1..MAX_LEAF against the
    // fixed message. Called once per key as a separate external frame so the
    // 256s keygen's memory is reclaimed between keys (a single frame doing
    // both keys exceeds the EVM memory limit — memory never frees within a
    // call).
    function prepareKey(uint256 keyIndex) external {
        bytes memory seed =
            abi.encodePacked("shrincs-invariant-key", keyIndex);
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(seed, MAX_LEAF);
        require(keygenOk, "handler keygen");
        publicKeyOf[keyIndex] = publicKey;
        commitmentOf[keyIndex] = _commitmentWord(publicKey);
        for (uint32 leaf = 1; leaf <= MAX_LEAF; leaf++) {
            UXMSS.StatefulSignature memory signature;
            bool signOk;
            (signature, signOk) = SHRINCSTestSigner.signStatefulRawAtLeaf(
                signingKey, leaf, abi.encodePacked(FIXED_MESSAGE)
            );
            require(signOk, "handler sign");
            signatureOf[keyIndex][leaf] = signature;
        }
    }

    // deployAccount: install the first prepared key and snapshot the epoch.
    // Called after every prepareKey.
    function deployAccount() external {
        account = new InvariantAccountHarness(commitmentOf[0]);
        ghostBitmapKeyVersion = account.keyVersion();
    }

    // actValidStatefulAction: consume the next policy-allowed leaf with a
    // valid replayed signature. Advances leaf tracking (monotonic cursor or
    // bitmap bit) exactly as the canonical action path would.
    function actValidStatefulAction(uint256) external {
        (uint256 keyIndex, bool found) = _currentKeyIndex();
        if (!found) return;
        SHRINCSAccountVerifierExample.StatefulPolicy policy =
            account.statefulPolicy();
        if (
            policy
                == SHRINCSAccountVerifierExample.StatefulPolicy
                .RecoveryRotation
        ) return;

        uint32 leaf;
        if (
            policy
                == SHRINCSAccountVerifierExample.StatefulPolicy
                .MonotonicIndex
        ) {
            leaf = account.nextStatefulLeafIndex();
            if (leaf == 0 || leaf > MAX_LEAF) return;
        } else {
            leaf = _firstUnusedLeaf();
            if (leaf == 0) return;
        }

        bool isBitmap = policy
            == SHRINCSAccountVerifierExample.StatefulPolicy.LeafBitmap;
        bytes32 digestBefore = _stateDigest();
        bool ok = account.verifyStatefulUncheckedForTest(
            publicKeyOf[keyIndex],
            abi.encodePacked(FIXED_MESSAGE),
            signatureOf[keyIndex][leaf]
        );
        if (ok) {
            ghostLeafConsumedThisEpoch = true;
            if (isBitmap) _recordBitmapLeaf(leaf);
        } else if (_stateDigest() != digestBefore) {
            ghostPurityViolated = true;
        }
        _afterOp();
    }

    // actGarbageStateful: a single-word mutation of a valid signature must
    // fail (never a second accepted encoding) and leave state untouched.
    function actGarbageStateful(uint256 leafSelector, bytes32 flip)
        external
    {
        (uint256 keyIndex, bool found) = _currentKeyIndex();
        if (!found) return;
        uint32 leaf = uint32(bound(leafSelector, 1, MAX_LEAF));
        UXMSS.StatefulSignature memory signature =
            signatureOf[keyIndex][leaf];
        signature.chains[0] =
            bytes32(uint256(signature.chains[0]) ^ (uint256(flip) | 1));

        bytes32 digestBefore = _stateDigest();
        bool ok = account.verifyStatefulUncheckedForTest(
            publicKeyOf[keyIndex], abi.encodePacked(FIXED_MESSAGE), signature
        );
        if (ok) {
            ghostMutationAccepted = true;
        } else if (_stateDigest() != digestBefore) {
            ghostPurityViolated = true;
        }
        _afterOp();
    }

    // actGarbageStateless: an empty stateless signature must be rejected with
    // no state change (fail-closed, I7).
    function actGarbageStateless(bytes32 actionType, bytes32 payloadHash)
        external
    {
        SPHINCSPlusCCore.StatelessSignature memory signature;
        bytes32 digestBefore = _stateDigest();
        bool ok = account.verifyStatelessAction(
            publicKeyOf[0], actionType, payloadHash, signature
        );
        if (ok) {
            ghostMutationAccepted = true;
        } else if (_stateDigest() != digestBefore) {
            ghostPurityViolated = true;
        }
        _afterOp();
    }

    // actUnarmedRotateFull: rotateFullKey with a garbage recovery signature
    // must fail closed. A true return would mean rotation happened without a
    // valid armed recovery signature (I6); any state change on false breaks
    // purity (I7).
    function actUnarmedRotateFull(uint256 targetSelector) external {
        (uint256 keyIndex, bool found) = _currentKeyIndex();
        if (!found) return;
        uint256 targetIndex = bound(targetSelector, 0, KEY_COUNT - 1);
        SPHINCSPlusCCore.StatelessSignature memory signature;
        bytes32 digestBefore = _stateDigest();
        bool ok = account.rotateFullKey(
            publicKeyOf[keyIndex], signature, _fullTarget(targetIndex)
        );
        if (ok) {
            ghostRotateGatingViolated = true;
        } else if (_stateDigest() != digestBefore) {
            ghostPurityViolated = true;
        }
        _afterOp();
    }

    // actArmRecovery: switch to recovery policy and arm recovery mode (owner
    // path; reverts once frozen). Exercises the recovery gating that
    // actUnarmedRotateFull probes.
    function actArmRecovery() external {
        try account.setStatefulPolicyRecoveryRotation() {
            try account.enterRecoveryMode() {} catch {}
        } catch {}
        _afterOp();
    }

    // actSetPolicyBitmap: owner switch to bitmap tracking. Once frozen the
    // call must revert and leave the policy unchanged (I5).
    function actSetPolicyBitmap() external {
        _trySetPolicy(0);
    }

    // actSetPolicyMonotonic: owner switch to monotonic tracking (I5). If a
    // leaf was already consumed this epoch the change must not take effect.
    function actSetPolicyMonotonic(uint256 leafSelector) external {
        uint32 initial = uint32(bound(leafSelector, 1, MAX_LEAF));
        SHRINCSAccountVerifierExample.StatefulPolicy before =
            account.statefulPolicy();
        try account.setStatefulPolicyMonotonicIndex(initial) {
            if (ghostLeafConsumedThisEpoch) ghostFrozenPolicyChanged = true;
        } catch {
            if (account.statefulPolicy() != before) {
                ghostFrozenPolicyChanged = true;
            }
        }
        _afterOp();
    }

    // actConsumeBudget: raise the stateless budget to a value in range so the
    // rotation-reset invariants have a nonzero budget to act on. Bounded to
    // the limit so the mutator never manufactures an out-of-range value.
    function actConsumeBudget(uint256 amount) external {
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        uint64 target = uint64(bound(amount, 0, limit));
        account.setStatelessSignaturesUsedForTest(target);
        _afterOp();
    }

    // actSimulateFullRotation: apply a completed full rotation. Mirrors the
    // real path's budget precheck (skip when already at the limit). The
    // consumed recovery signature and the whole budget are then reset to
    // zero, and the key epoch advances (I2, I3).
    function actSimulateFullRotation(uint256 targetSelector) external {
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        if (account.statelessSignaturesUsed() >= limit) return;
        uint256 targetIndex = bound(targetSelector, 0, KEY_COUNT - 1);
        uint256 nonceBefore = account.nonce();
        uint256 keyVersionBefore = account.keyVersion();
        account.applyFullRotationForTest(commitmentOf[targetIndex]);
        if (account.statelessSignaturesUsed() != 0) {
            ghostResetViolated = true;
        }
        _checkRotationAdvanced(nonceBefore, keyVersionBefore);
        _afterOp();
    }

    // actSimulateStatefulRotation: apply a completed stateful-only rotation.
    // Mirrors the real path's budget precheck (skip when at the limit). The
    // recovery signature is consumed (budget += 1) and carried into the new
    // epoch: budget must advance by exactly one, never reset (I3).
    function actSimulateStatefulRotation(uint256 targetSelector) external {
        uint64 limit = SHRINCSParams.STATELESS_SIGNATURE_LIMIT;
        uint64 budgetBefore = account.statelessSignaturesUsed();
        if (budgetBefore >= limit) return;
        uint256 targetIndex = bound(targetSelector, 0, KEY_COUNT - 1);
        uint256 nonceBefore = account.nonce();
        uint256 keyVersionBefore = account.keyVersion();
        account.applyStatefulRotationForTest(commitmentOf[targetIndex]);
        if (account.statelessSignaturesUsed() != budgetBefore + 1) {
            ghostResetViolated = true;
        }
        _checkRotationAdvanced(nonceBefore, keyVersionBefore);
        _afterOp();
    }

    // bitmapMonotoneHolds: every leaf recorded used under the current epoch
    // must still read used (I4). Stale records from a prior epoch are ignored
    // because the bitmap is per keyVersion.
    function bitmapMonotoneHolds() external view returns (bool) {
        if (ghostBitmapKeyVersion != account.keyVersion()) return true;
        for (uint256 i = 0; i < ghostUsedLeaves.length; i++) {
            if (!account.isLeafUsed(ghostUsedLeaves[i])) return false;
        }
        return true;
    }

    // _trySetPolicy: shared owner-policy-change probe for I5. `which`
    // selects bitmap (0). Latches a violation if a change took effect after a
    // leaf was consumed this epoch, tracked independently of the wrapper's
    // freeze flag.
    function _trySetPolicy(uint256) internal {
        SHRINCSAccountVerifierExample.StatefulPolicy before =
            account.statefulPolicy();
        try account.setStatefulPolicyLeafBitmap() {
            if (ghostLeafConsumedThisEpoch) ghostFrozenPolicyChanged = true;
        } catch {
            if (account.statefulPolicy() != before) {
                ghostFrozenPolicyChanged = true;
            }
        }
        _afterOp();
    }

    function _recordBitmapLeaf(uint32 leaf) internal {
        if (ghostBitmapKeyVersion != account.keyVersion()) {
            delete ghostUsedLeaves;
            ghostBitmapKeyVersion = account.keyVersion();
        }
        ghostUsedLeaves.push(leaf);
    }

    function _firstUnusedLeaf() internal view returns (uint32) {
        for (uint32 leaf = 1; leaf <= MAX_LEAF; leaf++) {
            if (!account.isLeafUsed(leaf)) return leaf;
        }
        return 0;
    }

    function _currentKeyIndex()
        internal
        view
        returns (uint256 keyIndex, bool found)
    {
        bytes32 current = account.currentSHRINCSPublicKey();
        for (uint256 i = 0; i < KEY_COUNT; i++) {
            if (commitmentOf[i] == current) return (i, true);
        }
        return (0, false);
    }

    function _fullTarget(uint256 keyIndex)
        internal
        view
        returns (SHRINCSCore.RotationTarget memory target)
    {
        SHRINCSCore.PublicKey memory publicKey = publicKeyOf[keyIndex];
        target = SHRINCSCore.RotationTarget({
            statefulPublicKey: publicKey.statefulPublicKey,
            publicKeyCommitment: publicKey.publicKeyCommitment,
            pkSeed: publicKey.pkSeed,
            hypertreeRoot: publicKey.hypertreeRoot
        });
    }

    // _checkRotationAdvanced: a rotation must bump both nonce and keyVersion
    // by exactly one (I1, I2 increase-on-rotation).
    function _checkRotationAdvanced(
        uint256 nonceBefore,
        uint256 keyVersionBefore
    ) internal {
        if (account.nonce() != nonceBefore + 1) {
            ghostNonceStuck = true;
        }
        if (account.keyVersion() != keyVersionBefore + 1) {
            ghostKeyVersionStuck = true;
        }
    }

    function _afterOp() internal {
        uint256 currentNonce = account.nonce();
        if (currentNonce < ghostPrevNonce) ghostNonceDecreased = true;
        ghostPrevNonce = currentNonce;
        uint256 currentKeyVersion = account.keyVersion();
        if (currentKeyVersion < ghostPrevKeyVersion) {
            ghostKeyVersionDecreased = true;
        }
        // A new key epoch clears the per-epoch consumption flag (freeze
        // lifts on rotation).
        if (currentKeyVersion != ghostPrevKeyVersion) {
            ghostLeafConsumedThisEpoch = false;
        }
        ghostPrevKeyVersion = currentKeyVersion;
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
                account.currentSHRINCSPublicKey(),
                account.isLeafUsed(1),
                account.isLeafUsed(2)
            )
        );
    }

    function _commitmentWord(SHRINCSCore.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 word)
    {
        bytes memory encoded = publicKey.publicKeyCommitment;
        assembly {
            word := mload(add(encoded, 32))
        }
    }
}

/// @title SHRINCSAccountInvariantsTest
/// @notice Wrapper state-machine invariants I1-I7 (security-testing plan
/// Part 2, P3/P10). A fuzz handler drives valid actions, adversarial calls,
/// owner policy changes, and simulated rotations; each invariant asserts a
/// latched ghost from the handler stayed clean.
/// @dev The handler exercises the leaf-tracking state machine via the raw
/// unchecked-message path (so setUp-signed material replays) and the
/// rotation state transitions via the internal install helpers. The
/// canonical nonce-advancing action path and the positive recovery-signature
/// gating are covered by the unit suite in
/// SHRINCSAccountVerifierExample.t.sol; this suite covers the monotonicity,
/// freeze, budget-reset, and fail-closed-purity properties under random
/// operation sequences.
contract SHRINCSAccountInvariantsTest is Test {
    SHRINCSAccountHandler internal handler;

    function setUp() public {
        handler = new SHRINCSAccountHandler();
        handler.prepareKey(0);
        handler.prepareKey(1);
        handler.deployAccount();

        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = handler.actValidStatefulAction.selector;
        selectors[1] = handler.actGarbageStateful.selector;
        selectors[2] = handler.actGarbageStateless.selector;
        selectors[3] = handler.actUnarmedRotateFull.selector;
        selectors[4] = handler.actArmRecovery.selector;
        selectors[5] = handler.actSetPolicyBitmap.selector;
        selectors[6] = handler.actSetPolicyMonotonic.selector;
        selectors[7] = handler.actConsumeBudget.selector;
        selectors[8] = handler.actSimulateFullRotation.selector;
        selectors[9] = handler.actSimulateStatefulRotation.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
        targetContract(address(handler));
    }

    // I1: the wrapper nonce never decreases and advances on every rotation.
    function invariant_I1_nonceMonotone() public view {
        assertFalse(handler.ghostNonceDecreased(), "nonce decreased");
        assertFalse(handler.ghostNonceStuck(), "nonce did not advance");
    }

    // I2: the installed-key version never decreases and advances on every
    // rotation.
    function invariant_I2_keyVersionMonotone() public view {
        assertFalse(
            handler.ghostKeyVersionDecreased(), "keyVersion decreased"
        );
        assertFalse(
            handler.ghostKeyVersionStuck(), "keyVersion did not advance"
        );
    }

    // I3: the stateless budget stays within its limit, resets to zero on a
    // full rotation, and is preserved across a stateful-only rotation.
    function invariant_I3_budgetConserved() public view {
        assertLe(
            handler.account().statelessSignaturesUsed(),
            SHRINCSParams.STATELESS_SIGNATURE_LIMIT,
            "budget over limit"
        );
        assertFalse(handler.ghostResetViolated(), "budget reset rule");
    }

    // I4: the consumption bitmap is monotone within a key epoch.
    function invariant_I4_bitmapMonotone() public view {
        assertTrue(handler.bitmapMonotoneHolds(), "bitmap not monotone");
    }

    // I5: policy is frozen after the first consumed stateful leaf.
    function invariant_I5_policyFreeze() public view {
        assertFalse(
            handler.ghostFrozenPolicyChanged(), "policy changed after freeze"
        );
    }

    // I6: rotation paths stay closed without an armed recovery signature.
    function invariant_I6_recoveryGating() public view {
        assertFalse(
            handler.ghostRotateGatingViolated(), "rotate without recovery"
        );
    }

    // I7: any false-returning call leaves observable state unchanged, and no
    // mutated signature is ever accepted.
    function invariant_I7_failClosedPurity() public view {
        assertFalse(handler.ghostPurityViolated(), "false return mutated");
        assertFalse(handler.ghostMutationAccepted(), "mutation accepted");
    }
}
