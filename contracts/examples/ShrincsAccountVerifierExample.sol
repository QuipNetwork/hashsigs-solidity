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

import {SHRINCS} from "../SHRINCS.sol";
import {ShrincsTypes} from "../ShrincsTypes.sol";

contract ShrincsAccountVerifierExample {
    enum StatefulPolicy {
        // Accept only the next expected stateful leaf index.
        MonotonicIndex,
        // Treat stateless signatures as recovery/rotation authority once recovery mode is entered.
        RecoveryRotation,
        // Track stateful leaf reuse with a per-key-version bitmap.
        LeafBitmap
    }

    // Freshly installed keys begin stateful signing at leaf 1.
    uint32 internal constant INITIAL_STATEFUL_LEAF_INDEX = 1;

    // Installed bundle commitment currently trusted by the wrapper.
    bytes32 public currentShrincsPublicKey;
    // Account owner allowed to change wrapper policy and enter recovery mode.
    address public owner;
    // Active SHRINCS parameter profile for the installed key bundle.
    ShrincsTypes.ParameterSetId public parameterSetId;
    // Canonical action/rotation nonce consumed on successful wrapper operations.
    uint256 public nonce;
    // Installed-key epoch incremented whenever a fresh key bundle is installed.
    uint256 public keyVersion;
    // Number of stateless signatures consumed under the current installed key.
    uint64 public statelessSignaturesUsed;
    // Current stateful leaf-tracking / recovery policy enforced by the wrapper.
    StatefulPolicy public statefulPolicy;
    // Next expected stateful leaf when monotonic tracking is active.
    uint32 public nextStatefulLeafIndex;
    // Whether the wrapper is currently in recovery mode for stateless rotation.
    bool public recoveryMode;

    mapping(uint256 keyVersion => mapping(uint256 wordIndex => uint256 usedBits)) internal usedLeafBitmap;

    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    event StatefulPolicySet(StatefulPolicy indexed policy, uint32 nextStatefulLeafIndex);
    event RecoveryModeEntered(uint256 indexed keyVersion);
    event KeyRotated(
        bytes32 indexed previousShrincsPublicKey,
        bytes32 indexed nextShrincsPublicKey,
        ShrincsTypes.ParameterSetId nextParameterSetId,
        uint256 nextKeyVersion
    );
    event StatefulSignatureVerified(uint32 indexed leafIndex, uint256 indexed nonce, uint256 indexed keyVersion);
    event StatelessSignatureVerified(uint64 usedCount, uint256 indexed nonce, uint256 indexed keyVersion);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    // constructor: Install the initial key commitment and start in the default safe wrapper mode.
    // 1. Record the deployer as the wrapper owner.
    // 2. Install the initial SHRINCS public-key commitment.
    // 3. Select the default parameter profile for the example wrapper.
    // 4. Start with monotonic stateful leaf tracking.
    // 5. Expect the first stateful signature to use leaf 1.
    constructor(bytes32 initialShrincsPublicKey) {
        // Record the deployer as the wrapper administrator.
        owner = msg.sender;
        // Install the first trusted SHRINCS public-key commitment.
        currentShrincsPublicKey = initialShrincsPublicKey;
        // Start the example wrapper on its default SHRINCS parameter profile.
        parameterSetId = ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20;
        // Default to ordered stateful signing under monotonic leaf tracking.
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        // Fresh keys begin consuming stateful leaves from index 1.
        nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
    }

    // verifyStatefulUncheckedMessage: Internal raw stateful verification for tests and support harnesses only.
    // 1. Recover the stateful leaf index from the auth-path length.
    // 2. Check the active leaf-tracking policy before any cryptographic work.
    // 3. Verify the caller-supplied message directly without building canonical action context.
    // 4. Commit the consumed leaf only after signature verification succeeds.
    // 5. Emit the usual stateful verification event without advancing the wrapper nonce.
    function verifyStatefulUncheckedMessage(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal returns (bool) {
        // This path bypasses canonical wrapper message construction and therefore remains internal-only.
        // Recover the consumed stateful leaf from the signature layout.
        uint32 leafIndex = uint32(signature.authPath.length);
        // Stop early if the active policy disallows this leaf.
        if (!precheckStatefulLeafUse(leafIndex)) return false;

        // Verify the caller-supplied message directly against the current installed key.
        bool ok =
            SHRINCS.verifyStatefulUncheckedMessage(parameterSetId, currentShrincsPublicKey, publicKey, message, signature);
        if (!ok) return false;

        // Record the leaf only after the signature is known to be valid.
        commitStatefulLeafUse(leafIndex);
        // Emit the same observability event as the canonical stateful action flow.
        emit StatefulSignatureVerified(leafIndex, nonce, keyVersion);
        return true;
    }

    // verifyStatefulAction: Canonical stateful account-action verification path.
    // 1. Recover the leaf index that this stateful signature consumes.
    // 2. Reject leaves that violate the active stateful policy.
    // 3. Build the canonical typed action context from wrapper-owned freshness state.
    // 4. Verify the signature against that canonical action message.
    // 5. Commit the leaf, emit the verification event, and then advance the nonce.
    function verifyStatefulAction(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatefulSignature calldata signature
    ) external returns (bool) {
        // Recover the consumed stateful leaf from the signature layout.
        uint32 leafIndex = uint32(signature.authPath.length);
        // Stop early if the active policy disallows this leaf.
        if (!precheckStatefulLeafUse(leafIndex)) return false;

        // Bind the action to this contract instance, nonce, and key epoch.
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        // Verify the canonical typed action under the installed key commitment.
        bool ok = SHRINCS.verifyStateful(parameterSetId, currentShrincsPublicKey, publicKey, context, signature);
        if (!ok) return false;

        // Consume the leaf only after the action signature verifies.
        commitStatefulLeafUse(leafIndex);
        // Emit before nonce advancement so observers see the consumed nonce value.
        emit StatefulSignatureVerified(leafIndex, nonce, keyVersion);
        // Advance freshness state after a successful action.
        nonce += 1;
        return true;
    }

    // verifyStatelessAction: Canonical stateless account-action verification path.
    // 1. Reject stateless actions when recovery mode gating forbids them.
    // 2. Enforce the profile's stateless usage budget for the current key epoch.
    // 3. Build the canonical typed action context from wrapper-owned freshness state.
    // 4. Verify the stateless signature against that canonical action message.
    // 5. Advance nonce and stateless-usage counters only after success.
    function verifyStatelessAction(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external returns (bool) {
        // Recovery-only policy forbids stateless actions until recovery mode is explicitly entered.
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && !recoveryMode) return false;
        // Enforce the per-key stateless usage budget from the active parameter profile.
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the action to this contract instance, nonce, and key epoch.
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        // Verify the canonical typed action under the installed key commitment.
        bool ok = SHRINCS.verifyStateless(parameterSetId, currentShrincsPublicKey, publicKey, context, signature);
        if (!ok) return false;

        // Advance wrapper freshness and stateless usage state after success.
        nonce += 1;
        statelessSignaturesUsed += 1;
        // Emit the consumed nonce value from the pre-increment state.
        emit StatelessSignatureVerified(statelessSignaturesUsed, nonce - 1, keyVersion);
        return true;
    }

    // rotateToFreshKey: Recovery-only path that replaces the installed stateful subkey.
    // 1. Require the wrapper to be in recovery-rotation mode.
    // 2. Require recovery mode to be actively entered by the owner.
    // 3. Enforce the stateless usage budget for the current key epoch.
    // 4. Build the canonical rotation context from wrapper-owned freshness state.
    // 5. Verify the stateless recovery signature and derive the next key commitment.
    // 6. Install the fresh key bundle and reset wrapper state for the new epoch.
    function rotateToFreshKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external returns (bool) {
        // Fresh-key rotation is available only in the dedicated recovery policy.
        if (statefulPolicy != StatefulPolicy.RecoveryRotation) {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if (!recoveryMode) return false;
        // Enforce the per-key stateless usage budget from the active parameter profile.
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the rotation to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});

        // Verify the stateless recovery signature and derive the next installed commitment.
        bytes32 nextCompositePublicKey = SHRINCS.statelessRotate(
            parameterSetId, currentShrincsPublicKey, currentPublicKey, context, recoverySignature, nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        // Install the next key bundle and reset wrapper state for the new epoch.
        installFreshKey(nextCompositePublicKey, nextKey.parameterSetId);
        return true;
    }

    // rotateFullKey: Recovery-only path that replaces the full installed SHRINCS key bundle.
    // 1. Require the wrapper to be in recovery-rotation mode.
    // 2. Require recovery mode to be actively entered by the owner.
    // 3. Enforce the stateless usage budget for the current key epoch.
    // 4. Build the canonical rotation context from wrapper-owned freshness state.
    // 5. Verify the stateless recovery signature and derive the next key commitment.
    // 6. Install the new key bundle and reset wrapper state for the new epoch.
    function rotateFullKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external returns (bool) {
        // Full-key rotation is available only in the dedicated recovery policy.
        if (statefulPolicy != StatefulPolicy.RecoveryRotation) {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if (!recoveryMode) return false;
        // Enforce the per-key stateless usage budget from the active parameter profile.
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the rotation to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});

        // Verify the stateless recovery signature and derive the next installed commitment.
        bytes32 nextCompositePublicKey = SHRINCS.statelessRotate(
            parameterSetId, currentShrincsPublicKey, currentPublicKey, context, recoverySignature, nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        // Install the next key bundle and reset wrapper state for the new epoch.
        installFreshKey(nextCompositePublicKey, nextKey.parameterSetId);
        return true;
    }

    // isLeafUsed: Read bitmap-based stateful leaf usage for the current key epoch.
    // 1. Select the 256-leaf word containing the requested leaf.
    // 2. Select the bit inside that word for the requested leaf.
    // 3. Return whether that bit has already been marked as used.
    function isLeafUsed(uint32 leafIndex) public view returns (bool) {
        // Group leaves into 256-bit words for compact bitmap storage.
        uint256 wordIndex = uint256(leafIndex) >> 8;
        // Select the bit inside that word corresponding to this leaf.
        uint256 bitIndex = uint256(leafIndex) & 0xff;
        // Return whether that bit has already been marked as used.
        return (usedLeafBitmap[keyVersion][wordIndex] & (uint256(1) << bitIndex)) != 0;
    }

    // setStatefulPolicyMonotonicIndex: Switch to monotonic stateful leaf tracking.
    // 1. Only the owner may change the wrapper policy.
    // 2. Prevent rollback to an earlier expected leaf index.
    // 3. Install monotonic tracking with the supplied next expected leaf.
    // 4. Exit recovery mode because the wrapper is returning to normal operation.
    // 5. Emit the policy update for off-chain observers.
    function setStatefulPolicyMonotonicIndex(uint32 initialLeafIndex) external onlyOwner {
        // Never allow policy changes to roll back the expected monotonic leaf cursor.
        require(initialLeafIndex >= nextStatefulLeafIndex, "stateful index rollback");
        // Switch into ordered stateful leaf tracking.
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        // Install the next expected stateful leaf supplied by the owner.
        nextStatefulLeafIndex = initialLeafIndex;
        // Leaving recovery-only mode returns the wrapper to normal operation.
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    // setStatefulPolicyRecoveryRotation: Switch to recovery-only stateless rotation mode.
    // 1. Only the owner may change the wrapper policy.
    // 2. Preserve or initialize the stateful leaf cursor for later normal operation.
    // 3. Require an explicit enterRecoveryMode() call before stateless recovery is accepted.
    // 4. Emit the policy update for off-chain observers.
    function setStatefulPolicyRecoveryRotation() external onlyOwner {
        // Switch into the policy where stateless signatures serve as recovery authority.
        statefulPolicy = StatefulPolicy.RecoveryRotation;
        // Ensure the stateful cursor stays initialized for later normal operation.
        if (nextStatefulLeafIndex == 0) {
            nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        }
        // Require an explicit enterRecoveryMode() call before recovery signatures are accepted.
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    // setStatefulPolicyLeafBitmap: Switch to bitmap-based stateful leaf tracking.
    // 1. Only the owner may change the wrapper policy.
    // 2. Preserve or initialize the stateful leaf cursor for future monotonic use.
    // 3. Exit recovery mode because the wrapper is returning to normal operation.
    // 4. Emit the policy update for off-chain observers.
    function setStatefulPolicyLeafBitmap() external onlyOwner {
        // Switch into out-of-order bitmap tracking for stateful leaf use.
        statefulPolicy = StatefulPolicy.LeafBitmap;
        // Ensure the stateful cursor stays initialized for future monotonic use.
        if (nextStatefulLeafIndex == 0) {
            nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        }
        // Leaving recovery-only mode returns the wrapper to normal operation.
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    // enterRecoveryMode: Arm the wrapper for recovery-only stateless rotations.
    // 1. Only the owner may enter recovery mode.
    // 2. Require the dedicated recovery-rotation policy to already be active.
    // 3. Flip the recovery-mode flag so stateless recovery rotations are accepted.
    // 4. Emit the recovery-mode event for off-chain observers.
    function enterRecoveryMode() external onlyOwner {
        // Recovery mode is meaningful only under the dedicated recovery policy.
        require(statefulPolicy == StatefulPolicy.RecoveryRotation, "recovery policy required");
        // Arm the wrapper so stateless recovery rotations are now accepted.
        recoveryMode = true;
        emit RecoveryModeEntered(keyVersion);
    }

    // precheckStatefulLeafUse: Check whether the active policy allows a stateful leaf before verification.
    // 1. Reject stateful signatures while recovery mode is actively using stateless authority.
    // 2. Under monotonic tracking, accept only the next expected leaf.
    // 3. Under bitmap tracking, accept only leaves that have not yet been marked used.
    // 4. Return true for any remaining policy branch.
    function precheckStatefulLeafUse(uint32 leafIndex) internal view returns (bool) {
        // While recovery mode is active, block all stateful signatures.
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && recoveryMode) return false;
        // Ordered tracking accepts exactly one next leaf.
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) return leafIndex == nextStatefulLeafIndex;
        // Bitmap tracking accepts any leaf that has not already been marked used.
        if (statefulPolicy == StatefulPolicy.LeafBitmap) return !isLeafUsed(leafIndex);
        return true;
    }

    // commitStatefulLeafUse: Record a successfully verified stateful leaf under the active policy.
    // 1. Under monotonic tracking, advance the next expected leaf by one.
    // 2. Under bitmap tracking, mark the corresponding bit for this leaf as used.
    // 3. Leave recovery-only mode unchanged because stateful signatures are blocked there.
    function commitStatefulLeafUse(uint32 leafIndex) internal {
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) {
            // Move the expected cursor forward after one successful monotonic use.
            nextStatefulLeafIndex += 1;
            return;
        }
        if (statefulPolicy == StatefulPolicy.LeafBitmap) {
            // Group leaves into 256-bit words for compact bitmap storage.
            uint256 wordIndex = uint256(leafIndex) >> 8;
            // Select the bit inside that word corresponding to this leaf.
            uint256 bitIndex = uint256(leafIndex) & 0xff;
            // Mark this leaf as consumed for the current key epoch.
            usedLeafBitmap[keyVersion][wordIndex] |= uint256(1) << bitIndex;
            return;
        }
    }

    // domainSeparator: Derive the wrapper's canonical signing domain.
    // 1. Start from a stable domain tag for this wrapper family.
    // 2. Bind the separator to the current chain id.
    // 3. Bind the separator to this contract instance.
    function domainSeparator() internal view returns (bytes32) {
        // Bind wrapper signatures to this product tag, chain, and deployed contract instance.
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, address(this)));
    }

    // installFreshKey: Install a fresh key bundle and reset wrapper state for the new key epoch.
    // 1. Preserve the previous installed key commitment for the rotation event.
    // 2. Install the next SHRINCS public-key commitment and parameter profile.
    // 3. Advance nonce and key version to close the old authorization epoch.
    // 4. Reset stateless usage and stateful leaf tracking for the new key.
    // 5. Return the wrapper to the default monotonic non-recovery policy.
    // 6. Emit rotation and policy-reset events for off-chain observers.
    function installFreshKey(bytes32 nextCompositePublicKey, ShrincsTypes.ParameterSetId nextParameterSetId) internal {
        // Preserve the previous key commitment for the rotation event payload.
        bytes32 previousShrincsPublicKey = currentShrincsPublicKey;
        // Install the next trusted SHRINCS public-key commitment.
        currentShrincsPublicKey = nextCompositePublicKey;
        // Switch to the next key bundle's parameter profile.
        parameterSetId = nextParameterSetId;
        // Advance nonce and key epoch so old authorizations cannot be replayed.
        nonce += 1;
        keyVersion += 1;
        // Reset per-key stateless usage accounting.
        statelessSignaturesUsed = 0;
        // Reset stateful signing to the first leaf of the new key epoch.
        nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        // Fresh installs return to the default safe wrapper policy.
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        // Recovery mode ends once the new key has been installed.
        recoveryMode = false;
        emit KeyRotated(previousShrincsPublicKey, nextCompositePublicKey, nextParameterSetId, keyVersion);
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }
}
