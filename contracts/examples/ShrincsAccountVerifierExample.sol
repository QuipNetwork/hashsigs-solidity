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
    // ERC-1271 success return value.
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    // Any non-magic value denotes signature failure.
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    // Envelope mode selecting canonical stateful account-action validation.
    uint8 internal constant ERC1271_MODE_STATEFUL_ACTION = 1;
    // Envelope mode selecting canonical stateless account-action validation.
    uint8 internal constant ERC1271_MODE_STATELESS_ACTION = 2;
    // Envelope mode selecting canonical compact account-action validation.
    uint8 internal constant ERC1271_MODE_COMPACT_ACTION = 3;

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
    // Canonical action/rotation nonce consumed on successful wrapper operations.
    uint256 public nonce;
    // Installed-key epoch incremented whenever a fresh key bundle is installed.
    uint256 public keyVersion;
    // Number of stateless signatures consumed under the current installed key.
    uint64 public statelessSignaturesUsed;
    // Current stateful leaf-tracking / recovery policy enforced by the wrapper.
    StatefulPolicy public statefulPolicy;
    // Whether stateful leaf consumption has frozen policy changes for the current key epoch.
    bool public statefulPolicyFrozen;
    // Next expected stateful leaf when monotonic tracking is active.
    uint32 public nextStatefulLeafIndex;
    // Whether the wrapper is currently in recovery mode for stateless rotation.
    bool public recoveryMode;

    mapping(uint256 keyVersion => mapping(uint256 wordIndex => uint256 usedBits)) internal usedLeafBitmap;
    mapping(bytes32 slotId => bool registered) public compactSlots;

    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    event StatefulPolicySet(StatefulPolicy indexed policy, uint32 nextStatefulLeafIndex);
    event RecoveryModeEntered(uint256 indexed keyVersion);
    event KeyRotated(
        bytes32 indexed previousShrincsPublicKey, bytes32 indexed nextShrincsPublicKey, uint256 nextKeyVersion
    );
    event StatefulSignatureVerified(uint32 indexed leafIndex, uint256 indexed nonce, uint256 indexed keyVersion);
    event StatelessSignatureVerified(uint64 usedCount, uint256 indexed nonce, uint256 indexed keyVersion);
    event CompactSignatureVerified(bytes32 indexed slotId, uint256 indexed nonce, uint256 indexed keyVersion);
    event CompactSlotRegistered(
        bytes32 indexed slotId, bytes32 subPkSeed, bytes32 subPkRoot, uint256 indexed nonce, uint256 indexed keyVersion
    );
    event CompactSlotRevoked(
        bytes32 indexed slotId, bytes32 subPkSeed, bytes32 subPkRoot, uint256 indexed nonce, uint256 indexed keyVersion
    );
    event StatelessRotationConsumed(
        uint64 usedCount,
        uint256 indexed nonce,
        uint256 indexed keyVersion,
        bytes32 indexed nextShrincsPublicKey,
        bool fullRotation
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    // isValidSignature: ERC-1271 compatibility view for canonical SHRINCS account-action signatures.
    // 1. Decode the leading envelope mode byte.
    // 2. Decode the remaining bytes as either a canonical stateful or stateless action envelope.
    // 3. Rebuild the current account action context from wrapper-owned state.
    // 4. Verify that the supplied hash matches the current canonical action hash.
    // 5. Verify the embedded SHRINCS signature without mutating wrapper state.
    // 6. Return 0xffffffff instead of reverting on malformed envelopes.
    // 7. Return the ERC-1271 magic value on success or 0xffffffff on failure.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        // A one-byte mode prefix is required before any envelope payload.
        if (signature.length < 1) return INVALID_SIGNATURE;

        uint8 mode = uint8(signature[0]);
        bytes calldata payload = signature[1:];

        if (mode == ERC1271_MODE_STATEFUL_ACTION) {
            try this.decodeAndCheckStateful1271Envelope(hash, payload) returns (bool ok) {
                if (ok) return MAGIC_VALUE;
            } catch {
                return INVALID_SIGNATURE;
            }
            return INVALID_SIGNATURE;
        }

        if (mode == ERC1271_MODE_STATELESS_ACTION) {
            try this.decodeAndCheckStateless1271Envelope(hash, payload) returns (bool ok) {
                if (ok) return MAGIC_VALUE;
            } catch {
                return INVALID_SIGNATURE;
            }
            return INVALID_SIGNATURE;
        }

        if (mode == ERC1271_MODE_COMPACT_ACTION) {
            try this.decodeAndCheckCompact1271Envelope(hash, payload) returns (bool ok) {
                if (ok) return MAGIC_VALUE;
            } catch {
                return INVALID_SIGNATURE;
            }
            return INVALID_SIGNATURE;
        }

        return INVALID_SIGNATURE;
    }

    // decodeAndCheckStateful1271Envelope: Self-call decoder for stateful ERC-1271 envelopes.
    // 1. Decode the canonical stateful envelope layout from bytes.
    // 2. Delegate the read-only cryptographic and policy checks.
    // 3. Allow isValidSignature(...) to catch malformed payloads and return INVALID_SIGNATURE.
    function decodeAndCheckStateful1271Envelope(bytes32 hash, bytes calldata payload)
        external
        view
        onlySelf
        returns (bool)
    {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            ShrincsTypes.StatefulSignature memory shrincsSignature
        ) = abi.decode(payload, (ShrincsTypes.PublicKey, bytes32, bytes32, ShrincsTypes.StatefulSignature));

        return this.isValidStatefulActionSignatureNow(hash, publicKey, actionType, payloadHash, shrincsSignature);
    }

    // decodeAndCheckStateless1271Envelope: Self-call decoder for stateless ERC-1271 envelopes.
    // 1. Decode the canonical stateless envelope layout from bytes.
    // 2. Delegate the read-only cryptographic and policy checks.
    // 3. Allow isValidSignature(...) to catch malformed payloads and return INVALID_SIGNATURE.
    function decodeAndCheckStateless1271Envelope(bytes32 hash, bytes calldata payload)
        external
        view
        onlySelf
        returns (bool)
    {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            ShrincsTypes.StatelessSignature memory shrincsSignature
        ) = abi.decode(payload, (ShrincsTypes.PublicKey, bytes32, bytes32, ShrincsTypes.StatelessSignature));

        return this.isValidStatelessActionSignatureNow(hash, publicKey, actionType, payloadHash, shrincsSignature);
    }

    // decodeAndCheckCompact1271Envelope: Self-call decoder for compact ERC-1271 envelopes.
    // 1. Decode the canonical compact envelope layout from bytes.
    // 2. Delegate the read-only compact slot and cryptographic checks.
    // 3. Allow isValidSignature(...) to catch malformed payloads and return INVALID_SIGNATURE.
    function decodeAndCheckCompact1271Envelope(bytes32 hash, bytes calldata payload)
        external
        view
        onlySelf
        returns (bool)
    {
        (bytes32 subPkSeed, bytes32 subPkRoot, bytes32 actionType, bytes32 payloadHash, bytes memory compactSignature) =
            abi.decode(payload, (bytes32, bytes32, bytes32, bytes32, bytes));

        return
            this.isValidCompactActionSignatureNow(hash, subPkSeed, subPkRoot, actionType, payloadHash, compactSignature);
    }

    // constructor: Install the initial key commitment and start in the default safe wrapper mode.
    // 1. Record the deployer as the wrapper owner.
    // 2. Install the initial SHRINCS public-key commitment.
    // 3. Start with monotonic stateful leaf tracking.
    // 4. Expect the first stateful signature to use leaf 1.
    constructor(bytes32 initialShrincsPublicKey) {
        // Record the deployer as the wrapper administrator.
        owner = msg.sender;
        // Install the first trusted SHRINCS public-key commitment.
        currentShrincsPublicKey = initialShrincsPublicKey;
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
        bool ok = SHRINCS.verifyStatefulUncheckedMessage(currentShrincsPublicKey, publicKey, message, signature);
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
        bool ok = SHRINCS.verifyStateful(currentShrincsPublicKey, publicKey, context, signature);
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
    // 2. Enforce the fixed stateless usage budget for the current key epoch.
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
        // Enforce the per-key stateless usage budget.
        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
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
        bool ok = SHRINCS.verifyStateless(currentShrincsPublicKey, publicKey, context, signature);
        if (!ok) return false;

        // Advance wrapper freshness and stateless usage state after success.
        nonce += 1;
        statelessSignaturesUsed += 1;
        // Emit the consumed nonce value from the pre-increment state.
        emit StatelessSignatureVerified(statelessSignaturesUsed, nonce - 1, keyVersion);
        return true;
    }

    // verifyCompactAction: Canonical compact account-action verification path.
    // 1. Require the compact slot to be registered.
    // 2. Build the canonical typed action context from wrapper-owned freshness state.
    // 3. Verify the raw JARDIN compact signature against that canonical action message.
    // 4. Advance nonce only after success; q remains signer-owned and untracked on-chain.
    function verifyCompactAction(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 actionType,
        bytes32 payloadHash,
        bytes calldata signature
    ) external returns (bool) {
        // Derive the persistent JARDIN compact slot key.
        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        // Reject any compact lane that has not been stateless-authorized.
        if (!compactSlots[slotId]) return false;

        // Bind the action to this contract instance, nonce, and key epoch.
        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        // Verify the canonical compact action under the registered compact sub-key.
        bool ok = SHRINCS.verifyCompact(subPkSeed, subPkRoot, context, signature);
        if (!ok) return false;

        // Emit before nonce advancement so observers see the consumed nonce value.
        emit CompactSignatureVerified(slotId, nonce, keyVersion);
        // Advance account freshness after a successful compact action.
        nonce += 1;
        return true;
    }

    // registerCompactSlot: Authorize a compact Type 2 lane with a stateless signature.
    // 1. Require the slot to be currently unregistered.
    // 2. Verify a stateless registration authorization under the installed key.
    // 3. Store compactSlots[keccak256(subPkSeed || subPkRoot)] = true.
    function registerCompactSlot(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) external returns (bool) {
        return updateCompactSlot(publicKey, signature, subPkSeed, subPkRoot, true);
    }

    // revokeCompactSlot: Revoke a compact Type 2 lane with a stateless signature.
    // 1. Require the slot to be currently registered.
    // 2. Verify a stateless revocation authorization under the installed key.
    // 3. Store compactSlots[keccak256(subPkSeed || subPkRoot)] = false.
    function revokeCompactSlot(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) external returns (bool) {
        return updateCompactSlot(publicKey, signature, subPkSeed, subPkRoot, false);
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
        ShrincsTypes.StatefulRotationTarget calldata nextKey
    ) external returns (bool) {
        // Fresh-key rotation is available only in the dedicated recovery policy.
        if (statefulPolicy != StatefulPolicy.RecoveryRotation) {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if (!recoveryMode) return false;
        // Enforce the per-key stateless usage budget.
        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the rotation to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});

        // Verify the stateless recovery signature and derive the next installed commitment.
        bytes32 nextCompositePublicKey = SHRINCS.rotateStatefulViaStateless(
            currentShrincsPublicKey, currentPublicKey, context, recoverySignature, nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        // Count and announce the consumed recovery signature before preserving the stateless budget
        // into the next stateful-only epoch.
        consumeStatelessRotationUse(nextCompositePublicKey, false);
        // Install the next stateful subkey while preserving stateless usage accounting because
        // the stateless key material is unchanged.
        installFreshStatefulKey(nextCompositePublicKey);
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
        // Enforce the per-key stateless usage budget.
        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the rotation to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});

        // Verify the stateless recovery signature and derive the next installed commitment.
        bytes32 nextCompositePublicKey =
            SHRINCS.statelessRotate(currentShrincsPublicKey, currentPublicKey, context, recoverySignature, nextKey);
        if (nextCompositePublicKey == bytes32(0)) return false;

        // Count and announce the consumed recovery signature as the final stateless use under the old key.
        consumeStatelessRotationUse(nextCompositePublicKey, true);
        // Install the next full key bundle and reset wrapper state for the new stateless epoch.
        installFreshFullKey(nextCompositePublicKey);
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

    // compactSlotId: Derive the persistent compact slot key.
    function compactSlotId(bytes32 subPkSeed, bytes32 subPkRoot) public pure returns (bytes32) {
        return SHRINCS.compactSlotId(subPkSeed, subPkRoot);
    }

    // setStatefulPolicyMonotonicIndex: Switch to monotonic stateful leaf tracking.
    // 1. Only the owner may change the wrapper policy.
    // 2. Reject policy changes after any successful stateful leaf use in this key epoch.
    // 3. Prevent rollback to an earlier expected leaf index.
    // 4. Install monotonic tracking with the supplied next expected leaf.
    // 5. Exit recovery mode because the wrapper is returning to normal operation.
    // 6. Emit the policy update for off-chain observers.
    function setStatefulPolicyMonotonicIndex(uint32 initialLeafIndex) external onlyOwner {
        // Freeze the stateful tracking model once any stateful leaf has been consumed in this epoch.
        require(!statefulPolicyFrozen, "stateful policy frozen");
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
    // 2. Reject policy changes after any successful stateful leaf use in this key epoch.
    // 3. Preserve or initialize the stateful leaf cursor for later normal operation.
    // 4. Require an explicit enterRecoveryMode() call before stateless recovery is accepted.
    // 5. Emit the policy update for off-chain observers.
    function setStatefulPolicyRecoveryRotation() external onlyOwner {
        // Freeze the stateful tracking model once any stateful leaf has been consumed in this epoch.
        require(!statefulPolicyFrozen, "stateful policy frozen");
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
    // 2. Reject policy changes after any successful stateful leaf use in this key epoch.
    // 3. Preserve or initialize the stateful leaf cursor for future monotonic use.
    // 4. Exit recovery mode because the wrapper is returning to normal operation.
    // 5. Emit the policy update for off-chain observers.
    function setStatefulPolicyLeafBitmap() external onlyOwner {
        // Freeze the stateful tracking model once any stateful leaf has been consumed in this epoch.
        require(!statefulPolicyFrozen, "stateful policy frozen");
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
    // 1. Reject all stateful signatures while the wrapper is configured for recovery-only stateless authority.
    // 2. Under monotonic tracking, accept only the next expected leaf.
    // 3. Under bitmap tracking, accept only leaves that have not yet been marked used.
    // 4. Return true for any remaining policy branch.
    function precheckStatefulLeafUse(uint32 leafIndex) internal view returns (bool) {
        // Recovery-rotation policy disables the stateful path entirely, whether or not recovery
        // mode has been explicitly armed yet.
        if (statefulPolicy == StatefulPolicy.RecoveryRotation) return false;
        // Ordered tracking accepts exactly one next leaf.
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) return leafIndex == nextStatefulLeafIndex;
        // Bitmap tracking accepts any leaf that has not already been marked used.
        if (statefulPolicy == StatefulPolicy.LeafBitmap) return !isLeafUsed(leafIndex);
        return true;
    }

    // isValidStatefulActionSignatureNow: Read-only self-call helper for canonical stateful action verification.
    // 1. Enforce the current stateful leaf policy without consuming the leaf.
    // 2. Rebuild the canonical action context from wrapper-owned state.
    // 3. Require the caller-supplied hash to match the current canonical stateful action hash.
    // 4. Verify the SHRINCS stateful action signature under the installed key commitment.
    function isValidStatefulActionSignatureNow(
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatefulSignature calldata signature
    ) external view onlySelf returns (bool) {
        uint32 leafIndex = uint32(signature.authPath.length);
        if (!precheckStatefulLeafUse(leafIndex)) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        if (SHRINCS.statefulActionMessageHash(currentShrincsPublicKey, context) != hash) return false;
        return SHRINCS.verifyStateful(currentShrincsPublicKey, publicKey, context, signature);
    }

    // isValidStatelessActionSignatureNow: Read-only self-call helper for canonical stateless action verification.
    // 1. Enforce current recovery-mode gating and stateless usage budget without consuming either.
    // 2. Rebuild the canonical action context from wrapper-owned state.
    // 3. Require the caller-supplied hash to match the current canonical stateless action hash.
    // 4. Verify the SHRINCS stateless action signature under the installed key commitment.
    function isValidStatelessActionSignatureNow(
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external view onlySelf returns (bool) {
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && !recoveryMode) return false;
        if (statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        if (SHRINCS.statelessActionMessageHash(currentShrincsPublicKey, context) != hash) return false;
        return SHRINCS.verifyStateless(currentShrincsPublicKey, publicKey, context, signature);
    }

    // isValidCompactActionSignatureNow: Read-only self-call helper for canonical compact action verification.
    // 1. Require the compact slot to be registered without mutating state.
    // 2. Rebuild the canonical action context from wrapper-owned state.
    // 3. Require the caller-supplied hash to match the current canonical compact action hash.
    // 4. Verify the raw compact signature under the registered sub-key.
    function isValidCompactActionSignatureNow(
        bytes32 hash,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 actionType,
        bytes32 payloadHash,
        bytes calldata signature
    ) external view onlySelf returns (bool) {
        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        if (!compactSlots[slotId]) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        if (SHRINCS.compactActionMessageHash(context) != hash) return false;
        return SHRINCS.verifyCompact(subPkSeed, subPkRoot, context, signature);
    }

    // commitStatefulLeafUse: Record a successfully verified stateful leaf under the active policy.
    // 1. Under monotonic tracking, advance the next expected leaf by one.
    // 2. Under bitmap tracking, mark the corresponding bit for this leaf as used.
    // 3. Freeze stateful policy changes for the remainder of the key epoch.
    // 4. Leave recovery-only mode unchanged because stateful signatures are blocked there.
    function commitStatefulLeafUse(uint32 leafIndex) internal {
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) {
            // Move the expected cursor forward after one successful monotonic use.
            nextStatefulLeafIndex += 1;
        } else if (statefulPolicy == StatefulPolicy.LeafBitmap) {
            // Group leaves into 256-bit words for compact bitmap storage.
            uint256 wordIndex = uint256(leafIndex) >> 8;
            // Select the bit inside that word corresponding to this leaf.
            uint256 bitIndex = uint256(leafIndex) & 0xff;
            // Mark this leaf as consumed for the current key epoch.
            usedLeafBitmap[keyVersion][wordIndex] |= uint256(1) << bitIndex;
        }
        // Any successful stateful verification fixes the tracking model for this key epoch.
        statefulPolicyFrozen = true;
    }

    // consumeStatelessRotationUse: Record one successful stateless recovery signature used for rotation.
    // 1. Increment the current stateless usage count under the old key epoch.
    // 2. Emit a dedicated rotation-usage event before any key install resets wrapper state.
    function consumeStatelessRotationUse(bytes32 nextCompositePublicKey, bool fullRotation) internal {
        statelessSignaturesUsed += 1;
        emit StatelessRotationConsumed(statelessSignaturesUsed, nonce, keyVersion, nextCompositePublicKey, fullRotation);
    }

    // updateCompactSlot: Verify a stateless slot update and write the compactSlots flag.
    // 1. Enforce current stateless gating and usage budget.
    // 2. Build the registration or revocation message for this slot.
    // 3. Verify the stateless authorization under the current installed key.
    // 4. Write exactly one slot flag and consume the account nonce after success.
    function updateCompactSlot(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bool registered
    ) internal returns (bool) {
        // Recovery-only policy gates stateless slot updates until recovery mode is armed.
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && !recoveryMode) return false;
        // Enforce the per-key stateless usage budget.
        if (statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT) return false;

        // Derive the JARDIN compact slot key.
        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        // Reject no-op updates so signatures are never consumed for an unchanged slot flag.
        if (compactSlots[slotId] == registered) return false;

        // Bind the update to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});
        // Choose the exact stateless authorization message for this slot operation.
        bytes32 message = registered
            ? SHRINCS.compactSlotRegistrationMessageHash(currentShrincsPublicKey, context, subPkSeed, subPkRoot)
            : SHRINCS.compactSlotRevocationMessageHash(currentShrincsPublicKey, context, subPkSeed, subPkRoot);
        // Verify the stateless signature over the slot update message.
        bool ok = SHRINCS.verifyStatelessUncheckedMessage(
            currentShrincsPublicKey, publicKey, abi.encodePacked(message), signature
        );
        if (!ok) return false;

        // Store the requested slot authorization state only after verification succeeds.
        compactSlots[slotId] = registered;
        // Count the stateless authorization under this installed key.
        statelessSignaturesUsed += 1;
        // Emit before nonce advancement so observers see the consumed nonce value.
        if (registered) {
            emit CompactSlotRegistered(slotId, subPkSeed, subPkRoot, nonce, keyVersion);
        } else {
            emit CompactSlotRevoked(slotId, subPkSeed, subPkRoot, nonce, keyVersion);
        }
        // Advance account freshness after the stateless slot update.
        nonce += 1;
        return true;
    }

    // domainSeparator: Derive the wrapper's canonical signing domain.
    // 1. Start from a stable domain tag for this wrapper family.
    // 2. Bind the separator to the current chain id.
    // 3. Bind the separator to this contract instance.
    function domainSeparator() internal view returns (bytes32) {
        // Bind wrapper signatures to this product tag, chain, and deployed contract instance.
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, address(this)));
    }

    // installRotatedKey: Install a rotated key bundle and reset wrapper state for the next epoch.
    // 1. Preserve the previous installed key commitment for the rotation event.
    // 2. Install the next SHRINCS public-key commitment.
    // 3. Advance nonce and key version to close the old authorization epoch.
    // 4. Reset or preserve stateless usage accounting according to the caller's intent.
    // 5. Reset stateful leaf tracking and policy-freeze state for the new key.
    // 6. Return the wrapper to the default monotonic non-recovery policy.
    // 7. Emit rotation and policy-reset events for off-chain observers.
    function installRotatedKey(bytes32 nextCompositePublicKey, bool resetStatelessUsage) internal {
        // Preserve the previous key commitment for the rotation event payload.
        bytes32 previousShrincsPublicKey = currentShrincsPublicKey;
        // Install the next trusted SHRINCS public-key commitment.
        currentShrincsPublicKey = nextCompositePublicKey;
        // Advance nonce and key epoch so old authorizations cannot be replayed.
        nonce += 1;
        keyVersion += 1;
        // Reset per-key stateless usage accounting only when the caller rotates the stateless key too.
        if (resetStatelessUsage) {
            statelessSignaturesUsed = 0;
        }
        // Reset stateful signing to the first leaf of the new key epoch.
        nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        // Fresh key epochs allow policy selection again until the first stateful leaf is consumed.
        statefulPolicyFrozen = false;
        // Fresh installs return to the default safe wrapper policy.
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        // Recovery mode ends once the new key has been installed.
        recoveryMode = false;
        emit KeyRotated(previousShrincsPublicKey, nextCompositePublicKey, keyVersion);
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    // installFreshStatefulKey: Install a fresh stateful subkey while preserving the stateless side.
    // 1. Install the next SHRINCS public-key commitment.
    // 2. Preserve stateless usage accounting because the stateless key material is unchanged.
    // 3. Reset stateful tracking and wrapper policy state for the next epoch.
    function installFreshStatefulKey(bytes32 nextCompositePublicKey) internal {
        installRotatedKey(nextCompositePublicKey, false);
    }

    // installFreshFullKey: Install a fully fresh SHRINCS bundle for the next key epoch.
    // 1. Install the next SHRINCS public-key commitment.
    // 2. Reset stateless usage accounting because the stateless key material changes too.
    // 3. Reset stateful tracking and wrapper policy state for the next epoch.
    function installFreshFullKey(bytes32 nextCompositePublicKey) internal {
        installRotatedKey(nextCompositePublicKey, true);
    }

    // installFreshKey: Backward-compatible alias for the full fresh-key install path.
    // 1. Preserve existing helper-call behavior in tests and support harnesses.
    // 2. Route to the semantic full-key install helper.
    function installFreshKey(bytes32 nextCompositePublicKey) internal {
        installFreshFullKey(nextCompositePublicKey);
    }
}
