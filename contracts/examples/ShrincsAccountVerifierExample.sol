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

    enum StatefulPolicy {
        // Accept only the next expected stateful leaf index.
        MonotonicIndex,
        // Treat stateless signatures as recovery/rotation authority once
        // recovery mode is entered.
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
    // Canonical action/rotation nonce consumed on successful wrapper
    // operations.
    uint256 public nonce;
    // Installed-key epoch incremented whenever a fresh key bundle is
    // installed.
    uint256 public keyVersion;
    // Number of stateless signatures consumed under the current installed
    // key.
    uint64 public statelessSignaturesUsed;
    // Current stateful leaf-tracking / recovery policy enforced by the
    // wrapper.
    StatefulPolicy public statefulPolicy;
    // Whether stateful leaf consumption has frozen policy changes for the
    // current key epoch.
    bool public statefulPolicyFrozen;
    // Next expected stateful leaf when monotonic tracking is active.
    uint32 public nextStatefulLeafIndex;
    // Whether the wrapper is currently in recovery mode for stateless
    // rotation.
    bool public recoveryMode;

    mapping(
        uint256 keyVersion => mapping(uint256 wordIndex => uint256 usedBits)
    ) internal usedLeafBitmap;

    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    // Raised when an ERC-1271 envelope does not re-encode to its exact
    // input bytes; isValidSignature converts it to INVALID_SIGNATURE.
    error NonCanonicalEnvelope();

    event StatefulPolicySet(
        StatefulPolicy indexed policy, uint32 nextStatefulLeafIndex
    );
    event RecoveryModeEntered(uint256 indexed keyVersion);
    event KeyRotated(
        bytes32 indexed previousShrincsPublicKey,
        bytes32 indexed nextShrincsPublicKey,
        uint256 nextKeyVersion
    );
    event StatefulSignatureVerified(
        uint32 indexed leafIndex,
        uint256 indexed nonce,
        uint256 indexed keyVersion
    );
    event StatelessSignatureVerified(
        uint64 usedCount, uint256 indexed nonce, uint256 indexed keyVersion
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

    /// @notice ERC-1271 compatibility view for canonical SHRINCS
    /// account-action signatures.
    /// @dev Decodes the leading envelope mode byte, decodes the remainder as
    /// a canonical stateful or stateless action envelope, rebuilds the
    /// current action context from wrapper-owned state, checks the supplied
    /// hash against the canonical action hash, and verifies the embedded
    /// SHRINCS signature without mutating state. Returns 0xffffffff instead
    /// of reverting on malformed envelopes.
    /// @dev Minimum gas: a stateful check costs roughly 260k gas and a
    /// stateless check roughly 2.69M gas. Each envelope is verified behind a
    /// try/catch self-call, so an inner out-of-gas (the 63/64 rule strands
    /// the hop while the outer frame keeps 1/64) is caught and returned as
    /// INVALID_SIGNATURE — a valid signature then reports invalid. Callers
    /// MUST forward gas comfortably above those figures.
    /// @param hash The 32-byte hash the signature must authorize.
    /// @param signature The mode-prefixed ERC-1271 envelope.
    /// @return The ERC-1271 magic value on success, 0xffffffff on failure.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        // A one-byte mode prefix is required before any envelope payload.
        if (signature.length < 1) return INVALID_SIGNATURE;

        uint8 mode = uint8(signature[0]);
        bytes calldata payload = signature[1:];

        if (mode == ERC1271_MODE_STATEFUL_ACTION) {
            try this.decodeAndCheckStateful1271Envelope(
                hash, payload
            ) returns (
                bool ok
            ) {
                if (ok) return MAGIC_VALUE;
            } catch {
                return INVALID_SIGNATURE;
            }
            return INVALID_SIGNATURE;
        }

        if (mode == ERC1271_MODE_STATELESS_ACTION) {
            try this.decodeAndCheckStateless1271Envelope(
                hash, payload
            ) returns (
                bool ok
            ) {
                if (ok) return MAGIC_VALUE;
            } catch {
                return INVALID_SIGNATURE;
            }
            return INVALID_SIGNATURE;
        }

        return INVALID_SIGNATURE;
    }

    /// @notice Self-call decoder for stateful ERC-1271 envelopes. onlySelf.
    /// @dev Decodes the canonical stateful envelope, rejects non-canonical
    /// encodings, and delegates the read-only cryptographic and policy
    /// checks. A revert here is caught by isValidSignature and reported as
    /// INVALID_SIGNATURE.
    /// @param hash The 32-byte hash the signature must authorize.
    /// @param payload The abi-encoded stateful envelope (no mode prefix).
    /// @return True when the decoded stateful signature is valid now.
    function decodeAndCheckStateful1271Envelope(
        bytes32 hash,
        bytes calldata payload
    ) external view onlySelf returns (bool) {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            ShrincsTypes.StatefulSignature memory shrincsSignature
        ) = abi.decode(
            payload,
            (
                ShrincsTypes.PublicKey,
                bytes32,
                bytes32,
                ShrincsTypes.StatefulSignature
            )
        );

        // Reject non-canonical encodings: re-encoding the decoded fields
        // must reproduce the exact envelope bytes (mirrors
        // ShrincsCodec.decodeStatefulEnvelope). Trailing bytes or padded
        // heads are rejected. The onlySelf revert is converted to
        // INVALID_SIGNATURE by isValidSignature.
        if (
            keccak256(payload)
                != keccak256(
                    abi.encode(
                        publicKey, actionType, payloadHash, shrincsSignature
                    )
                )
        ) {
            revert NonCanonicalEnvelope();
        }

        return this.isValidStatefulActionSignatureNow(
            hash, publicKey, actionType, payloadHash, shrincsSignature
        );
    }

    /// @notice Self-call decoder for stateless ERC-1271 envelopes. onlySelf.
    /// @dev Decodes the canonical stateless envelope, rejects non-canonical
    /// encodings, and delegates the read-only cryptographic and policy
    /// checks. A revert here is caught by isValidSignature and reported as
    /// INVALID_SIGNATURE.
    /// @param hash The 32-byte hash the signature must authorize.
    /// @param payload The abi-encoded stateless envelope (no mode prefix).
    /// @return True when the decoded stateless signature is valid now.
    function decodeAndCheckStateless1271Envelope(
        bytes32 hash,
        bytes calldata payload
    ) external view onlySelf returns (bool) {
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            ShrincsTypes.StatelessSignature memory shrincsSignature
        ) = abi.decode(
            payload,
            (
                ShrincsTypes.PublicKey,
                bytes32,
                bytes32,
                ShrincsTypes.StatelessSignature
            )
        );

        // Reject non-canonical encodings: re-encoding the decoded fields
        // must reproduce the exact envelope bytes (mirrors
        // ShrincsCodec.decodeStatefulEnvelope). Trailing bytes or padded
        // heads are rejected. The onlySelf revert is converted to
        // INVALID_SIGNATURE by isValidSignature.
        if (
            keccak256(payload)
                != keccak256(
                    abi.encode(
                        publicKey, actionType, payloadHash, shrincsSignature
                    )
                )
        ) {
            revert NonCanonicalEnvelope();
        }

        return this.isValidStatelessActionSignatureNow(
            hash, publicKey, actionType, payloadHash, shrincsSignature
        );
    }

    /// @notice Install the initial key commitment and start in the default
    /// safe wrapper mode.
    /// @dev Records the deployer as owner, installs the initial commitment,
    /// starts with monotonic stateful leaf tracking, and expects the first
    /// stateful signature to use leaf 1.
    /// @param initialShrincsPublicKey The initial installed bundle
    /// commitment.
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

    // verifyStatefulUncheckedMessage: Internal raw stateful verification for
    // tests and support harnesses only.
    // 1. Recover the stateful leaf index from the auth-path length.
    // 2. Check the active leaf-tracking policy before any cryptographic work.
    // 3. Verify the caller-supplied message directly without building
    // canonical action context.
    // 4. Commit the consumed leaf only after signature verification succeeds.
    // 5. Emit the usual stateful verification event without advancing the
    // wrapper nonce.
    function verifyStatefulUncheckedMessage(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal returns (bool) {
        // This path bypasses canonical wrapper message construction and
        // therefore remains internal-only. Recover the consumed stateful leaf
        // from the signature layout.
        uint32 leafIndex = uint32(signature.authPath.length);
        // Stop early if the active policy disallows this leaf.
        if (!precheckStatefulLeafUse(leafIndex)) return false;

        // Verify the caller-supplied message directly against the current
        // installed key.
        bool ok = SHRINCS.verifyStatefulUncheckedMessage(
            currentShrincsPublicKey, publicKey, message, signature
        );
        if (!ok) return false;

        // Record the leaf only after the signature is known to be valid.
        commitStatefulLeafUse(leafIndex);
        // Emit the same observability event as the canonical stateful action
        // flow.
        emit StatefulSignatureVerified(leafIndex, nonce, keyVersion);
        return true;
    }

    /// @notice Canonical stateful account-action verification path.
    /// @dev Recovers the consumed leaf index, rejects leaves that violate
    /// the active policy, builds the canonical typed action context from
    /// wrapper freshness state, verifies the signature, then commits the
    /// leaf, emits the event, and advances the nonce.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param actionType The action type bound into the canonical hash.
    /// @param payloadHash The action payload hash.
    /// @param signature The stateful signature.
    /// @return True when the action signature verifies and is consumed.
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
        // forgefmt: disable-next-line
        ShrincsTypes.ActionContext memory context =
            ShrincsTypes.ActionContext({
                domainSeparator: domainSeparator(),
                nonce: nonce,
                keyVersion: keyVersion,
                actionType: actionType,
                payloadHash: payloadHash
            });

        // Verify the canonical typed action under the installed key
        // commitment.
        bool ok = SHRINCS.verifyStateful(
            currentShrincsPublicKey, publicKey, context, signature
        );
        if (!ok) return false;

        // Consume the leaf only after the action signature verifies.
        commitStatefulLeafUse(leafIndex);
        // Emit before nonce advancement so observers see the consumed nonce
        // value.
        emit StatefulSignatureVerified(leafIndex, nonce, keyVersion);
        // Advance freshness state after a successful action.
        nonce += 1;
        return true;
    }

    /// @notice Canonical stateless account-action verification path.
    /// @dev Rejects stateless actions when recovery-mode gating forbids
    /// them, enforces the per-key stateless usage budget, builds the
    /// canonical typed action context, verifies the signature, then advances
    /// the nonce and stateless-usage counters only after success.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param actionType The action type bound into the canonical hash.
    /// @param payloadHash The action payload hash.
    /// @param signature The stateless signature.
    /// @return True when the action signature verifies and is consumed.
    function verifyStatelessAction(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external returns (bool) {
        // Recovery-only policy forbids stateless actions until recovery mode
        // is explicitly entered.
        if (
            statefulPolicy == StatefulPolicy.RecoveryRotation
                && !recoveryMode
        ) return false;
        // Enforce the per-key stateless usage budget.
        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the action to this contract instance, nonce, and key epoch.
        // forgefmt: disable-next-line
        ShrincsTypes.ActionContext memory context =
            ShrincsTypes.ActionContext({
                domainSeparator: domainSeparator(),
                nonce: nonce,
                keyVersion: keyVersion,
                actionType: actionType,
                payloadHash: payloadHash
            });

        // Verify the canonical typed action under the installed key
        // commitment.
        bool ok = SHRINCS.verifyStateless(
            currentShrincsPublicKey, publicKey, context, signature
        );
        if (!ok) return false;

        // Advance wrapper freshness and stateless usage state after success.
        nonce += 1;
        statelessSignaturesUsed += 1;
        // Emit the consumed nonce value from the pre-increment state.
        emit StatelessSignatureVerified(
            statelessSignaturesUsed, nonce - 1, keyVersion
        );
        return true;
    }

    /// @notice Recovery-only path that replaces the installed stateful
    /// subkey.
    /// @dev Requires recovery-rotation policy with recovery mode armed,
    /// enforces the stateless usage budget, builds the canonical rotation
    /// context, verifies the stateless recovery signature to derive the next
    /// commitment, then installs the fresh stateful subkey while preserving
    /// stateless usage accounting.
    /// @param currentPublicKey The currently installed public-key bundle.
    /// @param recoverySignature The stateless recovery signature.
    /// @param nextKey The stateful-only rotation target.
    /// @return True when rotation succeeds.
    function rotateToFreshKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.StatefulRotationTarget calldata nextKey
    ) external returns (bool) {
        // Fresh-key rotation is available only in the dedicated recovery
        // policy.
        if (statefulPolicy != StatefulPolicy.RecoveryRotation) {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless
        // recovery is accepted.
        if (!recoveryMode) return false;
        // Enforce the per-key stateless usage budget.
        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the rotation to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({
                domainSeparator: domainSeparator(),
                nonce: nonce,
                keyVersion: keyVersion
            });

        // Verify the stateless recovery signature and derive the next
        // installed commitment.
        bytes32 nextCompositePublicKey = SHRINCS.rotateStatefulViaStateless(
            currentShrincsPublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        // Count and announce the consumed recovery signature before
        // preserving the stateless budget into the next stateful-only epoch.
        consumeStatelessRotationUse(nextCompositePublicKey, false);
        // Install the next stateful subkey while preserving stateless usage
        // accounting because the stateless key material is unchanged.
        installFreshStatefulKey(nextCompositePublicKey);
        return true;
    }

    /// @notice Recovery-only path that replaces the full installed SHRINCS
    /// key bundle.
    /// @dev Requires recovery-rotation policy with recovery mode armed,
    /// enforces the stateless usage budget, builds the canonical rotation
    /// context, verifies the stateless recovery signature to derive the next
    /// commitment, then installs the new full key bundle and resets wrapper
    /// state for the new stateless epoch.
    /// @param currentPublicKey The currently installed public-key bundle.
    /// @param recoverySignature The stateless recovery signature.
    /// @param nextKey The full-key rotation target.
    /// @return True when rotation succeeds.
    function rotateFullKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external returns (bool) {
        // Full-key rotation is available only in the dedicated recovery
        // policy.
        if (statefulPolicy != StatefulPolicy.RecoveryRotation) {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless
        // recovery is accepted.
        if (!recoveryMode) return false;
        // Enforce the per-key stateless usage budget.
        uint64 limit = ShrincsTypes.STATELESS_SIGNATURE_LIMIT;
        if (statelessSignaturesUsed >= limit) return false;

        // Bind the rotation to this contract instance, nonce, and key epoch.
        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({
                domainSeparator: domainSeparator(),
                nonce: nonce,
                keyVersion: keyVersion
            });

        // Verify the stateless recovery signature and derive the next
        // installed commitment.
        bytes32 nextCompositePublicKey = SHRINCS.statelessRotate(
            currentShrincsPublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        // Count and announce the consumed recovery signature as the final
        // stateless use under the old key.
        consumeStatelessRotationUse(nextCompositePublicKey, true);
        // Install the next full key bundle and reset wrapper state for the
        // new stateless epoch.
        installFreshFullKey(nextCompositePublicKey);
        return true;
    }

    /// @notice Read bitmap-based stateful leaf usage for the current key
    /// epoch.
    /// @dev Selects the 256-leaf word and bit for the requested leaf and
    /// reports whether that bit is marked used under the current keyVersion.
    /// @param leafIndex The stateful leaf index to query.
    /// @return True when the leaf is already marked used this epoch.
    function isLeafUsed(uint32 leafIndex) public view returns (bool) {
        // Group leaves into 256-bit words for compact bitmap storage.
        uint256 wordIndex = uint256(leafIndex) >> 8;
        // Select the bit inside that word corresponding to this leaf.
        uint256 bitIndex = uint256(leafIndex) & 0xff;
        // Return whether that bit has already been marked as used.
        return (usedLeafBitmap[keyVersion][wordIndex]
                    & (uint256(1) << bitIndex)) != 0;
    }

    /// @notice Switch to monotonic stateful leaf tracking. Owner only.
    /// @dev Rejects changes after any stateful leaf use this epoch, prevents
    /// rollback below the current cursor, installs monotonic tracking with
    /// the supplied next expected leaf, exits recovery mode, and emits the
    /// policy update.
    /// @param initialLeafIndex The next expected stateful leaf index.
    function setStatefulPolicyMonotonicIndex(uint32 initialLeafIndex)
        external
        onlyOwner
    {
        // Freeze the stateful tracking model once any stateful leaf has been
        // consumed in this epoch.
        require(!statefulPolicyFrozen, "stateful policy frozen");
        // Never allow policy changes to roll back the expected monotonic leaf
        // cursor.
        require(
            initialLeafIndex >= nextStatefulLeafIndex,
            "stateful index rollback"
        );
        // Switch into ordered stateful leaf tracking.
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        // Install the next expected stateful leaf supplied by the owner.
        nextStatefulLeafIndex = initialLeafIndex;
        // Leaving recovery-only mode returns the wrapper to normal operation.
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    /// @notice Switch to recovery-only stateless rotation mode. Owner only.
    /// @dev Rejects changes after any stateful leaf use this epoch, keeps
    /// the stateful cursor initialized for later normal operation, and
    /// requires an explicit enterRecoveryMode() call before stateless
    /// recovery is accepted. Emits the policy update.
    function setStatefulPolicyRecoveryRotation() external onlyOwner {
        // Freeze the stateful tracking model once any stateful leaf has been
        // consumed in this epoch.
        require(!statefulPolicyFrozen, "stateful policy frozen");
        // Switch into the policy where stateless signatures serve as recovery
        // authority.
        statefulPolicy = StatefulPolicy.RecoveryRotation;
        // Ensure the stateful cursor stays initialized for later normal
        // operation.
        if (nextStatefulLeafIndex == 0) {
            nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        }
        // Require an explicit enterRecoveryMode() call before recovery
        // signatures are accepted.
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    /// @notice Switch to bitmap-based stateful leaf tracking. Owner only.
    /// @dev Rejects changes after any stateful leaf use this epoch, keeps
    /// the stateful cursor initialized for future monotonic use, exits
    /// recovery mode, and emits the policy update.
    function setStatefulPolicyLeafBitmap() external onlyOwner {
        // Freeze the stateful tracking model once any stateful leaf has been
        // consumed in this epoch.
        require(!statefulPolicyFrozen, "stateful policy frozen");
        // Switch into out-of-order bitmap tracking for stateful leaf use.
        statefulPolicy = StatefulPolicy.LeafBitmap;
        // Ensure the stateful cursor stays initialized for future monotonic
        // use.
        if (nextStatefulLeafIndex == 0) {
            nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        }
        // Leaving recovery-only mode returns the wrapper to normal operation.
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    /// @notice Arm the wrapper for recovery-only stateless rotations. Owner
    /// only.
    /// @dev Requires the recovery-rotation policy to be active, then flips
    /// the recovery-mode flag so stateless recovery rotations are accepted
    /// and emits the recovery-mode event.
    function enterRecoveryMode() external onlyOwner {
        // Recovery mode is meaningful only under the dedicated recovery
        // policy.
        require(
            statefulPolicy == StatefulPolicy.RecoveryRotation,
            "recovery policy required"
        );
        // Arm the wrapper so stateless recovery rotations are now accepted.
        recoveryMode = true;
        emit RecoveryModeEntered(keyVersion);
    }

    // precheckStatefulLeafUse: Check whether the active policy allows a
    // stateful leaf before verification.
    // 1. Reject all stateful signatures while the wrapper is configured for
    // recovery-only stateless authority.
    // 2. Under monotonic tracking, accept only the next expected leaf.
    // 3. Under bitmap tracking, accept only leaves that have not yet been
    // marked used.
    // 4. Return true for any remaining policy branch.
    function precheckStatefulLeafUse(uint32 leafIndex)
        internal
        view
        returns (bool)
    {
        // Recovery-rotation policy disables the stateful path entirely,
        // whether or not recovery mode has been explicitly armed yet.
        if (statefulPolicy == StatefulPolicy.RecoveryRotation) return false;
        // Ordered tracking accepts exactly one next leaf.
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) {
            return leafIndex == nextStatefulLeafIndex;
        }
        // Bitmap tracking accepts any leaf that has not already been marked
        // used.
        if (statefulPolicy == StatefulPolicy.LeafBitmap) {
            return !isLeafUsed(leafIndex);
        }
        return true;
    }

    /// @notice Read-only self-call helper for canonical stateful action
    /// verification. onlySelf.
    /// @dev Enforces the stateful leaf policy without consuming the leaf,
    /// rebuilds the canonical action context, requires the supplied hash to
    /// match the canonical stateful action hash, and verifies the signature.
    /// @param hash The 32-byte hash the signature must authorize.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param actionType The action type bound into the canonical hash.
    /// @param payloadHash The action payload hash.
    /// @param signature The stateful signature.
    /// @return True when the stateful signature is valid now.
    function isValidStatefulActionSignatureNow(
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatefulSignature calldata signature
    ) external view onlySelf returns (bool) {
        uint32 leafIndex = uint32(signature.authPath.length);
        if (!precheckStatefulLeafUse(leafIndex)) return false;

        // forgefmt: disable-next-line
        ShrincsTypes.ActionContext memory context =
            ShrincsTypes.ActionContext({
                domainSeparator: domainSeparator(),
                nonce: nonce,
                keyVersion: keyVersion,
                actionType: actionType,
                payloadHash: payloadHash
            });

        if (
            SHRINCS.statefulActionMessageHash(
                    currentShrincsPublicKey, context
                ) != hash
        ) return false;
        return SHRINCS.verifyStateful(
            currentShrincsPublicKey, publicKey, context, signature
        );
    }

    /// @notice Read-only self-call helper for canonical stateless action
    /// verification. onlySelf.
    /// @dev Enforces recovery-mode gating and the stateless usage budget
    /// without consuming either, rebuilds the canonical action context,
    /// requires the supplied hash to match the canonical stateless action
    /// hash, and verifies the signature.
    /// @param hash The 32-byte hash the signature must authorize.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param actionType The action type bound into the canonical hash.
    /// @param payloadHash The action payload hash.
    /// @param signature The stateless signature.
    /// @return True when the stateless signature is valid now.
    function isValidStatelessActionSignatureNow(
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external view onlySelf returns (bool) {
        if (
            statefulPolicy == StatefulPolicy.RecoveryRotation
                && !recoveryMode
        ) return false;
        if (
            statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT
        ) return false;

        // forgefmt: disable-next-line
        ShrincsTypes.ActionContext memory context =
            ShrincsTypes.ActionContext({
                domainSeparator: domainSeparator(),
                nonce: nonce,
                keyVersion: keyVersion,
                actionType: actionType,
                payloadHash: payloadHash
            });

        if (
            SHRINCS.statelessActionMessageHash(
                    currentShrincsPublicKey, context
                ) != hash
        ) return false;
        return SHRINCS.verifyStateless(
            currentShrincsPublicKey, publicKey, context, signature
        );
    }

    // commitStatefulLeafUse: Record a successfully verified stateful leaf
    // under the active policy.
    // 1. Under monotonic tracking, advance the next expected leaf by one.
    // 2. Under bitmap tracking, mark the corresponding bit for this leaf as
    // used.
    // 3. Freeze stateful policy changes for the remainder of the key epoch.
    // 4. Leave recovery-only mode unchanged because stateful signatures are
    // blocked there.
    function commitStatefulLeafUse(uint32 leafIndex) internal {
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) {
            // Move the expected cursor forward after one successful monotonic
            // use.
            nextStatefulLeafIndex += 1;
        } else if (statefulPolicy == StatefulPolicy.LeafBitmap) {
            // Group leaves into 256-bit words for compact bitmap storage.
            uint256 wordIndex = uint256(leafIndex) >> 8;
            // Select the bit inside that word corresponding to this leaf.
            uint256 bitIndex = uint256(leafIndex) & 0xff;
            // Mark this leaf as consumed for the current key epoch.
            usedLeafBitmap[keyVersion][wordIndex] |= uint256(1) << bitIndex;
        }
        // Any successful stateful verification fixes the tracking model for
        // this key epoch.
        statefulPolicyFrozen = true;
    }

    // consumeStatelessRotationUse: Record one successful stateless recovery
    // signature used for rotation.
    // 1. Increment the current stateless usage count under the old key epoch.
    // 2. Emit a dedicated rotation-usage event before any key install resets
    // wrapper state.
    function consumeStatelessRotationUse(
        bytes32 nextCompositePublicKey,
        bool fullRotation
    ) internal {
        statelessSignaturesUsed += 1;
        emit StatelessRotationConsumed(
            statelessSignaturesUsed,
            nonce,
            keyVersion,
            nextCompositePublicKey,
            fullRotation
        );
    }

    // domainSeparator: Derive the wrapper's canonical signing domain.
    // 1. Start from a stable domain tag for this wrapper family.
    // 2. Bind the separator to the current chain id.
    // 3. Bind the separator to this contract instance.
    function domainSeparator() internal view returns (bytes32) {
        // Bind wrapper signatures to this product tag, chain, and deployed
        // contract instance.
        return
            keccak256(abi.encode(DOMAIN_TAG, block.chainid, address(this)));
    }

    // installRotatedKey: Install a rotated key bundle and reset wrapper state
    // for the next epoch.
    // 1. Preserve the previous installed key commitment for the rotation
    // event.
    // 2. Install the next SHRINCS public-key commitment.
    // 3. Advance nonce and key version to close the old authorization epoch.
    // 4. Reset or preserve stateless usage accounting according to the
    // caller's intent.
    // 5. Reset stateful leaf tracking and policy-freeze state for the new
    // key.
    // 6. Return the wrapper to the default monotonic non-recovery policy.
    // 7. Emit rotation and policy-reset events for off-chain observers.
    function installRotatedKey(
        bytes32 nextCompositePublicKey,
        bool resetStatelessUsage
    ) internal {
        // Preserve the previous key commitment for the rotation event
        // payload.
        bytes32 previousShrincsPublicKey = currentShrincsPublicKey;
        // Install the next trusted SHRINCS public-key commitment.
        currentShrincsPublicKey = nextCompositePublicKey;
        // Advance nonce and key epoch so old authorizations cannot be
        // replayed.
        nonce += 1;
        keyVersion += 1;
        // Reset per-key stateless usage accounting only when the caller
        // rotates the stateless key too.
        if (resetStatelessUsage) {
            statelessSignaturesUsed = 0;
        }
        // Reset stateful signing to the first leaf of the new key epoch.
        nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        // Fresh key epochs allow policy selection again until the first
        // stateful leaf is consumed.
        statefulPolicyFrozen = false;
        // Fresh installs return to the default safe wrapper policy.
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        // Recovery mode ends once the new key has been installed.
        recoveryMode = false;
        emit KeyRotated(
            previousShrincsPublicKey, nextCompositePublicKey, keyVersion
        );
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    // installFreshStatefulKey: Install a fresh stateful subkey while
    // preserving the stateless side.
    // 1. Install the next SHRINCS public-key commitment.
    // 2. Preserve stateless usage accounting because the stateless key
    // material is unchanged.
    // 3. Reset stateful tracking and wrapper policy state for the next epoch.
    function installFreshStatefulKey(bytes32 nextCompositePublicKey)
        internal
    {
        installRotatedKey(nextCompositePublicKey, false);
    }

    // installFreshFullKey: Install a fully fresh SHRINCS bundle for the next
    // key epoch.
    // 1. Install the next SHRINCS public-key commitment.
    // 2. Reset stateless usage accounting because the stateless key material
    // changes too.
    // 3. Reset stateful tracking and wrapper policy state for the next epoch.
    function installFreshFullKey(bytes32 nextCompositePublicKey) internal {
        installRotatedKey(nextCompositePublicKey, true);
    }

    // installFreshKey: Backward-compatible alias for the full fresh-key
    // install path.
    // 1. Preserve existing helper-call behavior in tests and support
    // harnesses.
    // 2. Route to the semantic full-key install helper.
    function installFreshKey(bytes32 nextCompositePublicKey) internal {
        installFreshFullKey(nextCompositePublicKey);
    }
}
