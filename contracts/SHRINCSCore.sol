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

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSCodec} from "./SHRINCSCodec.sol";
import {UXMSS} from "./UXMSS.sol";
import {SPHINCSPlusCCore} from "./SPHINCSPlusCCore.sol";

library SHRINCSCore {
    // Hash-suite identifiers bound into canonical action and rotation hashes.
    uint32 internal constant HASH_SUITE_KECCAK_256 = 1;
    // Sentinel for an unsupported hash suite. Referenced only by tests
    // today; kept as a named constant so fail-closed suite checks and
    // negative tests have a stable non-keccak identifier.
    uint32 internal constant HASH_SUITE_UNSUPPORTED = 2;
    // Operation tags domain-separating each signed message family.
    bytes32 internal constant OP_VERIFY_STATEFUL =
        keccak256("shrincs-verify-stateful");
    bytes32 internal constant OP_VERIFY_STATELESS =
        keccak256("shrincs-verify-stateless");
    bytes32 internal constant OP_ROTATE_STATEFUL =
        keccak256("shrincs-rotate-stateful");
    bytes32 internal constant OP_ROTATE_FULL =
        keccak256("shrincs-rotate-full");

    struct PublicKey {
        // Encoded stateful fast-path public key.
        bytes statefulPublicKey;
        // Commitment binding the full hybrid public-key bundle together.
        bytes publicKeyCommitment;
        // Stateless SPHINCS-style public seed.
        bytes pkSeed;
        // Stateless SPHINCS-style public root.
        bytes hypertreeRoot;
    }

    struct SigningKey {
        // Secret seed used to derive stateful WOTS-C chain secrets.
        bytes32 statefulSkSeed;
        // Secret PRF seed used to derive stateful WOTS-C message randomizers.
        bytes32 statefulPrfSeed;
        // Public seed used in stateful WOTS-C and stateful tree hashing.
        bytes32 statefulPkSeed;
        // Root of the stateful unbalanced tree committed in the public key.
        bytes32 statefulRoot;
        // Highest stateful leaf index this key may sign with.
        uint32 maxStatefulSignatures;
        // Next monotonic stateful leaf index to consume.
        uint32 nextStatefulLeafIndex;
        // Stateless SK.seed-style material used to derive FORS-C and
        // hypertree WOTS-C secrets.
        bytes32 statelessSkSeed;
        // Stateless SK.prf-style material used to derive stateless message
        // randomizers.
        bytes32 statelessPrfSeed;
        // Global public seed used in FORS-C, hypertree WOTS-C, and Merkle
        // node hashing.
        bytes32 pkSeed;
        // Top hypertree root committed in the public key.
        bytes32 hypertreeRoot;
    }

    struct StatefulRotationTarget {
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
    }

    struct RotationContext {
        // Contract/application domain binding for the rotation intent.
        bytes32 domainSeparator;
        // Replay-protection nonce consumed by the wrapper.
        uint256 nonce;
        // Installed-key epoch that this rotation authorizes from.
        uint256 keyVersion;
    }

    struct ActionContext {
        // Contract/application domain binding for the action intent.
        bytes32 domainSeparator;
        // Replay-protection nonce consumed by the wrapper.
        uint256 nonce;
        // Installed-key epoch that this action is valid under.
        uint256 keyVersion;
        // Typed action discriminator chosen by the integrating account logic.
        bytes32 actionType;
        // Hash of the typed payload authorized by the signature.
        bytes32 payloadHash;
    }

    struct RotationTarget {
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
        // Replacement stateless public seed.
        bytes pkSeed;
        // Replacement stateless public root.
        bytes hypertreeRoot;
    }

    // verifyStateful: Verify a stateful SHRINCS action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical stateful action hash from the installed key
    // commitment and action context.
    // 3. Verify the stateful WOTS-C / unbalanced-XMSS style signature against
    // that message hash.
    function verifyStateful(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata publicKey,
        SHRINCSCore.ActionContext memory context,
        UXMSS.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!validActionContext(context)) return false;
        // Canonical stateful verification signs the typed action context
        // hash, not arbitrary caller-provided bytes.
        bytes memory message = abi.encodePacked(
            statefulActionMessageHash(expectedPublicKeyCommitment, context)
        );
        // Delegate the stateful signature equation checks to the lower-level
        // helper.
        return verifyStatefulUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }

    // verifyStateless: Verify a stateless SHRINCS action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical stateless action hash from the installed key
    // commitment and action context.
    // 3. Verify FORS-C and then carry the reconstructed root up the hypertree
    // to the public root.
    function verifyStateless(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata publicKey,
        SHRINCSCore.ActionContext memory context,
        SPHINCSPlusCCore.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!validActionContext(context)) return false;
        // Canonical stateless verification signs the typed action context
        // hash, not arbitrary caller-provided bytes.
        bytes memory message = abi.encodePacked(
            statelessActionMessageHash(expectedPublicKeyCommitment, context)
        );
        // Delegate FORS-C plus hypertree verification to the lower-level
        // helper.
        return verifyStatelessUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }

    // rotateStatefulViaStateless: Authorize replacing only the stateful
    // subkey via a stateless recovery signature.
    // 1. Validate the current key bundle, rotation context, and next stateful
    // key payload.
    // 2. Recompute the next stateful-bundle commitment and require it to
    // match the declared commitment.
    // 3. Build the canonical rotation message hash.
    // 4. Verify the stateless recovery signature over that hash under the
    // current installed key.
    // 5. Return the next bundle commitment on success, or bytes32(0) on
    // failure.
    function rotateStatefulViaStateless(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext memory context,
        SPHINCSPlusCCore.StatelessSignature calldata recoverySignature,
        SHRINCSCore.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32 nextPublicKeyCommitment) {
        if (!SHRINCSCodec.validPublicKey(currentPublicKey)) {
            return bytes32(0);
        }
        // The current public key must match the installed bundle commitment
        // the caller expects.
        if (!SHRINCSCodec.matchesExpectedPublicKeyCommitment(
                currentPublicKey, expectedPublicKeyCommitment
            )) {
            return bytes32(0);
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!validRotationContext(context)) return bytes32(0);
        // Stateful subkey rotation carries only a replacement stateful public
        // key payload.
        if (
            nextStatefulKey.statefulPublicKey.length
                != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) return bytes32(0);
        {
            // Decode the fixed-width stateful key to check operational limits
            // such as maxSignatures.
            (
                UXMSS.StatefulPublicKey memory decodedNextStatefulKey,
                bool ok
            ) = SHRINCSCodec.decodeStatefulPublicKey(
                nextStatefulKey.statefulPublicKey
            );
            if (!ok) return bytes32(0);
            if (decodedNextStatefulKey.maxSignatures == 0) {
                return bytes32(0);
            }
        }
        // Rebuild the next installed bundle commitment using the replacement
        // stateful key plus the current stateless seed/root, since this
        // rotation does not replace the stateless side.
        bytes32 computedNextPublicKeyCommitment =
            SHRINCSCodec.publicKeyCommitmentFromParts(
                nextStatefulKey.statefulPublicKey,
                currentPublicKey.pkSeed,
                currentPublicKey.hypertreeRoot
            );
        // The declared next bundle commitment must be present and exactly 32
        // bytes.
        if (nextStatefulKey.publicKeyCommitment.length != 32) {
            return bytes32(0);
        }
        bytes32 declaredNextPublicKeyCommitment;
        bytes calldata declaredNextPublicKeyCommitmentBytes =
            nextStatefulKey.publicKeyCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            declaredNextPublicKeyCommitment := calldataload(
                declaredNextPublicKeyCommitmentBytes.offset
            )
        }
        // Reject any mismatch between the declared and recomputed next
        // installed-key commitment.
        if (
            declaredNextPublicKeyCommitment
                != computedNextPublicKeyCommitment
        ) return bytes32(0);
        // Bind the current installed bundle commitment, rotation context, and
        // next bundle commitment into one canonical recovery message.
        bytes memory recoveryMessage = abi.encodePacked(
            statefulRotationMessageHash(
                expectedPublicKeyCommitment,
                currentPublicKey,
                context,
                nextStatefulKey
            )
        );
        // The stateless recovery signature must authorize exactly that
        // canonical rotation message.
        if (!verifyStatelessUncheckedMessage(
                expectedPublicKeyCommitment,
                currentPublicKey,
                recoveryMessage,
                recoverySignature
            )) {
            return bytes32(0);
        }
        // On success, return the commitment the wrapper should install as the
        // next bundle id.
        return computedNextPublicKeyCommitment;
    }

    // statelessRotate: Authorize replacing the full SHRINCS bundle via a
    // stateless recovery signature.
    // 1. Validate the current key bundle, rotation context, and full next-key
    // payload.
    // 2. Recompute the next full-bundle commitment and require it to match
    // the declared commitment.
    // 3. Build the canonical full-rotation message hash.
    // 4. Verify the stateless recovery signature over that hash under the
    // current installed key.
    // 5. Return the next bundle commitment on success, or bytes32(0) on
    // failure.
    function statelessRotate(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext memory context,
        SPHINCSPlusCCore.StatelessSignature calldata recoverySignature,
        SHRINCSCore.RotationTarget calldata nextKey
    ) internal pure returns (bytes32 nextPublicKeyCommitment) {
        if (!SHRINCSCodec.validPublicKey(currentPublicKey)) {
            return bytes32(0);
        }
        // The current public key must match the installed bundle commitment
        // the caller expects.
        if (!SHRINCSCodec.matchesExpectedPublicKeyCommitment(
                currentPublicKey, expectedPublicKeyCommitment
            )) {
            return bytes32(0);
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!validRotationContext(context)) return bytes32(0);
        // The replacement bundle must contain fixed-width stateful,
        // commitment, seed, and root fields.
        if (
            nextKey.statefulPublicKey.length
                != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) return bytes32(0);
        if (nextKey.publicKeyCommitment.length != 32) return bytes32(0);
        if (nextKey.pkSeed.length != 32) return bytes32(0);
        if (nextKey.hypertreeRoot.length != 32) return bytes32(0);
        {
            // Decode the replacement stateful key to reject unusable
            // zero-budget keys.
            (
                UXMSS.StatefulPublicKey memory decodedNextStatefulKey,
                bool ok
            ) = SHRINCSCodec.decodeStatefulPublicKey(
                nextKey.statefulPublicKey
            );
            if (!ok) return bytes32(0);
            if (decodedNextStatefulKey.maxSignatures == 0) {
                return bytes32(0);
            }
        }
        // Rebuild the full replacement bundle commitment from all next-key
        // components.
        bytes32 computedNextPublicKeyCommitment =
            SHRINCSCodec.publicKeyCommitmentFromParts(
                nextKey.statefulPublicKey,
                nextKey.pkSeed,
                nextKey.hypertreeRoot
            );
        bytes32 declaredNextPublicKeyCommitment;
        bytes calldata declaredNextPublicKeyCommitmentBytes =
            nextKey.publicKeyCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            declaredNextPublicKeyCommitment := calldataload(
                declaredNextPublicKeyCommitmentBytes.offset
            )
        }
        // Reject any mismatch between the declared and recomputed next
        // installed-key commitment.
        if (
            declaredNextPublicKeyCommitment
                != computedNextPublicKeyCommitment
        ) return bytes32(0);

        // Bind the current installed bundle commitment, rotation context, and
        // full next bundle commitment into one canonical recovery message.
        bytes memory recoveryMessage = abi.encodePacked(
            fullRotationMessageHash(
                expectedPublicKeyCommitment,
                currentPublicKey,
                context,
                nextKey
            )
        );
        // The stateless recovery signature must authorize exactly that
        // canonical full rotation.
        if (!verifyStatelessUncheckedMessage(
                expectedPublicKeyCommitment,
                currentPublicKey,
                recoveryMessage,
                recoverySignature
            )) {
            return bytes32(0);
        }
        // On success, return the next bundle commitment the wrapper should
        // install.
        return computedNextPublicKeyCommitment;
    }

    // verifyStatefulUncheckedMessage: Verify a stateful signature after the
    // caller has already constructed the exact signed message bytes.
    // 1. Check that the public key uses the compiled fixed layout.
    // 2. Check the installed public-key commitment and the public-key
    // encoding.
    // 3. Decode the compact stateful public key embedded inside the SHRINCS
    // public bundle.
    // 4. Delegate the cryptographic verification to the stateful component
    // library.
    function verifyStatefulUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata publicKey,
        bytes memory message,
        UXMSS.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // The public key must satisfy the compiled fixed key shape.
        if (!SHRINCSCodec.validPublicKey(publicKey)) return false;
        // The bundled public key must match the installed public-key
        // commitment.
        if (!SHRINCSCodec.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return false;
        // Decode the compact stateful public key fields from the public
        // bundle.
        (UXMSS.StatefulPublicKey memory statefulKey, bool ok) =
            SHRINCSCodec.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        // The component library owns the stateful WOTS-C and unbalanced-tree
        // verification rules.
        return UXMSS.verify(
            statefulKey.pkSeed,
            statefulKey.root,
            statefulKey.maxSignatures,
            message,
            signature
        );
    }

    // statefulActionMessageHash: Build the canonical stateful action message
    // hash.
    // 1. Bind the stateful operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the account-layer action context fields.
    function statefulActionMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed
        // key commitment, and the account-layer action context so signatures
        // cannot be replayed across operation families or account epochs.
        return keccak256(
            abi.encodePacked(
                SHRINCSCore.OP_VERIFY_STATEFUL,
                SHRINCSCore.HASH_SUITE_KECCAK_256,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    // statelessActionMessageHash: Build the canonical stateless action
    // message hash.
    // 1. Bind the stateless operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the account-layer action context fields.
    function statelessActionMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed
        // key commitment, and the account-layer action context for the
        // stateless path.
        return keccak256(
            abi.encodePacked(
                SHRINCSCore.OP_VERIFY_STATELESS,
                SHRINCSCore.HASH_SUITE_KECCAK_256,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    // statefulRotationMessageHash: Build the canonical message hash
    // authorizing a stateless-to-stateful rotation.
    // 1. Bind the stateful-rotation operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the rotation context.
    // 5. Bind the current and next bundle commitments.
    function statefulRotationMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext memory context,
        SHRINCSCore.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        // The canonical stateful-rotation hash binds an operation tag, hash
        // suite, installed key commitment, rotation context, and both the
        // current and next bundle ids.
        return keccak256(
            abi.encodePacked(
                SHRINCSCore.OP_ROTATE_STATEFUL,
                SHRINCSCore.HASH_SUITE_KECCAK_256,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.publicKeyCommitment,
                nextStatefulKey.publicKeyCommitment
            )
        );
    }

    // fullRotationMessageHash: Build the canonical message hash authorizing a
    // full next-key bundle.
    // 1. Bind the full-rotation operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the rotation context.
    // 5. Bind the current and next bundle commitments.
    function fullRotationMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata currentPublicKey,
        SHRINCSCore.RotationContext memory context,
        SHRINCSCore.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        // The canonical full-rotation hash binds an operation tag, hash
        // suite, installed key commitment, rotation context, and both the
        // current and next bundle ids.
        return keccak256(
            abi.encodePacked(
                SHRINCSCore.OP_ROTATE_FULL,
                SHRINCSCore.HASH_SUITE_KECCAK_256,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.publicKeyCommitment,
                nextKey.publicKeyCommitment
            )
        );
    }

    // verifyStatelessUncheckedMessage: Verify a stateless signature after the
    // caller has already constructed the exact signed message bytes.
    // 1. Validate the current key bundle and fixed public-key layout.
    // 2. Delegate FORS-C plus hypertree verification to the stateless
    // component library.
    function verifyStatelessUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        SHRINCSCore.PublicKey calldata publicKey,
        bytes memory message,
        SPHINCSPlusCCore.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // The current public key must match the installed bundle commitment
        // expected by the caller.
        if (!SHRINCSCodec.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return false;
        // The current key bundle must satisfy the compiled fixed public-key
        // shape.
        if (!SHRINCSCodec.validPublicKey(publicKey)) return false;

        // The component library owns the FORS-C and hypertree verification
        // rules over the stateless public seed and root.
        return SPHINCSPlusCCore.verify(
            publicKey.pkSeed, publicKey.hypertreeRoot, message, signature
        );
    }

    // validActionContext: Perform lightweight structural checks for canonical
    // action contexts.
    // 1. Require a nonzero domain separator.
    // 2. Require a nonzero action type.
    // 3. Require a nonzero payload hash.
    function validActionContext(SHRINCSCore.ActionContext memory context)
        internal
        pure
        returns (bool)
    {
        // Domain separation must be explicit.
        if (context.domainSeparator == bytes32(0)) return false;
        // The action type must not be left unspecified.
        if (context.actionType == bytes32(0)) return false;
        // The payload must commit to some nonzero value.
        return context.payloadHash != bytes32(0);
    }

    // validRotationContext: Perform lightweight structural checks for
    // canonical rotation contexts.
    // 1. Require a nonzero domain separator.
    function validRotationContext(SHRINCSCore.RotationContext memory context)
        internal
        pure
        returns (bool)
    {
        return context.domainSeparator != bytes32(0);
    }
}
