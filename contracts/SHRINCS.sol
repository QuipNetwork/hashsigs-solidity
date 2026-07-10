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

import {ShrincsTypes} from "./ShrincsTypes.sol";
import {ShrincsUtils} from "./ShrincsUtils.sol";
import {ShrincsStateful} from "./ShrincsStateful.sol";
import {ShrincsForsC} from "./ShrincsForsC.sol";
import {ShrincsHypertree} from "./ShrincsHypertree.sol";

library SHRINCS {
    // verifyStateful: Verify a stateful SHRINCS action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical stateful action hash from the installed key
    // commitment and action context.
    // 3. Verify the stateful WOTS-C / unbalanced-XMSS style signature against
    // that message hash.
    function verifyStateful(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext memory context,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!ShrincsUtils.validActionContext(context)) return false;
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
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext memory context,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!ShrincsUtils.validActionContext(context)) return false;
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32 nextPublicKeyCommitment) {
        if (!ShrincsUtils.validPublicKey(currentPublicKey)) {
            return bytes32(0);
        }
        // The current public key must match the installed bundle commitment
        // the caller expects.
        if (!ShrincsUtils.matchesExpectedPublicKeyCommitment(
                currentPublicKey, expectedPublicKeyCommitment
            )) {
            return bytes32(0);
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!ShrincsUtils.validRotationContext(context)) return bytes32(0);
        // Stateful subkey rotation carries only a replacement stateful public
        // key payload.
        if (
            nextStatefulKey.statefulPublicKey.length
                != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES
        ) return bytes32(0);
        {
            // Decode the fixed-width stateful key to check operational limits
            // such as maxSignatures.
            (
                ShrincsTypes.StatefulPublicKey memory decodedNextStatefulKey,
                bool ok
            ) = ShrincsUtils.decodeStatefulPublicKey(
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
            ShrincsUtils.publicKeyCommitmentFromParts(
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) internal pure returns (bytes32 nextPublicKeyCommitment) {
        if (!ShrincsUtils.validPublicKey(currentPublicKey)) {
            return bytes32(0);
        }
        // The current public key must match the installed bundle commitment
        // the caller expects.
        if (!ShrincsUtils.matchesExpectedPublicKeyCommitment(
                currentPublicKey, expectedPublicKeyCommitment
            )) {
            return bytes32(0);
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!ShrincsUtils.validRotationContext(context)) return bytes32(0);
        // The replacement bundle must contain fixed-width stateful,
        // commitment, seed, and root fields.
        if (
            nextKey.statefulPublicKey.length
                != ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES
        ) return bytes32(0);
        if (nextKey.publicKeyCommitment.length != 32) return bytes32(0);
        if (nextKey.pkSeed.length != 32) return bytes32(0);
        if (nextKey.hypertreeRoot.length != 32) return bytes32(0);
        {
            // Decode the replacement stateful key to reject unusable
            // zero-budget keys.
            (
                ShrincsTypes.StatefulPublicKey memory decodedNextStatefulKey,
                bool ok
            ) = ShrincsUtils.decodeStatefulPublicKey(
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
            ShrincsUtils.publicKeyCommitmentFromParts(
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
    // 1. Treat the provided bytes as the final message that was signed.
    // 2. Delegate the cryptographic verification to the stateful component
    // library.
    function verifyStatefulUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        // The component library owns the stateful WOTS-C and unbalanced-tree
        // verification rules.
        return ShrincsStateful.verifyStatefulUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
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
        ShrincsTypes.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed
        // key commitment, and the account-layer action context so signatures
        // cannot be replayed across operation families or account epochs.
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_VERIFY_STATEFUL,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
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
        ShrincsTypes.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed
        // key commitment, and the account-layer action context for the
        // stateless path.
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_VERIFY_STATELESS,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        // The canonical stateful-rotation hash binds an operation tag, hash
        // suite, installed key commitment, rotation context, and both the
        // current and next bundle ids.
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_ROTATE_STATEFUL,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        // The canonical full-rotation hash binds an operation tag, hash
        // suite, installed key commitment, rotation context, and both the
        // current and next bundle ids.
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_ROTATE_FULL,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
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
    // 2. Reconstruct the FORS-C root from the signed message bytes and FORS
    // proof.
    // 3. Carry that root up the hypertree and compare it to the public root.
    function verifyStatelessUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // The current public key must match the installed bundle commitment
        // expected by the caller.
        if (!ShrincsUtils.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return false;
        // The current key bundle must satisfy the compiled fixed public-key
        // shape.
        if (!ShrincsUtils.validPublicKey(publicKey)) return false;
        // A stateless signature must carry at least one hypertree layer.
        if (signature.hypertree.length == 0) return false;

        // Reconstruct the FORS root from the message, FORS
        // randomness/counter, and revealed leaves.
        (bytes32 forsRoot, bool ok) = ShrincsForsC.verifyForsCAndReturnRoot(
            publicKey,
            message,
            signature.fors,
            signature.hypertree[0].treeIndex,
            signature.hypertree[0].leafIndex
        );
        if (!ok) return false;
        // Carry the reconstructed FORS root up the hypertree until it matches
        // the public root.
        return ShrincsHypertree.verifyHypertree(
            publicKey, forsRoot, signature.hypertree
        );
    }
}
