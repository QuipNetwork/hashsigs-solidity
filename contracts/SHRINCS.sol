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
import {ShrincsCompact} from "./ShrincsCompact.sol";
import {ShrincsForsC} from "./ShrincsForsC.sol";
import {ShrincsHypertree} from "./ShrincsHypertree.sol";

// SHRINCS: Facade for account-level stateless and compact verification.
//
// Design references:
// - JARDIN writeUp Section 4.1: Type 1 stateless registration and Type 2
//   compact FORS+C transactions.
//   https://github.com/nconsigny/JARDIN/blob/main/writeUp.md
// - JARDIN writeUp Section 6: compact slots keyed by
//   keccak256(subPkSeed || subPkRoot).
// - JARDIN writeUp Section 7: compact q lives in the Type 2 signature, not
//   account storage.
// - FIPS 205 Algorithms 14-17: FORS key generation, signing, and public-key
//   reconstruction.
//   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
library SHRINCS {
    // verifyStateless: Verify a direct stateless account action.
    //
    // Use case:
    // - Root-authority path for actions signed by the installed key.
    // - Slower than compact Type 2, but independent of compact slot state.
    //
    // 1. Validate the typed action context shape.
    // 2. Build the stateless action transcript from installed pkSeed/root.
    // 3. Reconstruct the FORS-C root from the signature.
    // 4. Carry that root up the hypertree to the installed public root.
    function verifyStateless(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext memory context,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!ShrincsUtils.validActionContext(context)) return false;

        // Canonical verification signs the typed action transcript, not
        // arbitrary caller-provided bytes.
        bytes memory message =
            abi.encodePacked(statelessActionMessageHash(expectedPkSeed, expectedHypertreeRoot, context));

        // Delegate FORS-C plus hypertree verification to the helper.
        return verifyStatelessUncheckedMessage(expectedPkSeed, expectedHypertreeRoot, publicKey, message, signature);
    }

    // verifyCompact: Verify a JARDIN-style compact Type 2 action signature.
    //
    // Use case:
    // - Frequent account actions through a registered compact slot.
    // - The caller must check compactSlots[compactSlotId(...)] first.
    //
    // 1. Validate the typed action context shape.
    // 2. Build the compact action transcript from account context only.
    // 3. Verify the raw FORS+C opening and balanced Merkle path.
    function verifyCompact(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        ShrincsTypes.ActionContext memory context,
        bytes calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!ShrincsUtils.validActionContext(context)) return false;

        // Build the canonical compact action hash. Slot authorization is an
        // account-layer check, not part of raw FORS+C verification.
        bytes32 message = compactActionMessageHash(context);

        // Delegate the JARDIN/FIPS raw compact equation to ShrincsCompact.
        return verifyCompactUncheckedMessage(subPkSeed, subPkRoot, message, signature);
    }

    // statelessRotate: Authorize replacing the installed stateless key.
    //
    // Use case:
    // - Root key rotation. This intentionally does not use
    //   statelessActionMessageHash because rotation has different fields and
    //   needs its own operation tag.
    //
    // 1. Validate the current key, rotation context, and next-key payload.
    // 2. Build the canonical full-rotation message hash.
    // 3. Verify that hash under the currently installed stateless key.
    function statelessRotate(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) internal pure returns (bool) {
        if (!ShrincsUtils.validPublicKey(currentPublicKey)) {
            return false;
        }

        // The caller's current public key must match installed storage.
        if (!ShrincsUtils.matchesExpectedStatelessKey(currentPublicKey, expectedPkSeed, expectedHypertreeRoot)) {
            return false;
        }

        // Rotation messages must still carry a nonzero domain binding.
        if (!ShrincsUtils.validRotationContext(context)) return false;

        // The replacement key must contain fixed-width seed and root fields.
        if (nextKey.pkSeed.length != 32) return false;
        if (nextKey.hypertreeRoot.length != 32) return false;

        // Bind the installed key, rotation context, current public key, and
        // replacement key into one rotation-specific transcript.
        bytes memory recoveryMessage = abi.encodePacked(
            fullRotationMessageHash(expectedPkSeed, expectedHypertreeRoot, currentPublicKey, context, nextKey)
        );

        // The current stateless key must authorize exactly that rotation.
        if (!verifyStatelessUncheckedMessage(
                expectedPkSeed, expectedHypertreeRoot, currentPublicKey, recoveryMessage, recoverySignature
            )) {
            return false;
        }
        return true;
    }

    // verifyCompactUncheckedMessage: Verify a compact signature over bytes32.
    //
    // Use case:
    // - Low-level helper for callers that already built the exact account
    //   message hash and already handled slot authorization.
    //
    // 1. Treat the supplied bytes32 as the final account/action message hash.
    // 2. Delegate raw JARDIN Type 2 verification to the compact library.
    function verifyCompactUncheckedMessage(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 message,
        bytes calldata signature
    ) internal pure returns (bool) {
        // The component library owns raw FORS-C and Merkle verification.
        return ShrincsCompact.verifyCompactRaw(subPkSeed, subPkRoot, message, signature);
    }

    // compactActionMessageHash: Build a compact Type 2 action transcript.
    //
    // Use case:
    // - Frequent action path through a registered compact slot.
    // - Does not bind slotId; slot authorization happens in account storage.
    //
    // Deviates from [JARDIN writeUp Section 4.1]: this repo uses 32-byte
    // public words and Keccak-256 throughout, rather than JARDIN's 16-byte
    // prototype parameters.
    //
    // Preimage:
    //   OP_VERIFY_COMPACT32 || HASH_SUITE_KECCAK_2564 ||
    //   domainSeparator32 || nonce32 || keyVersion32 ||
    //   actionType32 || payloadHash32.
    //
    // The compact verifier uses this result as JARDIN message32 inside:
    //   H_msg(R, subPkSeed, subPkRoot, counter || M*).
    //
    // 1. Bind the compact operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the account-layer action context fields.
    function compactActionMessageHash(ShrincsTypes.ActionContext memory context) internal pure returns (bytes32 out) {
        return compactActionMessageHash(
            context.domainSeparator, context.nonce, context.keyVersion, context.actionType, context.payloadHash
        );
    }

    // compactActionMessageHash: Build compact Type 2 action hash from fields.
    //
    // Buffer layout:
    //   ptr+000: OP_VERIFY_COMPACT32
    //   ptr+032: HASH_SUITE_KECCAK_2564
    //   ptr+036: domainSeparator32
    //   ptr+068: nonce32
    //   ptr+100: keyVersion32
    //   ptr+132: actionType32
    //   ptr+164: payloadHash32
    //
    // Exact packed length: 32 + 4 + 5 * 32 = 196 bytes.
    function compactActionMessageHash(
        bytes32 domainSeparator,
        uint256 nonce,
        uint256 keyVersion,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal pure returns (bytes32 out) {
        // Cache constants so assembly mirrors abi.encodePacked.
        bytes32 op = ShrincsTypes.OP_VERIFY_COMPACT;
        uint32 suite = ShrincsTypes.HASH_SUITE_KECCAK_256;
        assembly {
            // Buffer layout is documented above this function.
            let ptr := mload(0x40)
            // OP_VERIFY_COMPACT.
            mstore(ptr, op)
            // HASH_SUITE_KECCAK_256 as uint32 in abi.encodePacked form.
            mstore(add(ptr, 32), shl(224, suite))
            // Account action fields.
            mstore(add(ptr, 36), domainSeparator)
            mstore(add(ptr, 68), nonce)
            mstore(add(ptr, 100), keyVersion)
            mstore(add(ptr, 132), actionType)
            mstore(add(ptr, 164), payloadHash)
            // Hash the exact packed preimage length.
            out := keccak256(ptr, 196)
            // Bump free memory past the rounded preimage.
            mstore(0x40, add(ptr, 224))
        }
    }

    // compactSlotId: Build the JARDIN compact-slot mapping key.
    //
    // Use case:
    // - Storage key for compact slot registration.
    // - Type 2 verification still receives subPkSeed/subPkRoot because raw
    //   FORS+C verification needs the public seed and Merkle root.
    //
    // Reference: JARDIN writeUp Section 6.
    //
    // Preimage: subPkSeed32 || subPkRoot32.
    // slotId = keccak256(subPkSeed32 || subPkRoot32).
    //
    // Buffer layout:
    //   ptr+000: subPkSeed32
    //   ptr+032: subPkRoot32
    function compactSlotId(bytes32 subPkSeed, bytes32 subPkRoot) internal pure returns (bytes32 out) {
        assembly {
            // Buffer layout is documented above this function.
            let ptr := mload(0x40)
            // Store subPkSeed.
            mstore(ptr, subPkSeed)
            // Store subPkRoot.
            mstore(add(ptr, 32), subPkRoot)
            // Hash the packed slot key.
            out := keccak256(ptr, 64)
        }
    }

    // compactSlotRegistrationMessageHash: Authorize adding a compact slot.
    //
    // Use case:
    // - Type 1 stateless signature authorizes a future Type 2 compact lane.
    // - The signed transcript binds only slotId, matching JARDIN's
    //   slots[H(subPkSeed, subPkRoot)] storage model.
    //
    // Preimage:
    //   OP_REGISTER_COMPACT_SLOT32 || HASH_SUITE_KECCAK_2564 ||
    //   domainSeparator32 || nonce32 || keyVersion32 || slotId32.
    function compactSlotRegistrationMessageHash(
        ShrincsTypes.RotationContext memory context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal pure returns (bytes32) {
        return compactSlotUpdateMessageHash(ShrincsTypes.OP_REGISTER_COMPACT_SLOT, context, subPkSeed, subPkRoot);
    }

    // compactSlotRevocationMessageHash: Authorize removing a compact slot.
    //
    // Use case:
    // - Type 1 stateless signature revokes a registered Type 2 compact lane.
    // - Revocation signs the same slotId shape with another operation tag.
    //
    // Preimage:
    //   OP_REVOKE_COMPACT_SLOT32 || HASH_SUITE_KECCAK_2564 ||
    //   domainSeparator32 || nonce32 || keyVersion32 || slotId32.
    function compactSlotRevocationMessageHash(
        ShrincsTypes.RotationContext memory context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal pure returns (bytes32) {
        return compactSlotUpdateMessageHash(ShrincsTypes.OP_REVOKE_COMPACT_SLOT, context, subPkSeed, subPkRoot);
    }

    // compactSlotUpdateMessageHash: Build a compact-slot update transcript.
    //
    // Important design choice:
    // - This signs slotId, not subPkSeed/subPkRoot separately.
    // - subPkSeed/subPkRoot remain function inputs only so slotId can be
    //   derived by the same code path the account uses for storage.
    //
    // Buffer layout:
    //   ptr+000: operation tag32
    //   ptr+032: HASH_SUITE_KECCAK_2564
    //   ptr+036: domainSeparator32
    //   ptr+068: nonce32
    //   ptr+100: keyVersion32
    //   ptr+132: slotId32
    //
    // Exact packed length: 32 + 4 + 3 * 32 + 32 = 164 bytes.
    function compactSlotUpdateMessageHash(
        bytes32 op,
        ShrincsTypes.RotationContext memory context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal pure returns (bytes32 out) {
        // Cache constants so assembly mirrors abi.encodePacked.
        uint32 suite = ShrincsTypes.HASH_SUITE_KECCAK_256;
        // Derive the JARDIN slot id from the compact public key.
        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        assembly {
            // Buffer layout is documented above this function.
            let ptr := mload(0x40)
            // Operation tag.
            mstore(ptr, op)
            // HASH_SUITE_KECCAK_256 as uint32 in abi.encodePacked form.
            mstore(add(ptr, 32), shl(224, suite))
            // Copy domainSeparator32 || nonce32 || keyVersion32.
            mcopy(add(ptr, 36), context, 96)
            // compactSlot = keccak256(subPkSeed || subPkRoot).
            mstore(add(ptr, 132), slotId)
            // Hash the exact packed preimage length.
            out := keccak256(ptr, 164)
            // Bump free memory past the rounded preimage.
            mstore(0x40, add(ptr, 192))
        }
    }

    // statelessActionMessageHash: Build a direct stateless action transcript.
    //
    // Use case:
    // - Direct action by the installed stateless key.
    // - Fallback/admin/high-value path when compact slot state is not used.
    // - Not used for key rotation; rotation has a separate operation tag and
    //   signs the replacement key fields explicitly.
    //
    // Preimage:
    //   OP_VERIFY_STATELESS32 || HASH_SUITE_KECCAK_2564 ||
    //   expectedPkSeed32 || expectedHypertreeRoot32 ||
    //   domainSeparator32 || nonce32 || keyVersion32 ||
    //   actionType32 || payloadHash32.
    //
    // 1. Bind the stateless operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed pkSeed/root.
    // 4. Bind the account-layer action context fields.
    function statelessActionMessageHash(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.ActionContext memory context
    ) internal pure returns (bytes32) {
        // Bind the installed key before action context so a signature cannot
        // be replayed after full stateless key rotation.
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_VERIFY_STATELESS,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
                expectedPkSeed,
                expectedHypertreeRoot,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    // fullRotationMessageHash: Build a stateless-key rotation transcript.
    //
    // Use case:
    // - Replace the installed pkSeed/hypertreeRoot pair.
    // - This is not a generic action transcript: it signs current and next
    //   public key material directly under OP_ROTATE_FULL.
    //
    // Preimage:
    //   OP_ROTATE_FULL32 || HASH_SUITE_KECCAK_2564 ||
    //   expectedPkSeed32 || expectedHypertreeRoot32 ||
    //   domainSeparator32 || nonce32 || keyVersion32 ||
    //   currentPkSeed || currentHypertreeRoot ||
    //   nextPkSeed || nextHypertreeRoot.
    //
    // 1. Bind the full-rotation operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed pkSeed/root.
    // 4. Bind the rotation context.
    // 5. Bind the current and next stateless public-key fields.
    function fullRotationMessageHash(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey memory currentPublicKey,
        ShrincsTypes.RotationContext memory context,
        ShrincsTypes.RotationTarget memory nextKey
    ) internal pure returns (bytes32) {
        // Bind both the expected installed key words and the current public
        // key object supplied to verification. This keeps the transcript tied
        // to the account's installed state and the concrete verifier input.
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_ROTATE_FULL,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
                expectedPkSeed,
                expectedHypertreeRoot,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.pkSeed,
                currentPublicKey.hypertreeRoot,
                nextKey.pkSeed,
                nextKey.hypertreeRoot
            )
        );
    }

    // verifyStatelessUncheckedMessage: Verify an already-built message.
    //
    // Use case:
    // - Low-level helper for non-action transcripts: compact slot updates and
    //   full key rotation.
    //
    // 1. Validate the current key bundle and fixed public-key layout.
    // 2. Reconstruct the FORS-C root from the signed message and proof.
    // 3. Carry that root up the hypertree and compare it to the public root.
    function verifyStatelessUncheckedMessage(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // The verifier input must match installed stateless key storage.
        if (!ShrincsUtils.matchesExpectedStatelessKey(publicKey, expectedPkSeed, expectedHypertreeRoot)) {
            return false;
        }

        // The current key must satisfy the fixed public-key shape.
        if (!ShrincsUtils.validPublicKey(publicKey)) return false;

        // A stateless signature must carry at least one hypertree layer.
        if (signature.hypertree.length == 0) return false;

        // Reconstruct the FORS root from message, randomness, and openings.
        (bytes32 forsRoot, bool ok) = ShrincsForsC.verifyForsCAndReturnRoot(
            publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
        );
        if (!ok) return false;

        // Carry the reconstructed FORS root up to the public root.
        return ShrincsHypertree.verifyHypertree(publicKey, forsRoot, signature.hypertree);
    }
}
