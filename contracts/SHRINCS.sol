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

library SHRINCS {
    // verifyStateless: Verify a stateless SHRINCS action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical stateless action hash from installed pkSeed/root and action context.
    // 3. Verify FORS-C and then carry the reconstructed root up the hypertree to the public root.
    function verifyStateless(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.ActionContext memory context,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!ShrincsUtils.validActionContext(context)) return false;
        // Canonical stateless verification signs the typed action context hash, not
        // arbitrary caller-provided bytes.
        bytes memory message =
            abi.encodePacked(statelessActionMessageHash(expectedPkSeed, expectedHypertreeRoot, context));
        // Delegate FORS-C plus hypertree verification to the lower-level helper.
        return verifyStatelessUncheckedMessage(expectedPkSeed, expectedHypertreeRoot, publicKey, message, signature);
    }

    // verifyCompact: Verify a JARDIN-style compact Type 2 action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical compact action hash from the account action context.
    // 3. Verify the raw compact FORS-C signature and balanced Merkle path.
    function verifyCompact(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        ShrincsTypes.ActionContext memory context,
        bytes calldata signature
    ) internal pure returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!ShrincsUtils.validActionContext(context)) return false;
        // Build the canonical compact action hash. Slot authorization is an account-layer check.
        bytes32 message = compactActionMessageHash(context);
        // Delegate the JARDIN/FIPS raw compact signature equation to ShrincsCompact.
        return verifyCompactUncheckedMessage(subPkSeed, subPkRoot, message, signature);
    }

    // statelessRotate: Authorize replacing the stateless pkSeed/root via a stateless recovery signature.
    // 1. Validate the current key bundle, rotation context, and full next-key payload.
    // 2. Build the canonical full-rotation message hash.
    // 3. Verify the stateless recovery signature over that hash under the current installed key.
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
        // The current public key must match the installed stateless key the caller expects.
        if (!ShrincsUtils.matchesExpectedStatelessKey(currentPublicKey, expectedPkSeed, expectedHypertreeRoot)) {
            return false;
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!ShrincsUtils.validRotationContext(context)) return false;
        // The replacement key must contain fixed-width seed and root fields.
        if (nextKey.pkSeed.length != 32) return false;
        if (nextKey.hypertreeRoot.length != 32) return false;

        // Bind the current installed stateless key, rotation context, and replacement key
        // into one canonical recovery message.
        bytes memory recoveryMessage = abi.encodePacked(
            fullRotationMessageHash(expectedPkSeed, expectedHypertreeRoot, currentPublicKey, context, nextKey)
        );
        // The stateless recovery signature must authorize exactly that canonical full rotation.
        if (!verifyStatelessUncheckedMessage(
                expectedPkSeed, expectedHypertreeRoot, currentPublicKey, recoveryMessage, recoverySignature
            )) {
            return false;
        }
        return true;
    }

    // verifyCompactUncheckedMessage: Verify a compact signature over an already-built message hash.
    // 1. Treat the supplied bytes32 as the final account/action message hash.
    // 2. Delegate raw JARDIN Type 2 verification to the compact component library.
    function verifyCompactUncheckedMessage(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 message,
        bytes calldata signature
    ) internal pure returns (bool) {
        // The component library owns raw FORS-C and balanced Merkle verification.
        return ShrincsCompact.verifyCompactRaw(subPkSeed, subPkRoot, message, signature);
    }

    // compactActionMessageHash: Build the canonical compact Type 2 action message hash.
    // Preimage:
    //   OP_VERIFY_COMPACT32 || HASH_SUITE_KECCAK_2564 ||
    //   domainSeparator32 || nonce32 || keyVersion32 || actionType32 || payloadHash32.
    // The compact verifier then uses this 32-byte result as JARDIN message32 inside:
    //   H_msg(R32, subPkSeed32, subPkRoot32, counter4 || TYPE2 || subPkSeed32 || subPkRoot32 || q1 || message32).
    // 1. Bind the compact operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the account-layer action context fields.
    function compactActionMessageHash(ShrincsTypes.ActionContext memory context) internal pure returns (bytes32 out) {
        return compactActionMessageHash(
            context.domainSeparator, context.nonce, context.keyVersion, context.actionType, context.payloadHash
        );
    }

    // compactActionMessageHash: Build compact Type 2 action hash from fields.
    function compactActionMessageHash(
        bytes32 domainSeparator,
        uint256 nonce,
        uint256 keyVersion,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal pure returns (bytes32 out) {
        // Cache constants so the assembly preimage stays close to abi.encodePacked semantics.
        bytes32 op = ShrincsTypes.OP_VERIFY_COMPACT;
        uint32 suite = ShrincsTypes.HASH_SUITE_KECCAK_256;
        assembly {
            // Allocate one fixed-size hash preimage.
            let ptr := mload(0x40)
            // OP_VERIFY_COMPACT.
            mstore(ptr, op)
            // HASH_SUITE_KECCAK_256 as uint32 in abi.encodePacked form.
            mstore(add(ptr, 32), shl(224, suite))
            // Write domainSeparator32 || nonce32 || keyVersion32 || actionType32 || payloadHash32.
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
    // Preimage: subPkSeed32 || subPkRoot32.
    // slotId = keccak256(subPkSeed32 || subPkRoot32).
    function compactSlotId(bytes32 subPkSeed, bytes32 subPkRoot) internal pure returns (bytes32 out) {
        assembly {
            // Use transient free-memory scratch for the two-word slot key.
            let ptr := mload(0x40)
            // Store subPkSeed.
            mstore(ptr, subPkSeed)
            // Store subPkRoot.
            mstore(add(ptr, 32), subPkRoot)
            // Hash the packed slot key.
            out := keccak256(ptr, 64)
        }
    }

    // compactSlotRegistrationMessageHash: Build the stateless authorization hash for slot registration.
    // Preimage:
    //   OP_REGISTER_COMPACT_SLOT32 || HASH_SUITE_KECCAK_2564 ||
    //   domainSeparator32 || nonce32 || keyVersion32 || slotId32 || subPkSeed32 || subPkRoot32.
    function compactSlotRegistrationMessageHash(
        ShrincsTypes.RotationContext memory context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal pure returns (bytes32) {
        return compactSlotUpdateMessageHash(ShrincsTypes.OP_REGISTER_COMPACT_SLOT, context, subPkSeed, subPkRoot);
    }

    // compactSlotRevocationMessageHash: Build the stateless authorization hash for slot revocation.
    // Preimage:
    //   OP_REVOKE_COMPACT_SLOT32 || HASH_SUITE_KECCAK_2564 ||
    //   domainSeparator32 || nonce32 || keyVersion32 || slotId32 || subPkSeed32 || subPkRoot32.
    function compactSlotRevocationMessageHash(
        ShrincsTypes.RotationContext memory context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal pure returns (bytes32) {
        return compactSlotUpdateMessageHash(ShrincsTypes.OP_REVOKE_COMPACT_SLOT, context, subPkSeed, subPkRoot);
    }

    // compactSlotUpdateMessageHash: Build a compact-slot update hash with the supplied operation tag.
    function compactSlotUpdateMessageHash(
        bytes32 op,
        ShrincsTypes.RotationContext memory context,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal pure returns (bytes32 out) {
        // Cache constants so the assembly preimage stays close to abi.encodePacked semantics.
        uint32 suite = ShrincsTypes.HASH_SUITE_KECCAK_256;
        // Derive the slot id from the exact compact public key being authorized.
        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        assembly {
            // Allocate one fixed-size hash preimage.
            let ptr := mload(0x40)
            // Operation tag.
            mstore(ptr, op)
            // HASH_SUITE_KECCAK_256 as uint32 in abi.encodePacked form.
            mstore(add(ptr, 32), shl(224, suite))
            // Copy domainSeparator32 || nonce32 || keyVersion32.
            mcopy(add(ptr, 36), context, 96)
            // compactSlot = keccak256(subPkSeed || subPkRoot).
            mstore(add(ptr, 132), slotId)
            // Compact public seed.
            mstore(add(ptr, 164), subPkSeed)
            // Compact public root.
            mstore(add(ptr, 196), subPkRoot)
            // Hash the exact packed preimage length.
            out := keccak256(ptr, 228)
            // Bump free memory past the rounded preimage.
            mstore(0x40, add(ptr, 256))
        }
    }

    // statelessActionMessageHash: Build the canonical stateless action message hash.
    // 1. Bind the stateless operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed pkSeed/root.
    // 4. Bind the account-layer action context fields.
    function statelessActionMessageHash(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed key
        // words, and the account-layer action context for the stateless path.
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

    // fullRotationMessageHash: Build the canonical message hash authorizing a full next-key bundle.
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
        // The canonical full-rotation hash binds an operation tag, hash suite,
        // installed key commitment, rotation context, and both the current and next bundle ids.
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

    // verifyStatelessUncheckedMessage: Verify a stateless signature after the caller has already
    // constructed the exact signed message bytes.
    // 1. Validate the current key bundle and fixed public-key layout.
    // 2. Reconstruct the FORS-C root from the signed message bytes and FORS proof.
    // 3. Carry that root up the hypertree and compare it to the public root.
    function verifyStatelessUncheckedMessage(
        bytes32 expectedPkSeed,
        bytes32 expectedHypertreeRoot,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        // The current public key must match the installed stateless key expected by the caller.
        if (!ShrincsUtils.matchesExpectedStatelessKey(publicKey, expectedPkSeed, expectedHypertreeRoot)) return false;
        // The current key bundle must satisfy the compiled fixed public-key shape.
        if (!ShrincsUtils.validPublicKey(publicKey)) return false;
        // A stateless signature must carry at least one hypertree layer.
        if (signature.hypertree.length == 0) return false;

        // Reconstruct the FORS root from the message, FORS randomness/counter, and revealed leaves.
        (bytes32 forsRoot, bool ok) = ShrincsForsC.verifyForsCAndReturnRoot(
            publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
        );
        if (!ok) return false;
        // Carry the reconstructed FORS root up the hypertree until it matches the public root.
        return ShrincsHypertree.verifyHypertree(publicKey, forsRoot, signature.hypertree);
    }
}
