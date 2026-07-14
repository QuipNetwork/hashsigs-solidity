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

// ShrincsAccountVerifierExample: Example stateless + compact account wrapper for SHRINCS.
//
// The wrapper demonstrates nonce/key-version binding, stateless signature accounting,
// full stateless key rotation, ERC-1271, and JARDIN-style compact slots.
contract ShrincsAccountVerifierExample {
    // ERC-1271 success return value.
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    // Any non-magic value denotes signature failure.
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    // Kept stable for existing stateless envelopes after removing mode 1.
    uint8 internal constant ERC1271_MODE_STATELESS_ACTION = 2;
    // Envelope mode selecting canonical compact account-action validation.
    uint8 internal constant ERC1271_MODE_COMPACT_ACTION = 3;

    // Installed stateless SPHINCS public seed currently trusted by the wrapper.
    bytes32 public currentPkSeed;
    // Installed stateless SPHINCS hypertree root currently trusted by the wrapper.
    bytes32 public currentHypertreeRoot;
    // Canonical action/rotation nonce consumed on successful wrapper operations.
    uint256 public nonce;
    // Installed-key epoch incremented whenever a fresh key bundle is installed.
    uint256 public keyVersion;
    // Number of stateless signatures consumed under the current installed key.
    uint64 public statelessSignaturesUsed;

    mapping(bytes32 slotId => bool registered) public compactSlots;

    bytes32 internal constant DOMAIN_TAG = keccak256("shrincs-account-v1");

    event KeyRotated(
        bytes32 indexed previousPkSeed,
        bytes32 indexed previousHypertreeRoot,
        bytes32 indexed nextPkSeed,
        bytes32 nextHypertreeRoot,
        uint256 nextKeyVersion
    );
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
        bytes32 indexed nextPkSeed,
        bytes32 nextHypertreeRoot,
        bool fullRotation
    );

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    // constructor: Install the initial stateless pkSeed/root pair.
    constructor(bytes32 initialPkSeed, bytes32 initialHypertreeRoot) {
        currentPkSeed = initialPkSeed;
        currentHypertreeRoot = initialHypertreeRoot;
    }

    // isValidSignature: ERC-1271 compatibility view for canonical SHRINCS account-action signatures.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length < 1) return INVALID_SIGNATURE;

        uint8 mode = uint8(signature[0]);
        bytes calldata payload = signature[1:];

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

    // decodeAndCheckStateless1271Envelope: Self-call decoder for stateless ERC-1271 envelopes.
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

    // verifyStatelessAction: Canonical stateless account-action verification path.
    function verifyStatelessAction(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external returns (bool) {
        if (statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        bool ok = SHRINCS.verifyStateless(currentPkSeed, currentHypertreeRoot, publicKey, context, signature);
        if (!ok) return false;

        nonce += 1;
        statelessSignaturesUsed += 1;
        emit StatelessSignatureVerified(statelessSignaturesUsed, nonce - 1, keyVersion);
        return true;
    }

    // verifyCompactAction: Canonical compact account-action verification path.
    function verifyCompactAction(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 actionType,
        bytes32 payloadHash,
        bytes calldata signature
    ) external returns (bool) {
        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        if (!compactSlots[slotId]) return false;
        if (actionType == bytes32(0)) return false;
        if (payloadHash == bytes32(0)) return false;

        uint256 currentNonce = nonce;
        uint256 currentKeyVersion = keyVersion;
        bytes32 message = SHRINCS.compactActionMessageHash(
            domainSeparator(), currentNonce, currentKeyVersion, actionType, payloadHash
        );

        bool ok = SHRINCS.verifyCompactUncheckedMessage(subPkSeed, subPkRoot, message, signature);
        if (!ok) return false;

        emit CompactSignatureVerified(slotId, currentNonce, currentKeyVersion);
        nonce = currentNonce + 1;
        return true;
    }

    // registerCompactSlot: Authorize a compact Type 2 lane with a stateless signature.
    function registerCompactSlot(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) external returns (bool) {
        return updateCompactSlot(publicKey, signature, subPkSeed, subPkRoot, true);
    }

    // revokeCompactSlot: Revoke a compact Type 2 lane with a stateless signature.
    function revokeCompactSlot(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) external returns (bool) {
        return updateCompactSlot(publicKey, signature, subPkSeed, subPkRoot, false);
    }

    // rotateFullKey: Replace the installed SHRINCS key bundle with stateless authorization.
    function rotateFullKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external returns (bool) {
        if (statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT) return false;

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});

        bool ok = SHRINCS.statelessRotate(
            currentPkSeed, currentHypertreeRoot, currentPublicKey, context, recoverySignature, nextKey
        );
        if (!ok) return false;

        bytes32 nextPkSeed;
        bytes32 nextHypertreeRoot;
        bytes calldata encodedNextPkSeed = nextKey.pkSeed;
        bytes calldata encodedNextHypertreeRoot = nextKey.hypertreeRoot;
        assembly {
            nextPkSeed := calldataload(encodedNextPkSeed.offset)
            nextHypertreeRoot := calldataload(encodedNextHypertreeRoot.offset)
        }
        consumeStatelessRotationUse(nextPkSeed, nextHypertreeRoot, true);
        installFreshFullKey(nextPkSeed, nextHypertreeRoot);
        return true;
    }

    // compactSlotId: Derive the persistent compact slot key.
    function compactSlotId(bytes32 subPkSeed, bytes32 subPkRoot) public pure returns (bytes32) {
        return SHRINCS.compactSlotId(subPkSeed, subPkRoot);
    }

    // isValidStatelessActionSignatureNow: Read-only self-call helper for canonical stateless action verification.
    function isValidStatelessActionSignatureNow(
        bytes32 hash,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external view onlySelf returns (bool) {
        if (statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        if (SHRINCS.statelessActionMessageHash(currentPkSeed, currentHypertreeRoot, context) != hash) return false;
        return SHRINCS.verifyStateless(currentPkSeed, currentHypertreeRoot, publicKey, context, signature);
    }

    // isValidCompactActionSignatureNow: Read-only self-call helper for canonical compact action verification.
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
        if (actionType == bytes32(0)) return false;
        if (payloadHash == bytes32(0)) return false;

        bytes32 message =
            SHRINCS.compactActionMessageHash(domainSeparator(), nonce, keyVersion, actionType, payloadHash);
        if (message != hash) return false;
        return SHRINCS.verifyCompactUncheckedMessage(subPkSeed, subPkRoot, message, signature);
    }

    // consumeStatelessRotationUse: Record one successful stateless signature used for rotation.
    function consumeStatelessRotationUse(bytes32 nextPkSeed, bytes32 nextHypertreeRoot, bool fullRotation) internal {
        statelessSignaturesUsed += 1;
        emit StatelessRotationConsumed(
            statelessSignaturesUsed, nonce, keyVersion, nextPkSeed, nextHypertreeRoot, fullRotation
        );
    }

    // updateCompactSlot: Verify a stateless slot update and write the compactSlots flag.
    function updateCompactSlot(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatelessSignature calldata signature,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bool registered
    ) internal returns (bool) {
        if (statelessSignaturesUsed >= ShrincsTypes.STATELESS_SIGNATURE_LIMIT) return false;

        bytes32 slotId = compactSlotId(subPkSeed, subPkRoot);
        if (compactSlots[slotId] == registered) return false;

        ShrincsTypes.RotationContext memory context =
            ShrincsTypes.RotationContext({domainSeparator: domainSeparator(), nonce: nonce, keyVersion: keyVersion});
        bytes32 message = registered
            ? SHRINCS.compactSlotRegistrationMessageHash(context, subPkSeed, subPkRoot)
            : SHRINCS.compactSlotRevocationMessageHash(context, subPkSeed, subPkRoot);

        bool ok = SHRINCS.verifyStatelessUncheckedMessage(
            currentPkSeed, currentHypertreeRoot, publicKey, abi.encodePacked(message), signature
        );
        if (!ok) return false;

        compactSlots[slotId] = registered;
        statelessSignaturesUsed += 1;
        if (registered) {
            emit CompactSlotRegistered(slotId, subPkSeed, subPkRoot, nonce, keyVersion);
        } else {
            emit CompactSlotRevoked(slotId, subPkSeed, subPkRoot, nonce, keyVersion);
        }
        nonce += 1;
        return true;
    }

    // domainSeparator: Derive the wrapper's canonical signing domain.
    function domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, address(this)));
    }

    // installRotatedKey: Install a rotated stateless key and reset wrapper state for the next epoch.
    function installRotatedKey(bytes32 nextPkSeed, bytes32 nextHypertreeRoot, bool resetStatelessUsage) internal {
        bytes32 previousPkSeed = currentPkSeed;
        bytes32 previousHypertreeRoot = currentHypertreeRoot;
        currentPkSeed = nextPkSeed;
        currentHypertreeRoot = nextHypertreeRoot;
        nonce += 1;
        keyVersion += 1;
        if (resetStatelessUsage) {
            statelessSignaturesUsed = 0;
        }
        emit KeyRotated(previousPkSeed, previousHypertreeRoot, nextPkSeed, nextHypertreeRoot, keyVersion);
    }

    // installFreshFullKey: Install a fully fresh SHRINCS bundle for the next key epoch.
    function installFreshFullKey(bytes32 nextPkSeed, bytes32 nextHypertreeRoot) internal {
        installRotatedKey(nextPkSeed, nextHypertreeRoot, true);
    }

    // installFreshKey: Backward-compatible alias for the full fresh-key install path.
    function installFreshKey(bytes32 nextPkSeed, bytes32 nextHypertreeRoot) internal {
        installFreshFullKey(nextPkSeed, nextHypertreeRoot);
    }
}
