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

import { SHRINCS } from "../SHRINCS.sol";
import { ShrincsTypes } from "../ShrincsTypes.sol";

contract ShrincsAccountVerifierExample {
    enum StatefulPolicy {
        None,
        MonotonicIndex,
        RecoveryRotation,
        LeafBitmap
    }

    bytes32 public currentShrincsPublicKey;
    address public owner;
    ShrincsTypes.ParameterSetId public parameterSetId;
    uint256 public nonce;
    uint256 public keyVersion;
    uint64 public statelessSignaturesUsed;
    StatefulPolicy public statefulPolicy;
    uint32 public nextStatefulLeafIndex;
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

    constructor(bytes32 initialShrincsPublicKey) {
        owner = msg.sender;
        currentShrincsPublicKey = initialShrincsPublicKey;
        parameterSetId = ShrincsTypes.ParameterSetId.Sphincs256sKeccakQ20;
    }

    function verifyStatefulRaw(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) external returns (bool) {
        // Low-level wrapper path. This verifies a caller-provided message directly and does not
        // advance nonce or build a canonical action hash. Callers must handle replay protection,
        // domain separation, and payload binding themselves. Prefer verifyStatefulAction(...).
        uint32 leafIndex = uint32(signature.authPath.length);
        if (!_precheckStatefulLeafUse(leafIndex)) return false;

        bool ok = SHRINCS.verifyStatefulUnsafeRaw(
            parameterSetId, currentShrincsPublicKey, publicKey, message, signature
        );
        if (!ok) return false;

        _commitStatefulLeafUse(leafIndex);
        emit StatefulSignatureVerified(leafIndex, nonce, keyVersion);
        return true;
    }

    function verifyStatefulAction(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatefulSignature calldata signature
    ) external returns (bool) {
        uint32 leafIndex = uint32(signature.authPath.length);
        if (!_precheckStatefulLeafUse(leafIndex)) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: _domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        bool ok = SHRINCS.verifyStateful(
            parameterSetId,
            currentShrincsPublicKey,
            publicKey,
            context,
            signature
        );
        if (!ok) return false;

        _commitStatefulLeafUse(leafIndex);
        emit StatefulSignatureVerified(leafIndex, nonce, keyVersion);
        nonce += 1;
        return true;
    }

    function verifyStatelessRaw(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external returns (bool) {
        // Low-level wrapper path. This verifies a caller-provided message directly and does not
        // advance nonce or build a canonical action hash. Callers must handle replay protection,
        // domain separation, and payload binding themselves. Prefer verifyStatelessAction(...).
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && !recoveryMode) return false;
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        bool ok = SHRINCS.verifyStatelessUnsafeRaw(
            parameterSetId, currentShrincsPublicKey, publicKey, message, signature
        );
        if (!ok) return false;

        statelessSignaturesUsed += 1;
        emit StatelessSignatureVerified(statelessSignaturesUsed, nonce, keyVersion);
        return true;
    }

    function verifyStatelessAction(
        ShrincsTypes.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsTypes.StatelessSignature calldata signature
    ) external returns (bool) {
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && !recoveryMode) return false;
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        ShrincsTypes.ActionContext memory context = ShrincsTypes.ActionContext({
            domainSeparator: _domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        bool ok = SHRINCS.verifyStateless(
            parameterSetId,
            currentShrincsPublicKey,
            publicKey,
            context,
            signature
        );
        if (!ok) return false;

        nonce += 1;
        statelessSignaturesUsed += 1;
        emit StatelessSignatureVerified(statelessSignaturesUsed, nonce - 1, keyVersion);
        return true;
    }

    function rotateToFreshKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external returns (bool) {
        if (statefulPolicy != StatefulPolicy.RecoveryRotation || !recoveryMode) return false;
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        ShrincsTypes.RotationContext memory context = ShrincsTypes.RotationContext({
            domainSeparator: _domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion
        });

        bytes32 nextCompositePublicKey = SHRINCS.statelessRotate(
            parameterSetId,
            currentShrincsPublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        _installFreshKey(nextCompositePublicKey, nextKey.parameterSetId);
        return true;
    }

    function rotateFullKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external returns (bool) {
        uint64 limit = ShrincsTypes.defaultParamsView(parameterSetId).statelessSignatureLimit;
        if (statelessSignaturesUsed >= limit) return false;

        ShrincsTypes.RotationContext memory context = ShrincsTypes.RotationContext({
            domainSeparator: _domainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion
        });

        bytes32 nextCompositePublicKey = SHRINCS.statelessRotate(
            parameterSetId,
            currentShrincsPublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        _installFreshKey(nextCompositePublicKey, nextKey.parameterSetId);
        return true;
    }

    function isLeafUsed(uint32 leafIndex) public view returns (bool) {
        uint256 wordIndex = uint256(leafIndex) >> 8;
        uint256 bitIndex = uint256(leafIndex) & 0xff;
        return (usedLeafBitmap[keyVersion][wordIndex] & (uint256(1) << bitIndex)) != 0;
    }

    function setStatefulPolicyNone() external onlyOwner {
        statefulPolicy = StatefulPolicy.None;
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    function setStatefulPolicyMonotonicIndex(uint32 initialLeafIndex) external onlyOwner {
        require(initialLeafIndex >= nextStatefulLeafIndex, "stateful index rollback");
        statefulPolicy = StatefulPolicy.MonotonicIndex;
        nextStatefulLeafIndex = initialLeafIndex;
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    function setStatefulPolicyRecoveryRotation() external onlyOwner {
        statefulPolicy = StatefulPolicy.RecoveryRotation;
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    function setStatefulPolicyLeafBitmap() external onlyOwner {
        statefulPolicy = StatefulPolicy.LeafBitmap;
        recoveryMode = false;
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }

    function enterRecoveryMode() external onlyOwner {
        require(statefulPolicy == StatefulPolicy.RecoveryRotation, "recovery policy required");
        recoveryMode = true;
        emit RecoveryModeEntered(keyVersion);
    }

    function _precheckStatefulLeafUse(uint32 leafIndex) internal view returns (bool) {
        if (statefulPolicy == StatefulPolicy.RecoveryRotation && recoveryMode) return false;
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) return leafIndex == nextStatefulLeafIndex;
        if (statefulPolicy == StatefulPolicy.LeafBitmap) return !isLeafUsed(leafIndex);
        return true;
    }

    function _commitStatefulLeafUse(uint32 leafIndex) internal {
        if (statefulPolicy == StatefulPolicy.MonotonicIndex) {
            nextStatefulLeafIndex += 1;
            return;
        }
        if (statefulPolicy == StatefulPolicy.LeafBitmap) {
            uint256 wordIndex = uint256(leafIndex) >> 8;
            uint256 bitIndex = uint256(leafIndex) & 0xff;
            usedLeafBitmap[keyVersion][wordIndex] |= uint256(1) << bitIndex;
        }
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, address(this)));
    }

    function _installFreshKey(
        bytes32 nextCompositePublicKey,
        ShrincsTypes.ParameterSetId nextParameterSetId
    ) internal {
        bytes32 previousShrincsPublicKey = currentShrincsPublicKey;
        currentShrincsPublicKey = nextCompositePublicKey;
        parameterSetId = nextParameterSetId;
        nonce += 1;
        keyVersion += 1;
        statelessSignaturesUsed = 0;
        nextStatefulLeafIndex = 0;
        statefulPolicy = StatefulPolicy.None;
        recoveryMode = false;
        emit KeyRotated(previousShrincsPublicKey, nextCompositePublicKey, nextParameterSetId, keyVersion);
        emit StatefulPolicySet(statefulPolicy, nextStatefulLeafIndex);
    }
}
