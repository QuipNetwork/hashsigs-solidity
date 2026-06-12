// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";

// Composite SHRINCS public-key commitment and layout validation. Answers two
// questions kept distinct from parameter/context validation: is the public key
// well-formed, and does it hash to the commitment it claims.
library ShrincsCommitment {
    // Recompute the composite SHRINCS public-key commitment from one stateful key
    // and the fixed stateless public components.
    function compositePublicKeyCommitment(
        bytes calldata statefulPublicKey,
        bytes calldata messagePkSeed,
        bytes calldata messageRoot,
        bytes calldata hypertreePkSeed,
        bytes calldata hypertreeRoot
    ) internal pure returns (bytes32 computed) {
        uint256 statefulPkLen = ShrincsType.STATEFUL_PUBLIC_KEY_BYTES;
        uint256 compositeInputLen = 18 + statefulPkLen + 32 + 32 + 32 + 32;

        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "shrincs-public-key")
            calldatacopy(add(ptr, 18), statefulPublicKey.offset, statefulPkLen)
            calldatacopy(add(ptr, add(18, statefulPkLen)), messagePkSeed.offset, 32)
            calldatacopy(add(ptr, add(50, statefulPkLen)), messageRoot.offset, 32)
            calldatacopy(add(ptr, add(82, statefulPkLen)), hypertreePkSeed.offset, 32)
            calldatacopy(add(ptr, add(114, statefulPkLen)), hypertreeRoot.offset, 32)
            computed := keccak256(ptr, compositeInputLen)
            mstore(0x40, add(ptr, 224))
        }
    }

    // Check the composite public-key layout and recompute its commitment from the
    // embedded stateful and stateless public components.
    function validStatefulCompositePublicKey(ShrincsType.PublicKey calldata publicKey) internal pure returns (bool) {
        if (publicKey.compositePublicKey.length != 32) return false;
        if (publicKey.statefulPublicKey.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES) return false;
        if (publicKey.messagePkSeed.length != 32) return false;
        if (publicKey.messageRoot.length != 32) return false;
        if (publicKey.hypertreePkSeed.length != 32) return false;
        if (publicKey.hypertreeRoot.length != 32) return false;

        bytes32 expected;
        bytes calldata compositePublicKey = publicKey.compositePublicKey;
        assembly {
            expected := calldataload(compositePublicKey.offset)
        }
        return compositePublicKeyCommitment(
            publicKey.statefulPublicKey,
            publicKey.messagePkSeed,
            publicKey.messageRoot,
            publicKey.hypertreePkSeed,
            publicKey.hypertreeRoot
        ) == expected;
    }

    function matchesExpectedCompositePublicKey(
        ShrincsType.PublicKey calldata publicKey,
        bytes32 expectedCompositePublicKey
    ) internal pure returns (bool) {
        if (expectedCompositePublicKey == bytes32(0)) return false;
        return ShrincsCodec.compositePublicKeyWord(publicKey.compositePublicKey) == expectedCompositePublicKey;
    }
}
