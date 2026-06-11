// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatefulPathVerifier } from "./ShrincsStatefulPathVerifier.sol";
import { ShrincsType } from "./ShrincsType.sol";

library SHRINCS {
    error NotImplemented(string step);

    // Stateful path:
    // 1. Validate the composite SHRINCS public key.
    // 2. Decode the stateful public-key payload.
    // 3. Verify WOTS-C reconstruction and the XMSS authentication path.
    function verifyStateful(
        ShrincsType.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsStatefulPathVerifier.Signature calldata signature
    ) internal pure returns (bool) {
        publicKey;
        message;
        signature;
        revert NotImplemented("verifyStateful");
    }

    // Stateless path:
    // 1. Validate the parameter set and composite SHRINCS public key.
    // 2. Verify FORS/FORS-C and recover the message root.
    // 3. Verify the hypertree layers and compare the final root.
    function verifyStateless(
        ShrincsType.Params calldata params,
        ShrincsType.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        params;
        publicKey;
        message;
        signature;
        revert NotImplemented("verifyStateless");
    }

    // Stateful-key rotation via the stateless recovery path:
    // 1. Verify a stateless recovery signature under the current SHRINCS key.
    // 2. Bind the signed payload to a fresh next stateful key.
    // 3. Return the next stateful-key commitment / payload expected by the caller.
    function rotateStatefulViaStateless(
        ShrincsType.Params calldata params,
        ShrincsType.PublicKey calldata currentPublicKey,
        bytes calldata recoveryMessage,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32 nextStatefulKeyCommitment) {
        params;
        currentPublicKey;
        recoveryMessage;
        recoverySignature;
        nextStatefulKey;
        revert NotImplemented("rotateStatefulViaStateless");
    }

    // Full SHRINCS key rotation:
    // 1. Verify a stateless recovery signature under the current SHRINCS key.
    // 2. Bind the signed payload to a fresh next SHRINCS key bundle.
    // 3. Return the next composite public key expected by the caller.
    function rotateFullShrincsKey(
        ShrincsType.Params calldata params,
        ShrincsType.PublicKey calldata currentPublicKey,
        bytes calldata recoveryMessage,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) internal pure returns (bytes32 nextCompositePublicKey) {
        params;
        currentPublicKey;
        recoveryMessage;
        recoverySignature;
        nextKey;
        revert NotImplemented("rotateShrincsKey");
    }

    // Optional single entry point if the integrating contract wants to route both
    // verification paths through one ABI.
    function verify(
        ShrincsType.VerificationPath path,
        bytes calldata encodedRequest
    ) internal pure returns (bool) {
        path;
        encodedRequest;
        revert NotImplemented("verify");
    }
}
