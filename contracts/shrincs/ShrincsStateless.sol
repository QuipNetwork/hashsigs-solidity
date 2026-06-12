// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsCodec} from "./ShrincsCodec.sol";
import {ShrincsCommitment} from "./ShrincsCommitment.sol";
import {ShrincsValidation} from "./ShrincsValidation.sol";
import {ShrincsFors} from "./ShrincsFors.sol";
import {ShrincsHypertree} from "./ShrincsHypertree.sol";

// Stateless verification orchestration: FORS-C reconstructs the message root,
// which then seeds the hypertree layer walk. Holds only the "how the pieces
// compose" logic; the primitives live in their own modules.
library ShrincsStateless {
    // Shared stateless verification core that accepts either calldata messages from
    // external callers or canonical in-memory rotation messages built by the
    // library.
    function verifyMemory(
        ShrincsType.ParameterSetId parameterSetId,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        return verifyRaw(
            parameterSetId,
            ShrincsCodec.compositePublicKeyWord(publicKey.compositePublicKey),
            publicKey,
            message,
            signature
        );
    }

    function verifyRaw(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        if (!ShrincsCommitment.matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        ShrincsType.ParamsView memory p = ShrincsValidation.paramsView(parameterSetId);
        if (!ShrincsValidation.validParams(p, publicKey)) return false;
        if (signature.hypertree.length == 0) return false;

        bytes memory messageRoot = ShrincsFors.verifyForsCAndReturnRoot(
            p, publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
        );
        if (messageRoot.length == 0) return false;
        return ShrincsHypertree.verifyHypertree(p, publicKey, messageRoot, signature.hypertree);
    }
}
