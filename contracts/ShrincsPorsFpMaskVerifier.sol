// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessHypertree } from "./ShrincsStatelessHypertree.sol";
import { ShrincsStatelessPorsFp } from "./ShrincsStatelessPorsFp.sol";

contract ShrincsPorsFpMaskVerifier is ShrincsStatelessPorsFp, ShrincsStatelessHypertree {
    function verify(
        VariantParams calldata params,
        PublicKey calldata publicKey,
        bytes calldata message,
        StatelessSignature calldata signature
    ) external pure returns (bool) {
        ParamsView memory p = variantParamsView(params, MODE_PORS_FP, true);
        if (!validParams(p, publicKey)) return false;

        if (signature.hypertree.length == 0) return false;
        bytes memory messageRoot = verifyPorsFpAndReturnRoot(
            p, publicKey, message, signature.pors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
        );
        if (messageRoot.length == 0) return false;

        return verifyHypertree(p, publicKey, messageRoot, signature.hypertree);
    }
}
