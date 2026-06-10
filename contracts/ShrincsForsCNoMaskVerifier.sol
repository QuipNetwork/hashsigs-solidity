// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessForsC } from './ShrincsStatelessForsC.sol';
import { ShrincsStatelessHypertree } from './ShrincsStatelessHypertree.sol';

contract ShrincsForsCNoMaskVerifier is ShrincsStatelessForsC, ShrincsStatelessHypertree {
    function verify(
        VariantParams calldata params,
        PublicKey calldata publicKey,
        bytes calldata message,
        StatelessSignature calldata signature
    ) external pure returns (bool) {
        ParamsView memory p = variantParamsView(params, MODE_FORS_C, false); // false for no mask
        if (!validParams(p, publicKey)) return false;

        if (signature.hypertree.length == 0) return false;
        bytes memory messageRoot = verifyForsCAndReturnRoot(p, publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex);
        if (messageRoot.length == 0) return false;

        return verifyHypertree(p, publicKey, messageRoot, signature.hypertree);
    }
}
