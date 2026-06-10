// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessForsC } from "./ShrincsStatelessForsC.sol";
import { ShrincsStatelessHypertree } from "./ShrincsStatelessHypertree.sol";
import { ShrincsStatelessPorsFp } from "./ShrincsStatelessPorsFp.sol";

contract ShrincsStatelessPathVerifier is ShrincsStatelessForsC, ShrincsStatelessPorsFp, ShrincsStatelessHypertree {
    function verify(Params calldata params, PublicKey calldata publicKey, bytes calldata message, StatelessSignature calldata signature)
        external
        pure
        virtual
        returns (bool)
    {
        ParamsView memory p = paramsView(params);
        if (!validParams(p, publicKey)) return false;

        bytes memory messageRoot;
        if (p.mode == MODE_FORS_C) {
            if (signature.hypertree.length == 0) return false;
            messageRoot = verifyForsCAndReturnRoot(
                p, publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
            );
        } else if (p.mode == MODE_PORS_FP) {
            if (signature.hypertree.length == 0) return false;
            messageRoot = verifyPorsFpAndReturnRoot(
                p, publicKey, message, signature.pors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
            );
        } else {
            return false;
        }
        if (messageRoot.length == 0) return false;

        return verifyHypertree(p, publicKey, messageRoot, signature.hypertree);
    }
}
