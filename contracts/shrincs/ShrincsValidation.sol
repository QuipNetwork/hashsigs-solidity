// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShrincsType} from "../ShrincsTypes.sol";
import {ShrincsCommitment} from "./ShrincsCommitment.sol";

// Parameter-set and action-context validation: the "are these inputs acceptable"
// failure domain, kept separate from commitment/layout checks.
library ShrincsValidation {
    // Resolve explicit params or fall back to the defaults registered in ShrincsType
    // for the selected parameter set and hash suite.
    function paramsView(ShrincsType.ParameterSetId parameterSetId)
        internal
        pure
        returns (ShrincsType.ParamsView memory)
    {
        return ShrincsType.defaultParamsView(parameterSetId);
    }

    // Enforce the parameter/profile invariants expected by this verifier and check
    // that the public key declares the same parameter-set identity.
    function validParams(ShrincsType.ParamsView memory params, ShrincsType.PublicKey calldata publicKey)
        internal
        pure
        returns (bool)
    {
        if (params.parameterSetId != ShrincsType.ParameterSetId.Sphincs256sKeccakQ20) return false;
        if (params.nBytes != 32) return false;
        if (params.parameterSetId != publicKey.parameterSetId) return false;
        if (params.h != 64 || params.d != 8 || params.a != 14) return false;
        if (params.k != 22 || params.w != 16 || params.l != 64) return false;
        if (params.wotsTargetSum != ShrincsType.WOTS_TARGET_SUM_STATEFUL) return false;
        if (!ShrincsCommitment.validStatefulCompositePublicKey(publicKey)) return false;
        if (uint256(params.k) * (uint256(1) << params.a) > type(uint32).max) return false;
        return true;
    }

    function validParameterSetBinding(
        ShrincsType.ParamsView memory params,
        ShrincsType.ParameterSetId requestedParameterSetId,
        ShrincsType.ParameterSetId declaredParameterSetId
    ) internal pure returns (bool) {
        return params.parameterSetId == requestedParameterSetId && declaredParameterSetId == requestedParameterSetId
            && params.hashSuiteId == ShrincsType.HASH_SUITE_KECCAK_256;
    }

    function validActionContext(ShrincsType.ActionContext memory context) internal pure returns (bool) {
        return
            context.domainSeparator != bytes32(0) && context.actionType != bytes32(0)
                && context.payloadHash != bytes32(0);
    }

    function validRotationContext(ShrincsType.RotationContext memory context) internal pure returns (bool) {
        return context.domainSeparator != bytes32(0);
    }
}
