// Copyright (C) 2026 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../../contracts/SPHINCSPlusC.sol";

/// @dev Test-only encoding and address-layout oracles. These helpers keep
/// explicit cross-checks for the production calldata re-tags without adding
/// unused functions to production libraries.
library SHRINCSTestCodec {
    function encodeStatefulEnvelope(
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.Signature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    function encodeStatelessEnvelope(
        SHRINCS.PublicKey memory publicKey,
        SPHINCSPlusC.Signature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    function addressWord32(
        uint32 layer,
        uint64 tree,
        uint32 addressType,
        uint32 keypair,
        uint32 chain,
        uint32 step
    ) internal pure returns (bytes32) {
        return bytes32(
            (uint256(layer) << 224) | (uint256(tree) << 128)
                | (uint256(addressType) << 96) | (uint256(keypair) << 64)
                | (uint256(chain) << 32) | uint256(step)
        );
    }
}
