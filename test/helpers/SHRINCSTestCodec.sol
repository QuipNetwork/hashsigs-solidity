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
