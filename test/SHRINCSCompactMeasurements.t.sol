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

import {SHRINCSCompactFixtures} from "./helpers/SHRINCSCompactFixtures.sol";

/// @notice Gas, calldata, and bytecode-size rows for the compact stateless
/// path on the Rust valid vector, with the ABI envelope size for scale.
/// Logged, not asserted,
/// except that both calls accept.
contract SHRINCSCompactMeasurementsTest is SHRINCSCompactFixtures {
    function setUp() public {
        deployVerifiers();
    }

    function testMeasureStateless() public {
        CompactCase memory c = loadCase("valid");
        bytes memory key = abi.encodePacked(c.commitment);

        uint256 start = gasleft();
        bytes4 result =
            verifier.verifyStateless(key, c.callerHash, c.compactPayload);
        uint256 shrincsGas = start - gasleft();
        assertEq(result, VERIFY_SELECTOR);

        start = gasleft();
        result =
            sibling.verify(c.sphincsKey, c.rawMessage, c.compactSignature);
        uint256 siblingGas = start - gasleft();
        assertEq(result, VERIFY_SELECTOR);

        emit log_named_uint("verifyStateless gas", shrincsGas);
        emit log_named_uint("SPHINCSPlusC verify gas", siblingGas);
        emit log_named_uint("ABI envelope bytes", c.abiEnvelope.length);
        emit log_named_uint("payload bytes", c.compactPayload.length);
        emit log_named_uint(
            "SHRINCS runtime bytes", address(verifier).code.length
        );
        emit log_named_uint(
            "SPHINCSPlusC runtime bytes", address(sibling).code.length
        );
    }
}
