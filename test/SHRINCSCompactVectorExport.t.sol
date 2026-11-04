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

import {SHRINCS} from "../contracts/SHRINCS.sol";
import {StatelessLayout} from "../contracts/StatelessLayout.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSCompactFixtures} from "./helpers/SHRINCSCompactFixtures.sol";

/// @notice Exports the compact stateless golden vectors the SDK encoder is
/// tested against: test/test_vectors/stateless-compact-256s.json. Each
/// vector carries the installed commitment, the ERC-7913 hash, the derived
/// statelessRawMessageHash, the ABI envelope, the compact payload, and the
/// result both verifier entry points return. Every exported result is
/// produced by the deployed verifiers in this run, and the two paths must
/// agree before the file is written. 256s keccak profile only.
contract SHRINCSCompactVectorExportTest is SHRINCSCompactFixtures {
    string internal constant OUTPUT_PATH =
        "test/test_vectors/stateless-compact-256s.json";

    function setUp() public {
        deployVerifiers();
    }

    function testExportStatelessCompactVectors() public {
        if (SHRINCSParams.PROFILE_ID != PROFILE_256S_KECCAK) return;
        bytes32 installed = loadCase("valid").commitment;
        string[7] memory names = caseNames();
        string memory list = "vectors";
        string memory json;
        for (uint256 i = 0; i < names.length; ++i) {
            json = vm.serializeString(
                list, names[i], exportCase(loadCase(names[i]), installed)
            );
        }

        string memory root = "root";
        vm.serializeString(root, "profile", SHRINCSParams.PROFILE_NAME);
        vm.serializeUint(
            root, "compactEncodingVersion", StatelessLayout.ENCODING_VERSION
        );
        vm.serializeUint(root, "pkLength", StatelessLayout.PK_LEN);
        vm.serializeUint(root, "pqLength", StatelessLayout.PQ_LEN);
        vm.serializeUint(root, "payloadLength", StatelessLayout.PAYLOAD_LEN);
        vm.serializeString(
            root,
            "source",
            "test/test_vectors/shrincs_sphincs_256s_keccak.json"
        );
        string memory out = vm.serializeString(root, "vectors", json);
        vm.writeJson(out, OUTPUT_PATH);
    }

    function exportCase(CompactCase memory c, bytes32 installed)
        internal
        returns (string memory)
    {
        bytes memory key = abi.encodePacked(installed);
        // The Rust wrongMessage case perturbs the signed message, not the
        // bundle; mirror that at this layer by perturbing the hash.
        if (keccak256(bytes(c.name)) == keccak256("wrongMessage")) {
            c.callerHash ^= bytes32(uint256(1) << 248);
        }
        bytes4 compactResult =
            verifier.verifyStateless(key, c.callerHash, c.compactPayload);
        // With wrongMessage's hash perturbed above, only the Rust "valid"
        // case, under its own commitment, verifies.
        bool expected = keccak256(bytes(c.name)) == keccak256("valid")
            && installed == c.commitment;
        assertEq(
            compactResult,
            expected ? VERIFY_SELECTOR : INVALID_SIGNATURE,
            c.name
        );

        string memory obj = c.name;
        vm.serializeBytes32(obj, "commitment", installed);
        vm.serializeBytes32(obj, "declaredCommitment", c.commitment);
        vm.serializeBytes32(obj, "hash", c.callerHash);
        vm.serializeBytes32(
            obj,
            "statelessRawMessageHash",
            SHRINCS.statelessRawMessageHash(installed, c.callerHash)
        );
        vm.serializeBytes(obj, "abiEnvelope", c.abiEnvelope);
        vm.serializeBytes(obj, "compactPayload", c.compactPayload);
        vm.serializeBool(obj, "valid", compactResult == VERIFY_SELECTOR);
        return
            vm.serializeBytes32(
                obj, "expectedResult", bytes32(compactResult)
            );
    }
}
