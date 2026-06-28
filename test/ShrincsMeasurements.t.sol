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

import {Test} from "../lib/forge-std/src/Test.sol";
import {Vm} from "../lib/forge-std/src/Vm.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsAccountVerifierExample} from "../contracts/examples/ShrincsAccountVerifierExample.sol";
import {ShrincsAccountSigningFacade} from "./helpers/ShrincsAccountSigningFacade.sol";
import {ShrincsStatelessVectorSigner} from "./helpers/ShrincsStatelessVectorSigner.sol";

contract MeasurementAccountSigningHarness is ShrincsStatelessVectorSigner {}

contract ShrincsMeasurementsTest is Test {
    string internal constant MEASUREMENT_VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";
    address internal constant STATEFUL_VECTOR_ACCOUNT = address(uint160(0xCAFE));
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes32 internal constant ACTION_TYPE = keccak256("measure");
    bytes32 internal constant PAYLOAD_HASH = keccak256("measurement payload");

    struct StatefulCase {
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.ActionContext context;
        ShrincsTypes.StatefulSignature signature;
        ShrincsAccountVerifierExample account;
        bytes message;
        bytes32 hash;
        bytes envelope;
    }

    struct StatelessCase {
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.ActionContext context;
        ShrincsTypes.StatelessSignature signature;
        ShrincsAccountVerifierExample account;
        bytes message;
        bytes32 hash;
        bytes envelope;
    }

    MeasurementAccountSigningHarness internal accountSigner;

    function setUp() public {
        vm.pauseGasMetering();
        accountSigner = new MeasurementAccountSigningHarness();
        vm.resumeGasMetering();
    }

    function testMeasureStatefulCanonicalWrapperCallGas() public {
        vm.pauseGasMetering();
        StatefulCase memory c = prepareStatefulCase(bytes("measure stateful wrapper seed"));
        bytes memory callData =
            abi.encodeCall(c.account.verifyStatefulAction, (c.publicKey, ACTION_TYPE, PAYLOAD_HASH, c.signature));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateful wrapper call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "stateful wrapper call must verify");
        emit log_named_uint("stateful.canonical_wrapper_call_gas", gas.gasTotalUsed);
    }

    function testMeasureStatefulERC1271CallGas() public {
        vm.pauseGasMetering();
        StatefulCase memory c = prepareStatefulCase(bytes("measure stateful 1271 seed"));
        bytes memory callData = abi.encodeCall(c.account.isValidSignature, (c.hash, c.envelope));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateful 1271 call must not revert");
        assertEq(abi.decode(returnData, (bytes4)), ERC1271_MAGIC_VALUE, "stateful 1271 must verify");
        emit log_named_uint("stateful.erc1271_call_gas", gas.gasTotalUsed);
    }

    function testMeasureStatelessCanonicalWrapperCallGas() public {
        vm.pauseGasMetering();
        StatelessCase memory c = prepareStatelessCase(bytes("measure stateless wrapper seed"));
        bytes memory callData =
            abi.encodeCall(c.account.verifyStatelessAction, (c.publicKey, ACTION_TYPE, PAYLOAD_HASH, c.signature));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateless wrapper call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "stateless wrapper call must verify");
        emit log_named_uint("stateless.canonical_wrapper_call_gas", gas.gasTotalUsed);
    }

    function testMeasureStatelessERC1271CallGas() public {
        vm.pauseGasMetering();
        StatelessCase memory c = prepareStatelessCase(bytes("measure stateless 1271 seed"));
        bytes memory callData = abi.encodeCall(c.account.isValidSignature, (c.hash, c.envelope));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateless 1271 call must not revert");
        assertEq(abi.decode(returnData, (bytes4)), ERC1271_MAGIC_VALUE, "stateless 1271 must verify");
        emit log_named_uint("stateless.erc1271_call_gas", gas.gasTotalUsed);
    }

    function prepareStatefulCase(bytes memory seedMaterial) internal returns (StatefulCase memory c) {
        seedMaterial;
        string memory vectors = vm.readFile(MEASUREMENT_VECTOR_PATH);
        bytes memory args = stripSelector(vm.parseJsonBytes(vectors, ".measurements.stateful.canonicalCalldata"));
        (
            ShrincsTypes.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            ShrincsTypes.StatefulSignature memory signature
        ) = abi.decode(args, (ShrincsTypes.PublicKey, bytes32, bytes32, ShrincsTypes.StatefulSignature));
        assertEq(actionType, ACTION_TYPE, "stateful vector action type mismatch");
        assertEq(payloadHash, PAYLOAD_HASH, "stateful vector payload hash mismatch");

        deployCodeTo(
            "ShrincsAccountVerifierExample.sol:ShrincsAccountVerifierExample",
            abi.encode(publicKeyCommitmentWord(publicKey)),
            STATEFUL_VECTOR_ACCOUNT
        );
        ShrincsAccountVerifierExample account = ShrincsAccountVerifierExample(STATEFUL_VECTOR_ACCOUNT);
        account.setStatefulPolicyMonotonicIndex(uint32(signature.q));

        ShrincsTypes.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(account, ACTION_TYPE, PAYLOAD_HASH);
        bytes32 hash = SHRINCS.statefulActionMessageHash(account.currentShrincsPublicKey(), context);
        bytes memory message = abi.encodePacked(hash);

        c.publicKey = publicKey;
        c.context = context;
        c.signature = signature;
        c.account = account;
        c.message = message;
        c.hash = hash;
        c.envelope = ShrincsAccountSigningFacade.encodeStateful1271Envelope(
            publicKey, ACTION_TYPE, PAYLOAD_HASH, signature
        );
    }

    function prepareStatelessCase(bytes memory seedMaterial) internal returns (StatelessCase memory c) {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "stateless keygen must succeed");

        ShrincsAccountVerifierExample account = new ShrincsAccountVerifierExample(publicKeyCommitmentWord(publicKey));
        bytes32 sessionId;
        (, sessionId, ok) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            accountSigner, account, signingKey, publicKey, ACTION_TYPE, PAYLOAD_HASH
        );
        assertTrue(ok, "stateless session must begin");

        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(accountSigner, sessionId);
        assertTrue(completeOk, "stateless signing must complete");

        ShrincsTypes.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(account, ACTION_TYPE, PAYLOAD_HASH);
        bytes32 hash = SHRINCS.statelessActionMessageHash(account.currentShrincsPublicKey(), context);
        bytes memory message = abi.encodePacked(hash);

        c.publicKey = publicKey;
        c.context = context;
        c.signature = signature;
        c.account = account;
        c.message = message;
        c.hash = hash;
        c.envelope = ShrincsAccountSigningFacade.encodeStateless1271Envelope(
            publicKey, ACTION_TYPE, PAYLOAD_HASH, signature
        );
    }

    function publicKeyCommitmentWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 out) {
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            out := mload(add(commitmentBytes, 32))
        }
    }

    function stripSelector(bytes memory input) internal pure returns (bytes memory output) {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length;) {
            output[i - 4] = input[i];
            unchecked {
                ++i;
            }
        }
    }
}
