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
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCSCodec} from "../contracts/SHRINCSCodec.sol";
import {SHRINCSCore} from "../contracts/SHRINCSCore.sol";
import {SPHINCSPlusCCore} from "../contracts/SPHINCSPlusCCore.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    ShrincsAccountSigningFacade
} from "./helpers/ShrincsAccountSigningFacade.sol";
import {
    ShrincsStatelessVectorSigner
} from "./helpers/ShrincsStatelessVectorSigner.sol";

contract MeasurementAccountSigningHarness is ShrincsStatelessVectorSigner {}

/// @dev Exposes the internal pinned SPHINCSPlusC address so the delegation
/// measurement can deploy the sibling where verifyStateless delegates.
contract MeasurementDelegationHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

contract ShrincsMeasurementsTest is Test {
    address internal constant STATEFUL_VECTOR_ACCOUNT =
        address(uint160(0xCAFE));
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes32 internal constant ACTION_TYPE = keccak256("measure");
    bytes32 internal constant PAYLOAD_HASH =
        keccak256("measurement payload");

    struct StatefulCase {
        SHRINCSCore.PublicKey publicKey;
        SHRINCSCore.ActionContext context;
        UXMSS.StatefulSignature signature;
        SHRINCSAccountVerifierExample account;
        bytes message;
        bytes32 hash;
        bytes envelope;
    }

    struct StatelessCase {
        SHRINCSCore.PublicKey publicKey;
        SHRINCSCore.ActionContext context;
        SPHINCSPlusCCore.StatelessSignature signature;
        SHRINCSAccountVerifierExample account;
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
        StatefulCase memory c =
            prepareStatefulCase(bytes("measure stateful wrapper seed"));
        bytes memory callData = abi.encodeCall(
            c.account.verifyStatefulAction,
            (c.publicKey, ACTION_TYPE, PAYLOAD_HASH, c.signature)
        );
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) =
            address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateful wrapper call must not revert");
        assertTrue(
            abi.decode(returnData, (bool)),
            "stateful wrapper call must verify"
        );
        emit log_named_uint(
            "stateful.canonical_wrapper_call_gas", gas.gasTotalUsed
        );
    }

    function testMeasureStatefulERC1271CallGas() public {
        vm.pauseGasMetering();
        StatefulCase memory c =
            prepareStatefulCase(bytes("measure stateful 1271 seed"));
        bytes memory callData =
            abi.encodeCall(c.account.isValidSignature, (c.hash, c.envelope));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) =
            address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateful 1271 call must not revert");
        assertEq(
            abi.decode(returnData, (bytes4)),
            ERC1271_MAGIC_VALUE,
            "stateful 1271 must verify"
        );
        emit log_named_uint("stateful.erc1271_call_gas", gas.gasTotalUsed);
    }

    function testMeasureStatelessCanonicalWrapperCallGas() public {
        vm.pauseGasMetering();
        StatelessCase memory c =
            prepareStatelessCase(bytes("measure stateless wrapper seed"));
        bytes memory callData = abi.encodeCall(
            c.account.verifyStatelessAction,
            (c.publicKey, ACTION_TYPE, PAYLOAD_HASH, c.signature)
        );
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) =
            address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateless wrapper call must not revert");
        assertTrue(
            abi.decode(returnData, (bool)),
            "stateless wrapper call must verify"
        );
        emit log_named_uint(
            "stateless.canonical_wrapper_call_gas", gas.gasTotalUsed
        );
    }

    function testMeasureStatelessERC1271CallGas() public {
        vm.pauseGasMetering();
        StatelessCase memory c =
            prepareStatelessCase(bytes("measure stateless 1271 seed"));
        bytes memory callData =
            abi.encodeCall(c.account.isValidSignature, (c.hash, c.envelope));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) =
            address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "stateless 1271 call must not revert");
        assertEq(
            abi.decode(returnData, (bytes4)),
            ERC1271_MAGIC_VALUE,
            "stateless 1271 must verify"
        );
        emit log_named_uint("stateless.erc1271_call_gas", gas.gasTotalUsed);
    }

    function prepareStatefulCase(bytes memory seedMaterial)
        internal
        returns (StatefulCase memory c)
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool keygenOk
        ) = ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(keygenOk, "stateful keygen must succeed");
        deployCodeTo(
            "SHRINCSAccountVerifierExample.sol:SHRINCSAccountVerifierExample",
            abi.encode(publicKeyCommitmentWord(publicKey)),
            STATEFUL_VECTOR_ACCOUNT
        );
        SHRINCSAccountVerifierExample account =
            SHRINCSAccountVerifierExample(STATEFUL_VECTOR_ACCOUNT);

        (
            ,
            SHRINCSCore.ActionContext memory context,
            UXMSS.StatefulSignature memory signature,
            bool signOk
        ) = ShrincsAccountSigningFacade.signStatefulActionNow(
            account, signingKey, ACTION_TYPE, PAYLOAD_HASH
        );
        assertTrue(signOk, "stateful signing must succeed");
        account.setStatefulPolicyMonotonicIndex(
            uint32(signature.authPath.length)
        );

        bytes32 hash = SHRINCSCore.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
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

    function prepareStatelessCase(bytes memory seedMaterial)
        internal
        returns (StatelessCase memory c)
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool ok
        ) = ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "stateless keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                publicKeyCommitmentWord(publicKey)
            );
        bytes32 sessionId;
        (, sessionId, ok) =
            ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
                accountSigner,
                account,
                signingKey,
                publicKey,
                ACTION_TYPE,
                PAYLOAD_HASH
            );
        assertTrue(ok, "stateless session must begin");

        // line-length: allow — fmt canonical tuple head exceeds cap
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = ShrincsAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "stateless signing must complete");

        SHRINCSCore.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(
                account, ACTION_TYPE, PAYLOAD_HASH
            );
        bytes32 hash = SHRINCSCore.statelessActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
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

    function testMeasureVerifyStatelessDelegationGas() public {
        vm.pauseGasMetering();
        (
            MeasurementDelegationHarness verifier,
            bytes memory key,
            bytes memory envelope,
            bytes32 hash
        ) = prepareVerifyStatelessDelegation(
            bytes("measure verifyStateless delegation seed")
        );
        bytes memory callData =
            abi.encodeCall(verifier.verifyStateless, (key, hash, envelope));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) =
            address(verifier).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "verifyStateless delegation must not revert");
        assertEq(
            abi.decode(returnData, (bytes4)),
            IERC7913SignatureVerifier.verify.selector,
            "verifyStateless delegation must verify"
        );
        emit log_named_uint(
            "stateless.verify_stateless_delegation_gas", gas.gasTotalUsed
        );
    }

    function prepareVerifyStatelessDelegation(bytes memory seedMaterial)
        internal
        returns (
            MeasurementDelegationHarness verifier,
            bytes memory key,
            bytes memory envelope,
            bytes32 hash
        )
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool ok
        ) = ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "delegation keygen must succeed");

        hash = keccak256("verifyStateless delegation message");
        bytes32 sessionId;
        (sessionId, ok) = accountSigner.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        assertTrue(ok, "delegation session must begin");
        // line-length: allow — fmt canonical tuple head exceeds cap
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = ShrincsAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "delegation signing must complete");

        verifier = new MeasurementDelegationHarness();
        deployCodeTo(
            "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak",
            "",
            verifier.pinned()
        );
        key = abi.encodePacked(publicKeyCommitmentWord(publicKey));
        envelope = SHRINCSCodec.encodeStatelessEnvelope(publicKey, signature);
    }

    function publicKeyCommitmentWord(SHRINCSCore.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 out)
    {
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            out := mload(add(commitmentBytes, 32))
        }
    }
}
