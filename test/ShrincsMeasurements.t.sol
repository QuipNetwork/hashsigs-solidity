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
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";

contract MeasurementAccountSigningHarness is ShrincsStatelessVectorSigner {}

contract CompactMeasurementHarness {
    // verifyRaw: Expose raw compact verification for gas measurement.
    function verifyRaw(bytes32 subPkSeed, bytes32 subPkRoot, bytes32 message, bytes calldata signature)
        external
        pure
        returns (bool)
    {
        return SHRINCS.verifyCompactUncheckedMessage(subPkSeed, subPkRoot, message, signature);
    }
}

contract ShrincsMeasurementsTest is Test {
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    uint8 internal constant ERC1271_MODE_COMPACT_ACTION = 3;
    uint8 internal constant COMPACT_Q = 11;
    bytes32 internal constant ACTION_TYPE = keccak256("measure");
    bytes32 internal constant PAYLOAD_HASH = keccak256("measurement payload");

    struct StatelessCase {
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.ActionContext context;
        ShrincsTypes.StatelessSignature signature;
        ShrincsAccountVerifierExample account;
        bytes message;
        bytes32 hash;
        bytes envelope;
    }

    struct CompactCase {
        bytes32 subPkSeed;
        bytes32 subPkRoot;
        ShrincsTypes.ActionContext context;
        ShrincsAccountVerifierExample account;
        bytes32 hash;
        bytes signature;
        bytes envelope;
    }

    struct CompactSlotUpdateCase {
        ShrincsTypes.PublicKey publicKey;
        ShrincsTypes.StatelessSignature signature;
        ShrincsAccountVerifierExample account;
        bytes32 subPkSeed;
        bytes32 subPkRoot;
    }

    MeasurementAccountSigningHarness internal accountSigner;
    CompactMeasurementHarness internal compactHarness;

    function setUp() public {
        vm.pauseGasMetering();
        accountSigner = new MeasurementAccountSigningHarness();
        compactHarness = new CompactMeasurementHarness();
        vm.resumeGasMetering();
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

    function testMeasureCompactRawVerifyGas() public {
        vm.pauseGasMetering();
        CompactCase memory c =
            prepareCompactActionCase(bytes("measure compact raw key"), bytes("measure compact raw slot"), COMPACT_Q);
        bytes memory callData =
            abi.encodeCall(compactHarness.verifyRaw, (c.subPkSeed, c.subPkRoot, c.hash, c.signature));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(compactHarness).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "compact raw call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "compact raw call must verify");
        emit log_named_uint("compact.raw_verify_call_gas", gas.gasTotalUsed);
    }

    function testMeasureCompactAccountVerifyGas() public {
        vm.pauseGasMetering();
        CompactCase memory c = prepareCompactActionCase(
            bytes("measure compact account key"), bytes("measure compact account slot"), COMPACT_Q
        );
        bytes memory callData = abi.encodeCall(
            c.account.verifyCompactAction, (c.subPkSeed, c.subPkRoot, ACTION_TYPE, PAYLOAD_HASH, c.signature)
        );
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "compact account call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "compact account call must verify");
        emit log_named_uint("compact.account_verify_call_gas", gas.gasTotalUsed);
    }

    function testMeasureCompactMultiQAccountVerifyGas() public {
        vm.pauseGasMetering();
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(bytes("measure compact multi q key"), 4);
        assertTrue(ok, "compact multi q keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot) =
            compactSlotKeygen(bytes("measure compact multi q slot"), 0);
        (bytes32 allAuthRoot, bytes32[7][128] memory authPaths) =
            ShrincsTestSigner.compactMerkleRootAndAllAuth(compactSkSeed, subPkSeed);
        assertEq(allAuthRoot, subPkRoot, "all compact q auth paths must share root");
        registerCompactSlotDuringSetup(account, signingKey, publicKey, subPkSeed, subPkRoot);

        uint256 minGas = type(uint256).max;
        uint256 maxGas;
        uint256 totalGas;
        for (uint256 i = 0; i < ShrincsTypes.COMPACT_Q_MAX;) {
            uint8 q = uint8(i);
            uint256 gasUsed = measureCompactQ(account, compactSkSeed, subPkSeed, subPkRoot, q, authPaths[i]);
            if (gasUsed < minGas) minGas = gasUsed;
            if (gasUsed > maxGas) maxGas = gasUsed;
            totalGas += gasUsed;
            emit log_named_uint(string.concat("compact.multi_q.", vm.toString(i), ".call_gas"), gasUsed);
            unchecked {
                ++i;
            }
        }

        emit log_named_uint("compact.multi_q_min_call_gas", minGas);
        emit log_named_uint("compact.multi_q_max_call_gas", maxGas);
        emit log_named_uint("compact.multi_q_avg_call_gas", totalGas / ShrincsTypes.COMPACT_Q_MAX);
    }

    function testMeasureCompactERC1271CallGas() public {
        vm.pauseGasMetering();
        CompactCase memory c =
            prepareCompactActionCase(bytes("measure compact 1271 key"), bytes("measure compact 1271 slot"), COMPACT_Q);
        bytes memory callData = abi.encodeCall(c.account.isValidSignature, (c.hash, c.envelope));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "compact 1271 call must not revert");
        assertEq(abi.decode(returnData, (bytes4)), ERC1271_MAGIC_VALUE, "compact 1271 must verify");
        emit log_named_uint("compact.erc1271_call_gas", gas.gasTotalUsed);
    }

    function testMeasureCompactSlotRegistrationGas() public {
        vm.pauseGasMetering();
        CompactSlotUpdateCase memory c = prepareCompactSlotRegistrationCase(
            bytes("measure compact registration key"), bytes("measure compact registration slot"), COMPACT_Q
        );
        bytes memory callData =
            abi.encodeCall(c.account.registerCompactSlot, (c.publicKey, c.signature, c.subPkSeed, c.subPkRoot));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "compact slot registration call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "compact slot registration must verify");
        assertTrue(c.account.compactSlots(c.account.compactSlotId(c.subPkSeed, c.subPkRoot)), "slot must be registered");
        emit log_named_uint("compact.slot_registration_call_gas", gas.gasTotalUsed);
    }

    function testMeasureCompactSlotRevocationGas() public {
        vm.pauseGasMetering();
        CompactSlotUpdateCase memory c = prepareCompactSlotRevocationCase(
            bytes("measure compact revocation key"), bytes("measure compact revocation slot"), COMPACT_Q
        );
        bytes memory callData =
            abi.encodeCall(c.account.revokeCompactSlot, (c.publicKey, c.signature, c.subPkSeed, c.subPkRoot));
        vm.resumeGasMetering();

        (bool success, bytes memory returnData) = address(c.account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "compact slot revocation call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "compact slot revocation must verify");
        assertFalse(c.account.compactSlots(c.account.compactSlotId(c.subPkSeed, c.subPkRoot)), "slot must be revoked");
        emit log_named_uint("compact.slot_revocation_call_gas", gas.gasTotalUsed);
    }

    function prepareStatelessCase(bytes memory seedMaterial) internal returns (StatelessCase memory c) {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "stateless keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
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
        bytes32 hash =
            SHRINCS.statelessActionMessageHash(account.currentPkSeed(), account.currentHypertreeRoot(), context);
        bytes memory message = abi.encodePacked(hash);

        c.publicKey = publicKey;
        c.context = context;
        c.signature = signature;
        c.account = account;
        c.message = message;
        c.hash = hash;
        c.envelope =
            ShrincsAccountSigningFacade.encodeStateless1271Envelope(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature);
    }

    function prepareCompactActionCase(bytes memory seedMaterial, bytes memory slotSeedMaterial, uint8 q)
        internal
        returns (CompactCase memory c)
    {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "compact keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot) = compactSlotKeygen(slotSeedMaterial, q);
        registerCompactSlotDuringSetup(account, signingKey, publicKey, subPkSeed, subPkRoot);

        ShrincsTypes.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(account, ACTION_TYPE, PAYLOAD_HASH);
        (bytes memory signature, bool signOk) =
            ShrincsTestSigner.signCompactAction(compactSkSeed, subPkSeed, subPkRoot, context, q);
        assertTrue(signOk, "compact signing must succeed");

        c.subPkSeed = subPkSeed;
        c.subPkRoot = subPkRoot;
        c.context = context;
        c.account = account;
        c.hash = SHRINCS.compactActionMessageHash(context);
        c.signature = signature;
        c.envelope = encodeCompact1271Envelope(subPkSeed, subPkRoot, ACTION_TYPE, PAYLOAD_HASH, signature);
    }

    function prepareCompactSlotRegistrationCase(bytes memory seedMaterial, bytes memory slotSeedMaterial, uint8 q)
        internal
        returns (CompactSlotUpdateCase memory c)
    {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "registration keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        (, bytes32 subPkSeed, bytes32 subPkRoot) = compactSlotKeygen(slotSeedMaterial, q);
        (ShrincsTypes.StatelessSignature memory signature, bool signOk) =
            signCompactSlotUpdate(account, signingKey, publicKey, subPkSeed, subPkRoot, true);
        assertTrue(signOk, "slot registration signing must succeed");

        c.publicKey = publicKey;
        c.signature = signature;
        c.account = account;
        c.subPkSeed = subPkSeed;
        c.subPkRoot = subPkRoot;
    }

    function prepareCompactSlotRevocationCase(bytes memory seedMaterial, bytes memory slotSeedMaterial, uint8 q)
        internal
        returns (CompactSlotUpdateCase memory c)
    {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool ok) =
            ShrincsAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "revocation keygen must succeed");

        ShrincsAccountVerifierExample account = newAccount(publicKey);
        (, bytes32 subPkSeed, bytes32 subPkRoot) = compactSlotKeygen(slotSeedMaterial, q);
        registerCompactSlotDuringSetup(account, signingKey, publicKey, subPkSeed, subPkRoot);

        (ShrincsTypes.StatelessSignature memory signature, bool signOk) =
            signCompactSlotUpdate(account, signingKey, publicKey, subPkSeed, subPkRoot, false);
        assertTrue(signOk, "slot revocation signing must succeed");

        c.publicKey = publicKey;
        c.signature = signature;
        c.account = account;
        c.subPkSeed = subPkSeed;
        c.subPkRoot = subPkRoot;
    }

    function compactSlotKeygen(bytes memory seedMaterial, uint8 q)
        internal
        pure
        returns (bytes32 compactSkSeed, bytes32 subPkSeed, bytes32 subPkRoot)
    {
        bool ok;
        (compactSkSeed, subPkSeed, subPkRoot, ok) = ShrincsTestSigner.compactSingleLaneKeygen(seedMaterial, q);
        require(ok, "compact slot keygen");
    }

    function registerCompactSlotDuringSetup(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot
    ) internal {
        (ShrincsTypes.StatelessSignature memory signature, bool signOk) =
            signCompactSlotUpdate(account, signingKey, publicKey, subPkSeed, subPkRoot, true);
        assertTrue(signOk, "slot registration signing must succeed");
        assertTrue(account.registerCompactSlot(publicKey, signature, subPkSeed, subPkRoot), "slot registration");
    }

    function signCompactSlotUpdate(
        ShrincsAccountVerifierExample account,
        ShrincsTypes.SigningKey memory signingKey,
        ShrincsTypes.PublicKey memory publicKey,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bool registered
    ) internal returns (ShrincsTypes.StatelessSignature memory signature, bool ok) {
        bytes32 sessionId;
        if (registered) {
            (, sessionId, ok) = ShrincsAccountSigningFacade.beginCompactSlotRegistrationSessionNow(
                accountSigner, account, signingKey, publicKey, subPkSeed, subPkRoot
            );
        } else {
            (, sessionId, ok) = ShrincsAccountSigningFacade.beginCompactSlotRevocationSessionNow(
                accountSigner, account, signingKey, publicKey, subPkSeed, subPkRoot
            );
        }
        if (!ok) return (signature, false);
        return ShrincsAccountSigningFacade.completeStatelessSession(accountSigner, sessionId);
    }

    function measureCompactQ(
        ShrincsAccountVerifierExample account,
        bytes32 compactSkSeed,
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        uint8 q,
        bytes32[7] memory authPath
    ) internal returns (uint256 gasUsed) {
        bytes32 payloadHash = keccak256(abi.encodePacked("measurement compact q", q));
        ShrincsTypes.ActionContext memory context =
            ShrincsAccountSigningFacade.actionContext(account, ACTION_TYPE, payloadHash);
        (bytes memory signature, bool signOk) =
            ShrincsTestSigner.signCompactActionWithAuth(compactSkSeed, subPkSeed, subPkRoot, context, q, authPath);
        assertTrue(signOk, "compact q signing must succeed");
        bytes memory callData =
            abi.encodeCall(account.verifyCompactAction, (subPkSeed, subPkRoot, ACTION_TYPE, payloadHash, signature));

        vm.resumeGasMetering();
        (bool success, bytes memory returnData) = address(account).call(callData);
        Vm.Gas memory gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(success, "compact q call must not revert");
        assertTrue(abi.decode(returnData, (bool)), "compact q call must verify");
        return gas.gasTotalUsed;
    }

    function encodeCompact1271Envelope(
        bytes32 subPkSeed,
        bytes32 subPkRoot,
        bytes32 actionType,
        bytes32 payloadHash,
        bytes memory signature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(ERC1271_MODE_COMPACT_ACTION), abi.encode(subPkSeed, subPkRoot, actionType, payloadHash, signature)
        );
    }

    function pkSeedWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 out) {
        bytes memory keyBytes = publicKey.pkSeed;
        assembly {
            out := mload(add(keyBytes, 32))
        }
    }

    function hypertreeRootWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 out) {
        bytes memory keyBytes = publicKey.hypertreeRoot;
        assembly {
            out := mload(add(keyBytes, 32))
        }
    }

    function newAccount(ShrincsTypes.PublicKey memory publicKey)
        internal
        returns (ShrincsAccountVerifierExample account)
    {
        account = new ShrincsAccountVerifierExample(pkSeedWord(publicKey), hypertreeRootWord(publicKey));
    }
}
