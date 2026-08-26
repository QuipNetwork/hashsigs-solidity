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

import {SHRINCSTestCodec} from "./helpers/SHRINCSTestCodec.sol";

import {Test} from "../lib/forge-std/src/Test.sol";
import {Vm} from "../lib/forge-std/src/Vm.sol";
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract MeasurementAccountSigningHarness is SHRINCSStatelessVectorSigner {}

/// @dev Common surface across every profile's SHRINCSPinned*.t.sol harness
/// (each `is` the profile's concrete SHRINCS verifier and adds `pinned()`).
/// Selecting the artifact string by SHRINCSParams.PROFILE_ID and deploying
/// through this interface lets the delegation measurement reach the right
/// concrete pair without statically importing any of them (only one
/// profile's concrete verifiers are ever compiled in a given build).
interface IMeasurementPinnedVerifier {
    function pinned() external pure returns (address);
    function verifyStateless(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}

/// @dev Raw stateless verification harness for the 128s profiles, where the
/// canonical account-context wrapper cannot be exercised with a fixed Rust
/// vector: the wrapper always re-derives its message hash from live
/// contract state (domain separator, nonce, key version), and a vector's
/// signature is only valid over the one fixed message Rust signed. This
/// harness calls the same underlying SHRINCS library verification the
/// wrapper itself calls, skipping only the context-hash derivation, so the
/// measured call still exercises production FORS-C plus hypertree
/// verification code.
contract MeasurementRawStatelessHarness {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    function verifyCanonical(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedCommitment, publicKey, message, signature
        );
    }

    function verifyErc1271(
        bytes32 expectedCommitment,
        bytes32 hash,
        SHRINCS.PublicKey calldata publicKey,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bytes4) {
        bool ok = SHRINCS.verifyStatelessUncheckedMessage(
            expectedCommitment, publicKey, abi.encodePacked(hash), signature
        );
        return ok ? MAGIC_VALUE : INVALID_SIGNATURE;
    }
}

contract SHRINCSMeasurementsTest is Test {
    address internal constant STATEFUL_VECTOR_ACCOUNT =
        address(uint160(0xCAFE));
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes32 internal constant ACTION_TYPE = keccak256("measure");
    bytes32 internal constant PAYLOAD_HASH =
        keccak256("measurement payload");

    // Profile identities ([DESIGN §3.4]), matched against the active
    // build's SHRINCSParams.PROFILE_ID to select artifact strings and the
    // in-process-vs-vector measurement path. Mirrors each profile's
    // PROFILE_NAME (contracts/profiles/*/SHRINCSParams.sol).
    bytes32 internal constant PROFILE_256S_KECCAK =
        keccak256(bytes("shrincs-256s-keccak"));
    bytes32 internal constant PROFILE_256S_SHA2 =
        keccak256(bytes("shrincs-256s-sha2"));
    bytes32 internal constant PROFILE_128S_Q18 =
        keccak256(bytes("shrincs-128s-q18-keccak"));
    bytes32 internal constant PROFILE_128S_Q20 =
        keccak256(bytes("shrincs-128s-q20-keccak"));

    struct StatefulCase {
        SHRINCS.PublicKey publicKey;
        SHRINCS.ActionContext context;
        SHRINCS.Signature signature;
        SHRINCSAccountVerifierExample account;
        bytes message;
        bytes32 hash;
        bytes envelope;
    }

    struct StatelessCase {
        SHRINCS.PublicKey publicKey;
        SHRINCS.ActionContext context;
        SPHINCSPlusC.Signature signature;
        SHRINCSAccountVerifierExample account;
        bytes message;
        bytes32 hash;
        bytes envelope;
    }

    // Legacy vector-decoding shapes, mirroring
    // test/SHRINCSSphincs128sVectors.t.sol: the Rust generator's abi-encoded
    // calldata bundles the public key without its publicKeyCommitment field
    // (read separately from the JSON), and the FORS-C/hypertree/WOTS+C
    // structs at their pre-rename field layout.
    struct LegacyPublicKey {
        bytes statefulPublicKey;
        bytes pkSeed;
        bytes hypertreeRoot;
    }

    struct LegacyForsEntry {
        bytes secretLeaf;
        bytes[] authPath;
    }

    struct LegacyForsSignature {
        bytes randomizer;
        uint32 counter;
        LegacyForsEntry[] entries;
    }

    struct LegacyWotsCSignature {
        bytes randomizer;
        uint32 counter;
        bytes[] chains;
    }

    struct LegacyHypertreeLayerSignature {
        bytes wotsCPkHash;
        LegacyWotsCSignature wotsCSignature;
        bytes[] authPath;
    }

    struct LegacyStatelessSignature {
        LegacyForsSignature fors;
        LegacyHypertreeLayerSignature[] hypertree;
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
        if (isStateless128sVectorProfile()) {
            (
                bytes32 commitment,
                SHRINCS.PublicKey memory publicKey,
                bytes memory message,
                SPHINCSPlusC.Signature memory signature
            ) = loadStatelessVectorCase();
            MeasurementRawStatelessHarness harness =
                new MeasurementRawStatelessHarness();
            bytes memory callData = abi.encodeCall(
                harness.verifyCanonical,
                (commitment, publicKey, message, signature)
            );
            vm.resumeGasMetering();

            (bool success, bytes memory returnData) =
                address(harness).call(callData);
            Vm.Gas memory gas = vm.lastCallGas();

            vm.pauseGasMetering();
            assertTrue(success, "128s vector canonical call must not revert");
            assertTrue(
                abi.decode(returnData, (bool)),
                "128s vector canonical call must verify"
            );
            emit log_named_uint(
                "stateless.canonical_wrapper_call_gas", gas.gasTotalUsed
            );
            return;
        }

        StatelessCase memory c =
            prepareStatelessCase(bytes("measure stateless wrapper seed"));
        bytes memory wrapperCallData = abi.encodeCall(
            c.account.verifyStatelessAction,
            (c.publicKey, ACTION_TYPE, PAYLOAD_HASH, c.signature)
        );
        vm.resumeGasMetering();

        (bool wrapperSuccess, bytes memory wrapperReturnData) =
            address(c.account).call(wrapperCallData);
        Vm.Gas memory wrapperGas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(wrapperSuccess, "stateless wrapper call must not revert");
        assertTrue(
            abi.decode(wrapperReturnData, (bool)),
            "stateless wrapper call must verify"
        );
        emit log_named_uint(
            "stateless.canonical_wrapper_call_gas", wrapperGas.gasTotalUsed
        );
    }

    function testMeasureStatelessERC1271CallGas() public {
        vm.pauseGasMetering();
        if (isStateless128sVectorProfile()) {
            (
                bytes32 commitment,
                SHRINCS.PublicKey memory publicKey,
                bytes memory message,
                SPHINCSPlusC.Signature memory signature
            ) = loadStatelessVectorCase();
            bytes32 hash = messageToHash(message);
            MeasurementRawStatelessHarness harness =
                new MeasurementRawStatelessHarness();
            bytes memory callData = abi.encodeCall(
                harness.verifyErc1271,
                (commitment, hash, publicKey, signature)
            );
            vm.resumeGasMetering();

            (bool success, bytes memory returnData) =
                address(harness).call(callData);
            Vm.Gas memory gas = vm.lastCallGas();

            vm.pauseGasMetering();
            assertTrue(success, "128s vector 1271 call must not revert");
            assertEq(
                abi.decode(returnData, (bytes4)),
                ERC1271_MAGIC_VALUE,
                "128s vector 1271 call must verify"
            );
            emit log_named_uint(
                "stateless.erc1271_call_gas", gas.gasTotalUsed
            );
            return;
        }

        StatelessCase memory c =
            prepareStatelessCase(bytes("measure stateless 1271 seed"));
        bytes memory erc1271CallData =
            abi.encodeCall(c.account.isValidSignature, (c.hash, c.envelope));
        vm.resumeGasMetering();

        (bool erc1271Success, bytes memory erc1271ReturnData) =
            address(c.account).call(erc1271CallData);
        Vm.Gas memory erc1271Gas = vm.lastCallGas();

        vm.pauseGasMetering();
        assertTrue(erc1271Success, "stateless 1271 call must not revert");
        assertEq(
            abi.decode(erc1271ReturnData, (bytes4)),
            ERC1271_MAGIC_VALUE,
            "stateless 1271 must verify"
        );
        emit log_named_uint(
            "stateless.erc1271_call_gas", erc1271Gas.gasTotalUsed
        );
    }

    function prepareStatefulCase(bytes memory seedMaterial)
        internal
        returns (StatefulCase memory c)
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(seedMaterial, 4);
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
            SHRINCS.ActionContext memory context,
            SHRINCS.Signature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            account, signingKey, ACTION_TYPE, PAYLOAD_HASH
        );
        assertTrue(signOk, "stateful signing must succeed");
        account.setStatefulPolicyMonotonicIndex(
            uint32(signature.authPath.length)
        );

        bytes32 hash = SHRINCS.statefulActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory message = abi.encodePacked(hash);

        c.publicKey = publicKey;
        c.context = context;
        c.signature = signature;
        c.account = account;
        c.message = message;
        c.hash = hash;
        c.envelope = SHRINCSAccountSigningFacade.encodeStateful1271Envelope(
            publicKey, ACTION_TYPE, PAYLOAD_HASH, signature
        );
    }

    function prepareStatelessCase(bytes memory seedMaterial)
        internal
        returns (StatelessCase memory c)
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "stateless keygen must succeed");

        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                publicKeyCommitmentWord(publicKey)
            );
        bytes32 sessionId;
        (, sessionId, ok) =
            SHRINCSAccountSigningFacade.beginStatelessActionSessionNow(
                accountSigner,
                account,
                signingKey,
                publicKey,
                ACTION_TYPE,
                PAYLOAD_HASH
            );
        assertTrue(ok, "stateless session must begin");

        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory signature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "stateless signing must complete");

        SHRINCS.ActionContext memory context =
            SHRINCSAccountSigningFacade.actionContext(
                account, ACTION_TYPE, PAYLOAD_HASH
            );
        bytes32 hash = SHRINCS.statelessActionMessageHash(
            account.currentSHRINCSPublicKey(), context
        );
        bytes memory message = abi.encodePacked(hash);

        c.publicKey = publicKey;
        c.context = context;
        c.signature = signature;
        c.account = account;
        c.message = message;
        c.hash = hash;
        c.envelope = SHRINCSAccountSigningFacade.encodeStateless1271Envelope(
            publicKey, ACTION_TYPE, PAYLOAD_HASH, signature
        );
    }

    function testMeasureVerifyStatelessDelegationGas() public {
        vm.pauseGasMetering();
        (
            IMeasurementPinnedVerifier verifier,
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
            IMeasurementPinnedVerifier verifier,
            bytes memory key,
            bytes memory envelope,
            bytes32 hash
        )
    {
        verifier = IMeasurementPinnedVerifier(
            deployCode(pinHarnessArtifact())
        );
        deployCodeTo(siblingArtifact(), "", verifier.pinned());

        if (isStateless128sVectorProfile()) {
            (
                bytes32 vectorCommitment,
                SHRINCS.PublicKey memory vectorPublicKey,
                bytes memory vectorMessage,
                SPHINCSPlusC.Signature memory vectorSignature
            ) = loadStatelessVectorCase();
            hash = messageToHash(vectorMessage);
            key = abi.encodePacked(vectorCommitment);
            envelope = SHRINCSTestCodec.encodeStatelessEnvelope(
                vectorPublicKey, vectorSignature
            );
            return (verifier, key, envelope, hash);
        }

        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(seedMaterial, 4);
        assertTrue(ok, "delegation keygen must succeed");

        hash = keccak256("verifyStateless delegation message");
        bytes32 sessionId;
        (sessionId, ok) = accountSigner.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        assertTrue(ok, "delegation session must begin");
        // line-length: allow — fmt canonical tuple head exceeds cap
        (SPHINCSPlusC.Signature memory signature, bool completeOk) = SHRINCSAccountSigningFacade.completeStatelessSession(
            accountSigner, sessionId
        );
        assertTrue(completeOk, "delegation signing must complete");

        key = abi.encodePacked(publicKeyCommitmentWord(publicKey));
        envelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
    }

    // pinHarnessArtifact / siblingArtifact: select the active profile's
    // concrete SHRINCS/SPHINCSPlusC artifact-name strings for deployCode
    // and deployCodeTo. Only one profile's concrete verifiers are ever
    // compiled at a time (foundry.toml skip lists), so this file imports
    // none of them statically and resolves the pair at runtime instead,
    // keyed on SHRINCSParams.PROFILE_ID. Each SHRINCSPinned*.t.sol harness
    // already `is` its profile's concrete SHRINCS verifier and exposes
    // `pinned()` (test/SHRINCSPinned256s.t.sol and siblings); reusing those
    // profile-gated files avoids a second set of per-profile wrappers.
    function pinHarnessArtifact() internal pure returns (string memory) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        if (id == PROFILE_256S_KECCAK) {
            return "SHRINCSPinned256s.t.sol:SHRINCS256sPinHarness";
        }
        if (id == PROFILE_256S_SHA2) {
            return "SHRINCSPinned256sSha2.t.sol:SHRINCS256sSha2PinHarness";
        }
        if (id == PROFILE_128S_Q18) {
            return "SHRINCSPinned128sQ18.t.sol:SHRINCS128sQ18PinHarness";
        }
        if (id == PROFILE_128S_Q20) {
            return "SHRINCSPinned128sQ20.t.sol:SHRINCS128sQ20PinHarness";
        }
        revert("SHRINCSMeasurements: unknown profile");
    }

    function siblingArtifact() internal pure returns (string memory) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        if (id == PROFILE_256S_KECCAK) {
            return "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak";
        }
        if (id == PROFILE_256S_SHA2) {
            return "SPHINCSPlusC256sSha2.sol:SPHINCSPlusC256sSha2";
        }
        if (id == PROFILE_128S_Q18) {
            return "SPHINCSPlusC128sQ18Keccak.sol:SPHINCSPlusC128sQ18Keccak";
        }
        if (id == PROFILE_128S_Q20) {
            return "SPHINCSPlusC128sQ20Keccak.sol:SPHINCSPlusC128sQ20Keccak";
        }
        revert("SHRINCSMeasurements: unknown profile");
    }

    function isStateless128sVectorProfile() internal pure returns (bool) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        return id == PROFILE_128S_Q18 || id == PROFILE_128S_Q20;
    }

    // 128s in-process stateless keygen/signing is compute-infeasible (full
    // 2^a FORS trees plus the fixed hypertree). loadStatelessVectorCase
    // feeds the Rust-anchored 128s stateless vector's valid case through
    // the same production verification the account wrapper uses, mirroring
    // test/SHRINCSSphincs128sVectors.t.sol's decode path.
    function loadStatelessVectorCase()
        internal
        returns (
            bytes32 commitment,
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        )
    {
        string memory vectors = vm.readFile(statelessVectorPath());
        vm.pauseGasMetering();
        bytes memory args = stripSelector(
            vm.parseJsonBytes(vectors, ".stateless.cases.valid.calldata")
        );
        vm.resumeGasMetering();

        LegacyPublicKey memory legacyPublicKey;
        LegacyStatelessSignature memory legacySignature;
        (legacyPublicKey, message, legacySignature) = abi.decode(
            args, (LegacyPublicKey, bytes, LegacyStatelessSignature)
        );

        publicKey = SHRINCS.PublicKey({
            statefulPublicKey: legacyPublicKey.statefulPublicKey,
            publicKeyCommitment: vm.parseJsonBytes(
                vectors,
                ".stateless.cases.valid.publicKey.publicKeyCommitment"
            ),
            pkSeed: legacyPublicKey.pkSeed,
            hypertreeRoot: legacyPublicKey.hypertreeRoot
        });
        commitment = publicKeyCommitmentWord(publicKey);
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    function statelessVectorPath() internal pure returns (string memory) {
        // q18 and q20 share every stateless field except the commitment
        // tag; pick the file by the stateless-signature budget, mirroring
        // SHRINCSSphincs128sVectors.t.sol.
        if (SHRINCSParams.STATELESS_SIGNATURE_LIMIT == 262_144) {
            return "test/test_vectors/shrincs_sphincs_128s_q18_keccak.json";
        }
        return "test/test_vectors/shrincs_sphincs_128s_q20_keccak.json";
    }

    // line-length: allow — fmt canonical header exceeds cap
    function convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (SPHINCSPlusC.Signature memory signature)
    {
        FORSMinusC.ForsEntry[] memory entries =
            new FORSMinusC.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = FORSMinusC.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf,
                authPath: legacy.fors.entries[i].authPath
            });
        }

        // forgefmt: disable-next-line
        Hypertree.HypertreeLayerSignature[] memory layers =
            new Hypertree.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = Hypertree.HypertreeLayerSignature({
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: WOTSPlusC.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature
                    .randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = SPHINCSPlusC.Signature({
            fors: FORSMinusC.ForsSignature({
                randomizer: legacy.fors.randomizer,
                counter: legacy.fors.counter,
                entries: entries
            }),
            hypertree: layers
        });
    }

    function stripSelector(bytes memory input)
        internal
        pure
        returns (bytes memory output)
    {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }

    // The vector's 32-byte "message" is the exact hash value the fixed
    // signature authorizes (bytes.length == 32 for every stateless
    // vector); reinterpreting it as a bytes32 word gives the same value
    // the delegation and 1271-shaped entrypoints take directly.
    function messageToHash(bytes memory message)
        internal
        pure
        returns (bytes32 out)
    {
        require(message.length == 32, "vector message must be 32 bytes");
        assembly {
            out := mload(add(message, 32))
        }
    }

    function publicKeyCommitmentWord(SHRINCS.PublicKey memory publicKey)
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
