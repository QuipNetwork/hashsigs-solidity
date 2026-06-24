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
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {ShrincsTypes} from "../contracts/ShrincsTypes.sol";
import {ShrincsAccountVerifierExample} from "../contracts/examples/ShrincsAccountVerifierExample.sol";
import {ShrincsAccountSigningFacade} from "./helpers/ShrincsAccountSigningFacade.sol";
import {ShrincsStatelessVectorSigner} from "./helpers/ShrincsStatelessVectorSigner.sol";
import {ShrincsTestSigner} from "./helpers/ShrincsTestSigner.sol";

contract MeasurementStatefulVerifierHarness {
    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatefulUncheckedMessage(expectedPublicKeyCommitment, publicKey, message, signature);
    }

    function measureVerifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatefulSignature calldata signature
    ) external view returns (bool ok, uint256 gasUsed) {
        uint256 beforeGas = gasleft();
        ok = SHRINCS.verifyStatefulUncheckedMessage(expectedPublicKeyCommitment, publicKey, message, signature);
        gasUsed = beforeGas - gasleft();
    }
}

contract MeasurementStatelessVerifierHarness {
    function verifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external pure returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(expectedPublicKeyCommitment, publicKey, message, signature);
    }

    function measureVerifyUnsafeRaw(
        bytes32 expectedPublicKeyCommitment,
        ShrincsTypes.PublicKey calldata publicKey,
        bytes calldata message,
        ShrincsTypes.StatelessSignature calldata signature
    ) external view returns (bool ok, uint256 gasUsed) {
        uint256 beforeGas = gasleft();
        ok = SHRINCS.verifyStatelessUncheckedMessage(expectedPublicKeyCommitment, publicKey, message, signature);
        gasUsed = beforeGas - gasleft();
    }
}

contract MeasurementAccountSigningHarness is ShrincsStatelessVectorSigner {}

contract ShrincsMeasurementsTest is Test {
    string internal constant VECTOR_PATH = "test/test_vectors/shrincs_sphincs_256s_keccak.json";
    bytes32 internal constant ACTION_TYPE = keccak256("measure");
    bytes32 internal constant PAYLOAD_HASH = keccak256("measurement payload");

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
        uint64 treeIndex;
        uint32 leafIndex;
        bytes wotsCPkHash;
        LegacyWotsCSignature wotsCSignature;
        bytes[] authPath;
    }

    struct LegacyStatelessSignature {
        LegacyForsSignature fors;
        LegacyHypertreeLayerSignature[] hypertree;
    }

    MeasurementStatefulVerifierHarness internal statefulVerifier;
    MeasurementStatelessVerifierHarness internal statelessVerifier;
    MeasurementAccountSigningHarness internal accountSigner;
    string internal vectors;

    function setUp() public {
        statefulVerifier = new MeasurementStatefulVerifierHarness();
        statelessVerifier = new MeasurementStatelessVerifierHarness();
        accountSigner = new MeasurementAccountSigningHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    function testMeasureCurrentShrincsStateful() public {
        (
            ShrincsTypes.SigningKey memory statefulSigningKey,
            ShrincsTypes.PublicKey memory statefulPublicKey,
            bool statefulKeygenOk
        ) = ShrincsTestSigner.keygen(bytes("measurement stateful seed"), 4);
        assertTrue(statefulKeygenOk, "stateful keygen must succeed");

        bytes memory statefulMessage = abi.encodePacked(keccak256("measurement stateful message"));
        (
            ,
            ShrincsTypes.StatefulSignature memory statefulSignature,
            bool statefulSignOk
        ) = ShrincsTestSigner.signStatefulRaw(statefulSigningKey, statefulMessage);
        assertTrue(statefulSignOk, "stateful signing must succeed");

        uint256 statefulSignerHashes =
            countStatefulSigningHashes(statefulSignature, statefulSigningKey.maxStatefulSignatures);
        uint256 statefulSignatureSize = rawStatefulSignatureSize(statefulSignature);
        uint256 statefulVerifierBodyGas =
            gasUsedForStatefulVerifyBody(statefulPublicKey, statefulMessage, statefulSignature);
        uint256 statefulFullExternalCallGas =
            gasUsedForStatefulVerifyExternal(statefulPublicKey, statefulMessage, statefulSignature);
        uint256 statefulCanonicalWrapperGas = gasUsedForStatefulCanonicalWrapper();

        emit log_named_uint("stateful.signer_hashes_excluding_keygen", statefulSignerHashes);
        emit log_named_uint("stateful.signature_size_bytes", statefulSignatureSize);
        emit log_named_uint("stateful.verifier_body_gas", statefulVerifierBodyGas);
        emit log_named_uint("stateful.full_external_call_gas", statefulFullExternalCallGas);
        emit log_named_uint("stateful.canonical_wrapper_gas", statefulCanonicalWrapperGas);
    }

    function testMeasureCurrentShrincsStateless() public {
        (
            ShrincsTypes.PublicKey memory statelessPublicKey,
            bytes memory statelessMessage,
            ShrincsTypes.StatelessSignature memory statelessSignature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");

        uint256 statelessSignerHashes = countStatelessSigningHashes(statelessSignature);
        uint256 statelessSignatureSize = rawStatelessSignatureSize(statelessSignature);
        uint256 statelessVerifierBodyGas =
            gasUsedForStatelessVerifyBody(statelessPublicKey, statelessMessage, statelessSignature);
        uint256 statelessFullExternalCallGas =
            gasUsedForStatelessVerifyExternal(statelessPublicKey, statelessMessage, statelessSignature);
        uint256 statelessCanonicalWrapperGas = gasUsedForStatelessCanonicalWrapper();

        emit log_named_uint("stateless.signer_hashes_excluding_keygen", statelessSignerHashes);
        emit log_named_uint("stateless.signature_size_bytes", statelessSignatureSize);
        emit log_named_uint("stateless.verifier_body_gas", statelessVerifierBodyGas);
        emit log_named_uint("stateless.full_external_call_gas", statelessFullExternalCallGas);
        emit log_named_uint("stateless.canonical_wrapper_gas", statelessCanonicalWrapperGas);
    }

    function gasUsedForStatefulVerifyBody(
        ShrincsTypes.PublicKey memory publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature memory signature
    ) internal returns (uint256 used) {
        bytes32 expectedPublicKeyCommitment = publicKeyCommitmentWord(publicKey);
        (bool ok, uint256 measured) =
            statefulVerifier.measureVerifyUnsafeRaw(expectedPublicKeyCommitment, publicKey, message, signature);
        assertTrue(ok, "stateful verifier measurement input must verify");
        used = measured;
    }

    function gasUsedForStatefulVerifyExternal(
        ShrincsTypes.PublicKey memory publicKey,
        bytes memory message,
        ShrincsTypes.StatefulSignature memory signature
    ) internal returns (uint256 used) {
        bytes32 expectedPublicKeyCommitment = publicKeyCommitmentWord(publicKey);
        uint256 beforeGas = gasleft();
        bool ok = statefulVerifier.verifyUnsafeRaw(expectedPublicKeyCommitment, publicKey, message, signature);
        used = beforeGas - gasleft();
        assertTrue(ok, "stateful external verifier measurement input must verify");
    }

    function gasUsedForStatelessVerifyBody(
        ShrincsTypes.PublicKey memory publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature memory signature
    ) internal returns (uint256 used) {
        bytes32 expectedPublicKeyCommitment = publicKeyCommitmentWord(publicKey);
        (bool ok, uint256 measured) =
            statelessVerifier.measureVerifyUnsafeRaw(expectedPublicKeyCommitment, publicKey, message, signature);
        assertTrue(ok, "stateless verifier measurement input must verify");
        used = measured;
    }

    function gasUsedForStatelessVerifyExternal(
        ShrincsTypes.PublicKey memory publicKey,
        bytes memory message,
        ShrincsTypes.StatelessSignature memory signature
    ) internal returns (uint256 used) {
        bytes32 expectedPublicKeyCommitment = publicKeyCommitmentWord(publicKey);
        uint256 beforeGas = gasleft();
        bool ok = statelessVerifier.verifyUnsafeRaw(expectedPublicKeyCommitment, publicKey, message, signature);
        used = beforeGas - gasleft();
        assertTrue(ok, "stateless external verifier measurement input must verify");
    }

    function gasUsedForStatefulCanonicalWrapper() internal returns (uint256 used) {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("measurement canonical stateful seed"), 4);
        assertTrue(keygenOk, "canonical stateful keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));

        (
            ,
            ,
            ShrincsTypes.StatefulSignature memory signature,
            bool signOk
        ) = ShrincsAccountSigningFacade.signStatefulActionNow(account, signingKey, ACTION_TYPE, PAYLOAD_HASH);
        assertTrue(signOk, "canonical stateful signing must succeed");

        uint256 beforeGas = gasleft();
        bool ok = account.verifyStatefulAction(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature);
        uint256 measured = beforeGas - gasleft();
        assertTrue(ok, "canonical stateful wrapper measurement must verify");
        used = measured;
    }

    function gasUsedForStatelessCanonicalWrapper() internal returns (uint256 used) {
        (ShrincsTypes.SigningKey memory signingKey, ShrincsTypes.PublicKey memory publicKey, bool keygenOk) =
            ShrincsAccountSigningFacade.keygen(bytes("measurement canonical stateless seed"), 4);
        assertTrue(keygenOk, "canonical stateless keygen must succeed");

        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(ShrincsAccountSigningFacade.publicKeyCommitmentWord(publicKey));

        (, bytes32 sessionId, bool beginOk) = ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
            accountSigner, account, signingKey, publicKey, ACTION_TYPE, PAYLOAD_HASH
        );
        assertTrue(beginOk, "canonical stateless signing must begin");

        (ShrincsTypes.StatelessSignature memory signature, bool completeOk) =
            ShrincsAccountSigningFacade.completeStatelessSession(accountSigner, sessionId);
        assertTrue(completeOk, "canonical stateless signing must complete");

        uint256 beforeGas = gasleft();
        bool ok = account.verifyStatelessAction(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature);
        uint256 measured = beforeGas - gasleft();
        assertTrue(ok, "canonical stateless wrapper measurement must verify");
        used = measured;
    }

    function publicKeyCommitmentWord(ShrincsTypes.PublicKey memory publicKey) internal pure returns (bytes32 out) {
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            out := mload(add(commitmentBytes, 32))
        }
    }

    function rawStatefulSignatureSize(ShrincsTypes.StatefulSignature memory signature)
        internal
        pure
        returns (uint256 size)
    {
        size = 32 + 4;
        size += 32 * signature.chains.length;
        size += 32 * signature.authPath.length;
    }

    function rawStatelessSignatureSize(ShrincsTypes.StatelessSignature memory signature)
        internal
        pure
        returns (uint256 size)
    {
        size += signature.fors.randomizer.length + 4;
        for (uint256 i = 0; i < signature.fors.entries.length; ++i) {
            size += signature.fors.entries[i].secretLeaf.length;
            for (uint256 j = 0; j < signature.fors.entries[i].authPath.length; ++j) {
                size += signature.fors.entries[i].authPath[j].length;
            }
        }

        for (uint256 i = 0; i < signature.hypertree.length; ++i) {
            size += 8 + 4;
            size += signature.hypertree[i].wotsCPkHash.length;
            size += signature.hypertree[i].wotsCSignature.randomizer.length + 4;
            for (uint256 j = 0; j < signature.hypertree[i].wotsCSignature.chains.length; ++j) {
                size += signature.hypertree[i].wotsCSignature.chains[j].length;
            }
            for (uint256 j = 0; j < signature.hypertree[i].authPath.length; ++j) {
                size += signature.hypertree[i].authPath[j].length;
            }
        }
    }

    function countStatefulSigningHashes(ShrincsTypes.StatefulSignature memory signature, uint32 maxStatefulSignatures)
        internal
        pure
        returns (uint256 count)
    {
        uint256 leafIndex = signature.authPath.length;
        uint256 attempts = uint256(signature.counter) + 1;
        count = 1; // stateful randomizer
        count += attempts; // one digest per grind attempt
        count += statefulWotsSigningHashes(); // successful WOTS-C chain revelation
        count += statefulAuthPathHashes(uint32(leafIndex), maxStatefulSignatures);
    }

    function statefulWotsSigningHashes() internal pure returns (uint256 count) {
        count = ShrincsTypes.WOTS_CHAINS_STATEFUL; // one chain secret per chain
        count += ShrincsTypes.WOTS_TARGET_SUM_STATEFUL; // total revealed chain steps at success
    }

    function statefulAuthPathHashes(uint32 leafIndex, uint32 maxStatefulSignatures)
        internal
        pure
        returns (uint256 count)
    {
        if (leafIndex < maxStatefulSignatures) {
            count += statefulSubtreeRootHashes(leafIndex + 1, maxStatefulSignatures);
        } else {
            count += 1; // empty tail marker
        }
        count += uint256(leafIndex - 1) * statefulWotsPublicKeyHashes();
    }

    function statefulSubtreeRootHashes(uint32 leafIndex, uint32 maxStatefulSignatures)
        internal
        pure
        returns (uint256 count)
    {
        count = 1; // statefulEmptyTail
        uint256 liveLeaves = uint256(maxStatefulSignatures) - uint256(leafIndex) + 1;
        count += liveLeaves * (statefulWotsPublicKeyHashes() + 1); // WOTS pk hash + parent hash per leaf
    }

    function statefulWotsPublicKeyHashes() internal pure returns (uint256 count) {
        count = uint256(ShrincsTypes.WOTS_CHAINS_STATEFUL) * uint256(ShrincsTypes.WOTS_BASE_STATEFUL);
        count += 1; // final compressed pk hash
    }

    function countStatelessSigningHashes(ShrincsTypes.StatelessSignature memory signature)
        internal
        pure
        returns (uint256 count)
    {
        uint256 forsAttempts = uint256(signature.fors.counter) + 1;
        uint256 forsDigestBytes = (
            uint256(ShrincsTypes.NUM_FORS_TREES) * uint256(ShrincsTypes.FORS_TREE_HEIGHT)
                + uint256(ShrincsTypes.HYPERTREE_HEIGHT) + 7
        ) / 8;
        uint256 forsDigestBlocks = (forsDigestBytes + 31) / 32;

        count = 1; // FORS randomizer
        count += forsDigestBlocks * forsAttempts; // FORS digest expansion hashes
        count += statelessForsTreeHashes() * signature.fors.entries.length;
        count += 1; // final "fors-pk" compression

        uint32 subtreeHeight = uint32(ShrincsTypes.HYPERTREE_HEIGHT / ShrincsTypes.NUM_HYPERTREE_LAYERS);
        uint256 authVirtualNodes = hypertreeAuthVirtualNodeHashes(subtreeHeight);
        uint256 rootVirtualNode = hypertreeVirtualNodeHashes(subtreeHeight);

        for (uint256 i = 0; i < signature.hypertree.length; ++i) {
            count += 1; // hypertree layer seed
            count += 1; // hypertree leaf seed
            count += 1; // hypertree wots sk seed
            count += statelessWotsPublicKeyHashes(); // current layer pk hash
            count += 1; // WOTS randomizer
            count += uint256(signature.hypertree[i].wotsCSignature.counter) + 1; // WOTS digest attempts
            count += statelessWotsSigningHashes(); // successful WOTS chain revelation
            count += authVirtualNodes; // auth-path sibling reconstruction
            count += rootVirtualNode; // next layer root reconstruction
        }
    }

    function statelessForsTreeHashes() internal pure returns (uint256 count) {
        uint256 leafCount = uint256(1) << ShrincsTypes.FORS_TREE_HEIGHT;
        count = 3 * leafCount - 1; // leaf secret + leaf hash per leaf, plus all internal nodes
    }

    function statelessWotsPublicKeyHashes() internal pure returns (uint256 count) {
        count = uint256(ShrincsTypes.NUM_WOTS_CHAINS) * uint256(ShrincsTypes.WOTS_CHAIN_LEN);
        count += 1; // final compressed pk hash
    }

    function statelessWotsSigningHashes() internal pure returns (uint256 count) {
        count = ShrincsTypes.NUM_WOTS_CHAINS; // one secret per chain
        count += ShrincsTypes.WOTS_TARGET_SUM_STATEFUL; // total revealed chain steps at success
    }

    function hypertreeAuthVirtualNodeHashes(uint32 subtreeHeight) internal pure returns (uint256 count) {
        for (uint32 level = 0; level < subtreeHeight; ++level) {
            count += hypertreeVirtualNodeHashes(level);
        }
    }

    function hypertreeVirtualNodeHashes(uint32 height) internal pure returns (uint256 count) {
        count = 2 + statelessWotsPublicKeyHashes(); // leafSeed + wotsSkSeed + leaf WOTS pk
        for (uint32 level = 0; level < height; ++level) {
            count = 2 * count + 1; // left subtree + right subtree + node hash
        }
    }

    function decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            ShrincsTypes.PublicKey memory publicKey,
            bytes memory message,
            ShrincsTypes.StatelessSignature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            LegacyPublicKey memory legacyPublicKey,
            bytes memory legacyMessage,
            LegacyStatelessSignature memory legacySignature
        ) = abi.decode(args, (LegacyPublicKey, bytes, LegacyStatelessSignature));

        publicKey = publicKeyFromParts(
            legacyPublicKey.statefulPublicKey, legacyPublicKey.pkSeed, legacyPublicKey.hypertreeRoot
        );
        bytes memory encodedCommitment =
            vm.parseJsonBytes(vectors, string.concat(trimCalldataSuffix(vectorKey), ".publicKey.publicKeyCommitment"));
        publicKey.publicKeyCommitment = encodedCommitment;

        message = legacyMessage;
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    function convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (ShrincsTypes.StatelessSignature memory signature)
    {
        ShrincsTypes.ForsEntry[] memory entries = new ShrincsTypes.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = ShrincsTypes.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf, authPath: legacy.fors.entries[i].authPath
            });
        }

        ShrincsTypes.HypertreeLayerSignature[] memory layers =
            new ShrincsTypes.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = ShrincsTypes.HypertreeLayerSignature({
                treeIndex: legacy.hypertree[i].treeIndex,
                leafIndex: legacy.hypertree[i].leafIndex,
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: ShrincsTypes.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature.randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = ShrincsTypes.StatelessSignature({
            fors: ShrincsTypes.ForsSignature({
                randomizer: legacy.fors.randomizer, counter: legacy.fors.counter, entries: entries
            }),
            hypertree: layers
        });
    }

    function publicKeyFromParts(bytes memory statefulPublicKey, bytes memory pkSeed, bytes memory hypertreeRoot)
        internal
        pure
        returns (ShrincsTypes.PublicKey memory)
    {
        bytes32 commitment = keccak256(abi.encodePacked("shrincs-public-key", statefulPublicKey, pkSeed, hypertreeRoot));
        return ShrincsTypes.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment),
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
    }

    function vectorArgs(string memory vectorKey) internal returns (bytes memory) {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
    }

    function trimCalldataSuffix(string memory path) internal pure returns (string memory trimmed) {
        bytes memory source = bytes(path);
        bytes memory suffix = bytes(".calldata");
        require(source.length >= suffix.length, "path too short");
        uint256 trimmedLength = source.length - suffix.length;
        bytes memory out = new bytes(trimmedLength);
        for (uint256 i = 0; i < trimmedLength; ++i) {
            out[i] = source[i];
        }
        trimmed = string(out);
    }

    function stripSelector(bytes memory input) internal pure returns (bytes memory output) {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }
}
