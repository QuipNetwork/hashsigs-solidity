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

import {Test} from "forge-std/Test.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";

contract Issue09CanonicalRootHarness {
    function validStatefulPublicKeyEncoding(bytes calldata encoded)
        external
        pure
        returns (bool)
    {
        return SHRINCS.validStatefulPublicKeyEncoding(encoded);
    }

    function validPublicKey(SHRINCS.PublicKey calldata publicKey)
        external
        pure
        returns (bool)
    {
        return SHRINCS.validPublicKey(publicKey);
    }

    function rotateStatefulViaStateless(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext calldata context,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external view returns (bytes32) {
        return SHRINCS.rotateStatefulViaStateless(
            expectedCommitment,
            currentPublicKey,
            context,
            recoverySignature,
            nextStatefulKey
        );
    }
}

contract Issue09CanonicalRootValidationTest is Test {
    // HASH_WORD_BYTES: width of every hash-sized field in the stateless
    // signature wire format. The verifier reads each randomizer, FORS
    // leaf, auth node, WOTS-C chain, and public-key hash with a single
    // calldataload and its shape checks pin them to one 32-byte word,
    // independent of the profile HASH_LEN.
    uint256 internal constant HASH_WORD_BYTES = 32;

    // ROTATION_REJECT_GAS_CEILING: gas ceiling for one rotation call
    // rejected on a noncanonical next stateful root, measured around the
    // staticcall alone with the signature already encoded. Under
    // 128s-q18 the guarded rejection costs 9_427 gas. Deleting the
    // canonical-root check in SHRINCS.rotateStatefulViaStateless lets
    // the same call reach the rotation-message hash and the FORS-C
    // digest for 20_024 gas, so this ceiling sits between the two with
    // roughly 50% headroom on each side.
    uint256 internal constant ROTATION_REJECT_GAS_CEILING = 14_000;

    Issue09CanonicalRootHarness internal harness;

    function setUp() public {
        harness = new Issue09CanonicalRootHarness();
    }

    function testFuzzAcceptsCanonicalStatefulRoot(bytes32 root) public view {
        bytes32 canonicalRoot = root & SHRINCSParams.HASH_MASK;
        assertTrue(
            harness.validStatefulPublicKeyEncoding(
                _statefulPublicKey(canonicalRoot)
            )
        );
    }

    function testFuzzRejectsDirtyStatefulRoot(bytes32 root) public view {
        bytes32 dirtyMask = ~SHRINCSParams.HASH_MASK;
        if (dirtyMask == bytes32(0)) return;
        bytes32 dirtyRoot = (root & SHRINCSParams.HASH_MASK)
            | (dirtyMask & bytes32(uint256(1)));
        assertFalse(
            harness.validStatefulPublicKeyEncoding(
                _statefulPublicKey(dirtyRoot)
            )
        );
    }

    function testValidPublicKeyAcceptsCanonicalRoot() public view {
        SHRINCS.PublicKey memory publicKey =
            _publicKey(bytes32(uint256(1)) & SHRINCSParams.HASH_MASK);
        assertTrue(harness.validPublicKey(publicKey));
    }

    function testValidPublicKeyRejectsDirtyRootWithMatchingCommitment()
        public
        view
    {
        bytes32 dirtyMask = ~SHRINCSParams.HASH_MASK;
        if (dirtyMask == bytes32(0)) return;
        SHRINCS.PublicKey memory publicKey =
            _publicKey(dirtyMask & bytes32(uint256(1)));
        assertFalse(harness.validPublicKey(publicKey));
    }

    function testRotateStatefulRejectsDirtyNextRoot() public view {
        bytes32 dirtyMask = ~SHRINCSParams.HASH_MASK;
        if (dirtyMask == bytes32(0)) return;

        SHRINCS.PublicKey memory currentPublicKey =
            _publicKey(bytes32(uint256(1)) & SHRINCSParams.HASH_MASK);
        bytes32 expectedCommitment = SHRINCS.publicKeyCommitmentFromParts(
            currentPublicKey.statefulPublicKey,
            currentPublicKey.pkSeed,
            currentPublicKey.hypertreeRoot
        );

        SHRINCS.RotationContext memory context = SHRINCS.RotationContext({
            domainSeparator: bytes32(uint256(1)), nonce: 0, keyVersion: 0
        });

        bytes32 dirtyRoot = dirtyMask & bytes32(uint256(1));
        bytes memory dirtyEncoded = _statefulPublicKey(dirtyRoot);
        SHRINCS.StatefulRotationTarget memory nextStatefulKey;
        nextStatefulKey.statefulPublicKey = dirtyEncoded;
        nextStatefulKey.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(
                dirtyEncoded,
                currentPublicKey.pkSeed,
                currentPublicKey.hypertreeRoot
            )
        );

        // Every array length in this recovery signature matches the
        // compiled profile, so it clears each shape check the stateless
        // verifier applies before hashing, and only the canonical-root
        // guard keeps the call away from that work. Encode it outside
        // the measured window: ABI-encoding a full-size stateless
        // signature costs several times the rejection itself and would
        // mask the difference the assertion below measures.
        bytes memory callData = abi.encodeCall(
            harness.rotateStatefulViaStateless,
            (
                expectedCommitment,
                currentPublicKey,
                context,
                _shapeValidRecoverySignature(),
                nextStatefulKey
            )
        );

        uint256 gasBefore = gasleft();
        (bool ok, bytes memory returnData) =
            address(harness).staticcall(callData);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "rejection must return, not revert");
        assertEq(abi.decode(returnData, (bytes32)), bytes32(0));
        // Without the canonical-root guard the same call rebuilds the
        // rotation message hash and runs the FORS-C digest, costing far
        // more than this ceiling. It stops there rather than walking
        // every FORS tree: the FORS-C convention requires the omitted
        // final tree to select leaf 0, and an unground randomizer meets
        // that only with probability 2^-FORS_TREE_HEIGHT. Reaching the
        // tree and hypertree walks would need a ground signature, which
        // costs 2^24 digest evaluations under the 128-bit profiles.
        assertLt(
            gasUsed,
            ROTATION_REJECT_GAS_CEILING,
            "dirty next root must be rejected before any stateless work"
        );

        bytes32 canonicalRoot = bytes32(uint256(1)) & SHRINCSParams.HASH_MASK;
        assertTrue(
            harness.validStatefulPublicKeyEncoding(
                _statefulPublicKey(canonicalRoot)
            )
        );
        assertFalse(harness.validStatefulPublicKeyEncoding(dirtyEncoded));
    }

    // _shapeValidRecoverySignature: Build a stateless recovery signature
    // sized for the compiled profile and filled with zero words. It is
    // cryptographically invalid, but every length the FORS-C and
    // hypertree verifiers check is correct, so a rotation that reaches
    // the stateless verifier pays for the digest work instead of
    // returning on a malformed-shape branch.
    function _shapeValidRecoverySignature()
        internal
        pure
        returns (SPHINCSPlusC.Signature memory signature)
    {
        // FORS-C omits the final FORS tree by forcing its leaf index to
        // zero, so verification expects k - 1 revealed entries.
        uint256 signedTrees = uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
        uint256 forsHeight = uint256(SHRINCSParams.FORS_TREE_HEIGHT);
        signature.fors.randomizer = new bytes(HASH_WORD_BYTES);
        signature.fors.entries = new FORSMinusC.ForsEntry[](signedTrees);
        for (uint256 tree = 0; tree < signedTrees; ++tree) {
            FORSMinusC.ForsEntry memory entry = signature.fors.entries[tree];
            entry.secretLeaf = new bytes(HASH_WORD_BYTES);
            entry.authPath = new bytes[](forsHeight);
            for (uint256 node = 0; node < forsHeight; ++node) {
                entry.authPath[node] = new bytes(HASH_WORD_BYTES);
            }
        }

        // Each layer carries one WOTS-C signature over NUM_WOTS_CHAINS
        // chains plus an auth path of one subtree height (h / d).
        uint256 layerCount = uint256(SHRINCSParams.NUM_HYPERTREE_LAYERS);
        uint256 chainCount = uint256(SHRINCSParams.NUM_WOTS_CHAINS);
        uint256 subtreeHeight =
            uint256(SHRINCSParams.HYPERTREE_HEIGHT) / layerCount;
        signature.hypertree =
            new Hypertree.HypertreeLayerSignature[](layerCount);
        for (uint256 layer = 0; layer < layerCount; ++layer) {
            Hypertree.HypertreeLayerSignature memory layerSignature =
                signature.hypertree[layer];
            layerSignature.wotsCPkHash = new bytes(HASH_WORD_BYTES);
            layerSignature.wotsCSignature.randomizer =
                new bytes(HASH_WORD_BYTES);
            layerSignature.wotsCSignature.chains = new bytes[](chainCount);
            for (uint256 chain = 0; chain < chainCount; ++chain) {
                layerSignature.wotsCSignature.chains[chain] =
                    new bytes(HASH_WORD_BYTES);
            }
            layerSignature.authPath = new bytes[](subtreeHeight);
            for (uint256 node = 0; node < subtreeHeight; ++node) {
                layerSignature.authPath[node] = new bytes(HASH_WORD_BYTES);
            }
        }
    }

    function _publicKey(bytes32 root)
        internal
        pure
        returns (SHRINCS.PublicKey memory publicKey)
    {
        publicKey.statefulPublicKey = _statefulPublicKey(root);
        publicKey.pkSeed = abi.encodePacked(bytes32(uint256(2)));
        publicKey.hypertreeRoot = abi.encodePacked(bytes32(uint256(3)));
        publicKey.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    function _statefulPublicKey(bytes32 root)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes32(uint256(4)), root, uint32(4));
    }
}
