// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

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
}

contract Issue09CanonicalRootValidationTest is Test {
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
