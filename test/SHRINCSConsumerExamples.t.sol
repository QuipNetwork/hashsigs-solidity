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
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {SHRINCSVerifier} from "../contracts/SHRINCSVerifier.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {
    SHRINCSERC7913ConsumerExample
} from "../contracts/examples/SHRINCSERC7913ConsumerExample.sol";
import {
    SHRINCSStatelessConsumerExample
} from "../contracts/examples/SHRINCSStatelessConsumerExample.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";

contract ConsumerStatefulVerifierHarness is SHRINCSVerifier {
    function _pinnedSphincsPlusC() internal pure override returns (address) {
        return address(0);
    }
}

contract ConsumerStatelessVerifierHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

contract ConsumerDelegationSigner is SHRINCSStatelessVectorSigner {}

contract RevertingERC7913Verifier {
    function verify(bytes calldata, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        revert("boom");
    }
}

contract SHRINCSConsumerExamplesTest is Test {
    ConsumerStatefulVerifierHarness internal statefulVerifier;
    ConsumerStatelessVerifierHarness internal statelessVerifier;
    ConsumerDelegationSigner internal signer;
    RevertingERC7913Verifier internal revertingVerifier;

    function setUp() public {
        statefulVerifier = new ConsumerStatefulVerifierHarness();
        signer = new ConsumerDelegationSigner();
        revertingVerifier = new RevertingERC7913Verifier();
    }

    function testERC7913ConsumerAcceptsValidStatefulSignature() public {
        (
            SHRINCSERC7913ConsumerExample consumer,
            bytes32 signedHash,
            bytes memory validEnvelope
        ) = buildStatefulConsumerFixture();

        assertTrue(
            consumer.isAuthorized(signedHash, validEnvelope),
            "generic consumer must accept a valid ERC-7913 stateful envelope"
        );
    }

    function testERC7913ConsumerRejectsTamperedStatefulHash() public {
        (
            SHRINCSERC7913ConsumerExample consumer,,
            bytes memory validEnvelope
        ) = buildStatefulConsumerFixture();

        assertFalse(
            consumer.isAuthorized(
                keccak256("different stateful hash"), validEnvelope
            ),
            "generic consumer must reject a hash the signature did not sign"
        );
    }

    function testERC7913ConsumerRequireAuthorizedOnValidStatefulSignature()
        public
    {
        (
            SHRINCSERC7913ConsumerExample consumer,
            bytes32 signedHash,
            bytes memory validEnvelope
        ) = buildStatefulConsumerFixture();

        consumer.requireAuthorized(signedHash, validEnvelope);
    }

    function testERC7913ConsumerRequireAuthorizedRevertsOnInvalidStatefulSig()
        public
    {
        (
            SHRINCSERC7913ConsumerExample consumer,,
            bytes memory validEnvelope
        ) = buildStatefulConsumerFixture();

        vm.expectRevert("invalid signature");
        consumer.requireAuthorized(
            keccak256("different stateful hash"), validEnvelope
        );
    }

    function testERC7913ConsumerReturnsFalseWhenVerifierReverts() public {
        // line-length: allow — fmt canonical constructor head exceeds cap
        SHRINCSERC7913ConsumerExample consumer = new SHRINCSERC7913ConsumerExample(
            address(revertingVerifier), abi.encodePacked(bytes32(uint256(1)))
        );
        assertFalse(
            consumer.isAuthorized(keccak256("hash"), bytes("signature")),
            "consumer must normalize verifier reverts to false"
        );
    }

    function testERC7913ConsumerRejectsBadConstructionInputs() public {
        vm.expectRevert("verifier is zero");
        new SHRINCSERC7913ConsumerExample(
            address(0), abi.encodePacked(bytes32(uint256(1)))
        );

        vm.expectRevert("trustedKey must be 32 bytes");
        new SHRINCSERC7913ConsumerExample(
            address(statefulVerifier), bytes("")
        );
    }

    function testStatelessConsumerAcceptsValidStatelessSignature() public {
        vm.skip(SHRINCSParams.HASH_LEN != 32);

        (
            SHRINCSStatelessConsumerExample consumer,
            bytes32 signedHash,
            bytes memory validEnvelope
        ) = buildStatelessConsumerFixture();

        assertTrue(
            consumer.isAuthorizedStateless(signedHash, validEnvelope),
            "stateless consumer must accept a valid delegated envelope"
        );
    }

    function testStatelessConsumerRejectsTamperedStatelessHash() public {
        vm.skip(SHRINCSParams.HASH_LEN != 32);

        (
            SHRINCSStatelessConsumerExample consumer,,
            bytes memory validEnvelope
        ) = buildStatelessConsumerFixture();

        assertFalse(
            consumer.isAuthorizedStateless(
                keccak256("different stateless hash"), validEnvelope
            ),
            "stateless consumer must reject a hash the signature did not sign"
        );
    }

    function testStatelessConsumerRequireAuthorizedOnValidStatelessSignature()
        public
    {
        vm.skip(SHRINCSParams.HASH_LEN != 32);

        (
            SHRINCSStatelessConsumerExample consumer,
            bytes32 signedHash,
            bytes memory validEnvelope
        ) = buildStatelessConsumerFixture();

        consumer.requireAuthorizedStateless(signedHash, validEnvelope);
    }

    function testStatelessConsumerRequireAuthorizedRevertsOnInvalidSignature()
        public
    {
        vm.skip(SHRINCSParams.HASH_LEN != 32);

        (
            SHRINCSStatelessConsumerExample consumer,,
            bytes memory validEnvelope
        ) = buildStatelessConsumerFixture();

        vm.expectRevert("invalid stateless signature");
        consumer.requireAuthorizedStateless(
            keccak256("different stateless hash"), validEnvelope
        );
    }

    function testStatelessConsumerReturnsFalseWhenVerifierReverts() public {
        // line-length: allow — fmt canonical constructor head exceeds cap
        SHRINCSStatelessConsumerExample consumer = new SHRINCSStatelessConsumerExample(
            address(revertingVerifier), abi.encodePacked(bytes32(uint256(1)))
        );
        assertFalse(
            consumer.isAuthorizedStateless(
                keccak256("hash"), bytes("signature")
            ),
            "stateless consumer must normalize verifier reverts to false"
        );
    }

    function testStatelessConsumerRejectsBadConstructionInputs() public {
        vm.expectRevert("verifier is zero");
        new SHRINCSStatelessConsumerExample(
            address(0), abi.encodePacked(bytes32(uint256(1)))
        );

        vm.expectRevert("trustedKey must be 32 bytes");
        new SHRINCSStatelessConsumerExample(
            address(statefulVerifier), bytes("")
        );
    }

    function buildStatefulConsumerFixture()
        internal
        returns (
            SHRINCSERC7913ConsumerExample consumer,
            bytes32 signedHash,
            bytes memory validEnvelope
        )
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSTestSigner.keygen(
            bytes("shrincs consumer stateful fixture"), 4
        );
        assertTrue(keygenOk, "in-test keygen must succeed");

        signedHash = keccak256("shrincs consumer stateful vector");
        bytes memory message = abi.encodePacked(signedHash);

        (SHRINCS.Signature memory signature, bool signOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        assertTrue(signOk, "stateful signing must succeed");

        bytes memory key = publicKey.publicKeyCommitment;
        validEnvelope =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
        consumer = new SHRINCSERC7913ConsumerExample(
            address(statefulVerifier), key
        );
    }

    function buildStatelessConsumerFixture()
        internal
        returns (
            SHRINCSStatelessConsumerExample consumer,
            bytes32 signedHash,
            bytes memory validEnvelope
        )
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool keygenOk
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("shrincs consumer stateless fixture"), 4
        );
        assertTrue(keygenOk, "in-test keygen must succeed");

        signedHash = keccak256("shrincs consumer stateless vector");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(signedHash)
        );
        assertTrue(beginOk, "stateless begin must succeed");

        SPHINCSPlusC.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        assertTrue(completeOk, "stateless completion must succeed");

        statelessVerifier = new ConsumerStatelessVerifierHarness();
        deployCodeTo(
            "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak",
            "",
            statelessVerifier.pinned()
        );

        bytes memory key = publicKey.publicKeyCommitment;
        validEnvelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
        consumer = new SHRINCSStatelessConsumerExample(
            address(statelessVerifier), key
        );
    }
}
