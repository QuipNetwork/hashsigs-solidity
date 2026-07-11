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
import {SHRINCSCodec} from "../contracts/SHRINCSCodec.sol";
import {SHRINCSCore} from "../contracts/SHRINCSCore.sol";
import {SPHINCSPlusCCore} from "../contracts/SPHINCSPlusCCore.sol";
import {UXMSS} from "../contracts/UXMSS.sol";
import {
    SHRINCSAccountVerifierExample
} from "../contracts/examples/SHRINCSAccountVerifierExample.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract CodecCanonicitySigner is SHRINCSStatelessVectorSigner {}

/// @notice Exposes each codec walk-B validator (the production `ok` flag)
/// and a re-encode-equality reference over calldata, so the differential
/// tests can prove the walk equals `keccak256(payload) ==
/// keccak256(abi.encode(decoded...))` for every envelope shape.
contract CodecCanonicityHarness {
    function walkStateful(bytes calldata payload)
        external
        pure
        returns (bool ok)
    {
        (,, ok) = SHRINCSCodec.decodeStatefulEnvelope(payload);
    }

    function walkStateless(bytes calldata payload)
        external
        pure
        returns (bool ok)
    {
        (,, ok) = SHRINCSCodec.decodeStatelessEnvelope(payload);
    }

    function walkStatelessSig(bytes calldata payload)
        external
        pure
        returns (bool ok)
    {
        (, ok) = SHRINCSCodec.decodeStatelessSignatureEnvelope(payload);
    }

    /// @dev Reference: decode then require re-encoding to reproduce the
    /// exact bytes. Reverts on malformed input (out of scope for the walk,
    /// which the production caller reaches only after this would revert).
    function refStateful(bytes calldata payload)
        external
        pure
        returns (bool)
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature
        ) = abi.decode(
            payload, (SHRINCSCore.PublicKey, UXMSS.StatefulSignature)
        );
        return
            keccak256(payload) == keccak256(abi.encode(publicKey, signature));
    }

    function refStateless(bytes calldata payload)
        external
        pure
        returns (bool)
    {
        (
            SHRINCSCore.PublicKey memory publicKey,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = abi.decode(
            payload,
            (SHRINCSCore.PublicKey, SPHINCSPlusCCore.StatelessSignature)
        );
        return
            keccak256(payload) == keccak256(abi.encode(publicKey, signature));
    }

    function refStatelessSig(bytes calldata payload)
        external
        pure
        returns (bool)
    {
        SPHINCSPlusCCore.StatelessSignature memory signature =
            abi.decode(payload, (SPHINCSPlusCCore.StatelessSignature));
        return keccak256(payload) == keccak256(abi.encode(signature));
    }
}

contract SHRINCSCodecCanonicityTest is Test {
    bytes32 internal constant ACTION_TYPE = keccak256("codec-canonicity");
    bytes32 internal constant PAYLOAD_HASH = keccak256("codec payload");

    CodecCanonicityHarness internal harness;
    CodecCanonicitySigner internal signer;

    bytes internal statefulEnvelope;
    bytes internal statelessEnvelope;
    bytes internal statelessSigEnvelope;

    function setUp() public {
        harness = new CodecCanonicityHarness();
        signer = new CodecCanonicitySigner();
        // Build each fixture in its own call frame (external self-call) so
        // EVM memory resets between them; the ~90 KB stateless build would
        // otherwise exceed the per-frame memory limit stacked on top of the
        // stateful build's allocations.
        statefulEnvelope = this.buildStatefulEnvelope();
        (statelessEnvelope, statelessSigEnvelope) =
            this.buildStatelessEnvelopes();

        // The fixtures are canonical under both the walk and the reference.
        assertTrue(harness.walkStateful(statefulEnvelope), "stateful walk");
        assertTrue(harness.refStateful(statefulEnvelope), "stateful ref");
        assertTrue(
            harness.walkStateless(statelessEnvelope), "stateless walk"
        );
        assertTrue(harness.refStateless(statelessEnvelope), "stateless ref");
        assertTrue(
            harness.walkStatelessSig(statelessSigEnvelope), "sig walk"
        );
        assertTrue(harness.refStatelessSig(statelessSigEnvelope), "sig ref");
    }

    // ---- Concrete negatives ----------------------------------------------

    function testStatefulTrailingByteRejected() public view {
        bytes memory mutated = bytes.concat(statefulEnvelope, hex"00");
        assertFalse(harness.walkStateful(mutated));
        _assertStatefulAgrees(mutated);
    }

    function testStatelessTrailingByteRejected() public view {
        bytes memory mutated = bytes.concat(statelessEnvelope, hex"00");
        assertFalse(harness.walkStateless(mutated));
        _assertStatelessAgrees(mutated);
    }

    function testStatelessSigTrailingByteRejected() public view {
        bytes memory mutated = bytes.concat(statelessSigEnvelope, hex"00");
        assertFalse(harness.walkStatelessSig(mutated));
        _assertStatelessSigAgrees(mutated);
    }

    function testStatefulNonMinimalTopOffsetRejected() public view {
        bytes memory mutated = _clone(statefulEnvelope);
        // Bump the PublicKey offset (word 0) above its minimal value 64.
        _setWord(mutated, 0, 96);
        assertFalse(harness.walkStateful(mutated));
        _assertStatefulAgrees(mutated);
    }

    function testStatelessSigNonMinimalTopOffsetRejected() public view {
        bytes memory mutated = _clone(statelessSigEnvelope);
        // Bump the StatelessSignature offset (word 0) above minimal value 32.
        _setWord(mutated, 0, 64);
        assertFalse(harness.walkStatelessSig(mutated));
        _assertStatelessSigAgrees(mutated);
    }

    // ---- Differential fuzz (walk verdict == re-encode reference) ---------

    /// forge-config: default.fuzz.runs = 200
    function testFuzzStatefulWalkMatchesReference(
        uint256 wordIndex,
        uint256 xorMask
    ) public view {
        _assertStatefulAgrees(
            _mutateWord(statefulEnvelope, wordIndex, xorMask)
        );
    }

    /// forge-config: default.fuzz.runs = 200
    function testFuzzStatelessWalkMatchesReference(
        uint256 wordIndex,
        uint256 xorMask
    ) public view {
        _assertStatelessAgrees(
            _mutateWord(statelessEnvelope, wordIndex, xorMask)
        );
    }

    /// forge-config: default.fuzz.runs = 200
    function testFuzzStatelessSigWalkMatchesReference(
        uint256 wordIndex,
        uint256 xorMask
    ) public view {
        _assertStatelessSigAgrees(
            _mutateWord(statelessSigEnvelope, wordIndex, xorMask)
        );
    }

    /// forge-config: default.fuzz.runs = 200
    function testFuzzStatefulByteFlipMatchesReference(
        uint256 pos,
        uint8 value
    ) public view {
        bytes memory mutated = _clone(statefulEnvelope);
        mutated[pos % mutated.length] = bytes1(value);
        _assertStatefulAgrees(mutated);
    }

    /// forge-config: default.fuzz.runs = 200
    function testFuzzStatelessByteFlipMatchesReference(
        uint256 pos,
        uint8 value
    ) public view {
        bytes memory mutated = _clone(statelessEnvelope);
        mutated[pos % mutated.length] = bytes1(value);
        _assertStatelessAgrees(mutated);
    }

    // ---- Agreement helpers -----------------------------------------------

    // The full invariant: the walk accepts EXACTLY the canonical encodings,
    // i.e. walk(p) == (abi.decode(p) succeeds AND re-encoding reproduces p).
    // A decode revert counts as non-canonical (refOk = false), which pins
    // that the walk also rejects any input abi.decode would revert on — the
    // property the revert-model change relies on to never revert on
    // malformed input.
    function _assertStatefulAgrees(bytes memory payload) internal view {
        bool refOk;
        try harness.refStateful(payload) returns (bool r) {
            refOk = r;
        } catch {
            refOk = false;
        }
        assertEq(
            harness.walkStateful(payload),
            refOk,
            "stateful walk must match re-encode reference"
        );
    }

    function _assertStatelessAgrees(bytes memory payload) internal view {
        bool refOk;
        try harness.refStateless(payload) returns (bool r) {
            refOk = r;
        } catch {
            refOk = false;
        }
        assertEq(
            harness.walkStateless(payload),
            refOk,
            "stateless walk must match re-encode reference"
        );
    }

    function _assertStatelessSigAgrees(bytes memory payload) internal view {
        bool refOk;
        try harness.refStatelessSig(payload) returns (bool r) {
            refOk = r;
        } catch {
            refOk = false;
        }
        assertEq(
            harness.walkStatelessSig(payload),
            refOk,
            "stateless-sig walk must match re-encode reference"
        );
    }

    // ---- Fixture builders -------------------------------------------------

    function buildStatefulEnvelope() external pure returns (bytes memory) {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSTestSigner.keygen(bytes("codec stateful fixture"), 4);
        require(ok, "stateful keygen");
        bytes memory message =
            abi.encodePacked(keccak256("codec stateful message"));
        (UXMSS.StatefulSignature memory signature, bool signOk) =
            SHRINCSTestSigner.signStatefulRawAtLeaf(signingKey, 1, message);
        require(signOk, "stateful sign");
        return abi.encode(publicKey, signature);
    }

    function buildStatelessEnvelopes()
        external
        returns (bytes memory statelessEnv, bytes memory statelessSigEnv)
    {
        (
            SHRINCSCore.SigningKey memory signingKey,
            SHRINCSCore.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("codec stateless fixture"), 4
        );
        require(ok, "stateless keygen");
        // forgefmt: disable-next-line
        SHRINCSAccountVerifierExample account =
            new SHRINCSAccountVerifierExample(
                SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 sessionId;
        (, sessionId, ok) =
            SHRINCSAccountSigningFacade.beginStatelessActionSessionNow(
                signer,
                account,
                signingKey,
                publicKey,
                ACTION_TYPE,
                PAYLOAD_HASH
            );
        require(ok, "begin stateless");
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = SHRINCSAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        require(completeOk, "complete stateless");
        statelessEnv = abi.encode(publicKey, signature);
        statelessSigEnv = abi.encode(signature);
    }

    // ---- Byte helpers -----------------------------------------------------

    function _clone(bytes memory src) internal pure returns (bytes memory) {
        return bytes.concat(src);
    }

    function _mutateWord(
        bytes memory src,
        uint256 wordIndex,
        uint256 xorMask
    ) internal pure returns (bytes memory mutated) {
        mutated = _clone(src);
        uint256 words = mutated.length / 32;
        uint256 pos = (wordIndex % words) * 32;
        _setWord(mutated, pos, _readWord(mutated, pos) ^ xorMask);
    }

    function _setWord(bytes memory data, uint256 pos, uint256 value)
        internal
        pure
    {
        assembly {
            mstore(add(add(data, 32), pos), value)
        }
    }

    function _readWord(bytes memory data, uint256 pos)
        internal
        pure
        returns (uint256 value)
    {
        assembly {
            value := mload(add(add(data, 32), pos))
        }
    }
}
