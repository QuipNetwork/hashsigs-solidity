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
import {SPHINCSPlusCCore} from "../contracts/SPHINCSPlusCCore.sol";
import {
    ShrincsAccountEnvelope
} from "../contracts/examples/ShrincsAccountEnvelope.sol";
import {
    ShrincsAccountVerifierExample
} from "../contracts/examples/ShrincsAccountVerifierExample.sol";
import {
    ShrincsAccountSigningFacade
} from "./helpers/ShrincsAccountSigningFacade.sol";
import {
    ShrincsStatelessVectorSigner
} from "./helpers/ShrincsStatelessVectorSigner.sol";

contract CanonicitySigner is ShrincsStatelessVectorSigner {}

/// @notice Exposes both canonicity checks over calldata so tests can pass a
/// memory payload through an external boundary (mirrors production, where the
/// payload is the calldata tail so out-of-bounds reads return zero).
contract CanonicityHarness {
    function structural(bytes calldata payload)
        external
        pure
        returns (bool)
    {
        return ShrincsAccountEnvelope.isCanonicalStatelessEnvelope(payload);
    }

    /// @dev Reference implementation: decode then require the re-encoding to
    /// reproduce the exact bytes. Reverts on malformed input (like the
    /// production decode hop, whose revert is caught before the validator
    /// would run).
    function referenceCanonical(bytes calldata payload)
        external
        pure
        returns (bool)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            SPHINCSPlusCCore.StatelessSignature memory signature
        ) = abi.decode(
            payload,
            (
                SHRINCS.PublicKey,
                bytes32,
                bytes32,
                SPHINCSPlusCCore.StatelessSignature
            )
        );
        return keccak256(payload)
            == keccak256(
            abi.encode(publicKey, actionType, payloadHash, signature)
        );
    }
}

contract ShrincsAccountEnvelopeCanonicityTest is Test {
    bytes32 internal constant ACTION_TYPE = keccak256("measure");
    bytes32 internal constant PAYLOAD_HASH =
        keccak256("measurement payload");

    // Byte offsets of framing words in the canonical stateless envelope,
    // taken from the fixed ABI template (see ShrincsAccountEnvelope):
    //   [0]   offset to PublicKey (128)
    //   [96]  offset to StatelessSignature (576)
    //   [256] statefulPublicKey length (68)
    // statefulPublicKey data spans bytes 288..355 (68 bytes); its final word
    // is bytes 352..383, so the 28 padding bytes are 356..383.
    uint256 internal constant OFF_PK = 0;
    uint256 internal constant OFF_SIG = 96;
    uint256 internal constant LEN_STATEFUL_PK = 256;
    uint256 internal constant PAD_START = 356;
    uint256 internal constant PAD_END = 383;

    CanonicityHarness internal harness;
    CanonicitySigner internal signer;
    bytes internal baseEnvelope;

    function setUp() public {
        harness = new CanonicityHarness();
        signer = new CanonicitySigner();
        baseEnvelope = _buildEnvelope();
        // Sanity: the fixture is canonical under both checks.
        assertTrue(harness.structural(baseEnvelope), "fixture structural");
        assertTrue(
            harness.referenceCanonical(baseEnvelope), "fixture reference"
        );
    }

    // ---- Concrete negative categories ------------------------------------

    function testCanonicalAccepted() public view {
        assertTrue(harness.structural(baseEnvelope));
    }

    function testDirtyPaddingRejectedAtEveryPosition() public view {
        for (uint256 pos = PAD_START; pos <= PAD_END; pos++) {
            bytes memory mutated = _clone(baseEnvelope);
            mutated[pos] = 0x01;
            assertFalse(
                harness.structural(mutated),
                "dirty statefulPublicKey padding must be rejected"
            );
            // decode ignores padding, so re-encode differs -> reference also
            // rejects; the two agree.
            _assertAgreeIfDecodes(mutated);
        }
    }

    function testNonMinimalTopOffsetRejected() public view {
        // Bump the PublicKey offset above its minimal value.
        bytes memory mutated = _clone(baseEnvelope);
        _setWord(mutated, OFF_PK, 160);
        assertFalse(harness.structural(mutated));
        _assertAgreeIfDecodes(mutated);
    }

    function testOffsetAliasingPreservingLengthRejected() public view {
        // Point the StatelessSignature offset at the PublicKey region. Total
        // length is unchanged (only an offset word is overwritten).
        bytes memory mutated = _clone(baseEnvelope);
        _setWord(mutated, OFF_SIG, _readWord(baseEnvelope, OFF_PK));
        assertFalse(harness.structural(mutated));
        _assertAgreeIfDecodes(mutated);
    }

    function testOversizedLengthRejected() public view {
        bytes memory mutated = _clone(baseEnvelope);
        _setWord(mutated, LEN_STATEFUL_PK, type(uint256).max);
        assertFalse(harness.structural(mutated));
        _assertAgreeIfDecodes(mutated);
    }

    function testGapBytesRejected() public view {
        // Insert 32 bytes after the PublicKey tail without updating offsets.
        bytes memory mutated = _spliceZeros(baseEnvelope, 576, 32);
        assertFalse(harness.structural(mutated));
        _assertAgreeIfDecodes(mutated);
    }

    function testTrailingBytesRejected() public view {
        bytes memory mutated = bytes.concat(baseEnvelope, hex"00");
        assertFalse(harness.structural(mutated));
        _assertAgreeIfDecodes(mutated);
    }

    function testTruncationRejected() public view {
        bytes memory mutated = _truncate(baseEnvelope, 1);
        assertFalse(harness.structural(mutated));
    }

    function testLengthChangingWordCountRejected() public view {
        // A length that keeps the same word count but leaves dirty padding
        // is non-canonical: shrink 68 -> 67 and force the uncovered byte
        // nonzero.
        bytes memory shrink = _clone(baseEnvelope);
        _setWord(shrink, LEN_STATEFUL_PK, 67);
        shrink[355] = 0x2a;
        assertFalse(harness.structural(shrink));
        _assertAgreeIfDecodes(shrink);

        // A length that changes the data-word count (68 -> 36, three words to
        // two) shifts every following offset, so the framing no longer
        // matches. (Growing to 96 with zero fill is genuinely canonical, so
        // that case is covered by the differential fuzz, not asserted here.)
        bytes memory shrinkWord = _clone(baseEnvelope);
        _setWord(shrinkWord, LEN_STATEFUL_PK, 36);
        assertFalse(harness.structural(shrinkWord));
        _assertAgreeIfDecodes(shrinkWord);
    }

    // ---- Differential fuzz ------------------------------------------------

    /// @dev Perturb one 32-byte-aligned word by XOR and require the
    /// structural walk to agree with the re-encode reference when the mutant
    /// decodes. This is the executable equivalence proof.
    /// forge-config: default.fuzz.runs = 200
    function testFuzzStructuralMatchesReference(
        uint256 wordIndex,
        uint256 xorMask
    ) public view {
        bytes memory mutated = _clone(baseEnvelope);
        uint256 words = mutated.length / 32;
        uint256 pos = (wordIndex % words) * 32;
        _setWord(mutated, pos, _readWord(mutated, pos) ^ xorMask);
        _assertAgreeIfDecodes(mutated);
    }

    /// @dev Random single-byte flips at fuzzed positions.
    /// forge-config: default.fuzz.runs = 200
    function testFuzzByteFlipMatchesReference(uint256 pos, uint8 value)
        public
        view
    {
        bytes memory mutated = _clone(baseEnvelope);
        mutated[pos % mutated.length] = bytes1(value);
        _assertAgreeIfDecodes(mutated);
    }

    // ---- Helpers ----------------------------------------------------------

    /// @dev When the payload decodes, the structural walk MUST match the
    /// re-encode reference exactly. When decode reverts, production returns
    /// INVALID before the validator runs, so its output is out of scope.
    function _assertAgreeIfDecodes(bytes memory payload) internal view {
        try harness.referenceCanonical(payload) returns (bool refOk) {
            assertEq(
                harness.structural(payload),
                refOk,
                "structural walk must match re-encode reference"
            );
        } catch {
            // decode reverted: not reachable by the production validator.
        }
    }

    function _buildEnvelope() internal returns (bytes memory) {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = ShrincsAccountSigningFacade.keygen(
            bytes("canonicity stateless fixture seed"), 4
        );
        require(ok, "keygen");
        // forgefmt: disable-next-line
        ShrincsAccountVerifierExample account =
            new ShrincsAccountVerifierExample(
                ShrincsAccountSigningFacade.publicKeyCommitmentWord(
                    publicKey
                )
            );
        bytes32 sessionId;
        (, sessionId, ok) =
            ShrincsAccountSigningFacade.beginStatelessActionSessionNow(
                signer,
                account,
                signingKey,
                publicKey,
                ACTION_TYPE,
                PAYLOAD_HASH
            );
        require(ok, "begin");
        // line-length: allow — fmt canonical tuple head exceeds cap
        (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool completeOk
        ) = ShrincsAccountSigningFacade.completeStatelessSession(
            signer, sessionId
        );
        require(completeOk, "complete");
        return abi.encode(publicKey, ACTION_TYPE, PAYLOAD_HASH, signature);
    }

    function _clone(bytes memory src) internal pure returns (bytes memory) {
        return bytes.concat(src);
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

    function _spliceZeros(bytes memory src, uint256 insertAt, uint256 count)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory head = new bytes(insertAt);
        for (uint256 i = 0; i < insertAt; i++) {
            head[i] = src[i];
        }
        bytes memory tail = new bytes(src.length - insertAt);
        for (uint256 i = 0; i < tail.length; i++) {
            tail[i] = src[insertAt + i];
        }
        return bytes.concat(head, new bytes(count), tail);
    }

    function _truncate(bytes memory src, uint256 drop)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(src.length - drop);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = src[i];
        }
    }
}
