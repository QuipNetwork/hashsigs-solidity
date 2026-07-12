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
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCSCodec} from "../contracts/SHRINCSCodec.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract DelegationSigner is SHRINCSStatelessVectorSigner {}

/// @dev Exposes the internal pinned SPHINCSPlusC address so the test can
/// deploy the sibling verifier exactly where verifyStateless delegates.
contract SHRINCS256sRetagHarness is SHRINCS256sKeccak {
    function pinned() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}

/// @dev External `bytes calldata` entrypoints exercising the three re-tag
/// decoders under test against the abi.decode path they must match. Each
/// digest reads every decoded field, so equal digests prove equal fields.
contract RetagDigestHarness {
    // stateful -----------------------------------------------------------
    function retagStateful(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey calldata publicKey,
            SHRINCS.Signature calldata signature
        ) = SHRINCSCodec.statefulEnvelope(payload);
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                signature.randomizer,
                signature.counter,
                signature.chains,
                signature.authPath
            )
        );
    }

    function abiStateful(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature
        ) = abi.decode(payload, (SHRINCS.PublicKey, SHRINCS.Signature));
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                signature.randomizer,
                signature.counter,
                signature.chains,
                signature.authPath
            )
        );
    }

    // stateless ----------------------------------------------------------
    function retagStateless(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey calldata publicKey,
            SPHINCSPlusC.Signature calldata signature
        ) = SHRINCSCodec.statelessEnvelope(payload);
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                signature
            )
        );
    }

    function abiStateless(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature
        ) = abi.decode(payload, (SHRINCS.PublicKey, SPHINCSPlusC.Signature));
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                signature
            )
        );
    }

    // signature-only -----------------------------------------------------
    function retagSignature(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        SPHINCSPlusC.Signature calldata signature =
            SHRINCSCodec.statelessSignatureEnvelope(payload);
        return keccak256(abi.encode(signature));
    }

    function abiSignature(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        SPHINCSPlusC.Signature memory signature =
            abi.decode(payload, (SPHINCSPlusC.Signature));
        return keccak256(abi.encode(signature));
    }
}

/// @notice Z3 proof suite for the SHRINCSCodec zero-copy calldata re-tag
/// decoders. Differential: every field read through a re-tag matches the
/// abi.decode of the same envelope. Adversarial: malformed envelopes driven
/// through the real verify path against a real vector key never wrong-accept.
/// Trichotomy (carried finding Z-6): arbitrary mutated envelope bytes land in
/// exactly one of {revert, invalid, success and decode-equivalent}.
/// Profile-gated 256s: the stateless/signature-only fixtures use the
/// in-Solidity stateless signer and the deployed SPHINCSPlusC 256s sibling.
contract SHRINCSCalldataRetagTest is Test {
    bytes4 internal constant SELECTOR =
        IERC7913SignatureVerifier.verify.selector;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    RetagDigestHarness internal digest;
    SHRINCS256sRetagHarness internal verifier;
    IERC7913SignatureVerifier internal sphincs;
    DelegationSigner internal signer;

    // Stateful fixture (cheap in-Solidity keygen + sign).
    bytes internal statefulKey;
    bytes internal statefulEnvelope;
    bytes32 internal statefulHash;

    // Stateless + signature-only fixtures (heavy 256s in-Solidity signer).
    bytes internal statelessKey;
    bytes internal statelessEnvelope;
    bytes internal signatureKey;
    bytes internal signatureEnvelope;
    bytes32 internal statelessHash;

    function setUp() public {
        digest = new RetagDigestHarness();
        signer = new DelegationSigner();

        _buildStatefulFixture();

        // Build the heavy stateless fixtures in their own frame so the
        // ~90 KB working set does not stack under later allocations.
        (
            statelessKey,
            statelessEnvelope,
            statelessHash,
            signatureKey,
            signatureEnvelope
        ) = this.buildStatelessFixtures();

        verifier = new SHRINCS256sRetagHarness();
        // The stateless delegation reaches the sibling at the pinned address.
        deployCodeTo(
            "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak",
            "",
            verifier.pinned()
        );
        // A second sibling instance drives the signature-only path directly.
        sphincs = IERC7913SignatureVerifier(
            deployCode("SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak")
        );
    }

    function _buildStatefulFixture() internal {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSTestSigner.keygen(bytes("shrincs z3 retag stateful"), 4);
        require(ok, "stateful keygen");

        statefulHash = keccak256("shrincs z3 retag stateful message");
        SHRINCS.Signature memory signature;
        bool signed;
        (signature, signed) = SHRINCSTestSigner.signStatefulRawAtLeaf(
            signingKey, 1, abi.encodePacked(statefulHash)
        );
        require(signed, "stateful sign");

        statefulKey = abi.encodePacked(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        statefulEnvelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
    }

    /// @dev External so the heavy stateless signing runs in its own memory
    /// frame. Produces the stateless envelope plus the signature-only
    /// envelope (and its 64-byte key) carved from the same signature.
    function buildStatelessFixtures()
        external
        returns (
            bytes memory sKey,
            bytes memory sEnvelope,
            bytes32 hash,
            bytes memory sigKey,
            bytes memory sigEnvelope
        )
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("shrincs z3 retag stateless"), 4
        );
        require(ok, "stateless keygen");

        hash = keccak256("shrincs z3 retag stateless message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(hash)
        );
        require(beginOk, "begin");
        SPHINCSPlusC.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "complete");

        sKey = abi.encodePacked(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        sEnvelope =
            SHRINCSCodec.encodeStatelessEnvelope(publicKey, signature);
        sigKey = SHRINCSCodec.encodeStatelessKey(
            signingKey.pkSeed, signingKey.hypertreeRoot
        );
        sigEnvelope =
            SHRINCSCodec.encodeStatelessSignatureEnvelope(signature);
    }

    // ---------------------------------------------------------------- //
    // Differential: re-tag reads == abi.decode reads.                  //
    // ---------------------------------------------------------------- //

    function testDifferentialStatefulVector() public view {
        assertEq(
            digest.retagStateful(statefulEnvelope),
            digest.abiStateful(statefulEnvelope),
            "stateful re-tag must read the same fields as abi.decode"
        );
    }

    function testDifferentialStatelessVector() public view {
        assertEq(
            digest.retagStateless(statelessEnvelope),
            digest.abiStateless(statelessEnvelope),
            "stateless re-tag must read the same fields as abi.decode"
        );
    }

    function testDifferentialSignatureVector() public view {
        assertEq(
            digest.retagSignature(signatureEnvelope),
            digest.abiSignature(signatureEnvelope),
            "signature re-tag must read the same fields as abi.decode"
        );
    }

    /// @dev Fuzz over well-formed, re-encoded stateful envelopes: for any
    /// field values the codec-encoded envelope decodes identically through
    /// the two-offset-word re-tag and abi.decode.
    function testFuzzDifferentialStatefulWellFormed(
        bytes calldata statefulPublicKey,
        bytes calldata commitment,
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes32 randomizer,
        uint32 counter,
        bytes32[] calldata chains,
        bytes32[] calldata authPath
    ) public view {
        SHRINCS.PublicKey memory publicKey =
            SHRINCS.PublicKey({
                statefulPublicKey: statefulPublicKey,
                publicKeyCommitment: commitment,
                pkSeed: pkSeed,
                hypertreeRoot: hypertreeRoot
            });
        SHRINCS.Signature memory signature = SHRINCS.Signature({
            randomizer: randomizer,
            counter: counter,
            chains: chains,
            authPath: authPath
        });
        bytes memory envelope =
            SHRINCSCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            digest.retagStateful(envelope),
            digest.abiStateful(envelope),
            "well-formed stateful re-tag must match abi.decode"
        );
    }

    /// @dev Fuzz over well-formed, re-encoded signature-only envelopes,
    /// exercising the single-offset-word re-tag over the deeply nested
    /// SPHINCSPlusC.Signature. Shapes vary in both dynamic members: a
    /// multi-entry FORS signature (1..4 entries) and a possibly non-empty
    /// hypertree (0..2 layers, each a fully populated WOTS-C layer), so the
    /// re-tag is proven against abi.decode across the full signature shape,
    /// not just the empty-hypertree / single-entry corner.
    function testFuzzDifferentialSignatureWellFormed(
        bytes calldata randomizer,
        uint32 counter,
        bytes calldata secretLeaf,
        bytes[] calldata authPath,
        uint8 entryShape,
        uint8 layerShape
    ) public view {
        uint256 entryCount = 1 + (uint256(entryShape) % 4);
        FORSMinusC.ForsEntry[] memory entries =
            new FORSMinusC.ForsEntry[](entryCount);
        for (uint256 i = 0; i < entryCount; i++) {
            entries[i] = FORSMinusC.ForsEntry({
                secretLeaf: secretLeaf, authPath: authPath
            });
        }
        uint256 layerCount = uint256(layerShape) % 3;
        Hypertree.HypertreeLayerSignature[] memory hypertree =
            new Hypertree.HypertreeLayerSignature[](layerCount);
        for (uint256 i = 0; i < layerCount; i++) {
            hypertree[i] = Hypertree.HypertreeLayerSignature({
                treeIndex: 0,
                leafIndex: 0,
                wotsCPkHash: secretLeaf,
                wotsCSignature: WOTSPlusC.WotsCSignature({
                    randomizer: randomizer,
                    counter: counter,
                    chains: authPath
                }),
                authPath: authPath
            });
        }
        SPHINCSPlusC.Signature memory signature = SPHINCSPlusC.Signature({
            fors: FORSMinusC.ForsSignature({
                randomizer: randomizer, counter: counter, entries: entries
            }),
            hypertree: hypertree
        });
        bytes memory envelope =
            SHRINCSCodec.encodeStatelessSignatureEnvelope(signature);
        assertEq(
            digest.retagSignature(envelope),
            digest.abiSignature(envelope),
            "well-formed signature re-tag must match abi.decode"
        );
    }

    // ---------------------------------------------------------------- //
    // Adversarial: malformed envelopes never wrong-accept through the  //
    // real verify path (revert OR the invalid selector, never success).//
    // ---------------------------------------------------------------- //

    function testAdversarialStatefulRejectsMalformed() public view {
        _assertStatefulNotSuccess(
            _e1b(statefulEnvelope, 0), "stateful E1b head 0"
        );
        _assertStatefulNotSuccess(
            _e1b(statefulEnvelope, 1), "stateful E1b head 1"
        );
        _assertStatefulNotSuccess(
            _truncate(statefulEnvelope), "stateful truncated"
        );
        _assertStatefulNotSuccess(
            _oobOffset(statefulEnvelope), "stateful OOB offset"
        );
        _assertStatefulNotSuccess(
            _aliasSecondOffset(statefulEnvelope), "stateful aliased"
        );
    }

    function testAdversarialStatelessRejectsMalformed() public view {
        _assertStatelessNotSuccess(
            _e1b(statelessEnvelope, 0), "stateless E1b head 0"
        );
        _assertStatelessNotSuccess(
            _e1b(statelessEnvelope, 1), "stateless E1b head 1"
        );
        _assertStatelessNotSuccess(
            _truncate(statelessEnvelope), "stateless truncated"
        );
        _assertStatelessNotSuccess(
            _oobOffset(statelessEnvelope), "stateless OOB offset"
        );
        _assertStatelessNotSuccess(
            _aliasSecondOffset(statelessEnvelope), "stateless aliased"
        );
    }

    function testAdversarialSignatureRejectsMalformed() public view {
        _assertSignatureNotSuccess(
            _e1b(signatureEnvelope, 0), "signature E1b head 0"
        );
        _assertSignatureNotSuccess(
            _truncate(signatureEnvelope), "signature truncated"
        );
        _assertSignatureNotSuccess(
            _oobOffset(signatureEnvelope), "signature OOB offset"
        );
        _assertSignatureNotSuccess(
            _aliasNestedOffset(signatureEnvelope), "signature nested aliased"
        );
    }

    // ---------------------------------------------------------------- //
    // Positive controls: the UNMUTATED valid envelopes verify through   //
    // the SAME entrypoints the adversarial cases use, so a broken       //
    // fixture cannot make every not-success assertion pass vacuously.   //
    // (The stateful positive control is                                 //
    // testStatefulNonCanonicalReencodingVerifies below.)               //
    // ---------------------------------------------------------------- //

    function testStatelessEnvelopeVerifies() public view {
        assertEq(
            verifier.verifyStateless(
                statelessKey, statelessHash, statelessEnvelope
            ),
            SELECTOR,
            "valid stateless envelope must verify (positive control)"
        );
    }

    function testSignatureEnvelopeVerifies() public view {
        assertEq(
            sphincs.verify(signatureKey, statelessHash, signatureEnvelope),
            SELECTOR,
            "valid signature envelope must verify (positive control)"
        );
    }

    // ---------------------------------------------------------------- //
    // Trichotomy (Z-6): arbitrary mutated envelope bytes land in       //
    // exactly one of {revert, invalid, success and decode-equivalent}. //
    // ---------------------------------------------------------------- //

    function testFuzzStatefulEnvelopeTrichotomy(
        uint16 position,
        bytes calldata overlay
    ) public view {
        bytes memory mutant = _overlay(statefulEnvelope, position, overlay);
        try verifier.verify(statefulKey, statefulHash, mutant) returns (
            bytes4 result
        ) {
            if (result == SELECTOR) {
                // Success is acceptable ONLY when the mutant abi.decodes to
                // field-equal structs of the valid envelope (the documented
                // byte-malleability widening).
                assertEq(
                    digest.abiStateful(mutant),
                    digest.abiStateful(statefulEnvelope),
                    "success only on a decode-equivalent envelope"
                );
            } else {
                assertEq(
                    result,
                    INVALID_SIGNATURE,
                    "non-success must be the invalid selector"
                );
            }
        } catch {
            // A revert on a malformed envelope is a safe rejection.
        }
    }

    /// @dev Demonstrates the success-and-equivalent trichotomy branch: a
    /// non-canonical re-encoding (trailing padding bytes) of the valid
    /// envelope still verifies and decodes to the same fields.
    function testStatefulNonCanonicalReencodingVerifies() public view {
        bytes memory padded = abi.encodePacked(statefulEnvelope, uint256(0));
        assertEq(
            verifier.verify(statefulKey, statefulHash, padded),
            SELECTOR,
            "trailing-padded envelope must still verify"
        );
        assertEq(
            digest.abiStateful(padded),
            digest.abiStateful(statefulEnvelope),
            "padded envelope must decode to the same fields"
        );
    }

    // ---------------------------------------------------------------- //
    // Not-success assertions per verify path.                          //
    // ---------------------------------------------------------------- //

    function _assertStatefulNotSuccess(
        bytes memory envelope,
        string memory label
    ) internal view {
        try verifier.verify(statefulKey, statefulHash, envelope) returns (
            bytes4 result
        ) {
            assertTrue(result != SELECTOR, label);
        } catch {}
    }

    function _assertStatelessNotSuccess(
        bytes memory envelope,
        string memory label
    ) internal view {
        try verifier.verifyStateless(
            statelessKey, statelessHash, envelope
        ) returns (
            bytes4 result
        ) {
            assertTrue(result != SELECTOR, label);
        } catch {}
    }

    function _assertSignatureNotSuccess(
        bytes memory envelope,
        string memory label
    ) internal view {
        try sphincs.verify(signatureKey, statelessHash, envelope) returns (
            bytes4 result
        ) {
            assertTrue(result != SELECTOR, label);
        } catch {}
    }

    // ---------------------------------------------------------------- //
    // Malformed-envelope constructors.                                 //
    // ---------------------------------------------------------------- //

    /// @dev E1b: set the head offset word at index `headWord` to 2^255, past
    /// solc's signed tail bound. `headWord` selects which head slot is
    /// corrupted: word 0 is the first head offset (the signature-only
    /// envelope's only head word, or a two-struct envelope's publicKey
    /// offset), word 1 is a two-struct envelope's second (signature) offset.
    function _e1b(bytes memory envelope, uint256 headWord)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        uint256 e1b = 1 << 255;
        uint256 slot = 32 + headWord * 32;
        assembly {
            mstore(add(out, slot), e1b)
        }
    }

    /// @dev Truncate the envelope by one byte.
    function _truncate(bytes memory envelope)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        assembly {
            mstore(out, sub(mload(out), 1))
        }
    }

    /// @dev Point the first head offset word far past the buffer end (still
    /// below 2^64, so solc's member access reverts on the OOB read).
    function _oobOffset(bytes memory envelope)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        uint256 oob = 0xffffffffffff;
        assembly {
            mstore(add(out, 32), oob)
        }
    }

    /// @dev Alias the second head offset onto the first, so both structs
    /// decode from the same tail.
    function _aliasSecondOffset(bytes memory envelope)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        assembly {
            mstore(add(out, 64), mload(add(out, 32)))
        }
    }

    /// @dev Alias the signature-only envelope's nested hypertree offset onto
    /// its fors offset. The one-word outer head has no head-level alias, so
    /// this in-bounds aliasing case lives one level down, inside the single
    /// wrapped SPHINCSPlusC.Signature struct.
    function _aliasNestedOffset(bytes memory envelope)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        // The outer offset at content[0..32) points to the struct start at
        // content byte 32; that struct's head is the fors offset at
        // content[32..64) and the hypertree offset at content[64..96). Point
        // the hypertree offset at the fors tail (both are struct-relative).
        assembly {
            mstore(add(out, 96), mload(add(out, 64)))
        }
    }

    /// @dev Overlay fuzzed bytes onto the envelope at a wrapped position.
    function _overlay(
        bytes memory envelope,
        uint16 position,
        bytes memory overlay
    ) internal pure returns (bytes memory out) {
        out = bytes.concat(envelope);
        if (out.length == 0) return out;
        for (uint256 i = 0; i < overlay.length; i++) {
            out[(uint256(position) + i) % out.length] = overlay[i];
        }
    }
}
