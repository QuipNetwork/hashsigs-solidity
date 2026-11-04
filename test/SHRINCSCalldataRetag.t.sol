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

import {
    StatelessSignatureTypes
} from "./helpers/StatelessSignatureTypes.sol";
import {SHRINCSTestCodec} from "./helpers/SHRINCSTestCodec.sol";

import {Test} from "../lib/forge-std/src/Test.sol";
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {StatelessLayout} from "../contracts/StatelessLayout.sol";
import {SHRINCS256sKeccak} from "../contracts/SHRINCS256sKeccak.sol";
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
        ) = SHRINCS.statefulEnvelope(payload);
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

    // stateful action ----------------------------------------------------
    // The four-word head interleaves two struct offsets around the two
    // inline action words; the digest reads all four so equal digests prove
    // the inline words match too, not just the two structs.
    function retagStatefulAction(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey calldata publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            SHRINCS.Signature calldata signature
        ) = SHRINCS.statefulActionEnvelope(payload);
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                actionType,
                payloadHash,
                signature.randomizer,
                signature.counter,
                signature.chains,
                signature.authPath
            )
        );
    }

    function abiStatefulAction(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            SHRINCS.Signature memory signature
        ) = abi.decode(
            payload, (SHRINCS.PublicKey, bytes32, bytes32, SHRINCS.Signature)
        );
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                actionType,
                payloadHash,
                signature.randomizer,
                signature.counter,
                signature.chains,
                signature.authPath
            )
        );
    }

    // stateless action ---------------------------------------------------
    function retagStatelessAction(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey calldata publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            bytes calldata signature
        ) = SHRINCS.statelessActionEnvelope(payload);
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                actionType,
                payloadHash,
                signature
            )
        );
    }

    function abiStatelessAction(bytes calldata payload)
        external
        pure
        returns (bytes32)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            bytes memory signature
        ) = abi.decode(payload, (SHRINCS.PublicKey, bytes32, bytes32, bytes));
        return keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                actionType,
                payloadHash,
                signature
            )
        );
    }

    // consumedStatelessAction: Digest over exactly the values the
    // stateless-action verify path consumes, so two envelopes with the same
    // digest authorize the same signature. The public-key fields enter
    // whole because validPublicKey width-pins all four and the installed
    // commitment binds them; the fixed-layout signature enters whole
    // because SPHINCSPlusC.verify accepts exactly StatelessLayout.PQ_LEN
    // bytes and reads every one of them.
    function consumedStatelessAction(bytes calldata payload)
        external
        pure
        returns (bytes32 consumed)
    {
        (
            SHRINCS.PublicKey calldata publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            bytes calldata signature
        ) = SHRINCS.statelessActionEnvelope(payload);
        consumed = keccak256(
            abi.encode(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                actionType,
                payloadHash,
                signature
            )
        );
    }
}

/// @notice Z3 proof suite for the zero-copy calldata re-tag decoders
/// (the dissolved codec library, now the SHRINCS.sol codec section).
/// Differential: every field read through a re-tag matches the
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
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    uint8 internal constant MODE_STATEFUL_ACTION = 1;
    uint8 internal constant MODE_STATELESS_ACTION = 2;

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
    bytes32 internal signatureHash;

    // Account-action fixtures (four-word head: two inline action words
    // between two struct offsets), driven through the wrapper's mode-1 /
    // mode-2 isValidSignature path. The `*Payload` bytes exclude the leading
    // ERC-1271 mode byte, so they are exactly the calldata the action re-tag
    // reads; the wrapper call re-prepends the mode byte.
    SHRINCSAccountVerifierExample internal statefulAccount;
    bytes internal statefulActionPayload;
    bytes32 internal statefulActionHash;

    SHRINCSAccountVerifierExample internal statelessAccount;
    bytes internal statelessActionPayload;
    bytes32 internal statelessActionHash;
    // Value-level digest of the valid stateless action payload, cached so
    // the trichotomy fuzz does not recompute it on every run.
    bytes32 internal statelessActionConsumed;

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
            signatureEnvelope,
            signatureHash
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

        _buildStatefulActionFixture();

        // Heavy stateless action signing in its own memory frame.
        address account;
        (account, statelessActionPayload, statelessActionHash) =
            this.buildStatelessActionFixtures();
        statelessAccount = SHRINCSAccountVerifierExample(account);
        statelessActionConsumed =
            digest.consumedStatelessAction(statelessActionPayload);
    }

    /// @dev Cheap in-Solidity stateful action fixture: keygen, install into a
    /// fresh wrapper, sign the canonical stateful action, and capture the
    /// mode-byte-free action envelope plus the canonical action hash.
    function _buildStatefulActionFixture() internal {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("shrincs z3 retag stateful action"), 4
        );
        require(ok, "stateful action keygen");

        statefulAccount = new SHRINCSAccountVerifierExample(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        bytes32 actionType = keccak256("z3 retag stateful action type");
        bytes32 payloadHash = keccak256("z3 retag stateful action payload");

        (
            ,
            SHRINCS.ActionContext memory context,
            SHRINCS.Signature memory signature,
            bool signOk
        ) = SHRINCSAccountSigningFacade.signStatefulActionNow(
            statefulAccount, signingKey, actionType, payloadHash
        );
        require(signOk, "stateful action sign");

        statefulActionHash = SHRINCS.statefulActionMessageHash(
            statefulAccount.currentSHRINCSPublicKey(), context
        );
        statefulActionPayload =
            abi.encode(publicKey, actionType, payloadHash, signature);
    }

    /// @dev External so the heavy stateless action signing runs in its own
    /// memory frame. Installs a fresh wrapper, signs the canonical stateless
    /// action, and returns the wrapper address, the mode-byte-free action
    /// envelope, and the canonical action hash.
    function buildStatelessActionFixtures()
        external
        returns (address account, bytes memory payload, bytes32 hash)
    {
        (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        ) = SHRINCSAccountSigningFacade.keygen(
            bytes("shrincs z3 retag stateless action"), 4
        );
        require(ok, "stateless action keygen");

        SHRINCSAccountVerifierExample acct;
        acct = new SHRINCSAccountVerifierExample(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        bytes32 actionType = keccak256("z3 retag stateless action type");
        bytes32 payloadHash = keccak256("z3 retag stateless action payload");

        (
            SHRINCS.ActionContext memory context,
            bytes32 sessionId,
            bool signOk
        ) = SHRINCSAccountSigningFacade.beginStatelessActionSessionNow(
                signer, acct, signingKey, publicKey, actionType, payloadHash
            );
        require(signOk, "stateless action begin");

        StatelessSignatureTypes.Signature memory signature;
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "stateless action complete");

        hash = SHRINCS.statelessActionMessageHash(
            acct.currentSHRINCSPublicKey(), context
        );
        payload = abi.encode(
            publicKey,
            actionType,
            payloadHash,
            SHRINCSTestCodec.encodeCompactSignature(signature)
        );
        account = address(acct);
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
        (signature, signed) = SHRINCSTestSigner.signStatefulAdapterAtLeaf(
            signingKey, publicKey, 1, statefulHash
        );
        require(signed, "stateful sign");

        statefulKey = abi.encodePacked(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey)
        );
        statefulEnvelope =
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
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
            bytes memory sigEnvelope,
            bytes32 sigHash
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
        sigHash = SHRINCS.statelessRawMessageHash(
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey),
            hash
        );
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey, publicKey, abi.encodePacked(sigHash)
        );
        require(beginOk, "begin");
        StatelessSignatureTypes.Signature memory signature;
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
            SHRINCSTestCodec.encodeCompactPayload(publicKey, signature);
        sigKey = SHRINCS.encodeStatelessKey(
            signingKey.pkSeed, signingKey.hypertreeRoot
        );
        sigEnvelope = SHRINCSTestCodec.encodeCompactSignature(signature);
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

    function testDifferentialStatefulActionVector() public view {
        assertEq(
            digest.retagStatefulAction(statefulActionPayload),
            digest.abiStatefulAction(statefulActionPayload),
            "stateful action re-tag must read the same fields as abi.decode"
        );
    }

    function testDifferentialStatelessActionVector() public view {
        assertEq(
            digest.retagStatelessAction(statelessActionPayload),
            digest.abiStatelessAction(statelessActionPayload),
            "stateless action re-tag must read the same fields as abi.decode"
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
            SHRINCSTestCodec.encodeStatefulEnvelope(publicKey, signature);
        assertEq(
            digest.retagStateful(envelope),
            digest.abiStateful(envelope),
            "well-formed stateful re-tag must match abi.decode"
        );
    }

    /// @dev Fuzz over well-formed stateful ACTION envelopes: the four-word
    /// head interleaves the two inline action words between the two struct
    /// offsets, so this proves the interleaved re-tag reads every field
    /// (including both inline words) identically to abi.decode.
    function testFuzzDifferentialStatefulActionWellFormed(
        bytes calldata statefulPublicKey,
        bytes calldata commitment,
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes32 actionType,
        bytes32 payloadHash,
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
            abi.encode(publicKey, actionType, payloadHash, signature);
        assertEq(
            digest.retagStatefulAction(envelope),
            digest.abiStatefulAction(envelope),
            "well-formed stateful action re-tag must match abi.decode"
        );
    }

    /// @dev Fuzz over well-formed stateless ACTION envelopes: the same
    /// four-word interleaved head as the stateful action, with the
    /// fixed-layout signature as a trailing `bytes` field, so the public-key
    /// re-tag and the bounded signature slice are proven against abi.decode
    /// across arbitrary field lengths.
    function testFuzzDifferentialStatelessActionWellFormed(
        bytes calldata pkBytes,
        bytes32 actionType,
        bytes32 payloadHash,
        bytes calldata signature
    ) public view {
        SHRINCS.PublicKey memory publicKey =
            SHRINCS.PublicKey({
                statefulPublicKey: pkBytes,
                publicKeyCommitment: pkBytes,
                pkSeed: pkBytes,
                hypertreeRoot: pkBytes
            });
        bytes memory envelope =
            abi.encode(publicKey, actionType, payloadHash, signature);
        assertEq(
            digest.retagStatelessAction(envelope),
            digest.abiStatelessAction(envelope),
            "well-formed stateless action re-tag must match abi.decode"
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

    /// @dev The flat payload has no offset words, so the head probes below
    /// land in field bytes (the stateful public key) and must fail the
    /// commitment check. Unlike the ABI envelope, this path never reverts,
    /// so each case asserts the exact invalid selector. Positive control:
    /// testStatelessEnvelopeVerifies.
    function testAdversarialStatelessRejectsMalformed() public view {
        _assertStatelessInvalid(
            _e1b(statelessEnvelope, 0), "stateless word 0 = 2^255"
        );
        _assertStatelessInvalid(
            _e1b(statelessEnvelope, 1), "stateless word 1 = 2^255"
        );
        _assertStatelessInvalid(
            _oobOffset(statelessEnvelope), "stateless word 0 huge"
        );
        _assertStatelessInvalid(
            _aliasSecondOffset(statelessEnvelope),
            "stateless word 1 = word 0"
        );
        _assertStatelessInvalid(
            _truncate(statelessEnvelope), "stateless one byte short"
        );
        _assertStatelessInvalid(
            bytes.concat(statelessEnvelope, bytes1(0)),
            "stateless one byte long"
        );
        _assertStatelessInvalid(
            _aliasLayers(
                statelessEnvelope,
                StatelessLayout.PK_LEN + StatelessLayout.FORS_LEN
            ),
            "stateless layer 0 = layer 1"
        );
    }

    /// @dev The same probes against the PQ section alone, through the
    /// signature-only verifier. Positive control:
    /// testSignatureEnvelopeVerifies.
    function testAdversarialSignatureRejectsMalformed() public view {
        _assertSignatureInvalid(
            _e1b(signatureEnvelope, 0), "signature word 0 = 2^255"
        );
        _assertSignatureInvalid(
            _oobOffset(signatureEnvelope), "signature word 0 huge"
        );
        _assertSignatureInvalid(
            _truncate(signatureEnvelope), "signature one byte short"
        );
        _assertSignatureInvalid(
            bytes.concat(signatureEnvelope, bytes1(0)),
            "signature one byte long"
        );
        _assertSignatureInvalid(
            _aliasLayers(signatureEnvelope, StatelessLayout.FORS_LEN),
            "signature layer 0 = layer 1"
        );
    }

    /// @dev statelessActionEnvelope is the one stateless path still reading
    /// offset words, so these probes hit the re-tag itself. The hash matches
    /// the signed action, so the flow reaches the probed offset. Positive
    /// control: testStatelessActionEnvelopeVerifies.
    function testAdversarialStatelessActionRejectsMalformed() public view {
        bytes memory valid = statelessActionPayload;
        _assertStatelessActionNotSuccess(
            _e1b(valid, 0), "action publicKey offset = 2^255"
        );
        _assertStatelessActionNotSuccess(
            _e1b(valid, 3), "action signature offset = 2^255"
        );
        _assertStatelessActionNotSuccess(
            _oobOffset(valid), "action publicKey offset huge"
        );
        _assertStatelessActionNotSuccess(
            _setWord(valid, 3, 0xffffffffffff),
            "action signature offset huge"
        );
        // The offset addition wraps: the length word is read one byte before
        // the payload, so the length no longer equals PQ_LEN.
        _assertStatelessActionNotSuccess(
            _setWord(valid, 3, type(uint256).max),
            "action signature offset wraps"
        );
        // The signature reads the public-key tail as its length and body.
        _assertStatelessActionNotSuccess(
            _setWord(valid, 3, _word(valid, 0)),
            "action signature aliases publicKey"
        );
        // abi.encode pads the signature to a word boundary, and cutting only
        // padding leaves the signature intact. Cut the padding plus one whole
        // word, so the last auth node reads as zeros past the calldata end.
        _assertStatelessActionNotSuccess(
            _truncateBy(
                valid, (32 - (StatelessLayout.PQ_LEN % 32)) % 32 + 32
            ),
            "action signature body truncated"
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
            "valid stateless payload must verify (positive control)"
        );
    }

    function testSignatureEnvelopeVerifies() public view {
        assertEq(
            sphincs.verify(signatureKey, signatureHash, signatureEnvelope),
            SELECTOR,
            "valid stateless signature must verify (positive control)"
        );
    }

    function testStatefulActionEnvelopeVerifies() public view {
        assertEq(
            statefulAccount.isValidSignature(
                statefulActionHash,
                abi.encodePacked(
                    bytes1(MODE_STATEFUL_ACTION), statefulActionPayload
                )
            ),
            MAGIC_VALUE,
            "valid stateful action envelope must verify (positive control)"
        );
    }

    function testStatelessActionEnvelopeVerifies() public view {
        assertEq(
            statelessAccount.isValidSignature(
                statelessActionHash,
                abi.encodePacked(
                    bytes1(MODE_STATELESS_ACTION), statelessActionPayload
                )
            ),
            MAGIC_VALUE,
            "valid stateless action envelope must verify (positive control)"
        );
    }

    /// @dev Pins the encoding malleability SHRINCS.statelessActionEnvelope
    /// accepts by design. The re-tag reads the signature in place and never
    /// checks the bytes around it, so a framing that leaves every field value
    /// unchanged is a second encoding of the same signature: not a forgery,
    /// but envelope bytes are not unique, so consumers must key on field
    /// values. The flat verify and verifyStateless payloads have no such
    /// framing, and SHRINCSCompactAdversarial pins their exact-length
    /// rejection. If this test fails, the accepted framing has changed.
    function testStatelessActionEnvelopeEncodingMalleability() public view {
        bytes memory valid = statelessActionPayload;
        // abi.encode pads the signature body up to a 32-byte boundary.
        uint256 padding = (32 - (StatelessLayout.PQ_LEN % 32)) % 32;
        assertGt(padding, 0, "the signature must be padded");

        _assertStatelessActionSecondEncoding(
            _truncateBy(valid, 1), "one padding byte removed"
        );
        _assertStatelessActionSecondEncoding(
            _truncateBy(valid, padding), "all padding removed"
        );
        _assertStatelessActionSecondEncoding(
            bytes.concat(valid, bytes32(uint256(7))), "trailing bytes added"
        );
        bytes memory dirtyPadding = bytes.concat(valid);
        dirtyPadding[dirtyPadding.length - 1] = 0xff;
        _assertStatelessActionSecondEncoding(dirtyPadding, "dirty padding");

        // The boundary: one more byte removes signature data, which then
        // reads as zero past the end of calldata and changes the signature.
        assertEq(
            statelessAccount.isValidSignature(
                statelessActionHash,
                abi.encodePacked(
                    bytes1(MODE_STATELESS_ACTION),
                    _truncateBy(valid, padding + 1)
                )
            ),
            INVALID_SIGNATURE,
            "removing signature data must be rejected"
        );
    }

    // ---------------------------------------------------------------- //
    // Finding 13: SPHINCSPlusCVerifier's only key guard is decodeKey    //
    // ok=false for length != 64. A wrong-length key must fail closed    //
    // (0xffffffff, no revert), and a right-length wrong-VALUE key must  //
    // fail the crypto check rather than wrong-accept.                   //
    // ---------------------------------------------------------------- //

    function testSphincsRejectsWrongLengthKey() public view {
        uint256[4] memory lengths = [uint256(0), 32, 63, 65];
        for (uint256 i = 0; i < lengths.length; i++) {
            assertEq(
                sphincs.verify(
                    new bytes(lengths[i]), signatureHash, signatureEnvelope
                ),
                INVALID_SIGNATURE,
                "wrong-length key must fail closed without reverting"
            );
        }
    }

    function testSphincsRejectsWrongValueKey() public view {
        // 64-byte, right-length key with the wrong pkSeed/hypertreeRoot: it
        // clears the length guard but must fail the FORS-C/hypertree check.
        bytes memory wrongKey = SHRINCS.encodeStatelessKey(
            keccak256("z3 retag wrong pkSeed"),
            keccak256("z3 retag wrong hypertreeRoot")
        );
        assertEq(wrongKey.length, 64, "wrong-value key must be 64 bytes");
        assertEq(
            sphincs.verify(wrongKey, signatureHash, signatureEnvelope),
            INVALID_SIGNATURE,
            "right-length wrong-value key must fail closed"
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
                // field-equal structs of the valid envelope. This fuzz only
                // overlays bytes in place (no truncation), so the
                // documented encoding-malleability widening coincides with
                // decode-equivalence here.
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

    /// @dev Overlay-mutation trichotomy for the stateful ACTION envelope,
    /// driven through the wrapper's mode-1 isValidSignature path (the only
    /// caller of statefulActionEnvelope). Every mutant either reverts, or
    /// returns a non-magic value, or (if it still yields the magic value)
    /// must abi.decode to field-equal structs (incl. the two inline action
    /// words) of the valid envelope. In-place overlays only (no truncation),
    /// so the malleability widening coincides with decode-equivalence.
    function testFuzzStatefulActionTrichotomy(
        uint16 position,
        bytes calldata overlay
    ) public view {
        bytes memory mutant = _overlay(
            statefulActionPayload, position, overlay
        );
        bytes memory envelope =
            abi.encodePacked(bytes1(MODE_STATEFUL_ACTION), mutant);
        try statefulAccount.isValidSignature(
            statefulActionHash, envelope
        ) returns (
            bytes4 result
        ) {
            if (result == MAGIC_VALUE) {
                assertEq(
                    digest.abiStatefulAction(mutant),
                    digest.abiStatefulAction(statefulActionPayload),
                    "magic only on a decode-equivalent action envelope"
                );
            } else {
                assertEq(
                    result,
                    INVALID_SIGNATURE,
                    "non-magic must be the invalid selector"
                );
            }
        } catch {
            // A revert on a malformed action envelope is a safe rejection.
        }
    }

    /// @dev Overlay-mutation trichotomy for the stateless ACTION envelope,
    /// driven through the wrapper's mode-2 isValidSignature path.
    ///
    /// Acceptance is pinned at the value level, not the byte level. The
    /// stateless verify path reads each hash-width `bytes` field as a
    /// single 32-byte calldata word and walks each dynamic array over a
    /// fixed element count, so a mutant may carry a longer field with the
    /// same 32-byte prefix (a 33-byte wotsCPkHash, say) or trailing array
    /// elements and still verify. That is the length malleability accepted
    /// in docs/guard-applicability-review.md rows 25-41, and it is why the
    /// stateful twin's byte-level decode-equivalence assertion does not
    /// carry over here. What must still hold is that an accepted mutant
    /// reproduces every value the verifier consumed from the valid
    /// payload.
    function testFuzzStatelessActionTrichotomy(
        uint16 position,
        bytes calldata overlay
    ) public view {
        bytes memory mutant = _overlay(
            statelessActionPayload, position, overlay
        );
        bytes memory envelope =
            abi.encodePacked(bytes1(MODE_STATELESS_ACTION), mutant);
        try statelessAccount.isValidSignature(
            statelessActionHash, envelope
        ) returns (
            bytes4 result
        ) {
            if (result == MAGIC_VALUE) {
                // Wrong-accept pin: the values the verifier consumed must
                // be the valid payload's. The re-tag reads are bounds-
                // checked against calldatasize rather than the envelope
                // slice, so a framing accepted inside the wrapper call can
                // still revert when replayed as this harness call's own
                // argument; that is a framing pathology, not a wrong-accept.
                try digest.consumedStatelessAction(mutant) returns (
                    bytes32 consumed
                ) {
                    assertEq(
                        consumed,
                        statelessActionConsumed,
                        "magic only on a value-equivalent action envelope"
                    );
                } catch {}
                // A materializing digest can itself revert on a
                // pathological-but-accepted framing; only compare when
                // abi.decode succeeds (as in the signature byte-flip).
                try digest.abiStatelessAction(mutant) returns (
                    bytes32 abiD
                ) {
                    assertEq(
                        digest.retagStatelessAction(mutant),
                        abiD,
                        "re-tag must match abi.decode on accepted framing"
                    );
                } catch {}
            } else {
                assertEq(
                    result,
                    INVALID_SIGNATURE,
                    "non-magic must be the invalid selector"
                );
            }
        } catch {
            // A revert on a malformed action envelope is a safe rejection.
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

    function _assertStatelessInvalid(
        bytes memory payload,
        string memory label
    ) internal view {
        assertEq(
            verifier.verifyStateless(statelessKey, statelessHash, payload),
            INVALID_SIGNATURE,
            label
        );
    }

    function _assertSignatureInvalid(
        bytes memory signature,
        string memory label
    ) internal view {
        assertEq(
            sphincs.verify(signatureKey, signatureHash, signature),
            INVALID_SIGNATURE,
            label
        );
    }

    /// @dev `payload` must verify and must read the same field values as the
    /// valid payload.
    function _assertStatelessActionSecondEncoding(
        bytes memory payload,
        string memory label
    ) internal view {
        assertEq(
            statelessAccount.isValidSignature(
                statelessActionHash,
                abi.encodePacked(bytes1(MODE_STATELESS_ACTION), payload)
            ),
            MAGIC_VALUE,
            label
        );
        assertEq(
            digest.consumedStatelessAction(payload),
            statelessActionConsumed,
            label
        );
    }

    function _assertStatelessActionNotSuccess(
        bytes memory payload,
        string memory label
    ) internal view {
        try statelessAccount.isValidSignature(
            statelessActionHash,
            abi.encodePacked(bytes1(MODE_STATELESS_ACTION), payload)
        ) returns (
            bytes4 result
        ) {
            assertTrue(result != MAGIC_VALUE, label);
        } catch {}
    }

    // ---------------------------------------------------------------- //
    // Malformed-envelope constructors.                                 //
    // ---------------------------------------------------------------- //

    /// @dev E1b: set the head offset word at index `headWord` to 2^255, past
    /// solc's signed tail bound. `headWord` selects which head slot is
    /// corrupted: word 0 is the first head offset (an envelope's publicKey
    /// offset), word 1 is a two-struct envelope's second (signature) offset,
    /// and word 3 is an action envelope's signature offset. On a flat
    /// stateless payload, the same bytes are field data instead of offsets.
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

    /// @dev Set the 32-byte word at index `index` to `value`.
    function _setWord(bytes memory envelope, uint256 index, uint256 value)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        uint256 slot = 32 + index * 32;
        // Memory layout of `out`:
        //   [0..32)                 length
        //   [slot..slot+32)         word `index`, overwritten
        assembly {
            mstore(add(out, slot), value)
        }
    }

    /// @dev Read the 32-byte word at index `index`.
    function _word(bytes memory envelope, uint256 index)
        internal
        pure
        returns (uint256 value)
    {
        uint256 slot = 32 + index * 32;
        // Memory layout of `envelope`:
        //   [0..32)                 length
        //   [slot..slot+32)         word `index`, read
        assembly {
            value := mload(add(envelope, slot))
        }
    }

    /// @dev Remove the last `count` bytes of the envelope.
    function _truncateBy(bytes memory envelope, uint256 count)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        // Memory layout of `out`:
        //   [0..32)                 length, reduced by `count`
        assembly {
            mstore(out, sub(mload(out), count))
        }
    }

    /// @dev Copy hypertree layer 1 over layer 0, keeping the total length, so
    /// only a check on the layer contents can reject it. `hypertreeOffset` is
    /// where the hypertree section starts in `envelope`.
    function _aliasLayers(bytes memory envelope, uint256 hypertreeOffset)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        for (uint256 i = 0; i < StatelessLayout.LAYER_LEN; ++i) {
            out[hypertreeOffset + i] =
                out[hypertreeOffset + StatelessLayout.LAYER_LEN + i];
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

    /// @dev Flip exactly one byte: XOR `flip` (non-zero) into the byte at
    /// `position % length`. In-place, so the envelope length is unchanged.
    function _flipByte(bytes memory envelope, uint256 position, uint8 flip)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(envelope);
        if (out.length == 0) return out;
        uint256 idx = position % out.length;
        out[idx] = bytes1(uint8(out[idx]) ^ flip);
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
