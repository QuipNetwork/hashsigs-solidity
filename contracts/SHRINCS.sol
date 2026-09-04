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

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {UXMSS} from "./UXMSS.sol";
import {SPHINCSPlusC} from "./SPHINCSPlusC.sol";

/// @title SHRINCS
/// @notice Storage-free verification core for the hybrid SHRINCS scheme:
/// builds canonical action and rotation hashes and runs the stateful and
/// stateless verify-and-decode logic used by the ERC-7913 verifier.
/// @dev Caller obligations. The shared verification stack is `view`: it
/// compiles with the SHA-256 hash suite, whose hashing helpers use
/// `staticcall` to precompile 0x02. No function reads or writes persistent
/// storage. On a well-formed but invalid signature the verify and
/// hash-building functions return a fail-closed boolean (never a
/// wrong-accept), and the ERC-7913 revert-vs-0xffffffff policy belongs to
/// the calling contract. On a malformed envelope they MAY revert: the re-tag
/// facades (statefulEnvelope, statelessActionEnvelope,
/// prepareStatelessDelegation, ...) point calldata structs at the fields in
/// place, and a framing that solc's calldata member access or a
/// reconstruction loop's index bound cannot read Panics — that revert is
/// the rejection channel. The guarantee is {revert, false}, never a
/// wrong-accept; the encoder/decoder revert-model note below states the
/// exact acceptance bound. All statefulness is the WRAPPER contract's
/// job: single-use tracking of stateful leaves, nonce and keyVersion
/// replay scoping, and installing the commitment a rotation returns.
/// SHRINCSAccountVerifierExample is the reference wrapper. Any future
/// storage-needing helper belongs in a separate wrapper/base contract at
/// the top of the inheritance chain, never in these libraries.
/// @dev Calldata typing. The verify path is `calldata` end-to-end: the
/// adapters and wrapper re-tag their calldata envelopes into typed struct
/// pointers and hand them straight down, with no abi.decode and no copy.
/// verify/verifyStatefulUncheckedMessage/verifyStatelessUncheckedMessage and
/// the whole component stack below them (UXMSS, SPHINCSPlusC, FORSMinusC,
/// Hypertree, and the folded public-key checks) take `calldata` structs;
/// `_toUxmss` re-tags the twin signature pointer in calldata at the single
/// stateful call boundary. The message bytes stay `memory`.
/// The rotation/context helpers (rotateStatefulViaStateless, statelessRotate,
/// and their message-hash builders) are likewise `calldata`-typed.
library SHRINCS {
    /// @dev A re-tagged stateless signature resolved its final byte before
    /// its own start or beyond the enclosing call's calldata.
    error InvalidStatelessSignatureSlice();

    // Sentinel for an unsupported hash suite. Kept as a named constant so
    // fail-closed suite checks and negative tests have a stable identifier
    // that never collides with a real suite id (keccak = 1, sha2 = 2). The
    // canonical action/rotation hashes bind the active suite id directly
    // from HashSuite.HASH_SUITE_ID.
    uint32 internal constant HASH_SUITE_UNSUPPORTED = 0xFFFFFFFF;
    // Operation tags domain-separating each signed message family.
    bytes32 internal constant OP_VERIFY_STATEFUL =
        keccak256("shrincs-verify-stateful");
    bytes32 internal constant OP_VERIFY_STATELESS =
        keccak256("shrincs-verify-stateless");
    bytes32 internal constant OP_ROTATE_STATEFUL =
        keccak256("shrincs-rotate-stateful");
    bytes32 internal constant OP_ROTATE_FULL =
        keccak256("shrincs-rotate-full");

    struct PublicKey {
        // Encoded stateful fast-path public key.
        bytes statefulPublicKey;
        // Commitment binding the full hybrid public-key bundle together.
        bytes publicKeyCommitment;
        // Stateless SPHINCS-style public seed.
        bytes pkSeed;
        // Stateless SPHINCS-style public root.
        bytes hypertreeRoot;
    }

    struct SigningKey {
        // Secret seed used to derive stateful WOTS-C chain secrets.
        bytes32 statefulSkSeed;
        // Secret PRF seed used to derive stateful WOTS-C message randomizers.
        bytes32 statefulPrfSeed;
        // Public seed used in stateful WOTS-C and stateful tree hashing.
        bytes32 statefulPkSeed;
        // Root of the stateful unbalanced tree committed in the public key.
        bytes32 statefulRoot;
        // Highest stateful leaf index this key may sign with.
        uint32 maxStatefulSignatures;
        // Next monotonic stateful leaf index to consume.
        uint32 nextStatefulLeafIndex;
        // Stateless SK.seed-style material used to derive FORS-C and
        // hypertree WOTS-C secrets.
        bytes32 statelessSkSeed;
        // Stateless SK.prf-style material used to derive stateless message
        // randomizers.
        bytes32 statelessPrfSeed;
        // Global public seed used in FORS-C, hypertree WOTS-C, and Merkle
        // node hashing.
        bytes32 pkSeed;
        // Top hypertree root committed in the public key.
        bytes32 hypertreeRoot;
    }

    struct StatefulRotationTarget {
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
    }

    struct RotationContext {
        // Contract/application domain binding for the rotation intent.
        bytes32 domainSeparator;
        // Replay-protection nonce consumed by the wrapper.
        uint256 nonce;
        // Installed-key epoch that this rotation authorizes from.
        uint256 keyVersion;
    }

    struct ActionContext {
        // Contract/application domain binding for the action intent.
        bytes32 domainSeparator;
        // Replay-protection nonce consumed by the wrapper.
        uint256 nonce;
        // Installed-key epoch that this action is valid under.
        uint256 keyVersion;
        // Typed action discriminator chosen by the integrating account logic.
        bytes32 actionType;
        // Hash of the typed payload authorized by the signature.
        bytes32 payloadHash;
    }

    struct RotationTarget {
        // Replacement encoded stateful public key.
        bytes statefulPublicKey;
        // Commitment that should identify the next installed bundle.
        bytes publicKeyCommitment;
        // Replacement stateless public seed.
        bytes pkSeed;
        // Replacement stateless public root.
        bytes hypertreeRoot;
    }

    // TWIN of UXMSS.Signature: the field list here and in UXMSS.Signature
    // must stay byte-identical. This is the hybrid data model's stateful
    // signature; _toUxmss re-tags the pointer to UXMSS.Signature at the
    // single call boundary rather than copying, and the twin-drift test
    // asserts abi.encode equality so any layout change here that is not
    // mirrored in UXMSS.Signature fails closed. A SHRINCS signature is
    // stateful by default; a stateless SHRINCS signature is exactly a
    // SPHINCSPlusC.Signature, which is why there is no stateless twin here.
    struct Signature {
        // Per-signature randomizer committed into the stateful message
        // digest.
        bytes32 randomizer;
        // Grinding counter used to satisfy the WOTS-C target-sum rule.
        uint32 counter;
        // Revealed WOTS-C chain values.
        bytes32[] chains;
        // Unbalanced authentication path proving the selected stateful leaf.
        bytes32[] authPath;
    }

    // verify: Facade stateful verify over a 32-byte hash. Packs the ERC-7913
    // hash into the signed message bytes and runs the stateful equation
    // checks against the installed commitment and public-key bundle.
    function verify(
        bytes32 expectedPublicKeyCommitment,
        bytes32 hash,
        PublicKey calldata publicKey,
        Signature calldata signature
    ) internal view returns (bool) {
        return verifyStatefulUncheckedMessage(
            expectedPublicKeyCommitment,
            publicKey,
            SPHINCSPlusC.toMessage(hash),
            signature
        );
    }

    // prepareStatelessDelegation: Encapsulate the stateless bundle checks the
    // SHRINCSVerifier ran inline before delegating to the pinned SPHINCSPlusC
    // sibling.
    // 1. Re-tag the stateless envelope in place (malformed reverts below).
    // 2. Run commitment-first bundle checks (commitment match, then shape).
    // 3. Extract the two 32-byte stateless seed words.
    // 4. Return the pinned-sibling delegate key and signature envelope;
    // any failure returns (false, "", "").
    function prepareStatelessDelegation(
        bytes32 expectedPublicKeyCommitment,
        bytes calldata envelope
    )
        internal
        pure
        returns (
            bool ok,
            bytes memory delegateKey,
            bytes memory delegateSignature
        )
    {
        (
            SHRINCS.PublicKey calldata publicKey,
            SPHINCSPlusC.Signature calldata signature
        ) = SHRINCS.statelessEnvelope(envelope);

        // Commitment first, then shape, mirroring the library stateless path.
        if (!SHRINCS.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return (false, "", "");
        if (!SHRINCS.validPublicKey(publicKey)) {
            return (false, "", "");
        }

        // validPublicKey has proven both fields are exactly 32 bytes.
        bytes calldata seed = publicKey.pkSeed;
        bytes calldata root = publicKey.hypertreeRoot;
        bytes32 pkSeed;
        bytes32 hypertreeRoot;
        // Memory-safe: reads two calldata words into stack variables; no
        // memory is written.
        assembly ("memory-safe") {
            pkSeed := calldataload(seed.offset)
            hypertreeRoot := calldataload(root.offset)
        }
        return (
            true,
            SHRINCS.encodeStatelessKey(pkSeed, hypertreeRoot),
            SHRINCS.sliceStatelessSignatureEnvelope(signature)
        );
    }

    // verifyStateful: Verify a stateful SHRINCS action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical stateful action hash from the installed key
    // commitment and action context.
    // 3. Verify the stateful WOTS-C / unbalanced-XMSS style signature against
    // that message hash.
    function verifyStateful(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.ActionContext memory context,
        SHRINCS.Signature calldata signature
    ) internal view returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!validActionContext(context)) return false;
        // Canonical stateful verification signs the typed action context
        // hash, not arbitrary caller-provided bytes.
        bytes memory message = abi.encodePacked(
            statefulActionMessageHash(expectedPublicKeyCommitment, context)
        );
        // Delegate the stateful signature equation checks to the lower-level
        // helper.
        return verifyStatefulUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }

    // verifyStateless: Verify a stateless SHRINCS action signature.
    // 1. Validate the typed action context shape.
    // 2. Build the canonical stateless action hash from the installed key
    // commitment and action context.
    // 3. Verify FORS-C and then carry the reconstructed root up the hypertree
    // to the public root.
    function verifyStateless(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.ActionContext memory context,
        SPHINCSPlusC.Signature calldata signature
    ) internal view returns (bool) {
        // Reject malformed or unscoped action contexts before hashing them.
        if (!validActionContext(context)) return false;
        // Canonical stateless verification signs the typed action context
        // hash, not arbitrary caller-provided bytes.
        bytes memory message = abi.encodePacked(
            statelessActionMessageHash(expectedPublicKeyCommitment, context)
        );
        // Delegate FORS-C plus hypertree verification to the lower-level
        // helper.
        return verifyStatelessUncheckedMessage(
            expectedPublicKeyCommitment, publicKey, message, signature
        );
    }

    // rotateStatefulViaStateless: Authorize replacing only the stateful
    // subkey via a stateless recovery signature.
    // 1. Validate the current key bundle, rotation context, and next stateful
    // key payload.
    // 2. Recompute the next stateful-bundle commitment and require it to
    // match the declared commitment.
    // 3. Build the canonical rotation message hash.
    // 4. Verify the stateless recovery signature over that hash under the
    // current installed key.
    // 5. Return the next bundle commitment on success, or bytes32(0) on
    // failure.
    function rotateStatefulViaStateless(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext memory context,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) internal view returns (bytes32 nextPublicKeyCommitment) {
        if (!SHRINCS.validPublicKey(currentPublicKey)) {
            return bytes32(0);
        }
        // The current public key must match the installed bundle commitment
        // the caller expects.
        if (!SHRINCS.matchesExpectedPublicKeyCommitment(
                currentPublicKey, expectedPublicKeyCommitment
            )) {
            return bytes32(0);
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!validRotationContext(context)) return bytes32(0);
        // Stateful subkey rotation carries only a replacement stateful public
        // key payload.
        if (!SHRINCS.validStatefulPublicKeyEncoding(
                nextStatefulKey.statefulPublicKey
            )) return bytes32(0);
        {
            // Decode the fixed-width stateful key to check operational limits
            // such as maxSignatures.
            (
                UXMSS.StatefulPublicKey memory decodedNextStatefulKey,
                bool ok
            ) = SHRINCS.decodeStatefulPublicKey(
                nextStatefulKey.statefulPublicKey
            );
            if (!ok) return bytes32(0);
            if (decodedNextStatefulKey.maxSignatures == 0) {
                return bytes32(0);
            }
        }
        // Rebuild the next installed bundle commitment using the replacement
        // stateful key plus the current stateless seed/root, since this
        // rotation does not replace the stateless side.
        bytes32 computedNextPublicKeyCommitment =
            SHRINCS.publicKeyCommitmentFromParts(
                nextStatefulKey.statefulPublicKey,
                currentPublicKey.pkSeed,
                currentPublicKey.hypertreeRoot
            );
        // The declared next bundle commitment must be present and exactly 32
        // bytes.
        if (nextStatefulKey.publicKeyCommitment.length != 32) {
            return bytes32(0);
        }
        bytes32 declaredNextPublicKeyCommitment;
        bytes calldata declaredNextPublicKeyCommitmentBytes =
            nextStatefulKey.publicKeyCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            declaredNextPublicKeyCommitment := calldataload(
                declaredNextPublicKeyCommitmentBytes.offset
            )
        }
        // Reject any mismatch between the declared and recomputed next
        // installed-key commitment.
        if (
            declaredNextPublicKeyCommitment
                != computedNextPublicKeyCommitment
        ) return bytes32(0);
        // Bind the current installed bundle commitment, rotation context, and
        // next bundle commitment into one canonical recovery message.
        bytes memory recoveryMessage = abi.encodePacked(
            statefulRotationMessageHash(
                expectedPublicKeyCommitment,
                currentPublicKey,
                context,
                nextStatefulKey
            )
        );
        // The stateless recovery signature must authorize exactly that
        // canonical rotation message.
        if (!verifyStatelessUncheckedMessage(
                expectedPublicKeyCommitment,
                currentPublicKey,
                recoveryMessage,
                recoverySignature
            )) {
            return bytes32(0);
        }
        // On success, return the commitment the wrapper should install as the
        // next bundle id.
        return computedNextPublicKeyCommitment;
    }

    // statelessRotate: Authorize replacing the full SHRINCS bundle via a
    // stateless recovery signature.
    // 1. Validate the current key bundle, rotation context, and full next-key
    // payload.
    // 2. Recompute the next full-bundle commitment and require it to match
    // the declared commitment.
    // 3. Build the canonical full-rotation message hash.
    // 4. Verify the stateless recovery signature over that hash under the
    // current installed key.
    // 5. Return the next bundle commitment on success, or bytes32(0) on
    // failure.
    function statelessRotate(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext memory context,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey
    ) internal view returns (bytes32 nextPublicKeyCommitment) {
        if (!SHRINCS.validPublicKey(currentPublicKey)) {
            return bytes32(0);
        }
        // The current public key must match the installed bundle commitment
        // the caller expects.
        if (!SHRINCS.matchesExpectedPublicKeyCommitment(
                currentPublicKey, expectedPublicKeyCommitment
            )) {
            return bytes32(0);
        }
        // Rotation messages must still carry a nonzero domain binding.
        if (!validRotationContext(context)) return bytes32(0);
        // The replacement bundle must have a canonical stateful key plus
        // fixed-width commitment, seed, and stateless-root fields.
        if (!SHRINCS.validStatefulPublicKeyEncoding(
                nextKey.statefulPublicKey
            )) return bytes32(0);
        if (nextKey.publicKeyCommitment.length != 32) return bytes32(0);
        if (nextKey.pkSeed.length != 32) return bytes32(0);
        if (nextKey.hypertreeRoot.length != 32) return bytes32(0);
        {
            // Decode the replacement stateful key to reject unusable
            // zero-budget keys.
            (
                UXMSS.StatefulPublicKey memory decodedNextStatefulKey,
                bool ok
            ) = SHRINCS.decodeStatefulPublicKey(nextKey.statefulPublicKey);
            if (!ok) return bytes32(0);
            if (decodedNextStatefulKey.maxSignatures == 0) {
                return bytes32(0);
            }
        }
        // Rebuild the full replacement bundle commitment from all next-key
        // components.
        bytes32 computedNextPublicKeyCommitment =
            SHRINCS.publicKeyCommitmentFromParts(
                nextKey.statefulPublicKey,
                nextKey.pkSeed,
                nextKey.hypertreeRoot
            );
        bytes32 declaredNextPublicKeyCommitment;
        bytes calldata declaredNextPublicKeyCommitmentBytes =
            nextKey.publicKeyCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            declaredNextPublicKeyCommitment := calldataload(
                declaredNextPublicKeyCommitmentBytes.offset
            )
        }
        // Reject any mismatch between the declared and recomputed next
        // installed-key commitment.
        if (
            declaredNextPublicKeyCommitment
                != computedNextPublicKeyCommitment
        ) return bytes32(0);

        // Bind the current installed bundle commitment, rotation context, and
        // full next bundle commitment into one canonical recovery message.
        bytes memory recoveryMessage = abi.encodePacked(
            fullRotationMessageHash(
                expectedPublicKeyCommitment,
                currentPublicKey,
                context,
                nextKey
            )
        );
        // The stateless recovery signature must authorize exactly that
        // canonical full rotation.
        if (!verifyStatelessUncheckedMessage(
                expectedPublicKeyCommitment,
                currentPublicKey,
                recoveryMessage,
                recoverySignature
            )) {
            return bytes32(0);
        }
        // On success, return the next bundle commitment the wrapper should
        // install.
        return computedNextPublicKeyCommitment;
    }

    // verifyStatefulUncheckedMessage: Verify a stateful signature after the
    // caller has already constructed the exact signed message bytes.
    // 1. Check that the public key uses the compiled fixed layout.
    // 2. Check the installed public-key commitment and the public-key
    // encoding.
    // 3. Decode the compact stateful public key embedded inside the SHRINCS
    // public bundle.
    // 4. Delegate the cryptographic verification to the stateful component
    // library.
    function verifyStatefulUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes memory message,
        SHRINCS.Signature calldata signature
    ) internal view returns (bool) {
        // The public key must satisfy the compiled fixed key shape.
        if (!SHRINCS.validPublicKey(publicKey)) return false;
        // The bundled public key must match the installed public-key
        // commitment.
        if (!SHRINCS.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return false;
        // Decode the compact stateful public key fields from the public
        // bundle.
        (UXMSS.StatefulPublicKey memory statefulKey, bool ok) =
            SHRINCS.decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        // The component library owns the stateful WOTS-C and unbalanced-tree
        // verification rules; re-tag the twin signature to UXMSS.Signature at
        // this single call boundary.
        return UXMSS.verify(
            statefulKey.pkSeed,
            statefulKey.root,
            statefulKey.maxSignatures,
            message,
            _toUxmss(signature)
        );
    }

    // Encoders and decoders (folded in from the dissolved codec library).
    // Byte-format definitions bridging ERC-7913 opaque bytes to typed
    // SHRINCS structs. Single source of truth for the verifier envelope
    // format; tests (and later the SDK) must encode through these helpers
    // so encoder and decoder cannot drift.
    //
    // Revert model: the production verify paths do not abi.decode. They
    // re-tag the calldata envelope (statefulEnvelope, statelessEnvelope,
    // statefulActionEnvelope, statelessActionEnvelope; the stateless
    // signature re-tag lives on SPHINCSPlusC) into typed calldata struct
    // pointers without copying or validating; each re-tag's own NatSpec
    // carries the safety story. Rejection is downstream: solc-generated
    // member access reverts on out-of-bounds offsets < 2^64,
    // out-of-bounds lengths, and dirty value-type high bits; a >= 2^255
    // head offset reads members as empty and the surviving KEEP guards
    // plus solc's index Panic drive it into {revert, false}. The
    // key/commitment decoders still length-check and report a wrong
    // length through `ok == false` without reverting. Acceptance is
    // wider than abi.decode's: any framing whose in-place field reads
    // reproduce a valid signature's field values verifies. The re-tag
    // reads are bounds-checked against calldatasize (the whole
    // transaction calldata), not the envelope slice, so they may read
    // into adjacent calldata such as the outer ABI zero-padding; under
    // masked-hash profiles even a tail-truncated envelope that abi.decode
    // would reject can verify. It is pure encoding malleability, never a
    // wrong-accept: accepted reads always equal a valid signature's exact
    // field values, so external consumers must key on decoded field
    // values, never on the envelope bytes. decodeStatefulEnvelope remains
    // an abi.decode helper for test/off-chain encoders only; no
    // production verify path calls it.

    /// @notice Decode an ERC-7913 `key` into the SHRINCS installed bundle
    /// commitment.
    /// @dev Requires the key to be exactly one 32-byte commitment word and
    /// loads it from calldata. Never reverts; malformed keys are reported
    /// through the ok flag.
    /// @param key The ERC-7913 key bytes (exactly 32 bytes).
    /// @return commitment The decoded 32-byte publicKeyCommitment. Named
    /// `commitment` here only to avoid shadowing this library's
    /// publicKeyCommitment(...) helper; the SHRINCS facade and the verifiers
    /// carry it in a `publicKeyCommitment` local.
    /// @return ok False when the key length is not 32.
    function decodePublicKeyCommitment(bytes calldata key)
        internal
        pure
        returns (bytes32 commitment, bool ok)
    {
        // The key format is exactly the 32-byte SHRINCS publicKeyCommitment,
        // nothing else.
        if (key.length != 32) return (bytes32(0), false);
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the 32-byte commitment word directly from calldata.
            commitment := calldataload(key.offset)
        }
        return (commitment, true);
    }

    /// @notice Decode the ERC-7913 `signature` envelope into typed SHRINCS
    /// structs.
    /// @dev Envelope layout is abi.encode(PublicKey, SHRINCS.Signature) with
    /// no mode prefix. abi.decode reverts on a malformed encoding (short
    /// buffer, out-of-range offset or length, or dirty value-type high bits);
    /// that revert is the rejection channel. Non-canonical framing abi.decode
    /// tolerates decodes to the same value and is accepted (byte-malleable).
    /// @param envelope The abi-encoded stateful envelope bytes.
    /// @return publicKey The decoded SHRINCS public-key bundle.
    /// @return signature The decoded stateful signature.
    /// @return ok Always true on return; a malformed envelope reverts.
    function decodeStatefulEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature,
            bool ok
        )
    {
        (publicKey, signature) =
            abi.decode(envelope, (SHRINCS.PublicKey, SHRINCS.Signature));
        return (publicKey, signature, true);
    }

    /// @notice Inverse of decodeStatelessKey.
    /// @dev Builds the SPHINCSPlusCVerifier key the sub-call verify expects.
    /// @param pkSeed The stateless SPHINCS-style public seed.
    /// @param hypertreeRoot The stateless SPHINCS-style public root.
    /// @return key The abi-encoded stateless key bytes (64 bytes).
    function encodeStatelessKey(bytes32 pkSeed, bytes32 hypertreeRoot)
        internal
        pure
        returns (bytes memory key)
    {
        return abi.encode(pkSeed, hypertreeRoot);
    }

    /// @notice Slice-copy re-encode of a re-tagged stateless signature into
    /// the SPHINCSPlusCVerifier signature envelope, with no field-by-field
    /// memory materialization.
    /// @dev Byte-identical to encodeStatelessSignatureEnvelope's
    /// abi.encode(signature) for every canonically framed signature:
    /// abi.encode of one dynamic value is a single 0x20 head offset word
    /// followed by that value's canonical body, and a re-tagged calldata
    /// signature already holds its canonical body contiguously, so the
    /// envelope is that head word plus ONE bulk calldatacopy of the body.
    /// The body length is the signature's own extent, derived from
    /// solc-checked members: hypertree is Signature's last field and authPath
    /// is HypertreeLayerSignature's last field, so the canonical encoding
    /// ends at the padded end of the last layer's last authPath element.
    /// Reading that end follows the nested calldata offsets solc resolves, so
    /// the copy spans the struct's true extent even when the outer envelope
    /// was truncated into adjacent calldata (matching abi.encode, which
    /// re-serializes from the in-place field reads; see the contract-level
    /// framing-malleability note). A malformed signature with an empty
    /// hypertree or empty last-layer authPath Panics on the index read and
    /// reverts, fail-closed within the verifier's documented {revert, false}
    /// model.
    /// @param signature Re-tagged stateless signature calldata pointer.
    /// @return envelope The abi-encoded stateless-signature envelope bytes.
    function sliceStatelessSignatureEnvelope(
        SPHINCSPlusC.Signature calldata signature
    ) internal pure returns (bytes memory envelope) {
        // hypertree is Signature's last field; authPath is the last field of
        // its element; so the canonical body ends at the last layer's last
        // authPath element. solc bounds-checks both index reads: an empty
        // hypertree or empty authPath Panics and reverts (fail-closed).
        uint256 lastLayer = signature.hypertree.length - 1;
        uint256 lastPath = signature.hypertree[lastLayer].authPath.length - 1;
        bytes calldata tail =
            signature.hypertree[lastLayer].authPath[lastPath];
        uint256 signatureStart;
        uint256 bodyEnd;
        assembly ("memory-safe") {
            signatureStart := signature
            bodyEnd := add(tail.offset, and(add(tail.length, 31), not(31)))
        }
        // solc validates nested calldata tails against calldatasize(), but
        // does not prove that independently resolved pointers are ordered.
        // Reject before subtracting so a wrapped/reordered tail cannot turn
        // into a near-2^256 calldatacopy and consume all forwarded gas.
        if (bodyEnd < signatureStart || bodyEnd > msg.data.length) {
            revert InvalidStatelessSignatureSlice();
        }
        // Memory-safe: allocates the envelope at the free-memory pointer,
        // writes its length and the single 0x20 head offset word, bulk-copies
        // the signature's canonical body from calldata, and bumps the
        // free-memory pointer past the (word-aligned) allocation.
        assembly ("memory-safe") {
            // Body = last authPath element's padded end - the signature's
            // calldata start. Accepted non-canonical framings can make this
            // length non-word-aligned, so reserve its rounded allocation.
            let body := sub(bodyEnd, signatureStart)
            envelope := mload(0x40)
            mstore(envelope, add(0x20, body))
            mstore(add(envelope, 0x20), 0x20)
            calldatacopy(add(envelope, 0x40), signatureStart, body)
            mstore(
                0x40,
                add(envelope, and(add(add(0x40, body), 31), not(31)))
            )
        }
    }

    /// @notice Zero-copy re-tag of a stateful envelope into typed calldata
    /// struct pointers.
    /// @dev Envelope layout is abi.encode(PublicKey, SHRINCS.Signature): the
    /// head is two offset words, one per dynamic struct. This re-tag reads
    /// those two offsets and returns calldata pointers without copying or
    /// validating them; it never reverts on its own and does no length or
    /// offset pre-check. All safety is downstream.
    /// Safety story (post-Z1/Z2 empirical review):
    /// - solc member access reverts on out-of-bounds offsets < 2^64,
    ///   out-of-bounds lengths, and dirty value-type high bits (E1a/E2);
    /// - a head offset >= 2^255 slips solc's signed tail bound and its
    ///   dynamic members read as EMPTY (E1b); downstream, solc's index
    ///   bounds-check Panics on the empty/short arrays inside the
    ///   constant-bounded verify loops, and the surviving KEEP guards
    ///   (installed-commitment match, validPublicKey shape pins, Hypertree
    ///   layers == d, UXMSS leaf-index cap) reject the rest, so E1b lands in
    ///   {revert, false};
    /// - framings whose in-place reads reproduce a valid signature's field
    ///   values are ACCEPTED by design: in-bounds offset aliasing, and
    ///   (the reads being bounds-checked against calldatasize, not the
    ///   envelope slice) reads that extend into adjacent calldata such as
    ///   the outer ABI padding, so a tail-truncated envelope can verify
    ///   under masked-hash profiles. This is pure encoding malleability,
    ///   never a wrong-accept; consumers must key on decoded field values,
    ///   never on envelope bytes (the acceptance model is documented at
    ///   the contract level, not guarded here).
    /// @param payload The abi-encoded stateful envelope calldata.
    /// @return publicKey Calldata pointer to the public-key bundle.
    /// @return signature Calldata pointer to the stateful signature.
    function statefulEnvelope(bytes calldata payload)
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            SHRINCS.Signature calldata signature
        )
    {
        // Pure calldata re-tag: reads two offset words into two calldata
        // pointers; no memory is read or written.
        assembly ("memory-safe") {
            publicKey := add(payload.offset, calldataload(payload.offset))
            signature := add(
                payload.offset,
                calldataload(add(payload.offset, 0x20))
            )
        }
    }

    /// @notice Zero-copy re-tag of a stateless envelope into typed calldata
    /// struct pointers.
    /// @dev Envelope layout is abi.encode(PublicKey, SPHINCSPlusC.Signature):
    /// the head is two offset words, one per dynamic struct. Same re-tag and
    /// same safety story as statefulEnvelope (E1a/E2 revert, E1b lands in
    /// {revert, false} via the downstream Panic backstop plus the KEEP
    /// guards, encoding malleability accepted by design).
    /// @param payload The abi-encoded stateless envelope calldata.
    /// @return publicKey Calldata pointer to the public-key bundle.
    /// @return signature Calldata pointer to the stateless signature.
    function statelessEnvelope(bytes calldata payload)
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            SPHINCSPlusC.Signature calldata signature
        )
    {
        // Pure calldata re-tag: reads two offset words into two calldata
        // pointers; no memory is read or written.
        assembly ("memory-safe") {
            publicKey := add(payload.offset, calldataload(payload.offset))
            signature := add(
                payload.offset,
                calldataload(add(payload.offset, 0x20))
            )
        }
    }

    /// @notice Zero-copy re-tag of a stateful account-action envelope into
    /// typed calldata pointers and the two inline action words.
    /// @dev Envelope layout is
    /// abi.encode(PublicKey, bytes32 actionType, bytes32 payloadHash,
    /// SHRINCS.Signature): a four-word head whose first/last words are the
    /// two dynamic-struct offsets and whose middle two words are the inline
    /// action fields. This re-tag reads all four without copying or
    /// validating; it never reverts on its own. Same safety story as
    /// statefulEnvelope (E1a/E2 revert, E1b lands in {revert, false} via the
    /// downstream Panic backstop plus the KEEP guards, encoding malleability
    /// accepted by design). The inline action words carry no offset, so they
    /// only feed the caller's canonical action-hash comparison; a wrong value
    /// fails that comparison rather than being trusted.
    /// @param payload The abi-encoded stateful action envelope calldata.
    /// @return publicKey Calldata pointer to the public-key bundle.
    /// @return actionType The inline action-type word.
    /// @return payloadHash The inline payload-hash word.
    /// @return signature Calldata pointer to the stateful signature.
    function statefulActionEnvelope(bytes calldata payload)
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            SHRINCS.Signature calldata signature
        )
    {
        // Pure calldata re-tag: reads two offset words into two calldata
        // pointers and two inline words; no memory is read or written.
        assembly ("memory-safe") {
            publicKey := add(payload.offset, calldataload(payload.offset))
            actionType := calldataload(add(payload.offset, 0x20))
            payloadHash := calldataload(add(payload.offset, 0x40))
            signature := add(
                payload.offset,
                calldataload(add(payload.offset, 0x60))
            )
        }
    }

    /// @notice Zero-copy re-tag of a stateless account-action envelope into
    /// typed calldata pointers and the two inline action words.
    /// @dev Envelope layout is
    /// abi.encode(PublicKey, bytes32 actionType, bytes32 payloadHash,
    /// SPHINCSPlusC.Signature): the same four-word head shape and the same
    /// safety story as statefulActionEnvelope.
    /// @param payload The abi-encoded stateless action envelope calldata.
    /// @return publicKey Calldata pointer to the public-key bundle.
    /// @return actionType The inline action-type word.
    /// @return payloadHash The inline payload-hash word.
    /// @return signature Calldata pointer to the stateless signature.
    function statelessActionEnvelope(bytes calldata payload)
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            bytes32 actionType,
            bytes32 payloadHash,
            SPHINCSPlusC.Signature calldata signature
        )
    {
        // Pure calldata re-tag: reads two offset words into two calldata
        // pointers and two inline words; no memory is read or written.
        assembly ("memory-safe") {
            publicKey := add(payload.offset, calldataload(payload.offset))
            actionType := calldataload(add(payload.offset, 0x20))
            payloadHash := calldataload(add(payload.offset, 0x40))
            signature := add(
                payload.offset,
                calldataload(add(payload.offset, 0x60))
            )
        }
    }

    // publicKeyCommitment: Recompute the bundle commitment from a fully
    // encoded public key.
    // 1. Domain-separate the commitment as a SHRINCS public-key bundle hash
    // profile-bound to "shrincs-public-key/<PROFILE_NAME>" (raw ASCII, no
    // length prefix), so a bundle can never verify under the wrong profile.
    // 2. Bind the stateful public key, stateless public seed, and hypertree
    // root.
    // 3. Return the installed public-key commitment.
    function publicKeyCommitment(SHRINCS.PublicKey calldata publicKey)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    // publicKeyCommitmentFromParts: Recompute the bundle commitment from
    // explicit component fields.
    // 1. Domain-separate the commitment as a SHRINCS public-key bundle hash
    // profile-bound to "shrincs-public-key/<PROFILE_NAME>" (raw ASCII, no
    // length prefix), matching publicKeyCommitment.
    // 2. Bind the stateful public key, stateless public seed, and hypertree
    // root.
    // 3. Return the installed public-key commitment.
    function publicKeyCommitmentFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
    }

    // matchesExpectedPublicKeyCommitment: Check that a bundled public key
    // matches an installed commitment.
    // 1. Load the declared commitment from calldata.
    // 2. Check it against the caller-supplied expected commitment.
    // 3. Recompute the bundle commitment and require it to match too.
    /// @dev Pairing precondition: this helper reads the first 32-byte word of
    /// publicKey.publicKeyCommitment without checking its length (the length
    /// pin dropped with the guard review). Every caller must pair it with a
    /// validPublicKey check on the same bundle, which pins
    /// publicKeyCommitment.length == 32; a short field would load adjacent
    /// calldata and fail the recomputed-commitment comparison, so the pairing
    /// is what keeps a short-commitment bundle out of the accept path.
    function matchesExpectedPublicKeyCommitment(
        SHRINCS.PublicKey calldata publicKey,
        bytes32 expectedPublicKeyCommitment
    ) internal pure returns (bool) {
        bytes calldata encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 actualCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the declared 32-byte commitment directly from calldata.
            actualCommitment := calldataload(encodedCommitment.offset)
        }
        // First require the declared field to match the expected installed
        // commitment.
        if (actualCommitment != expectedPublicKeyCommitment) return false;
        // Then require the whole public-key bundle to recompute to that same
        // commitment.
        return publicKeyCommitment(publicKey) == expectedPublicKeyCommitment;
    }

    // validStatefulPublicKeyEncoding: Pin the packed stateful-key width and
    // require its root to be canonical under the active profile hash mask.
    // The 128-bit profiles use only the high HASH_LEN bytes, so nonzero low
    // bytes can never equal a root reconstructed by verification.
    function validStatefulPublicKeyEncoding(bytes calldata encoded)
        internal
        pure
        returns (bool)
    {
        if (encoded.length != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES) {
            return false;
        }
        bytes32 root;
        assembly ("memory-safe") {
            root := calldataload(add(encoded.offset, 32))
        }
        return (root & SHRINCSParams.HASH_MASK) == root;
    }

    // validPublicKey: Validate public-key shape and embedded commitment.
    // 1. Check the encoded stateful key width and canonical root.
    // 2. Check the commitment, public-seed, and hypertree-root lengths.
    // 3. Recompute the bundle commitment and require it to match.
    function validPublicKey(SHRINCS.PublicKey calldata publicKey)
        internal
        pure
        returns (bool)
    {
        // Reject a wrong-width key or a stateful root with noncanonical
        // low bytes under a truncated profile.
        if (!SHRINCS.validStatefulPublicKeyEncoding(
                publicKey.statefulPublicKey
            )) return false;
        if (publicKey.publicKeyCommitment.length != 32) return false;
        // The stateless public seed is always one hash output wide.
        if (publicKey.pkSeed.length != 32) return false;
        // The hypertree root is always one hash output wide.
        if (publicKey.hypertreeRoot.length != 32) return false;
        bytes calldata encodedCommitment = publicKey.publicKeyCommitment;
        bytes32 expectedCommitment;
        // Memory-safe: reads one calldata word into a stack variable; no
        // memory is written.
        assembly ("memory-safe") {
            // Load the embedded 32-byte commitment directly from calldata.
            expectedCommitment := calldataload(encodedCommitment.offset)
        }
        return publicKeyCommitment(publicKey) == expectedCommitment;
    }

    // decodeStatefulPublicKey: Decode the fixed-width stateful public-key
    // payload into typed fields.
    // 1. Allocate the decoded struct in memory.
    // 2. Copy the public seed, root, and max-signatures fields from calldata.
    // 3. Return the decoded struct together with a success flag.
    /// @dev Rejects every length other than the fixed 68-byte encoding before
    /// the fixed-offset assembly reads, returning a zero struct and false.
    function decodeStatefulPublicKey(bytes calldata encoded)
        internal
        pure
        returns (UXMSS.StatefulPublicKey memory publicKey, bool ok)
    {
        if (encoded.length != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES) {
            return (
                UXMSS.StatefulPublicKey({
                    pkSeed: bytes32(0), root: bytes32(0), maxSignatures: 0
                }),
                false
            );
        }

        // Decoded StatefulPublicKey layout (0x60 bytes) written at the
        // free-memory pointer:
        //   [0x00..0x20) pkSeed
        //   [0x20..0x40) root
        //   [0x40..0x60) maxSignatures (high 4 bytes of the last input word)
        // The final calldata word (encoded.offset+0x40) reads the 4-byte
        // maxSignatures field in its high bytes: STATEFUL_PUBLIC_KEY_BYTES is
        // 68, so only bytes [64,68) carry maxSignatures and the shr discards
        // the trailing bytes read from the adjacent calldata.
        // Memory-safe: allocates 0x60 bytes and advances the free-memory
        // pointer past them; reads stay inside the calldata region.
        assembly ("memory-safe") {
            // Allocate the decoded struct starting at the free-memory
            // pointer.
            publicKey := mload(0x40)
            // Copy the first 32 bytes as the stateful public seed.
            mstore(publicKey, calldataload(encoded.offset))
            // Copy the next 32 bytes as the stateful root.
            mstore(
                add(publicKey, 0x20),
                calldataload(add(encoded.offset, 32))
            )
            // Copy the high 4 bytes of the final word as maxSignatures.
            mstore(
                add(publicKey, 0x40),
                shr(224, calldataload(add(encoded.offset, 64)))
            )
            // Bump the free-memory pointer past the decoded struct.
            mstore(0x40, add(publicKey, 0x60))
        }
        return (publicKey, true);
    }

    // _toUxmss: Re-tag a SHRINCS.Signature memory pointer as its
    // UXMSS.Signature twin at the single call boundary into the stateful
    // component library.
    function _toUxmss(Signature calldata signature)
        private
        pure
        returns (UXMSS.Signature calldata converted)
    {
        // SHRINCS.Signature and UXMSS.Signature are deliberate twins
        // with identical layouts (see the struct comments and the
        // twin-drift test); re-tag the calldata pointer instead of copying.
        // Memory-safe: no memory is read or written.
        assembly ("memory-safe") {
            converted := signature
        }
    }

    // statefulActionMessageHash: Build the canonical stateful action message
    // hash.
    // 1. Bind the stateful operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the account-layer action context fields.
    function statefulActionMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed
        // key commitment, and the account-layer action context so signatures
        // cannot be replayed across operation families or account epochs.
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATEFUL,
                HashSuite.HASH_SUITE_ID,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    // statelessActionMessageHash: Build the canonical stateless action
    // message hash.
    // 1. Bind the stateless operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the account-layer action context fields.
    function statelessActionMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.ActionContext memory context
    ) internal pure returns (bytes32) {
        // The canonical hash binds an operation tag, hash suite, installed
        // key commitment, and the account-layer action context for the
        // stateless path.
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATELESS,
                HashSuite.HASH_SUITE_ID,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    // statefulRawMessageHash: Bind an ERC-7913 caller-supplied hash to the
    // stateful operation family, active hash suite, and complete installed
    // SHRINCS public-key commitment.
    function statefulRawMessageHash(
        bytes32 expectedPublicKeyCommitment,
        bytes32 hash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATEFUL,
                HashSuite.HASH_SUITE_ID,
                expectedPublicKeyCommitment,
                hash
            )
        );
    }

    // statelessRawMessageHash: Stateless counterpart of
    // statefulRawMessageHash. The distinct operation tag prevents signatures
    // from crossing between the two raw adapter paths.
    function statelessRawMessageHash(
        bytes32 expectedPublicKeyCommitment,
        bytes32 hash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_VERIFY_STATELESS,
                HashSuite.HASH_SUITE_ID,
                expectedPublicKeyCommitment,
                hash
            )
        );
    }

    // statefulRotationMessageHash: Build the canonical message hash
    // authorizing a stateless-to-stateful rotation.
    // 1. Bind the stateful-rotation operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the rotation context.
    // 5. Bind the current and next bundle commitments.
    function statefulRotationMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext memory context,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        // The canonical stateful-rotation hash binds an operation tag, hash
        // suite, installed key commitment, rotation context, and both the
        // current and next bundle ids.
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_ROTATE_STATEFUL,
                HashSuite.HASH_SUITE_ID,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.publicKeyCommitment,
                nextStatefulKey.publicKeyCommitment
            )
        );
    }

    // fullRotationMessageHash: Build the canonical message hash authorizing a
    // full next-key bundle.
    // 1. Bind the full-rotation operation tag.
    // 2. Bind the hash suite.
    // 3. Bind the expected installed key commitment.
    // 4. Bind the rotation context.
    // 5. Bind the current and next bundle commitments.
    function fullRotationMessageHash(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext memory context,
        SHRINCS.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        // The canonical full-rotation hash binds an operation tag, hash
        // suite, installed key commitment, rotation context, and both the
        // current and next bundle ids.
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_ROTATE_FULL,
                HashSuite.HASH_SUITE_ID,
                expectedPublicKeyCommitment,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.publicKeyCommitment,
                nextKey.publicKeyCommitment
            )
        );
    }

    // verifyStatelessUncheckedMessage: Verify a stateless signature after the
    // caller has already constructed the exact signed message bytes.
    // 1. Validate the current key bundle and fixed public-key layout.
    // 2. Delegate FORS-C plus hypertree verification to the stateless
    // component library.
    function verifyStatelessUncheckedMessage(
        bytes32 expectedPublicKeyCommitment,
        SHRINCS.PublicKey calldata publicKey,
        bytes memory message,
        SPHINCSPlusC.Signature calldata signature
    ) internal view returns (bool) {
        // The current public key must match the installed bundle commitment
        // expected by the caller.
        if (!SHRINCS.matchesExpectedPublicKeyCommitment(
                publicKey, expectedPublicKeyCommitment
            )) return false;
        // The current key bundle must satisfy the compiled fixed public-key
        // shape.
        if (!SHRINCS.validPublicKey(publicKey)) return false;

        // The component library owns the FORS-C and hypertree verification
        // rules over the stateless public seed and root.
        return SPHINCSPlusC.verify(
            publicKey.pkSeed, publicKey.hypertreeRoot, message, signature
        );
    }

    // validActionContext: Perform lightweight structural checks for canonical
    // action contexts.
    // 1. Require a nonzero domain separator.
    // 2. Require a nonzero action type.
    // 3. Require a nonzero payload hash.
    function validActionContext(SHRINCS.ActionContext memory context)
        internal
        pure
        returns (bool)
    {
        // Domain separation must be explicit.
        if (context.domainSeparator == bytes32(0)) return false;
        // The action type must not be left unspecified.
        if (context.actionType == bytes32(0)) return false;
        // The payload must commit to some nonzero value.
        return context.payloadHash != bytes32(0);
    }

    // validRotationContext: Perform lightweight structural checks for
    // canonical rotation contexts.
    // 1. Require a nonzero domain separator.
    function validRotationContext(SHRINCS.RotationContext memory context)
        internal
        pure
        returns (bool)
    {
        return context.domainSeparator != bytes32(0);
    }
}
