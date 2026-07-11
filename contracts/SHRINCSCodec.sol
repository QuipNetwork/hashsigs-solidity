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

import {SHRINCSCore} from "./SHRINCSCore.sol";
import {UXMSS} from "./UXMSS.sol";
import {SPHINCSPlusCCore} from "./SPHINCSPlusCCore.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

/// @notice Byte-format definitions bridging ERC-7913 opaque bytes to typed
/// SHRINCS structs.
/// @dev Single source of truth for the verifier envelope format; tests (and
/// later the SDK) must encode through this library so encoder and decoder
/// cannot drift.
/// @dev House rule: this library never reverts. Every decoder validates the
/// input structurally over calldata (the walk-B validators below) and
/// reports malformed input through an `ok` boolean; revert policy belongs to
/// the calling contract. The structural walk is equivalent to re-encode
/// equality (`keccak256(payload) == keccak256(abi.encode(decoded...))`) for
/// each envelope's type shape but never re-materializes the (up to ~90 KB)
/// structure; the differential tests pin that equivalence over a mutation
/// battery. See SHRINCSAccountEnvelope for the reference walk and the
/// argument for why the walk equals re-encode equality on canonical framing.
library SHRINCSCodec {
    // Envelope shape selectors for the shared walk-B validator. Each names
    // the canonical ABI tuple the walk enforces.
    //   SHAPE_STATEFUL_ENVELOPE   = abi.encode(PublicKey, StatefulSignature)
    //   SHAPE_STATELESS_ENVELOPE  = abi.encode(PublicKey, StatelessSignature)
    //   SHAPE_STATELESS_SIGNATURE = abi.encode(StatelessSignature)
    uint256 private constant SHAPE_STATEFUL_ENVELOPE = 0;
    uint256 private constant SHAPE_STATELESS_ENVELOPE = 1;
    uint256 private constant SHAPE_STATELESS_SIGNATURE = 2;

    /// @notice Decode an ERC-7913 `key` into the SHRINCS installed bundle
    /// commitment.
    /// @dev Requires the key to be exactly one 32-byte commitment word and
    /// loads it from calldata. Never reverts; malformed keys are reported
    /// through the ok flag.
    /// @param key The ERC-7913 key bytes (exactly 32 bytes).
    /// @return commitment The decoded 32-byte publicKeyCommitment.
    /// @return ok False when the key length is not 32.
    function decodeKey(bytes calldata key)
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
    /// @dev Envelope layout is abi.encode(PublicKey, StatefulSignature) with
    /// no mode prefix. Never reverts: the structural walk over calldata
    /// (SHAPE_STATEFUL_ENVELOPE) rejects any non-canonical encoding through
    /// the `ok` flag before abi.decode, which is then infallible on the
    /// validated bytes.
    /// @param envelope The abi-encoded stateful envelope bytes.
    /// @return publicKey The decoded SHRINCS public-key bundle.
    /// @return signature The decoded stateful signature.
    /// @return ok False when the envelope is not the canonical encoding.
    function decodeStatefulEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            SHRINCSCore.PublicKey memory publicKey,
            UXMSS.StatefulSignature memory signature,
            bool ok
        )
    {
        if (!_isCanonicalEnvelope(envelope, SHAPE_STATEFUL_ENVELOPE)) {
            return (publicKey, signature, false);
        }
        (publicKey, signature) = abi.decode(
            envelope, (SHRINCSCore.PublicKey, UXMSS.StatefulSignature)
        );
        return (publicKey, signature, true);
    }

    /// @notice Inverse of decodeStatefulEnvelope.
    /// @dev Encodes the bundle and stateful signature with the exact layout
    /// the decoder expects, so tests and off-chain encoders share one format
    /// definition with the verifier.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param signature The stateful signature.
    /// @return envelope The abi-encoded stateful envelope bytes.
    function encodeStatefulEnvelope(
        SHRINCSCore.PublicKey memory publicKey,
        UXMSS.StatefulSignature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    /// @notice Decode the SHRINCS stateless-adapter envelope into typed
    /// structs.
    /// @dev Envelope layout is abi.encode(PublicKey, StatelessSignature)
    /// with no mode prefix. Never reverts: the structural walk over calldata
    /// (SHAPE_STATELESS_ENVELOPE) rejects any non-canonical encoding through
    /// the `ok` flag before abi.decode.
    /// @param envelope The abi-encoded stateless envelope bytes.
    /// @return publicKey The decoded SHRINCS public-key bundle.
    /// @return signature The decoded stateless signature.
    /// @return ok False when the envelope is not the canonical encoding.
    function decodeStatelessEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            SHRINCSCore.PublicKey memory publicKey,
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool ok
        )
    {
        if (!_isCanonicalEnvelope(envelope, SHAPE_STATELESS_ENVELOPE)) {
            return (publicKey, signature, false);
        }
        (publicKey, signature) = abi.decode(
            envelope,
            (SHRINCSCore.PublicKey, SPHINCSPlusCCore.StatelessSignature)
        );
        return (publicKey, signature, true);
    }

    /// @notice Inverse of decodeStatelessEnvelope.
    /// @dev Shares one format definition with the decoder so the verifier,
    /// tests, and off-chain encoders cannot drift.
    /// @param publicKey The SHRINCS public-key bundle.
    /// @param signature The stateless signature.
    /// @return envelope The abi-encoded stateless envelope bytes.
    function encodeStatelessEnvelope(
        SHRINCSCore.PublicKey memory publicKey,
        SPHINCSPlusCCore.StatelessSignature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(publicKey, signature);
    }

    /// @notice Decode the SPHINCSPlusC-adapter key into its two seed words.
    /// @dev Key layout is abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot),
    /// exactly 64 bytes of static words with no framing freedom, so a length
    /// check plus two calldata loads is a complete canonicity check. Never
    /// reverts; malformed keys are reported through the ok flag.
    /// @param key The ERC-7913 key bytes (exactly 64 bytes).
    /// @return pkSeed The stateless SPHINCS-style public seed.
    /// @return hypertreeRoot The stateless SPHINCS-style public root.
    /// @return ok False when the key length is not 64.
    function decodeStatelessKey(bytes calldata key)
        internal
        pure
        returns (bytes32 pkSeed, bytes32 hypertreeRoot, bool ok)
    {
        // Two static bytes32 words abi.encode to exactly 64 bytes.
        if (key.length != 64) return (bytes32(0), bytes32(0), false);
        // Memory-safe: reads two calldata words into stack variables; no
        // memory is written.
        assembly ("memory-safe") {
            pkSeed := calldataload(key.offset)
            hypertreeRoot := calldataload(add(key.offset, 32))
        }
        return (pkSeed, hypertreeRoot, true);
    }

    /// @notice Inverse of decodeStatelessKey.
    /// @dev Builds the SPHINCSPlusC-adapter key the sub-call verify expects.
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

    /// @notice Decode the SPHINCSPlusC-adapter envelope into a typed
    /// stateless signature.
    /// @dev Envelope layout is abi.encode(StatelessSignature) with no mode
    /// prefix. Never reverts: the structural walk over calldata
    /// (SHAPE_STATELESS_SIGNATURE) rejects any non-canonical encoding through
    /// the `ok` flag before abi.decode.
    /// @param envelope The abi-encoded stateless-signature envelope bytes.
    /// @return signature The decoded stateless signature.
    /// @return ok False when the envelope is not the canonical encoding.
    function decodeStatelessSignatureEnvelope(bytes calldata envelope)
        internal
        pure
        returns (
            SPHINCSPlusCCore.StatelessSignature memory signature,
            bool ok
        )
    {
        if (!_isCanonicalEnvelope(envelope, SHAPE_STATELESS_SIGNATURE)) {
            return (signature, false);
        }
        signature =
            abi.decode(envelope, (SPHINCSPlusCCore.StatelessSignature));
        return (signature, true);
    }

    /// @notice Inverse of decodeStatelessSignatureEnvelope.
    /// @dev Builds the SPHINCSPlusC-adapter signature envelope the sub-call
    /// verify expects, so the delegation path re-encodes through one format
    /// definition.
    /// @param signature The stateless signature.
    /// @return envelope The abi-encoded stateless-signature envelope bytes.
    function encodeStatelessSignatureEnvelope(
        SPHINCSPlusCCore.StatelessSignature memory signature
    ) internal pure returns (bytes memory envelope) {
        return abi.encode(signature);
    }

    /// @notice Convert the ERC-7913 32-byte hash into the SHRINCS signed
    /// message bytes.
    /// @dev ERC-7913 hands a bytes32 hash; SHRINCS signs raw message bytes.
    /// The hash IS the message: exactly its 32 bytes, packed.
    /// @param hash The 32-byte ERC-7913 hash.
    /// @return message The message bytes SHRINCS signs (the 32 hash bytes).
    function toMessage(bytes32 hash)
        internal
        pure
        returns (bytes memory message)
    {
        return abi.encodePacked(hash);
    }

    // publicKeyCommitment: Recompute the bundle commitment from a fully
    // encoded public key.
    // 1. Domain-separate the commitment as a SHRINCS public-key bundle hash.
    // 2. Bind the stateful public key, stateless public seed, and hypertree
    // root.
    // 3. Return the installed public-key commitment.
    function publicKeyCommitment(SHRINCSCore.PublicKey calldata publicKey)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "shrincs-public-key",
                publicKey.statefulPublicKey,
                publicKey.pkSeed,
                publicKey.hypertreeRoot
            )
        );
    }

    // publicKeyCommitmentFromParts: Recompute the bundle commitment from
    // explicit component fields.
    // 1. Domain-separate the commitment as a SHRINCS public-key bundle hash.
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
                "shrincs-public-key",
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
    }

    // matchesExpectedPublicKeyCommitment: Check that a bundled public key
    // matches an installed commitment.
    // 1. Require a nonzero expected installed-key commitment.
    // 2. Require a 32-byte encoded commitment field inside the public key.
    // 3. Load the declared commitment from calldata.
    // 4. Check it against the caller-supplied expected commitment.
    // 5. Recompute the bundle commitment and require it to match too.
    function matchesExpectedPublicKeyCommitment(
        SHRINCSCore.PublicKey calldata publicKey,
        bytes32 expectedPublicKeyCommitment
    ) internal pure returns (bool) {
        // A missing installed-key commitment is always invalid.
        if (expectedPublicKeyCommitment == bytes32(0)) return false;
        // The encoded commitment field must always be one hash output wide.
        if (publicKey.publicKeyCommitment.length != 32) return false;
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

    // validPublicKey: Validate public-key byte lengths and confirm its
    // embedded commitment is correct.
    // 1. Check the encoded stateful public-key length.
    // 2. Check the commitment, public-seed, and hypertree-root lengths.
    // 3. Load the embedded commitment from calldata.
    // 4. Recompute the bundle commitment and require it to match the embedded
    // field.
    function validPublicKey(SHRINCSCore.PublicKey calldata publicKey)
        internal
        pure
        returns (bool)
    {
        // The stateful public key has a fixed packed byte width.
        if (
            publicKey.statefulPublicKey.length
                != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) return false;
        // The embedded commitment field is always one hash output wide.
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
    // 1. Check the exact packed byte width of the encoded stateful public
    // key.
    // 2. Allocate the decoded struct in memory.
    // 3. Copy the public seed, root, and max-signatures fields from calldata.
    // 4. Return the decoded struct together with a success flag.
    function decodeStatefulPublicKey(bytes calldata encoded)
        internal
        pure
        returns (UXMSS.StatefulPublicKey memory publicKey, bool ok)
    {
        if (encoded.length != SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES) {
            return (publicKey, false);
        }
        // Decoded StatefulPublicKey layout (0x60 bytes) written at the
        // free-memory pointer:
        //   [0x00..0x20) pkSeed
        //   [0x20..0x40) root
        //   [0x40..0x60) maxSignatures (high 4 bytes of the last input word)
        // Memory-safe: allocates 0x60 bytes and advances the free-memory
        // pointer past them.
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

    // _isCanonicalEnvelope: structural walk-B validator shared by the
    // stateful/stateless envelope decoders. True iff `payload` is the
    // canonical ABI encoding of the tuple named by `shape`:
    //   SHAPE_STATEFUL_ENVELOPE   (PublicKey, StatefulSignature)
    //   SHAPE_STATELESS_ENVELOPE  (PublicKey, StatelessSignature)
    //   SHAPE_STATELESS_SIGNATURE (StatelessSignature)
    // Equivalent to keccak256(payload) ==
    // keccak256(abi.encode(decoded...)) for each shape, but computed by
    // structural validation instead of re-encoding (copied from
    // SHRINCSAccountEnvelope; see that library's header for why the walk
    // equals re-encode equality on canonical framing). Fails closed on any
    // malformed or non-canonical input.
    function _isCanonicalEnvelope(bytes calldata payload, uint256 shape)
        private
        pure
        returns (bool ok)
    {
        // The walk reads calldata directly. Three read primitives encode the
        // CODINGSTANDARDS §5 boundary:
        //   word  - unchecked calldataload, used ONLY as an operand of an
        //           equality against a constant or the running cursor. Under
        //           the §5 framing-read exception needs no bounds check: the
        //           payload sits at the calldata tail, so a read past its end
        //           returns zero, and zero != the expected nonzero
        //           offset/head-size -> fail closed.
        //   rdLen - checked read for a value that feeds arithmetic or a loop
        //           bound (a `bytes` length or an array count). Strict §5:
        //           the word must be in range and must not exceed
        //           payload.length -> fail closed.
        //   rdPad - checked read for a dynamic `bytes` final (padding) word.
        //           Its low bytes are compared against zero, where an
        //           out-of-bounds zero would fail OPEN, so it must NOT use
        //           the framing-read exception; only its range is checked.
        //   dirty-bit reject - word in a zero-compare (shr(N, word)) on a
        //           uint32/uint64 field, rejecting the dirty high bits
        //           abi.decode would revert on. An OOB read yields zero and
        //           passes locally, so this is not fail-closed alone; it is
        //           safe only because a bounds-checked read (rdLen/rdPad)
        //           follows on every accepting path before the
        //           full-consumption anchor (in `layer` the two dirty checks
        //           precede the first checked read).
        // ABI framing template (byte offsets relative to each tuple/array
        // head; `L` a length/count word, `O` an offset word, `.` a leaf
        // value or padding word the walk skips):
        //   PublicKey = (bytes,bytes,bytes,bytes)  head 128 = 4x[O]
        //   StatefulSignature = (bytes32 randomizer, uint32 counter,
        //     bytes32[] chains, bytes32[] authPath)
        //     head 128 = [.][.][O chains][O authPath]; each bytes32[] tail is
        //     [L count][count value words] with no offsets and no padding.
        //   StatelessSignature = (ForsSignature fors, HypertreeLayer[] hyper)
        //     head 64 = [O fors][O hyper]
        //   ForsSignature = (bytes randomizer, uint32 counter, ForsEntry[])
        //     head 96 = [O randomizer][. counter][O entries]
        //   ForsEntry = (bytes secretLeaf, bytes[] authPath)  head 64 = 2x[O]
        //   HypertreeLayer = (uint64 treeIndex, uint32 leafIndex,
        //     bytes wotsCPkHash, WotsCSignature wotsC, bytes[] authPath)
        //     head 160 = [.][.][O pkHash][O wots][O authPath]
        //   WotsCSignature = (bytes randomizer, uint32 counter, bytes[])
        //     head 96 = [O randomizer][. counter][O chains]
        assembly {
            let poff := payload.offset
            let plen := payload.length

            function word(po, pos) -> w {
                w := calldataload(add(po, pos))
            }
            function rdLen(po, pl, pos) -> v, okv {
                v := calldataload(add(po, pos))
                okv := and(iszero(gt(add(pos, 32), pl)), iszero(gt(v, pl)))
            }
            function rdPad(po, pl, pos) -> v, okv {
                v := calldataload(add(po, pos))
                okv := iszero(gt(add(pos, 32), pl))
            }

            // `bytes` tail at pos = [len][data...]. Returns end and ok.
            function bytesVal(po, pl, pos) -> end, good {
                let len, okl := rdLen(po, pl, pos)
                // (len + 31) / 32, later * 32, is exact ceiling rounding of
                // the byte length up to a whole word; no precision is lost.
                // slither-disable-next-line divide-before-multiply
                let dataWords := div(add(len, 31), 32)
                let dataStart := add(pos, 32)
                let rem := mod(len, 32)
                let padOk := 1
                if rem {
                    let lastPos := add(dataStart, mul(sub(dataWords, 1), 32))
                    let lw, okp := rdPad(po, pl, lastPos)
                    let padMask := sub(shl(mul(sub(32, rem), 8), 1), 1)
                    padOk := and(okp, iszero(and(lw, padMask)))
                }
                end := add(dataStart, mul(dataWords, 32))
                good := and(okl, padOk)
            }

            // bytes[] at base = [count][offsets][tails]. Returns end and ok.
            function bytesArr(po, pl, base) -> end, good {
                let count, okc := rdLen(po, pl, base)
                if iszero(okc) { leave }
                let headBase := add(base, 32)
                let cursor := mul(count, 32)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    if iszero(
                        eq(word(po, add(headBase, mul(i, 32))), cursor)
                    ) {
                        leave
                    }
                    let e, g := bytesVal(po, pl, add(headBase, cursor))
                    if iszero(g) { leave }
                    cursor := sub(e, headBase)
                }
                end := add(headBase, cursor)
                good := 1
            }

            // bytes32[] at base = [count][value words]; no offsets, no
            // padding. Leaf value words are skipped like any other leaf.
            function wordArr(po, pl, base) -> end, good {
                let count, okc := rdLen(po, pl, base)
                if iszero(okc) { leave }
                end := add(add(base, 32), mul(count, 32))
                good := 1
            }

            function forsEntry(po, pl, base) -> end, good {
                // (bytes secretLeaf, bytes[] authPath), head 64.
                if iszero(eq(word(po, base), 64)) { leave }
                let e, g := bytesVal(po, pl, add(base, 64))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 32)), sub(e, base))) {
                    leave
                }
                end, g := bytesArr(po, pl, e)
                good := g
            }

            function forsEntryArr(po, pl, base) -> end, good {
                let count, okc := rdLen(po, pl, base)
                if iszero(okc) { leave }
                let headBase := add(base, 32)
                let cursor := mul(count, 32)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    if iszero(
                        eq(word(po, add(headBase, mul(i, 32))), cursor)
                    ) {
                        leave
                    }
                    let e, g := forsEntry(po, pl, add(headBase, cursor))
                    if iszero(g) { leave }
                    cursor := sub(e, headBase)
                }
                end := add(headBase, cursor)
                good := 1
            }

            function fors(po, pl, base) -> end, good {
                // (bytes randomizer, uint32 counter, ForsEntry[]), head 96.
                if iszero(eq(word(po, base), 96)) { leave }
                // counter (slot 1) is a uint32: dirty high bits are
                // canonical framing but revert abi.decode, so reject them.
                if shr(32, word(po, add(base, 32))) { leave }
                let e, g := bytesVal(po, pl, add(base, 96))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 64)), sub(e, base))) {
                    leave
                }
                end, g := forsEntryArr(po, pl, e)
                good := g
            }

            function wotsC(po, pl, base) -> end, good {
                // (bytes randomizer, uint32 counter, bytes[] chains) head 96
                if iszero(eq(word(po, base), 96)) { leave }
                // counter (slot 1) is a uint32: reject dirty high bits.
                if shr(32, word(po, add(base, 32))) { leave }
                let e, g := bytesVal(po, pl, add(base, 96))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 64)), sub(e, base))) {
                    leave
                }
                end, g := bytesArr(po, pl, e)
                good := g
            }

            function layer(po, pl, base) -> end, good {
                // (uint64, uint32, bytes wotsCPkHash, WotsCSignature,
                //  bytes[] authPath), head 160.
                // treeIndex (uint64, slot 0) and leafIndex (uint32, slot 1)
                // must have clean high bits or abi.decode reverts.
                if shr(64, word(po, base)) { leave }
                if shr(32, word(po, add(base, 32))) { leave }
                if iszero(eq(word(po, add(base, 64)), 160)) {
                    leave
                }
                let e, g := bytesVal(po, pl, add(base, 160))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 96)), sub(e, base))) {
                    leave
                }
                e, g := wotsC(po, pl, e)
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 128)), sub(e, base))) {
                    leave
                }
                end, g := bytesArr(po, pl, e)
                good := g
            }

            function hypertree(po, pl, base) -> end, good {
                let count, okc := rdLen(po, pl, base)
                if iszero(okc) { leave }
                let headBase := add(base, 32)
                let cursor := mul(count, 32)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    if iszero(
                        eq(word(po, add(headBase, mul(i, 32))), cursor)
                    ) {
                        leave
                    }
                    let e, g := layer(po, pl, add(headBase, cursor))
                    if iszero(g) { leave }
                    cursor := sub(e, headBase)
                }
                end := add(headBase, cursor)
                good := 1
            }

            function publicKey(po, pl, base) -> end, good {
                // (bytes, bytes, bytes, bytes), head 128.
                if iszero(eq(word(po, base), 128)) { leave }
                let e, g := bytesVal(po, pl, add(base, 128))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 32)), sub(e, base))) {
                    leave
                }
                e, g := bytesVal(po, pl, e)
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 64)), sub(e, base))) {
                    leave
                }
                e, g := bytesVal(po, pl, e)
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 96)), sub(e, base))) {
                    leave
                }
                end, g := bytesVal(po, pl, e)
                good := g
            }

            function statefulSig(po, pl, base) -> end, good {
                // (bytes32 randomizer, uint32 counter, bytes32[] chains,
                //  bytes32[] authPath), head 128. chains offset (head slot
                //  2, byte 64) is fixed at 128.
                // counter (slot 1) is a uint32: reject dirty high bits.
                if shr(32, word(po, add(base, 32))) { leave }
                if iszero(eq(word(po, add(base, 64)), 128)) {
                    leave
                }
                let e, g := wordArr(po, pl, add(base, 128))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 96)), sub(e, base))) {
                    leave
                }
                end, g := wordArr(po, pl, e)
                good := g
            }

            function statelessSig(po, pl, base) -> end, good {
                // (ForsSignature, HypertreeLayer[]), head 64.
                if iszero(eq(word(po, base), 64)) { leave }
                let e, g := fors(po, pl, add(base, 64))
                if iszero(g) { leave }
                if iszero(eq(word(po, add(base, 32)), sub(e, base))) {
                    leave
                }
                end, g := hypertree(po, pl, e)
                good := g
            }

            switch shape
            // (StatelessSignature): head 32 = [O sig], offset fixed at 32.
            case 2 {
                if eq(word(poff, 0), 32) {
                    let sigEnd, gsig := statelessSig(poff, plen, 32)
                    if and(gsig, eq(sigEnd, plen)) { ok := 1 }
                }
            }
            // (PublicKey, sig): head 64 = [O pk][O sig]; pk offset fixed at
            // 64, sig offset must equal the end of the pk tail. shape 0
            // walks a StatefulSignature, shape 1 a StatelessSignature.
            default {
                if eq(word(poff, 0), 64) {
                    let pkEnd, gpk := publicKey(poff, plen, 64)
                    if and(gpk, eq(word(poff, 32), pkEnd)) {
                        let sigEnd := 0
                        let gsig := 0
                        switch shape
                        case 0 {
                            sigEnd, gsig := statefulSig(poff, plen, pkEnd)
                        }
                        default {
                            sigEnd, gsig := statelessSig(poff, plen, pkEnd)
                        }
                        if and(gsig, eq(sigEnd, plen)) { ok := 1 }
                    }
                }
            }
        }
    }
}
