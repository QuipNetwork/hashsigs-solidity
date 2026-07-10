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

/// @notice Canonicity checks for the account wrapper's ERC-1271 envelopes.
/// @dev The stateless envelope is a ~90 KB structure; the naive canonicity
/// check `keccak256(payload) == keccak256(abi.encode(decoded...))`
/// re-materializes the whole thing (~491k gas). This library instead walks
/// the ABI framing in place over calldata and proves the input is the
/// canonical encoding without ever re-encoding it. Integrators copy the
/// example wrapper; keep this walk readable and auditable against
/// ShrincsTypes.
library ShrincsAccountEnvelope {
    /// @notice True iff `payload` is the canonical ABI encoding of a
    /// stateless action envelope `abi.encode(PublicKey, bytes32, bytes32,
    /// StatelessSignature)`.
    /// @dev Equivalent to `keccak256(payload) ==
    /// keccak256(abi.encode(abi.decode(payload)))` for this envelope's type
    /// shape, but computed by structural validation instead of re-encoding.
    ///
    /// Why the walk is equivalent to re-encode equality. The canonical ABI
    /// encoding of a value is unique: every dynamic child sits at the minimal
    /// sequential offset, every length field is exact, dynamic `bytes` tails
    /// are zero-padded to a word, and nothing trails the last tail item. The
    /// only freedom in a canonical encoding is the leaf *value* bytes; the
    /// framing (offsets, length words, tail padding) is a fixed template
    /// determined by the array counts and `bytes` lengths the value carries.
    /// `abi.decode` tolerates non-canonical framing (non-minimal offsets, gap
    /// bytes, dirty tail padding, trailing bytes), so re-encode equality is
    /// what rejects it. The walk below rejects exactly the same inputs: it
    /// reads the *actual* counts/lengths from `payload` (never assuming the
    /// SHRINCS profile constants), requires every offset word to equal the
    /// running canonical cursor, requires every dynamic `bytes` to be
    /// zero-padded, and requires the walk to consume exactly `payload.length`
    /// bytes. A differential fuzz test pins this equivalence against the
    /// re-encode reference over a mutation battery.
    ///
    /// ABI framing template (byte offsets relative to each tuple/array head;
    /// `L` marks a length/count word, `O` an offset word, `.` leaf value or
    /// padding words the walk skips):
    ///   T0 = (PublicKey pk, bytes32 actionType, bytes32 payloadHash,
    ///         StatelessSignature sig)   head 128 = [O pk][.][.][O sig]
    ///   PublicKey = (bytes,bytes,bytes,bytes)  head 128 = 4x[O]; each tail
    ///     [L][data...]; statefulPublicKey (len 68) has a padded final word.
    ///   StatelessSignature = (ForsSignature fors, HypertreeLayer[] hyper)
    ///     head 64 = [O fors][O hyper]
    ///   ForsSignature = (bytes randomizer, uint32 counter, ForsEntry[])
    ///     head 96 = [O randomizer][. counter][O entries]
    ///   ForsEntry = (bytes secretLeaf, bytes[] authPath)  head 64 = 2x[O]
    ///   HypertreeLayer = (uint64 treeIndex, uint32 leafIndex,
    ///     bytes wotsCPkHash, WotsCSignature wotsC, bytes[] authPath)
    ///     head 160 = [.][.][O pkHash][O wots][O authPath]
    ///   WotsCSignature = (bytes randomizer, uint32 counter, bytes[] chains)
    ///     head 96 = [O randomizer][. counter][O chains]
    ///   T[] dynamic array = [L count][count x O][tails]; offsets relative to
    ///     the word after the count.
    /// @param payload The stateless envelope bytes (no mode prefix).
    /// @return ok True when `payload` is in canonical form.
    function isCanonicalStatelessEnvelope(bytes calldata payload)
        internal
        pure
        returns (bool ok)
    {
        // The walk reads calldata directly. Three read primitives encode the
        // CODINGSTANDARDS §5 boundary:
        //   word  - unchecked calldataload, used ONLY as an operand of an
        //           equality against a constant or the running cursor. Under
        //           the §5 framing-read exception needs no bounds check:
        //           the payload sits at the calldata tail, so a read past
        //           its end returns zero, and zero != the expected nonzero
        //           offset/head-size -> fail closed.
        //   rdLen - checked read for a value that feeds arithmetic or a loop
        //           bound (a `bytes` length or an array count). Strict §5:
        //           the word must be in range, and the value must not exceed
        //           payload.length (a larger value is non-canonical and
        //           would overflow the cursor arithmetic) -> fail closed.
        //   rdPad - checked read for a dynamic `bytes` final (padding) word.
        //           Its low bytes are compared against zero, where an
        //           out-of-bounds zero would fail OPEN, so it must NOT use
        //           the framing-read exception; only its range is checked,
        //           its value (real leaf data) is unconstrained.
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
                // leave-free so the optimizer can inline this into the hot
                // array loops; failure is threaded through `good`, not an
                // early return. When okl is false `len` is unbounded, so the
                // arithmetic below may wrap, but `good` is zero and the
                // caller discards `end`.
                let len, okl := rdLen(po, pl, pos)
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
                    // framing-read: offset compared to cursor, OOB 0 fails.
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
                if iszero(eq(word(po, add(base, 64)), 160)) { leave }
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

            // T0 head is 128 bytes: pk offset, actionType, payloadHash, sig
            // offset. pk tail follows the head; sig tail follows the pk tail.
            if eq(word(poff, 0), 128) {
                let pkEnd, gpk := publicKey(poff, plen, 128)
                if and(gpk, eq(word(poff, 96), pkEnd)) {
                    let sigEnd, gsig := statelessSig(poff, plen, pkEnd)
                    // Anchor: the walk must consume exactly the whole
                    // payload, which rejects trailing bytes and any framing
                    // that leaves a gap.
                    if and(gsig, eq(sigEnd, plen)) { ok := 1 }
                }
            }
        }
    }
}
