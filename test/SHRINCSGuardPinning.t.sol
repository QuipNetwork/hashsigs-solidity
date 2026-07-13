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
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";

// GUARD-PINNING SAFETY ENVELOPE (epic Z1).
//
// This suite pins the OUTCOME of the ~29 input guards named in the guard-
// applicability review (docs/guard-applicability-review.md) across the
// guard-pruning drops. For every dropped guard's adversarial input class, the
// review proves the real verify path lands in {revert, false} — never a
// wrong-accept. These tests assert exactly that OUTCOME, not the MECHANISM:
// each adversarial call is made through an external harness inside try/catch,
// and a revert (Panic) and a `false` return are treated identically as "not a
// wrong-accept". That is why every assertion here passes BYTE-FOR-BYTE
// IDENTICALLY before and after the guards are dropped:
//   * BEFORE the drop the still-present shape/length/count guard returns
//     `false` (the try branch, ok == false);
//   * AFTER the drop the same input either reverts (Panic 0x32 from a fixed-
//     count loop indexing a short/empty array — caught by the catch branch)
//     or fails a downstream hash/target-sum compare and returns `false`.
// No test asserts a specific error or Panic selector.
//
// LONG-ARRAY MALLEABILITY (review rows 20, 26, 42, ...). A valid envelope
// with an OVER-LONG count/length array is the accepted-by-design
// byte-malleability case: pre-drop the count guard rejects it (`false`);
// post-drop the extra
// element is never read, so the same-message envelope re-encodes to a second
// byte-string that verifies IDENTICALLY (`true`). That `false` -> `true` flip
// is the whole point of dropping the guard and therefore CANNOT be pinned
// by a before/after-identical assertion. The two `...Long...` tests below pin
// the half that IS invariant across the drop: padding an array grants no
// forgery of a DIFFERENT message. The pure same-message acceptance is
// documented here rather than asserted (see each test's comment).
//
// NOT APPLICABLE: "stateful randomizer wrong length". SHRINCS.Signature
// .randomizer is a fixed `bytes32` (SHRINCS.sol / UXMSS.sol twin), so there
// is no length word to malform and no guard to drop. The FORS-C and WOTS-C
// randomizers ARE variable-length `bytes` and are covered below.

// StatefulHarness: exposes the stateful verify core as an EXTERNAL call so
// the tests can wrap it in try/catch and treat a revert as a rejection.
contract StatefulHarness {
    function verifyUnsafeRaw(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SHRINCS.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatefulUncheckedMessage(
            expectedCompositePublicKey, publicKey, message, signature
        );
    }
}

// StatelessHarness: same, for the FORS-C + hypertree stateless verify core.
contract StatelessHarness {
    function verifyUnsafeRaw(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata message,
        SPHINCSPlusC.Signature calldata signature
    ) external view returns (bool) {
        return SHRINCS.verifyStatelessUncheckedMessage(
            expectedCompositePublicKey, publicKey, message, signature
        );
    }
}

contract SHRINCSGuardPinningTest is Test {
    string internal constant VECTOR_PATH =
        "test/test_vectors/shrincs_sphincs_256s_keccak.json";

    // A 32-byte message the vector signers never signed; used by the long-
    // array malleability tests to force a rejection through the crypto (not
    // the dropped count guard).
    bytes internal constant WRONG_MESSAGE =
        hex"5a315a315a315a315a315a315a315a315a315a315a315a315a315a315a315a31";

    struct LegacyStatefulPublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    struct LegacyStatefulSignature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[64] chains;
        bytes32[] authPath;
    }

    struct LegacyPublicKey {
        bytes statefulPublicKey;
        bytes pkSeed;
        bytes hypertreeRoot;
    }

    struct LegacyForsEntry {
        bytes secretLeaf;
        bytes[] authPath;
    }

    struct LegacyForsSignature {
        bytes randomizer;
        uint32 counter;
        LegacyForsEntry[] entries;
    }

    struct LegacyWotsCSignature {
        bytes randomizer;
        uint32 counter;
        bytes[] chains;
    }

    struct LegacyHypertreeLayerSignature {
        bytes wotsCPkHash;
        LegacyWotsCSignature wotsCSignature;
        bytes[] authPath;
    }

    struct LegacyStatelessSignature {
        LegacyForsSignature fors;
        LegacyHypertreeLayerSignature[] hypertree;
    }

    StatefulHarness internal stateful;
    StatelessHarness internal stateless;
    string internal vectors;

    function setUp() public {
        stateful = new StatefulHarness();
        stateless = new StatelessHarness();
        vectors = vm.readFile(VECTOR_PATH);
    }

    // ---------------------------------------------------------------------
    // Anchors: the unmutated vectors verify. These pass in BOTH the pre-drop
    // and post-drop worlds (a valid signature is never rejected by a guard),
    // and prove each mutation below deviates from a genuinely-accepting
    // baseline rather than from a trivially-failing one.
    // ---------------------------------------------------------------------

    function testStatefulValidVectorVerifies() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        assertTrue(
            stateful.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateful valid vector must verify (anchor)"
        );
    }

    function testStatelessValidVectorVerifies() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        assertTrue(
            stateless.verifyUnsafeRaw(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless valid vector must verify (anchor)"
        );
    }

    // ---------------------------------------------------------------------
    // Stateful (UXMSS) input classes.
    // ---------------------------------------------------------------------

    // Class: stateful leaf-0 signature (empty authPath). Review rows
    // 18/21/22. leafIndex := authPath.length, so an empty path claims the
    // reserved leaf 0. Pre-drop UXMSS.sol:79 returns false; post-drop it
    // Panics on authPath[0] or fails the crypto compare (the
    // rootFromUnbalancedPath length check it once hit was itself dropped in
    // Z1).
    function testStatefulLeafZeroEmptyAuthPathRejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.authPath = new bytes32[](0);
        assertTrue(
            statefulRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateful leaf-0 empty authPath must not wrong-accept"
        );
    }

    // Class: wrong stateful chains count (SHORT). Review row 20.
    // Pre-drop UXMSS.sol:84 returns false; post-drop the fixed 64-chain loop
    // Panics indexing the short array.
    function testStatefulShortChainCountRejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.chains = dropLastBytes32(signature.chains);
        assertTrue(
            statefulRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateful short chain count must not wrong-accept"
        );
    }

    // Class: wrong stateful chains count (LONG) — malleability safety pin.
    // Review row 20. Pre-drop UXMSS.sol:84 rejects the 65-chain array
    // (`false`). Post-drop the extra chain is never read, so the SAME-message
    // envelope re-encodes to a second byte-string that verifies IDENTICALLY
    // (accepted-by-design malleability). That false->true flip is not
    // pinnable by a before/after-identical assertion; what IS invariant, and
    // pinned here, is that padding the chains cannot forge a DIFFERENT
    // message:
    // over WRONG_MESSAGE the reconstruction misses the target sum / root in
    // both worlds.
    function testStatefulLongChainCountMalleabilitySafety() public {
        (
            SHRINCS.PublicKey memory publicKey,,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        signature.chains = appendBytes32(signature.chains);
        assertTrue(
            statefulRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                WRONG_MESSAGE,
                signature
            ),
            "padded stateful chains must not forge a different message"
        );
    }

    // ---------------------------------------------------------------------
    // Stateless (FORS-C + hypertree) input classes.
    // ---------------------------------------------------------------------

    // Class: FORS entries count wrong (SHORT). Review row 26.
    // Pre-drop FORSMinusC.sol:83 returns false; post-drop the fixed k-1 loop
    // Panics indexing the short entries array.
    function testStatelessShortForsEntriesRejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries = dropLastForsEntries(signature.fors.entries);
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless short FORS entries must not wrong-accept"
        );
    }

    // Class: FORS entries count wrong (LONG) — malleability safety pin.
    // Review row 26. Pre-drop FORSMinusC.sol:83 rejects the k-th entry
    // (`false`); post-drop the extra entry is never read, so a same-message
    // envelope re-encodes and verifies identically (accepted malleability).
    // Pinned invariant: a padded entries array cannot forge WRONG_MESSAGE.
    function testStatelessLongForsEntriesMalleabilitySafety() public {
        (
            SHRINCS.PublicKey memory publicKey,,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries = appendForsEntry(signature.fors.entries);
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                WRONG_MESSAGE,
                signature
            ),
            "padded FORS entries must not forge a different message"
        );
    }

    // Class: FORS entry authPath wrong height. Review row 28.
    // Pre-drop FORSMinusC.sol:149 returns false; post-drop the fixed-height
    // path loop Panics indexing the short path.
    function testStatelessForsEntryAuthPathWrongHeightRejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath =
            dropLastBytes(signature.fors.entries[0].authPath);
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless FORS authPath wrong height must not wrong-accept"
        );
    }

    // Class: FORS authNode length != 32. Review row 29.
    // Pre-drop FORSMinusC.sol:242 returns the zero-root sentinel -> false;
    // post-drop the mload-32 read consumes adjacent bytes and the FORS pk
    // compare fails closed.
    function testStatelessForsAuthNodeLengthNot32Rejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].authPath[0] = hex"1234";
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless FORS authNode != 32 must not wrong-accept"
        );
    }

    // Class: FORS secretLeaf length != 32. Review row 27.
    // Pre-drop FORSMinusC.sol:146 returns false; post-drop hashForsLeaf32
    // mloads 32 bytes over adjacent memory and the tree root fails to match.
    function testStatelessForsSecretLeafLengthNot32Rejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.entries[0].secretLeaf = hex"1234";
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless FORS secretLeaf != 32 must not wrong-accept"
        );
    }

    // Class: stateless (FORS-C) randomizer wrong length. Review row 25.
    // Pre-drop FORSMinusC.sol:80 returns false; post-drop the fors-digest
    // mloads exactly 32 bytes and the derived coordinates fail the compare.
    function testStatelessForsRandomizerWrongLengthRejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.fors.randomizer = hex"1234";
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless FORS randomizer wrong length must not wrong-accept"
        );
    }

    // Class: hypertree layer wotsCPkHash length != 32. Review row 35.
    // Pre-drop Hypertree.sol:103 returns false; post-drop the mload-32 read
    // over adjacent memory yields a subtree leaf that fails the pkHash /
    // root compare.
    function testStatelessHypertreeWotsCPkHashLengthNot32Rejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].wotsCPkHash = hex"1234";
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless hypertree wotsCPkHash != 32 must not wrong-accept"
        );
    }

    // Class: hypertree layer authPath wrong length. Review row 42/36.
    // Pre-drop Hypertree.sol:417 returns false; post-drop the fixed-height
    // subtree path loop Panics indexing the short authPath.
    function testStatelessHypertreeLayerAuthPathWrongLengthRejected()
        public
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath =
            dropLastBytes(signature.hypertree[0].authPath);
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless hypertree authPath wrong length must not wrong-accept"
        );
    }

    // Class: hypertree layer authNode length != 32. Twin of FORS row 29
    // (maintainer ruling 2026-07-12): Hypertree.sol path-walk authNode pin
    // dropped for class consistency. Pre-drop the length pin returns the
    // (bytes32(0), false) sentinel -> false; post-drop the mload-32 read
    // consumes the short element's zero-padded word and the reconstructed
    // subtree root fails the installed-root compare closed.
    function testStatelessHypertreeAuthNodeLengthNot32Rejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].authPath[0] = hex"1234";
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless hypertree authNode != 32 must not wrong-accept"
        );
    }

    // Class: hypertree WOTS-C chain element length != 32. Review row 41.
    // Pre-drop Hypertree.sol:284 returns false; post-drop the mload-32 chain
    // read over adjacent memory reconstructs a wrong endpoint and the pkHash
    // compare fails closed.
    function testStatelessHypertreeChainElementLengthNot32Rejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree[0].wotsCSignature.chains[0] = hex"1234";
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless hypertree chain element != 32 must not wrong-accept"
        );
    }

    // Class: empty hypertree layers array. Review rows 31/32.
    // Pre-drop Hypertree.sol:61 returns false; post-drop the pre-loop
    // layers[0] read Panics on the empty array.
    function testStatelessEmptyHypertreeLayersRejected() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        signature.hypertree = new Hypertree.HypertreeLayerSignature[](0);
        assertTrue(
            statelessRejected(
                compositePublicKeyWord(publicKey),
                publicKey,
                message,
                signature
            ),
            "stateless empty hypertree layers must not wrong-accept"
        );
    }

    // ---------------------------------------------------------------------
    // Outcome assertions: a revert (Panic) and a `false` return are the SAME
    // safe outcome. Returns true iff the verify path did NOT wrong-accept.
    // ---------------------------------------------------------------------

    function statefulRejected(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey memory publicKey,
        bytes memory message,
        SHRINCS.Signature memory signature
    ) internal view returns (bool) {
        try stateful.verifyUnsafeRaw(
            expectedCompositePublicKey, publicKey, message, signature
        ) returns (
            bool ok
        ) {
            // A clean `false` is a rejection; a `true` here would be a
            // wrong-accept and must fail the test.
            return !ok;
        } catch {
            // Any revert (e.g. Panic 0x32 from a short/empty array) is also a
            // safe rejection.
            return true;
        }
    }

    function statelessRejected(
        bytes32 expectedCompositePublicKey,
        SHRINCS.PublicKey memory publicKey,
        bytes memory message,
        SPHINCSPlusC.Signature memory signature
    ) internal view returns (bool) {
        try stateless.verifyUnsafeRaw(
            expectedCompositePublicKey, publicKey, message, signature
        ) returns (
            bool ok
        ) {
            return !ok;
        } catch {
            return true;
        }
    }

    // ---------------------------------------------------------------------
    // Vector loading + reconstruction (mirrors
    // SHRINCSSphincs256sVectors.t.sol so these tests decode the same
    // Rust-anchored 256s vectors).
    // ---------------------------------------------------------------------

    function compositePublicKeyWord(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 word)
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

    function decodeStatefulVector(string memory vectorKey)
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            LegacyStatefulPublicKey memory legacyKey,
            bytes memory legacyMessage,
            LegacyStatefulSignature memory legacySignature
        ) = abi.decode(
            args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature)
        );

        (SHRINCS.PublicKey memory statelessPublicKey,,) =
            decodeStatelessVector(".stateless.cases.valid.calldata");

        bytes memory encodedStatefulKey = abi.encodePacked(
            legacyKey.pkSeed, legacyKey.root, bytes4(legacyKey.maxSignatures)
        );

        publicKey = publicKeyFromParts(
            encodedStatefulKey,
            statelessPublicKey.pkSeed,
            statelessPublicKey.hypertreeRoot
        );

        message = legacyMessage;
        signature = SHRINCS.Signature({
            randomizer: legacySignature.randomizer,
            counter: legacySignature.counter,
            chains: fixedToDynamicChains(legacySignature.chains),
            authPath: legacySignature.authPath
        });
    }

    function decodeStatelessVector(string memory vectorKey)
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        )
    {
        bytes memory args = vectorArgs(vectorKey);
        (
            LegacyPublicKey memory legacyPublicKey,
            bytes memory legacyMessage,
            LegacyStatelessSignature memory legacySignature
        ) = abi.decode(
            args, (LegacyPublicKey, bytes, LegacyStatelessSignature)
        );

        publicKey = publicKeyFromParts(
            legacyPublicKey.statefulPublicKey,
            legacyPublicKey.pkSeed,
            legacyPublicKey.hypertreeRoot
        );
        bytes memory encodedCommitment = vm.parseJsonBytes(
            vectors,
            string.concat(
                trimCalldataSuffix(vectorKey),
                ".publicKey.publicKeyCommitment"
            )
        );
        publicKey.publicKeyCommitment = encodedCommitment;

        message = legacyMessage;
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    // line-length: allow — fmt canonical header exceeds cap
    function convertLegacyStatelessSignature(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (SPHINCSPlusC.Signature memory signature)
    {
        FORSMinusC.ForsEntry[] memory entries =
            new FORSMinusC.ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = FORSMinusC.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf,
                authPath: legacy.fors.entries[i].authPath
            });
        }

        // forgefmt: disable-next-line
        Hypertree.HypertreeLayerSignature[] memory layers =
            new Hypertree.HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            layers[i] = Hypertree.HypertreeLayerSignature({
                wotsCPkHash: legacy.hypertree[i].wotsCPkHash,
                wotsCSignature: WOTSPlusC.WotsCSignature({
                    randomizer: legacy.hypertree[i].wotsCSignature
                    .randomizer,
                    counter: legacy.hypertree[i].wotsCSignature.counter,
                    chains: legacy.hypertree[i].wotsCSignature.chains
                }),
                authPath: legacy.hypertree[i].authPath
            });
        }

        signature = SPHINCSPlusC.Signature({
            fors: FORSMinusC.ForsSignature({
                randomizer: legacy.fors.randomizer,
                counter: legacy.fors.counter,
                entries: entries
            }),
            hypertree: layers
        });
    }

    function fixedToDynamicChains(bytes32[64] memory fixedChains)
        internal
        pure
        returns (bytes32[] memory chains)
    {
        chains = new bytes32[](64);
        for (uint256 i = 0; i < 64; ++i) {
            chains[i] = fixedChains[i];
        }
    }

    function publicKeyFromParts(
        bytes memory statefulPublicKey,
        bytes memory pkSeed,
        bytes memory hypertreeRoot
    ) internal pure returns (SHRINCS.PublicKey memory) {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                "shrincs-public-key/",
                SHRINCSParams.PROFILE_NAME,
                statefulPublicKey,
                pkSeed,
                hypertreeRoot
            )
        );
        return SHRINCS.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(commitment),
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });
    }

    function vectorArgs(string memory vectorKey)
        internal
        returns (bytes memory)
    {
        vm.pauseGasMetering();
        bytes memory callData = vm.parseJsonBytes(vectors, vectorKey);
        vm.resumeGasMetering();
        return stripSelector(callData);
    }

    function stripSelector(bytes memory input)
        internal
        pure
        returns (bytes memory output)
    {
        output = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; ++i) {
            output[i - 4] = input[i];
        }
    }

    function trimCalldataSuffix(string memory path)
        internal
        pure
        returns (string memory trimmed)
    {
        bytes memory source = bytes(path);
        bytes memory suffix = bytes(".calldata");
        require(source.length >= suffix.length, "path too short");
        uint256 trimmedLength = source.length - suffix.length;
        bytes memory out = new bytes(trimmedLength);
        for (uint256 i = 0; i < trimmedLength; ++i) {
            out[i] = source[i];
        }
        trimmed = string(out);
    }

    // ---------------------------------------------------------------------
    // Array mutation helpers.
    // ---------------------------------------------------------------------

    function dropLastBytes32(bytes32[] memory input)
        internal
        pure
        returns (bytes32[] memory output)
    {
        output = new bytes32[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function appendBytes32(bytes32[] memory input)
        internal
        pure
        returns (bytes32[] memory output)
    {
        output = new bytes32[](input.length + 1);
        for (uint256 i = 0; i < input.length; ++i) {
            output[i] = input[i];
        }
        // Arbitrary extra element the verify loop must never read.
        output[input.length] = keccak256("z1 extra chain element");
    }

    function dropLastBytes(bytes[] memory input)
        internal
        pure
        returns (bytes[] memory output)
    {
        output = new bytes[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function dropLastForsEntries(FORSMinusC.ForsEntry[] memory input)
        internal
        pure
        returns (FORSMinusC.ForsEntry[] memory output)
    {
        output = new FORSMinusC.ForsEntry[](input.length - 1);
        for (uint256 i = 0; i < output.length; ++i) {
            output[i] = input[i];
        }
    }

    function appendForsEntry(FORSMinusC.ForsEntry[] memory input)
        internal
        pure
        returns (FORSMinusC.ForsEntry[] memory output)
    {
        output = new FORSMinusC.ForsEntry[](input.length + 1);
        for (uint256 i = 0; i < input.length; ++i) {
            output[i] = input[i];
        }
        // Duplicate the first entry as a well-formed extra the loop never
        // reaches; the malformation under test is the COUNT, not the shape.
        output[input.length] = input[0];
    }
}
