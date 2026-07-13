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
// LONG-ARRAY MALLEABILITY (review rows 20, 26). A valid envelope with an
// OVER-LONG count/length array is the accepted-by-design byte-malleability
// case: pre-drop the count guard rejected it (`false`); post-drop the extra
// element is never read (UXMSS loops WOTS_CHAINS_STATEFUL times, FORS-C loops
// NUM_FORS_TREES - 1 times — both fixed counts, never the array `.length`),
// so the SAME-message envelope verifies IDENTICALLY (`true`). The two
// `...Long...` tests below pin exactly that property over the CORRECT
// (signed) message: padding the array leaves the verify outcome unchanged
// from the unpadded anchor. Were the extra element ever read, the
// reconstruction would change and the correct-message verification would
// flip to `false`; asserting the outcome is unchanged is therefore a real
// pin of "extra element never read", not the vacuous
// rejection-over-a-wrong-message it replaced.
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
    // Profile identities ([DESIGN §3.4]), matched against the active build's
    // SHRINCSParams.PROFILE_ID to select the profile's Rust-anchored vector
    // JSON (mirrors SHRINCSMeasurements.t.sol). The loop-bound constants each
    // dropped-guard backstop relies on differ per profile (chains 64 vs 32,
    // FORS trees 22 vs 6, tree height 14 vs 24, layers 8 vs 1), so the
    // never-wrong-accept battery must run against every profile's own
    // vectors, not the 256s-keccak file alone.
    bytes32 internal constant PROFILE_256S_KECCAK =
        keccak256(bytes("shrincs-256s-keccak"));
    bytes32 internal constant PROFILE_256S_SHA2 =
        keccak256(bytes("shrincs-256s-sha2"));
    bytes32 internal constant PROFILE_128S_Q18 =
        keccak256(bytes("shrincs-128s-q18-keccak"));
    bytes32 internal constant PROFILE_128S_Q20 =
        keccak256(bytes("shrincs-128s-q20-keccak"));

    // The profile's stateful WOTS-C chain count discriminates the fixed-array
    // decode struct below: solc rejects a cross-library constant member as a
    // fixed-array length, so the two shipped sizes (64 at 256s, 32 at 128s)
    // get one concrete struct each and decodeStatefulVector branches on this.
    uint256 internal constant STATEFUL_CHAINS =
        SHRINCSParams.WOTS_CHAINS_STATEFUL;

    struct LegacyStatefulPublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    // 256s/256s-sha2 stateful WOTS-C reveals 64 chains; both 128s profiles
    // reveal 32 (WOTS_CHAINS_STATEFUL). One concrete struct per shipped size;
    // decodeStatefulVector picks by STATEFUL_CHAINS.
    struct LegacyStatefulSignature64 {
        bytes32 randomizer;
        uint32 counter;
        bytes32[64] chains;
        bytes32[] authPath;
    }

    struct LegacyStatefulSignature32 {
        bytes32 randomizer;
        uint32 counter;
        bytes32[32] chains;
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
        vectors = vm.readFile(vectorPath());
    }

    // vectorPath: select the active profile's Rust-anchored vector JSON by
    // PROFILE_ID (mirrors SHRINCSMeasurements.t.sol). Every profile's file
    // carries both a stateful and a stateless valid case plus tamper cases;
    // the guard-pinning mutations are applied to the valid case in-Solidity.
    function vectorPath() internal pure returns (string memory) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        if (id == PROFILE_256S_KECCAK) {
            return "test/test_vectors/shrincs_sphincs_256s_keccak.json";
        }
        if (id == PROFILE_256S_SHA2) {
            return "test/test_vectors/shrincs_sphincs_256s_sha2.json";
        }
        if (id == PROFILE_128S_Q18) {
            return "test/test_vectors/shrincs_sphincs_128s_q18_keccak.json";
        }
        if (id == PROFILE_128S_Q20) {
            return "test/test_vectors/shrincs_sphincs_128s_q20_keccak.json";
        }
        revert("SHRINCSGuardPinning: unknown profile");
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
    // Review row 20. Post-drop the extra chain is never read (UXMSS loops
    // WOTS_CHAINS_STATEFUL times, not chains.length), so padding a valid
    // signature over its CORRECT message leaves the verify outcome
    // unchanged from the unpadded anchor (`true`). Were the extra chain
    // read, the WOTS-C target sum / root reconstruction would change and
    // verification would flip to `false`; asserting the outcome is
    // unchanged pins "extra element never read" for real (replaces the
    // vacuous rejection-over-WRONG_MESSAGE check, which rejected with or
    // without the padding).
    function testStatefulLongChainCountMalleabilitySafety() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        ) = decodeStatefulVector(".stateful.cases.valid.calldata");
        bytes32 word = compositePublicKeyWord(publicKey);
        bool baseline =
            stateful.verifyUnsafeRaw(word, publicKey, message, signature);
        assertTrue(baseline, "anchor: unpadded stateful vector verifies");
        signature.chains = appendBytes32(signature.chains);
        assertEq(
            stateful.verifyUnsafeRaw(word, publicKey, message, signature),
            baseline,
            "padding valid chains must not change correct-message outcome"
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
    // Review row 26. Post-drop the extra entry is never read (FORS-C loops
    // NUM_FORS_TREES - 1 times, not entries.length), so padding a valid
    // signature over its CORRECT message leaves the verify outcome
    // unchanged from the unpadded anchor (`true`). Were the extra entry
    // read, the FORS digest / root reconstruction would change and
    // verification would flip to `false`; asserting the outcome is
    // unchanged pins "extra element never read" for real (replaces the
    // vacuous rejection-over-WRONG_MESSAGE check).
    function testStatelessLongForsEntriesMalleabilitySafety() public {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        ) = decodeStatelessVector(".stateless.cases.valid.calldata");
        bytes32 word = compositePublicKeyWord(publicKey);
        bool baseline =
            stateless.verifyUnsafeRaw(word, publicKey, message, signature);
        assertTrue(baseline, "anchor: unpadded stateless vector verifies");
        signature.fors.entries = appendForsEntry(signature.fors.entries);
        assertEq(
            stateless.verifyUnsafeRaw(word, publicKey, message, signature),
            baseline,
            "padding valid FORS entries must not change outcome"
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
        LegacyStatefulPublicKey memory legacyKey;
        (legacyKey, message, signature) = decodeLegacyStateful(args);

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
    }

    // decodeLegacyStateful: abi.decode the stateful vector calldata against
    // the profile's fixed-chain-count struct and rebuild the
    // profile-agnostic SHRINCS.Signature. Branches on STATEFUL_CHAINS
    // because the Rust calldata inlines the chains as a fixed-size array
    // whose length must match the decode struct exactly.
    function decodeLegacyStateful(bytes memory args)
        internal
        pure
        returns (
            LegacyStatefulPublicKey memory legacyKey,
            bytes memory message,
            SHRINCS.Signature memory signature
        )
    {
        if (STATEFUL_CHAINS == 64) {
            LegacyStatefulSignature64 memory legacySignature;
            (legacyKey, message, legacySignature) = abi.decode(
                args,
                (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature64)
            );
            bytes32[] memory chains = new bytes32[](64);
            for (uint256 i = 0; i < 64; ++i) {
                chains[i] = legacySignature.chains[i];
            }
            signature = SHRINCS.Signature({
                randomizer: legacySignature.randomizer,
                counter: legacySignature.counter,
                chains: chains,
                authPath: legacySignature.authPath
            });
            return (legacyKey, message, signature);
        }

        LegacyStatefulSignature32 memory legacySignature32;
        (legacyKey, message, legacySignature32) = abi.decode(
            args, (LegacyStatefulPublicKey, bytes, LegacyStatefulSignature32)
        );
        bytes32[] memory chains32 = new bytes32[](32);
        for (uint256 i = 0; i < 32; ++i) {
            chains32[i] = legacySignature32.chains[i];
        }
        signature = SHRINCS.Signature({
            randomizer: legacySignature32.randomizer,
            counter: legacySignature32.counter,
            chains: chains32,
            authPath: legacySignature32.authPath
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
