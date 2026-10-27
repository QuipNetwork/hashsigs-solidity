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
import {
    IERC7913SignatureVerifier
} from "../contracts/interfaces/IERC7913SignatureVerifier.sol";
import {SHRINCS} from "../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {Hypertree} from "../contracts/Hypertree.sol";
import {WOTSPlusC} from "../contracts/WOTSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "./helpers/SHRINCSTestSigner.sol";
import {
    SHRINCSAccountSigningFacade
} from "./helpers/SHRINCSAccountSigningFacade.sol";
import {
    SHRINCSStatelessVectorSigner
} from "./helpers/SHRINCSStatelessVectorSigner.sol";

contract DelegationSigner is SHRINCSStatelessVectorSigner {}

/// @dev Common surface of every profile's SHRINCSPinned*.t.sol harness (each
/// `is` the profile's concrete SHRINCS verifier and adds `pinned()`).
/// Selecting the artifact string by SHRINCSParams.PROFILE_ID and deploying
/// through this interface lets the delegation battery reach the right
/// concrete verifier without statically importing any (only one profile's
/// concrete verifiers compile in a given build). Mirrors
/// SHRINCSMeasurements.t.sol's IMeasurementPinnedVerifier.
interface IPinnedStatelessVerifier {
    function pinned() external pure returns (address);
    function verifyStateless(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}

/// @notice Exercises every profile's SHRINCSVerifier verifyStateless
/// delegation to a locally deployed SPHINCSPlusC sibling at the pinned
/// CREATE3 address. Verifier and sibling are selected by
/// SHRINCSParams.PROFILE_ID
/// and deployed via deployCode (SHRINCSMeasurements pattern), so the battery
/// runs under all four profiles. The valid stateless fixture is produced
/// in-Solidity on the 256s profiles (feasible) and read from the profile's
/// Rust-anchored vector JSON on the 128s profiles (in-Solidity 128s stateless
/// keygen/signing is compute-infeasible), mirroring SHRINCSMeasurements.
contract SHRINCSStatelessDelegationTest is Test {
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    // Profile identities ([DESIGN §3.4]), matched against the active build's
    // SHRINCSParams.PROFILE_ID to select artifact strings, the fixture path
    // (in-Solidity vs vector), and the masked-hash truncation expectation.
    bytes32 internal constant PROFILE_256S_KECCAK =
        keccak256(bytes("shrincs-256s-keccak"));
    bytes32 internal constant PROFILE_256S_SHA2 =
        keccak256(bytes("shrincs-256s-sha2"));
    bytes32 internal constant PROFILE_128S_Q18 =
        keccak256(bytes("shrincs-128s-q18-keccak"));
    bytes32 internal constant PROFILE_128S_Q20 =
        keccak256(bytes("shrincs-128s-q20-keccak"));

    // Legacy vector-decoding shapes, mirroring
    // test/SHRINCSSphincs128sVectors.t.sol: the Rust generator's abi-encoded
    // calldata bundles the public key without its publicKeyCommitment field
    // (read separately from the JSON) and the FORS-C/hypertree/WOTS+C structs
    // at their pre-rename field layout.
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

    IPinnedStatelessVerifier internal verifier;
    DelegationSigner internal signer;

    bytes32 internal signedHash;
    bytes internal validKey;
    bytes internal validEnvelope;

    function setUp() public {
        signer = new DelegationSigner();
        // Build the valid stateless fixture first (in a dedicated frame) so
        // its ~90 KB working set does not stack under later allocations.
        (validKey, validEnvelope, signedHash) = this.buildValidFixture();

        // Deploy the active profile's concrete SHRINCS verifier (its pin
        // harness) and the SPHINCSPlusC sibling exactly where it delegates,
        // so verifyStateless reaches real verification code.
        verifier = IPinnedStatelessVerifier(deployCode(pinHarnessArtifact()));
        deployCodeTo(siblingArtifact(), "", verifier.pinned());
    }

    function testVerifyStatelessValidSignatureReturnsSelector() public view {
        assertEq(
            verifier.verifyStateless(validKey, signedHash, validEnvelope),
            IERC7913SignatureVerifier.verify.selector,
            "valid stateless signature must delegate and verify"
        );
    }

    function testVerifyStatelessRejectsWrongCommitment() public view {
        bytes memory wrongKey =
            abi.encodePacked(keccak256("some other commitment"));
        assertEq(
            verifier.verifyStateless(wrongKey, signedHash, validEnvelope),
            INVALID_SIGNATURE,
            "wrong commitment must be rejected before delegation"
        );
    }

    function testVerifyStatelessRejectsBadKeyLength() public view {
        bytes memory badKey = hex"1234";
        assertEq(
            verifier.verifyStateless(badKey, signedHash, validEnvelope),
            INVALID_SIGNATURE,
            "malformed key must be rejected"
        );
    }

    // Re-tag model: a one-byte truncation leaves every re-tagged offset and
    // length in bounds, so the bundle check passes and the delegate
    // signature is rebuilt from the same fields. On an UNMASKED profile
    // (HASH_LEN == 32) the last node loses a byte, the sibling's FORS-C plus
    // hypertree reconstruction fails, and verifyStateless returns 0xffffffff
    // without reverting (a malformed case moving within {revert, false}). On
    // a MASKED-hash profile (HASH_LEN != 32) maskHash already zeroes the low
    // bytes, so the stripped tail read back from the outer ABI zero-padding
    // is bit-identical and the signature still verifies — pure encoding
    // malleability over the SAME authorized hash, never a wrong-accept. Same
    // discriminator and outcome as SHRINCSVerifier's stateful
    // testTailTruncationAcceptedUnderMaskedProfile, here on the stateless
    // delegation path (closing the masked stateless-truncation gap).
    function testVerifyStatelessTailTruncationMatchesProfile() public view {
        bytes4 expected = SHRINCSParams.HASH_LEN != 32
            ? IERC7913SignatureVerifier.verify.selector
            : INVALID_SIGNATURE;

        bytes memory truncated = validEnvelope;
        assembly {
            mstore(truncated, sub(mload(truncated), 1))
        }
        assertEq(
            verifier.verifyStateless(validKey, signedHash, truncated),
            expected,
            "1-byte tail truncation outcome must match the profile"
        );
    }

    // Pins the delegation slice-build behavior change (epic Z5). The
    // signature's public-key bundle is the valid fixture's, so the commitment
    // and validPublicKey checks pass and prepareStatelessDelegation reaches
    // SHRINCS.sliceStatelessSignatureEnvelope. That build indexes the
    // last hypertree layer's last authPath element; on an empty last-layer
    // authPath (or an empty hypertree) the index reads Panic. verifyStateless
    // wraps the delegation build in no try/catch, so the Panic propagates and
    // the call lands in {revert, false} — never a wrong-accept. The prior
    // canonicity walk rejected these at a sibling-side length check; nothing
    // else pins the new revert. Panic-revert is the expected arm here.
    function testVerifyStatelessSliceBuildRevertsOnMalformedAuthPath()
        public
    {
        (bytes memory emptyAuthPath, bytes memory emptyHypertree) =
            this.buildMalformedEnvelopes();
        assertTrue(
            verifyStatelessRejected(emptyAuthPath),
            "empty last-layer authPath must not wrong-accept"
        );
        assertTrue(
            verifyStatelessRejected(emptyHypertree),
            "empty hypertree must not wrong-accept"
        );
    }

    function testVerifyStatelessRejectsTamperedHash() public view {
        assertEq(
            verifier.verifyStateless(
                validKey, keccak256("other hash"), validEnvelope
            ),
            INVALID_SIGNATURE,
            "a hash the signature does not authorize must fail"
        );
    }

    /// @dev Sibling-commitment replay. A stateless signature produced under
    /// bundle A must not verify when re-presented under a DIFFERENT bundle B
    /// that keeps A's pkSeed and hypertreeRoot — so the delegate key
    /// abi.encode(pkSeed, hypertreeRoot) is byte-identical — but carries a
    /// different statefulPublicKey. B is internally consistent: its embedded
    /// publicKeyCommitment is the real commitment over B's own parts, so the
    /// commitment-vs-key check and validPublicKey inside
    /// prepareStatelessDelegation both pass and the call reaches the pinned
    /// SPHINCSPlusC sibling with the same delegate key and the same signature
    /// bytes A used. The probe below pins exactly that. The only thing left
    /// separating the two bundles is the message binding in
    /// SHRINCSVerifier.verifyStateless (statelessRawMessageHash over the
    /// installed commitment), so the call must return 0xffffffff. Dropping
    /// the commitment from that binding turns this case into a wrong-accept.
    function testVerifyStatelessRejectsSignatureUnderSiblingCommitment()
        public
    {
        (bytes32 siblingCommitment, bytes memory siblingEnvelope) =
            this.buildSiblingCase();
        bytes32 validCommitment = abi.decode(validKey, (bytes32));
        assertTrue(
            siblingCommitment != validCommitment,
            "sibling bundle must carry its own distinct commitment"
        );

        // Non-vacuity: both bundles clear the commitment and shape checks and
        // hand the pinned sibling the identical delegate key, so a rejection
        // below can only come from the message binding.
        (bool validOk, bytes memory validDelegateKey) =
            this.probeStatelessDelegation(validEnvelope, validCommitment);
        (bool siblingOk, bytes memory siblingDelegateKey) =
            this.probeStatelessDelegation(siblingEnvelope, siblingCommitment);
        assertTrue(validOk, "valid bundle must reach delegation");
        assertTrue(siblingOk, "sibling bundle must reach delegation");
        assertEq(
            siblingDelegateKey,
            validDelegateKey,
            "sibling bundle must delegate under the same key"
        );

        assertEq(
            verifier.verifyStateless(
                abi.encodePacked(siblingCommitment),
                signedHash,
                siblingEnvelope
            ),
            INVALID_SIGNATURE,
            "a signature made under a sibling commitment must be rejected"
        );
    }

    /// @dev The deliberate revert-model property, on the one external call
    /// the memory restructure left in the verifier surface. With no try/catch
    /// around the stateless delegation, an out-of-gas in the pinned
    /// SPHINCSPlusC sibling is not swallowed to 0xffffffff: stranding that
    /// delegation hop under the 63/64 rule on a VALID signature makes the
    /// outer verifyStateless REVERT, so a genuine signature can never be
    /// misreported as invalid because of a gas shortfall. (The stateful
    /// verify path no longer makes any external call, so it has no equivalent
    /// hop to strand.) Profile-agnostic: a range of gas budgets below the
    /// happy-path cost is swept (the exact strand point differs per profile),
    /// and the invariant is pinned at every budget — a shortfall on a VALID
    /// signature either completes with the verify selector or reverts with
    /// empty returndata, and NEVER returns a swallowed 0xffffffff.
    function testVerifyStatelessRevertsWhenDelegationStrandedOnValidSig()
        public
    {
        bytes4 selector = IERC7913SignatureVerifier.verify.selector;
        // Full gas: the valid stateless signature delegates and verifies.
        assertEq(
            verifier.verifyStateless(validKey, signedHash, validEnvelope),
            selector,
            "control: valid stateless signature verifies with ample gas"
        );

        // Measure the happy-path cost, then sweep budgets below it. The
        // measurement is an upper bound (encode/return overhead is charged in
        // this frame), so which budget first strands the delegation varies by
        // profile; the sweep does not depend on the exact strand point.
        uint256 gasBefore = gasleft();
        verifier.verifyStateless(validKey, signedHash, validEnvelope);
        uint256 happyGas = gasBefore - gasleft();

        bytes memory callData = abi.encodeCall(
            verifier.verifyStateless, (validKey, signedHash, validEnvelope)
        );
        bool sawStrand = false;
        // Budgets 62/64 .. 2/64 of the measured happy cost (step 4/64).
        for (uint256 step = 0; step < 16; ++step) {
            uint256 budget = happyGas * (62 - step * 4) / 64;
            (bool ok, bytes memory ret) =
                address(verifier).call{gas: budget}(callData);
            if (ok) {
                assertEq(
                    abi.decode(ret, (bytes4)),
                    selector,
                    // line-length: allow — one unbreakable string token
                    "a reduced-gas success must still verify, never swallow the shortfall to 0xffffffff"
                );
            } else {
                sawStrand = true;
                assertEq(
                    ret.length,
                    0,
                    "an out-of-gas revert carries no return data"
                );
            }
        }
        assertTrue(
            sawStrand, "some reduced-gas budget must strand into a revert"
        );
    }

    /// @dev Builds the valid stateless fixture: the ERC-7913 key (the 32-byte
    /// bundle commitment), the stateless envelope, and the raw 32-byte hash
    /// message verifyStateless passes to the pinned verifier. External so it
    /// runs in its own memory frame.
    function buildValidFixture()
        external
        returns (bytes memory key, bytes memory envelope, bytes32 hash)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,
            bytes32 commitment,
            bytes32 messageHash
        ) = obtainValidCase();
        key = abi.encodePacked(commitment);
        envelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
        hash = messageHash;
    }

    /// @dev Builds two envelopes whose public-key bundle is the valid case's
    /// (so the installed-commitment and validPublicKey checks pass) but whose
    /// stateless signature is malformed so the delegation slice-build Panics:
    /// one with an empty last-layer authPath, one with an empty hypertree.
    /// External so the large working set runs in its own memory frame.
    function buildMalformedEnvelopes()
        external
        returns (bytes memory emptyAuthPath, bytes memory emptyHypertree)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,,
        ) = obtainValidCase();

        // Empty the last layer's authPath: slice-build's authPath[last] index
        // read Panics; the bundle is untouched so it reaches the slice build.
        uint256 last = signature.hypertree.length - 1;
        signature.hypertree[last].authPath = new bytes[](0);
        emptyAuthPath =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);

        // Empty the whole hypertree: slice-build's hypertree[last] index read
        // Panics.
        signature.hypertree = new Hypertree.HypertreeLayerSignature[](0);
        emptyHypertree =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
    }

    /// @dev Builds bundle B for the sibling-commitment replay: the valid
    /// case's public-key bundle with a different statefulPublicKey, its own
    /// recomputed publicKeyCommitment, and the valid case's stateless
    /// signature unchanged. pkSeed and hypertreeRoot are carried over, so B
    /// delegates under the same key as A. External so the large working set
    /// runs in its own memory frame.
    function buildSiblingCase()
        external
        returns (bytes32 commitment, bytes memory envelope)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,,
        ) = obtainValidCase();

        publicKey.statefulPublicKey =
            siblingStatefulPublicKey(publicKey.statefulPublicKey);
        commitment = SHRINCS.publicKeyCommitmentFromParts(
            publicKey.statefulPublicKey,
            publicKey.pkSeed,
            publicKey.hypertreeRoot
        );
        publicKey.publicKeyCommitment = abi.encodePacked(commitment);
        envelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
    }

    /// @dev Calldata probe over SHRINCS.prepareStatelessDelegation: reports
    /// whether an envelope clears the commitment-vs-key and validPublicKey
    /// checks and which delegate key it hands the pinned sibling. External
    /// because prepareStatelessDelegation re-tags a calldata envelope.
    function probeStatelessDelegation(
        bytes calldata envelope,
        bytes32 commitment
    ) external pure returns (bool ok, bytes memory delegateKey) {
        (ok, delegateKey,) =
            SHRINCS.prepareStatelessDelegation(commitment, envelope);
    }

    /// @dev The valid stateless case for the active profile: in-Solidity
    /// keygen + signing on the 256s profiles (feasible), or the
    /// Rust-anchored 128s stateless vector's valid case on the 128s profiles
    /// (in-Solidity 128s stateless signing is compute-infeasible — the full
    /// 2^a FORS trees plus the fixed hypertree). Mirrors
    /// SHRINCSMeasurements.t.sol.
    function obtainValidCase()
        internal
        returns (
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,
            bytes32 commitment,
            bytes32 hash
        )
    {
        if (isStateless128sVectorProfile()) {
            bytes memory message;
            (commitment, publicKey, message, signature) =
                loadStatelessVectorCase();
            hash = messageToHash(message);
            return (publicKey, signature, commitment, hash);
        }

        SHRINCS.SigningKey memory signingKey;
        bool ok;
        (signingKey, publicKey, ok) = SHRINCSAccountSigningFacade.keygen(
            bytes("stateless delegation fixture"), 4
        );
        require(ok, "keygen");

        hash = keccak256("stateless delegation message");
        (bytes32 sessionId, bool beginOk) = signer.beginSession(
            signingKey,
            publicKey,
            abi.encodePacked(
                SHRINCS.statelessRawMessageHash(
                    SHRINCSAccountSigningFacade.publicKeyCommitmentWord(
                        publicKey
                    ),
                    hash
                )
            )
        );
        require(beginOk, "begin");
        bool completeOk;
        (signature, completeOk) =
            SHRINCSAccountSigningFacade.completeStatelessSession(
                signer, sessionId
            );
        require(completeOk, "complete");
        commitment =
            SHRINCSAccountSigningFacade.publicKeyCommitmentWord(publicKey);
    }

    /// @dev Outcome-only rejection check for the slice-build pin: a revert
    /// (Panic) and a `0xffffffff` return are the same safe outcome. Returns
    /// true iff verifyStateless did NOT wrong-accept.
    function verifyStatelessRejected(bytes memory envelope)
        internal
        view
        returns (bool)
    {
        try verifier.verifyStateless(
            validKey, signedHash, envelope
        ) returns (
            bytes4 selector
        ) {
            return selector == INVALID_SIGNATURE;
        } catch {
            return true;
        }
    }

    // pinHarnessArtifact / siblingArtifact: select the active profile's
    // concrete SHRINCS/SPHINCSPlusC artifact-name strings for deployCode and
    // deployCodeTo. Only one profile's concrete verifiers compile at a time
    // (foundry.toml skip lists), so this file imports none of them statically
    // and resolves the pair at runtime, keyed on SHRINCSParams.PROFILE_ID.
    // Each SHRINCSPinned*.t.sol harness already `is` its profile's concrete
    // SHRINCS verifier and exposes `pinned()`; reusing those avoids a second
    // set of per-profile wrappers (mirrors SHRINCSMeasurements.t.sol).
    function pinHarnessArtifact() internal pure returns (string memory) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        if (id == PROFILE_256S_KECCAK) {
            return "SHRINCSPinned256s.t.sol:SHRINCS256sPinHarness";
        }
        if (id == PROFILE_256S_SHA2) {
            return "SHRINCSPinned256sSha2.t.sol:SHRINCS256sSha2PinHarness";
        }
        if (id == PROFILE_128S_Q18) {
            return "SHRINCSPinned128sQ18.t.sol:SHRINCS128sQ18PinHarness";
        }
        if (id == PROFILE_128S_Q20) {
            return "SHRINCSPinned128sQ20.t.sol:SHRINCS128sQ20PinHarness";
        }
        revert("SHRINCSStatelessDelegation: unknown profile");
    }

    function siblingArtifact() internal pure returns (string memory) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        if (id == PROFILE_256S_KECCAK) {
            return "SPHINCSPlusC256sKeccak.sol:SPHINCSPlusC256sKeccak";
        }
        if (id == PROFILE_256S_SHA2) {
            return "SPHINCSPlusC256sSha2.sol:SPHINCSPlusC256sSha2";
        }
        if (id == PROFILE_128S_Q18) {
            return "SPHINCSPlusC128sQ18Keccak.sol:SPHINCSPlusC128sQ18Keccak";
        }
        if (id == PROFILE_128S_Q20) {
            return "SPHINCSPlusC128sQ20Keccak.sol:SPHINCSPlusC128sQ20Keccak";
        }
        revert("SHRINCSStatelessDelegation: unknown profile");
    }

    function isStateless128sVectorProfile() internal pure returns (bool) {
        bytes32 id = SHRINCSParams.PROFILE_ID;
        return id == PROFILE_128S_Q18 || id == PROFILE_128S_Q20;
    }

    // 128s in-process stateless keygen/signing is compute-infeasible (full
    // 2^a FORS trees plus the fixed hypertree). loadStatelessVectorCase feeds
    // the Rust-anchored 128s stateless vector's valid case through the same
    // production verification the account wrapper uses, mirroring
    // SHRINCSSphincs128sVectors.t.sol's decode path.
    function loadStatelessVectorCase()
        internal
        returns (
            bytes32 commitment,
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            SPHINCSPlusC.Signature memory signature
        )
    {
        string memory vectors = vm.readFile(statelessVectorPath());
        bytes memory args = stripSelector(
            vm.parseJsonBytes(vectors, ".stateless.cases.valid.calldata")
        );

        LegacyPublicKey memory legacyPublicKey;
        LegacyStatelessSignature memory legacySignature;
        (legacyPublicKey, message, legacySignature) = abi.decode(
            args, (LegacyPublicKey, bytes, LegacyStatelessSignature)
        );
        message = vm.parseJsonBytes(vectors, ".stateless.callerHash");

        publicKey = SHRINCS.PublicKey({
            statefulPublicKey: legacyPublicKey.statefulPublicKey,
            publicKeyCommitment: vm.parseJsonBytes(
                vectors,
                ".stateless.cases.valid.publicKey.publicKeyCommitment"
            ),
            pkSeed: legacyPublicKey.pkSeed,
            hypertreeRoot: legacyPublicKey.hypertreeRoot
        });
        commitment = publicKeyCommitmentWord(publicKey);
        signature = convertLegacyStatelessSignature(legacySignature);
    }

    function statelessVectorPath() internal pure returns (string memory) {
        // q18 and q20 share every stateless field except the commitment tag;
        // pick the file by the stateless-signature budget, mirroring
        // SHRINCSSphincs128sVectors.t.sol.
        if (SHRINCSParams.STATELESS_SIGNATURE_LIMIT == 262_144) {
            return "test/test_vectors/shrincs_sphincs_128s_q18_keccak.json";
        }
        return "test/test_vectors/shrincs_sphincs_128s_q20_keccak.json";
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

    // The vector's 32-byte "message" is the exact hash value the fixed
    // signature authorizes (bytes.length == 32 for every stateless vector);
    // reinterpreting it as a bytes32 word gives the same value the delegation
    // entrypoint takes directly.
    function messageToHash(bytes memory message)
        internal
        pure
        returns (bytes32 out)
    {
        require(message.length == 32, "vector message must be 32 bytes");
        assembly {
            out := mload(add(message, 32))
        }
    }

    /// @dev Re-encodes an encoded stateful public key with a different
    /// stateful pkSeed, keeping the root and maxSignatures verbatim so the
    /// result keeps the profile's canonical (HASH_MASK-clean) root and still
    /// passes SHRINCS.validStatefulPublicKeyEncoding.
    function siblingStatefulPublicKey(bytes memory encoded)
        internal
        pure
        returns (bytes memory)
    {
        require(
            encoded.length == SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES,
            "sibling: stateful public key width"
        );
        bytes32 statefulPkSeed;
        bytes32 statefulRoot;
        uint32 maxSignatures;
        // Encoded stateful public key in memory, 68 bytes
        // (SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES), length word at +0:
        //   [+32..+64)   statefulPkSeed  (32 bytes)
        //   [+64..+96)   statefulRoot    (32 bytes)
        //   [+96..+100)  maxSignatures   (4 bytes, uint32)
        // maxSignatures is read from the word at +68 (the last 32 data
        // bytes, fully in bounds) and masked to its low 4 bytes rather
        // than from +96, which would read past the array.
        assembly ("memory-safe") {
            statefulPkSeed := mload(add(encoded, 32))
            statefulRoot := mload(add(encoded, 64))
            maxSignatures := and(mload(add(encoded, 68)), 0xffffffff)
        }
        return SHRINCSTestSigner.encodeStatefulPublicKey(
            keccak256(abi.encodePacked(statefulPkSeed, "sibling")),
            statefulRoot,
            maxSignatures
        );
    }

    function publicKeyCommitmentWord(SHRINCS.PublicKey memory publicKey)
        internal
        pure
        returns (bytes32 out)
    {
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            out := mload(add(commitmentBytes, 32))
        }
    }
}
