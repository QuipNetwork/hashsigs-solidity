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

import {StatelessSignatureTypes} from "./StatelessSignatureTypes.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "../../contracts/SPHINCSPlusC.sol";
import {FORSMinusC} from "../../contracts/FORSMinusC.sol";
import {Hypertree} from "../../contracts/Hypertree.sol";
import {WOTSPlusC} from "../../contracts/WOTSPlusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestCodec} from "./SHRINCSTestCodec.sol";

/// @dev Surface of the active profile's pinned SHRINCS verifier harness
/// (SHRINCSPinned*.t.sol), resolved by artifact name at runtime.
interface ICompactPinnedVerifier {
    function pinned() external pure returns (address);
    function verifyStateless(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}

/// @dev Surface of the active profile's SPHINCSPlusC sibling.
interface ICompactSibling {
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}

/// @notice Shared fixtures for the compact stateless tests: deploys the
/// active profile's SHRINCS verifier and its SPHINCSPlusC sibling at the
/// pinned address, and decodes the profile's Rust-anchored stateless
/// vectors into struct form so they can be re-encoded both ways (ABI
/// envelope and StatelessLayout payload). Runs under every profile.
abstract contract SHRINCSCompactFixtures is Test {
    bytes4 internal constant VERIFY_SELECTOR = 0x024ad318;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    bytes32 internal constant PROFILE_256S_KECCAK =
        keccak256(bytes("shrincs-256s-keccak"));
    bytes32 internal constant PROFILE_256S_SHA2 =
        keccak256(bytes("shrincs-256s-sha2"));
    bytes32 internal constant PROFILE_128S_Q18 =
        keccak256(bytes("shrincs-128s-q18-keccak"));
    bytes32 internal constant PROFILE_128S_Q20 =
        keccak256(bytes("shrincs-128s-q20-keccak"));

    // Legacy vector-decoding shapes, mirroring SHRINCSStatelessDelegation.
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

    /// @dev One stateless vector case in both encodings.
    struct CompactCase {
        string name;
        bytes32 commitment;
        bytes32 callerHash;
        bytes32 rawMessage;
        bytes sphincsKey;
        bytes abiEnvelope;
        // Expected verdicts. At the SHRINCS layer the verifier signs over
        // callerHash, which wrongMessage shares with valid (Rust perturbs
        // only the raw message), so both verify there. At the SPHINCSPlusC
        // layer wrongMessage's raw message fails, while
        // tamperedComponentPublicKey changes only the stateful key, so its
        // signature still verifies under the unchanged pkSeed,
        // hypertreeRoot, and raw message. Every other case fails both.
        bool expectedValid;
        bool expectedSphincsValid;
        bytes compactPayload;
        bytes compactSignature;
    }

    ICompactPinnedVerifier internal verifier;
    ICompactSibling internal sibling;
    string internal vectors;

    function deployVerifiers() internal {
        verifier = ICompactPinnedVerifier(deployCode(pinHarnessArtifact()));
        deployCodeTo(siblingArtifact(), "", verifier.pinned());
        sibling = ICompactSibling(verifier.pinned());
        vectors = vm.readFile(vectorPath());
    }

    /// @dev Copy of data[from:to].
    function byteRange(bytes memory data, uint256 from, uint256 to)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }

    function caseNames() internal pure returns (string[7] memory) {
        return [
            "valid",
            "wrongMessage",
            "tamperedFors",
            "tamperedHypertreeAuth",
            "tamperedHypertreeWotsPkHash",
            "wrongPublicRoot",
            "tamperedComponentPublicKey"
        ];
    }

    /// @dev Loads `.stateless.cases.<name>` and encodes it both ways.
    function loadCase(string memory name)
        internal
        view
        returns (CompactCase memory out)
    {
        (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            StatelessSignatureTypes.Signature memory signature
        ) = decodeCase(name);
        out.name = name;
        out.commitment = word(publicKey.publicKeyCommitment);
        out.callerHash =
            word(vm.parseJsonBytes(vectors, ".stateless.callerHash"));
        out.rawMessage = word(message);
        out.sphincsKey = abi.encode(
            word(publicKey.pkSeed), word(publicKey.hypertreeRoot)
        );
        out.abiEnvelope =
            SHRINCSTestCodec.encodeStatelessEnvelope(publicKey, signature);
        bytes32 id = keccak256(bytes(name));
        out.expectedValid =
            id == keccak256("valid") || id == keccak256("wrongMessage");
        out.expectedSphincsValid = id == keccak256("valid")
            || id == keccak256("tamperedComponentPublicKey");
        out.compactPayload =
            SHRINCSTestCodec.encodeCompactPayload(publicKey, signature);
        out.compactSignature =
            SHRINCSTestCodec.encodeCompactSignature(signature);
    }

    function decodeCase(string memory name)
        internal
        view
        returns (
            SHRINCS.PublicKey memory publicKey,
            bytes memory message,
            StatelessSignatureTypes.Signature memory signature
        )
    {
        string memory prefix = string.concat(".stateless.cases.", name);
        bytes memory raw =
            vm.parseJsonBytes(vectors, string.concat(prefix, ".calldata"));
        bytes memory args = new bytes(raw.length - 4);
        for (uint256 i = 0; i < args.length; ++i) {
            args[i] = raw[i + 4];
        }
        LegacyPublicKey memory legacyPublicKey;
        LegacyStatelessSignature memory legacySignature;
        (legacyPublicKey, message, legacySignature) = abi.decode(
            args, (LegacyPublicKey, bytes, LegacyStatelessSignature)
        );
        publicKey = SHRINCS.PublicKey({
            statefulPublicKey: legacyPublicKey.statefulPublicKey,
            publicKeyCommitment: vm.parseJsonBytes(
                vectors,
                string.concat(prefix, ".publicKey.publicKeyCommitment")
            ),
            pkSeed: legacyPublicKey.pkSeed,
            hypertreeRoot: legacyPublicKey.hypertreeRoot
        });
        signature = convertLegacy(legacySignature);
    }

    function convertLegacy(LegacyStatelessSignature memory legacy)
        internal
        pure
        returns (StatelessSignatureTypes.Signature memory signature)
    {
        // line-length: allow — fmt canonical declaration exceeds cap
        StatelessSignatureTypes.ForsEntry[] memory entries = new StatelessSignatureTypes
            .ForsEntry[](legacy.fors.entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            entries[i] = StatelessSignatureTypes.ForsEntry({
                secretLeaf: legacy.fors.entries[i].secretLeaf,
                authPath: legacy.fors.entries[i].authPath
            });
        }
        // forgefmt: disable-next-line
        StatelessSignatureTypes.HypertreeLayerSignature[] memory layers =
            new StatelessSignatureTypes
                .HypertreeLayerSignature[](legacy.hypertree.length);
        for (uint256 i = 0; i < layers.length; ++i) {
            LegacyHypertreeLayerSignature memory layer = legacy.hypertree[i];
            layers[i] = StatelessSignatureTypes.HypertreeLayerSignature({
                wotsCPkHash: layer.wotsCPkHash,
                wotsCSignature: StatelessSignatureTypes.WotsCSignature({
                    randomizer: layer.wotsCSignature.randomizer,
                    counter: layer.wotsCSignature.counter,
                    chains: layer.wotsCSignature.chains
                }),
                authPath: layer.authPath
            });
        }
        signature = StatelessSignatureTypes.Signature({
            fors: StatelessSignatureTypes.ForsSignature({
                randomizer: legacy.fors.randomizer,
                counter: legacy.fors.counter,
                entries: entries
            }),
            hypertree: layers
        });
    }

    function word(bytes memory data) internal pure returns (bytes32 out) {
        require(data.length >= 32, "fixture word: short");
        assembly ("memory-safe") {
            out := mload(add(data, 32))
        }
    }

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
        revert("SHRINCSCompactFixtures: unknown profile");
    }

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
        revert("SHRINCSCompactFixtures: unknown profile");
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
        revert("SHRINCSCompactFixtures: unknown profile");
    }
}
