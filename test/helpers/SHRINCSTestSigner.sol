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

import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {UXMSS} from "../../contracts/UXMSS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {Hash} from "../../contracts/Hash.sol";

/// @notice TEST-ONLY Solidity signer helpers that mirror the Rust signer for
/// stateful flows.
/// @dev This library is kept under `test/helpers` so it does not become part
/// of the production Solidity surface. It is used for deterministic keygen
/// and stateful-signing tests.
library SHRINCSTestSigner {
    uint32 internal constant INITIAL_STATEFUL_LEAF_INDEX = 1;
    uint32 internal constant MAX_STATEFUL_SIGNATURES_LIMIT = 4096;
    uint32 internal constant WOTS_C_MAX_GRIND_COUNTER = 1 << 24;
    // 256s hypertree geometry (d = 8). This helper's stateless keygen
    // carries the 256s layer count deliberately: the full 128s stateless
    // hypertree keygen (single layer, 2^18 WOTS leaves) is computationally
    // infeasible on-chain, so under 128s this helper's hypertree root is
    // non-canonical and is NOT used for stateless correctness. 128s
    // stateless coverage is vector-driven (SHRINCSSphincs128sVectors);
    // 128s stateful tests use only the stateful subtree, which is
    // independent of this constant.
    uint8 internal constant NUM_HYPERTREE_LAYERS = 8;

    function keygen(bytes memory seedMaterial, uint32 maxStatefulSignatures)
        internal
        pure
        returns (
            SHRINCS.SigningKey memory signingKey,
            SHRINCS.PublicKey memory publicKey,
            bool ok
        )
    {
        if (maxStatefulSignatures == 0) {
            return (signingKey, publicKey, false);
        }
        if (maxStatefulSignatures > MAX_STATEFUL_SIGNATURES_LIMIT) {
            return (signingKey, publicKey, false);
        }

        bytes32 statefulSkSeed =
            derive32("shrincs-stateful-sk-seed", seedMaterial, "");
        bytes32 statefulPrfSeed =
            derive32("shrincs-stateful-prf-seed", seedMaterial, "");
        bytes32 statefulPkSeed =
            derive32("shrincs-stateful-pk-seed", seedMaterial, "");
        bytes32 statefulRoot = statefulSubtreeRoot(
            statefulSkSeed,
            statefulPkSeed,
            INITIAL_STATEFUL_LEAF_INDEX,
            maxStatefulSignatures
        );
        bytes32 statelessSkSeed =
            derive32("shrincs-stateless-sk-seed", seedMaterial, "");
        bytes32 statelessPrfSeed =
            derive32("shrincs-stateless-prf-seed", seedMaterial, "");
        bytes32 pkSeed = derive32("shrincs-pk-seed", seedMaterial, "");
        bytes32 hypertreeRoot = hypertreePublicRoot(statelessSkSeed, pkSeed);

        signingKey = SHRINCS.SigningKey({
            statefulSkSeed: statefulSkSeed,
            statefulPrfSeed: statefulPrfSeed,
            statefulPkSeed: statefulPkSeed,
            statefulRoot: statefulRoot,
            maxStatefulSignatures: maxStatefulSignatures,
            nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
            statelessSkSeed: statelessSkSeed,
            statelessPrfSeed: statelessPrfSeed,
            pkSeed: pkSeed,
            hypertreeRoot: hypertreeRoot
        });

        bytes memory statefulPublicKey = encodeStatefulPublicKey(
            statefulPkSeed, statefulRoot, maxStatefulSignatures
        );
        bytes32 publicKeyCommitment = SHRINCS.publicKeyCommitmentFromParts(
            statefulPublicKey,
            abi.encodePacked(pkSeed),
            abi.encodePacked(hypertreeRoot)
        );
        publicKey = SHRINCS.PublicKey({
            statefulPublicKey: statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(publicKeyCommitment),
            pkSeed: abi.encodePacked(pkSeed),
            hypertreeRoot: abi.encodePacked(hypertreeRoot)
        });
        return (signingKey, publicKey, true);
    }

    function signStatefulRaw(
        SHRINCS.SigningKey memory signingKey,
        bytes memory message
    )
        internal
        pure
        returns (
            SHRINCS.SigningKey memory nextSigningKey,
            SHRINCS.Signature memory signature,
            bool ok
        )
    {
        uint32 leafIndex = signingKey.nextStatefulLeafIndex;
        if (leafIndex == 0) return (nextSigningKey, signature, false);
        if (leafIndex > signingKey.maxStatefulSignatures) {
            return (nextSigningKey, signature, false);
        }

        (signature, ok) =
            signStatefulRawAtLeaf(signingKey, leafIndex, message);
        if (!ok) return (nextSigningKey, signature, false);

        nextSigningKey = signingKey;
        nextSigningKey.nextStatefulLeafIndex = leafIndex + 1;
        return (nextSigningKey, signature, true);
    }

    function signStatefulAction(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.ActionContext memory context
    )
        internal
        pure
        returns (
            SHRINCS.SigningKey memory nextSigningKey,
            SHRINCS.Signature memory signature,
            bool ok
        )
    {
        if (publicKey.publicKeyCommitment.length != 32) {
            return (nextSigningKey, signature, false);
        }
        bytes32 expectedPublicKeyCommitment;
        bytes memory commitmentBytes = publicKey.publicKeyCommitment;
        assembly {
            expectedPublicKeyCommitment := mload(add(commitmentBytes, 32))
        }
        bytes memory message = abi.encodePacked(
            SHRINCS.statefulActionMessageHash(
                expectedPublicKeyCommitment, context
            )
        );
        return signStatefulRaw(signingKey, message);
    }

    function derive32(
        bytes memory domain,
        bytes memory seed,
        bytes memory data
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, seed, data));
    }

    function signStatefulRawAtLeaf(
        SHRINCS.SigningKey memory signingKey,
        uint32 leafIndex,
        bytes memory message
    ) internal pure returns (SHRINCS.Signature memory signature, bool ok) {
        if (leafIndex == 0) return (signature, false);
        if (leafIndex > signingKey.maxStatefulSignatures) {
            return (signature, false);
        }

        (signature, ok) = signStatefulWotsC(
            signingKey.statefulSkSeed,
            signingKey.statefulPrfSeed,
            signingKey.statefulPkSeed,
            leafIndex,
            message
        );
        if (!ok) return (signature, false);
        signature.authPath = statefulAuthPath(
            signingKey.statefulSkSeed,
            signingKey.statefulPkSeed,
            leafIndex,
            signingKey.maxStatefulSignatures
        );
        return (signature, true);
    }

    function encodeStatefulPublicKey(
        bytes32 pkSeed,
        bytes32 root,
        uint32 maxSignatures
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(pkSeed, root, maxSignatures);
    }

    function statefulSubtreeRoot(
        bytes32 skSeed,
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 maxSignatures
    ) internal pure returns (bytes32 right) {
        right = statefulEmptyTail(pkSeed, maxSignatures);
        for (uint32 currentLeaf = maxSignatures; currentLeaf >= leafIndex;) {
            bytes32 leaf = statefulWotsPkHash(skSeed, pkSeed, currentLeaf);
            right = statefulParentHash(pkSeed, currentLeaf, leaf, right);
            if (currentLeaf == leafIndex) break;
            unchecked {
                --currentLeaf;
            }
        }
    }

    function statefulWotsPkHash(
        bytes32 skSeed,
        bytes32 pkSeed,
        uint32 leafIndex
    ) internal pure returns (bytes32) {
        bytes memory endpoints = new bytes(
            uint256(SHRINCSParams.WOTS_CHAINS_STATEFUL) * 32
        );
        for (
            uint32 chainIndex = 0;
            chainIndex < SHRINCSParams.WOTS_CHAINS_STATEFUL;

        ) {
            bytes32 secret =
                statefulChainSecret(skSeed, pkSeed, leafIndex, chainIndex);
            bytes32 endpoint = statefulChainNoMask(
                pkSeed,
                leafIndex,
                chainIndex,
                secret,
                0,
                SHRINCSParams.WOTS_BASE_STATEFUL - 1
            );
            setSlice32(endpoints, endpoint, uint256(chainIndex) * 32);
            unchecked {
                ++chainIndex;
            }
        }
        // Mirror the verifier's high-aligned truncation (maskHash): the
        // reconstructed stateful WOTS-C leaf is masked, so the signer's
        // leaf must be too. No-op at 256s (all-ones mask).
        return Hash.maskHash(
            keccak256(
                abi.encodePacked(
                    "uxmss-wots-pk", pkSeed, leafIndex, endpoints
                )
            )
        );
    }

    function signStatefulWotsC(
        bytes32 skSeed,
        bytes32 prfSeed,
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory message
    ) internal pure returns (SHRINCS.Signature memory signature, bool ok) {
        bytes32 randomizer = keccak256(
            abi.encodePacked(
                "uxmss-wots-randomizer", prfSeed, leafIndex, message
            )
        );

        for (uint32 counter = 0; counter < WOTS_C_MAX_GRIND_COUNTER;) {
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "uxmss-wots-digits",
                    pkSeed,
                    leafIndex,
                    randomizer,
                    counter,
                    message
                )
            );
            uint32 digitSum;
            bytes32[] memory chains =
                new bytes32[](SHRINCSParams.WOTS_CHAINS_STATEFUL);
            for (
                uint32 chainIndex = 0;
                chainIndex < SHRINCSParams.WOTS_CHAINS_STATEFUL;

            ) {
                uint32 digit = baseW16Digit(digest, chainIndex);
                digitSum += digit;
                bytes32 secret = statefulChainSecret(
                    skSeed, pkSeed, leafIndex, chainIndex
                );
                chains[chainIndex] = statefulChainNoMask(
                    pkSeed, leafIndex, chainIndex, secret, 0, digit
                );
                unchecked {
                    ++chainIndex;
                }
            }
            if (digitSum == SHRINCSParams.WOTS_TARGET_SUM_STATEFUL) {
                signature = SHRINCS.Signature({
                    randomizer: randomizer,
                    counter: counter,
                    chains: chains,
                    authPath: new bytes32[](0)
                });
                return (signature, true);
            }
            unchecked {
                ++counter;
            }
        }
        return (signature, false);
    }

    function statefulChainSecret(
        bytes32 skSeed,
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIndex
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "uxmss-wots-chain-secret",
                skSeed,
                pkSeed,
                leafIndex,
                chainIndex
            )
        );
    }

    function statefulChainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIndex,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        out = value;
        for (uint32 stepOffset = 0; stepOffset < steps;) {
            bytes32 addressWord = Hash.addressWord32(
                0,
                0,
                UXMSS.AddressTypeWotsHash,
                leafIndex,
                chainIndex,
                start + stepOffset
            );
            // Truncate each chain step, mirroring the verifier's
            // HashSuite.hashWotsCChainNoMask32 maskHash. No-op at 256s.
            // F-08: the stateful walk uses "uxmss-wots-chain" (16 bytes)
            // to separate its chain domain from the stateless hypertree.
            out = Hash.maskHash(
                keccak256(
                    abi.encodePacked(
                        "uxmss-wots-chain", pkSeed, addressWord, out
                    )
                )
            );
            unchecked {
                ++stepOffset;
            }
        }
    }

    function statefulParentHash(
        bytes32 pkSeed,
        uint32 leftLeafIndex,
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        // Truncate the parent node, mirroring the verifier's
        // statefulParentHash maskHash. No-op at 256s.
        return Hash.maskHash(
            keccak256(
                abi.encodePacked(
                    "uxmss-node", pkSeed, leftLeafIndex, left, right
                )
            )
        );
    }

    function statefulEmptyTail(bytes32 pkSeed, uint32 leafIndex)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("uxmss-empty-tail", pkSeed, leafIndex)
        );
    }

    function statefulAuthPath(
        bytes32 skSeed,
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 maxSignatures
    ) internal pure returns (bytes32[] memory path) {
        path = new bytes32[](leafIndex);
        if (leafIndex < maxSignatures) {
            path[0] = statefulSubtreeRoot(
                skSeed, pkSeed, leafIndex + 1, maxSignatures
            );
        } else {
            path[0] = statefulEmptyTail(pkSeed, leafIndex);
        }
        uint256 offset = 1;
        for (uint32 previousLeaf = leafIndex - 1; previousLeaf >= 1;) {
            path[offset] = statefulWotsPkHash(skSeed, pkSeed, previousLeaf);
            unchecked {
                ++offset;
            }
            if (previousLeaf == 1) break;
            unchecked {
                --previousLeaf;
            }
        }
    }

    function hypertreePublicRoot(bytes32 statelessSkSeed, bytes32 pkSeed)
        internal
        pure
        returns (bytes32)
    {
        bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds =
            hypertreeLayerSeeds(statelessSkSeed);
        uint32 topLayer = NUM_HYPERTREE_LAYERS - 1;
        uint32 subtreeHeight =
            uint32(SHRINCSParams.HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
        return hypertreeVirtualNode(
            pkSeed, layerSeeds[topLayer], topLayer, 0, subtreeHeight, 0
        );
    }

    function hypertreeLayerSeeds(bytes32 statelessSkSeed)
        internal
        pure
        returns (bytes32[NUM_HYPERTREE_LAYERS] memory layerSeeds)
    {
        for (uint8 layer = 0; layer < NUM_HYPERTREE_LAYERS;) {
            layerSeeds[layer] = keccak256(
                abi.encodePacked(
                    "hypertree-layer-seed", statelessSkSeed, bytes1(layer)
                )
            );
            unchecked {
                ++layer;
            }
        }
    }

    function hypertreeVirtualNode(
        bytes32 pkSeed,
        bytes32 layerSeed,
        uint32 layer,
        uint64 tree,
        uint32 height,
        uint32 index
    ) internal pure returns (bytes32) {
        if (height == 0) {
            return hypertreeLeaf(pkSeed, layerSeed, layer, tree, index);
        }
        bytes32 left = hypertreeVirtualNode(
            pkSeed, layerSeed, layer, tree, height - 1, index << 1
        );
        uint32 rightIndex = (index << 1) | 1;
        bytes32 right = hypertreeVirtualNode(
            pkSeed, layerSeed, layer, tree, height - 1, rightIndex
        );
        bytes32 addressWord =
            hypertreeAddressWord(layer, tree, height, index);
        // Truncate the hypertree node, mirroring the verifier's
        // hashHypertreeNode32 maskHash. No-op at 256s.
        return Hash.maskHash(
            keccak256(
                abi.encodePacked(
                    "hypertree-node", pkSeed, addressWord, left, right
                )
            )
        );
    }

    function hypertreeLeaf(
        bytes32 pkSeed,
        bytes32 layerSeed,
        uint32 layer,
        uint64 tree,
        uint32 leaf
    ) internal pure returns (bytes32) {
        bytes32 leafSeed = keccak256(
            abi.encodePacked("hypertree-leaf-seed", layerSeed, tree, leaf)
        );
        bytes32 skSeed =
            keccak256(abi.encodePacked("hypertree-wots-sk-seed", leafSeed));
        return statelessWotsCPublicKey(pkSeed, skSeed, layer, tree, leaf);
    }

    function statelessWotsCPublicKey(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair
    ) internal pure returns (bytes32) {
        bytes memory endpoints = new bytes(
            uint256(SHRINCSParams.NUM_WOTS_CHAINS) * 32
        );
        for (uint32 chain = 0; chain < SHRINCSParams.NUM_WOTS_CHAINS;) {
            bytes32 secret = statelessWotsCSecret(skSeed, chain);
            bytes32 endpoint = statelessWotsCChain(
                pkSeed,
                layer,
                tree,
                keypair,
                chain,
                secret,
                0,
                SHRINCSParams.WOTS_CHAIN_LEN - 1
            );
            setSlice32(endpoints, endpoint, uint256(chain) * 32);
            unchecked {
                ++chain;
            }
        }
        // Truncate the WOTS-C public-key hash, mirroring the verifier's
        // verifyWotsC32 maskHash. No-op at 256s.
        return Hash.maskHash(
            keccak256(abi.encodePacked("wots-c-pk", pkSeed, endpoints))
        );
    }

    function statelessWotsCSecret(bytes32 skSeed, uint32 chain)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("wots-c-secret", skSeed, chain));
    }

    function statelessWotsCChain(
        bytes32 pkSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        uint32 chain,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        out = value;
        for (uint32 step = start; step < start + steps;) {
            bytes32 addressWord = Hash.addressWord32(
                layer, tree, UXMSS.AddressTypeWotsHash, keypair, chain, step
            );
            // Truncate each stateless chain step, mirroring the
            // verifier's WOTSPlusC.hashWotsCChainNoMask32 maskHash.
            // No-op at 256s.
            out = Hash.maskHash(
                keccak256(
                    abi.encodePacked(
                        "wots-c-chain", pkSeed, addressWord, out
                    )
                )
            );
            unchecked {
                ++step;
            }
        }
    }

    function hypertreeAddressWord(
        uint32 layer,
        uint64 treeIndex,
        uint32 nodeHeight,
        uint32 parentIndex
    ) internal pure returns (bytes32) {
        bytes32 out;
        assembly {
            out := or(shl(224, layer), shl(128, treeIndex))
            out := or(out, shl(96, 2))
            out := or(out, or(shl(32, nodeHeight), parentIndex))
        }
        return out;
    }

    function setSlice32(bytes memory dst, bytes32 src, uint256 offset)
        internal
        pure
    {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    function baseW16Digit(bytes32 digest, uint256 index)
        internal
        pure
        returns (uint32 digit)
    {
        uint8 packedByte = uint8(digest[index >> 1]);
        return
            index & 1 == 0
                ? uint32(packedByte >> 4)
                : uint32(packedByte & 0x0f);
    }
}
