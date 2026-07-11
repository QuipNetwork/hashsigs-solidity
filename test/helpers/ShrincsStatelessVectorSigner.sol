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

import {ShrincsTestSigner} from "./ShrincsTestSigner.sol";
import {SHRINCS} from "../../contracts/SHRINCS.sol";
import {SPHINCSPlusCCore} from "../../contracts/SPHINCSPlusCCore.sol";
import {FORSMinusC} from "../../contracts/FORSMinusC.sol";
import {Hypertree} from "../../contracts/Hypertree.sol";
import {UXMSS} from "../../contracts/UXMSS.sol";
import {ShrincsParams} from "shrincs-profile/ShrincsParams.sol";
import {SHRINCSHash} from "../../contracts/SHRINCSHash.sol";

/// @notice TEST-ONLY staged stateless SHRINCS signer for on-demand vector
/// generation.
/// @dev This contract is intentionally placed under `test/helpers` so it does
/// not enter the production Solidity surface. It keeps the exact production
/// math and final signature layout, but splits stateless signing into
/// storage-backed phases.
contract ShrincsStatelessVectorSigner {
    uint32 internal constant MAX_GRIND_COUNTER = 1 << 24;
    uint8 internal constant NUM_HYPERTREE_LAYERS = 8;

    struct Session {
        bool active;
        bool forsPrepared;
        bool forsFinalized;
        bool signatureFinalized;
        bool hypertreeLayerStarted;
        bool hypertreeWotsDone;
        bool hypertreeAuthPathDone;
        SHRINCS.SigningKey signingKey;
        SHRINCS.PublicKey publicKey;
        bytes message;
        bytes forsDigest;
        uint64 bottomTreeIndex;
        uint32 bottomLeafIndex;
        uint32 nextForsTree;
        bytes32[] forsRoots;
        bytes32 currentHypertreeRoot;
        uint64 currentHypertreeTreeIndex;
        uint32 currentHypertreeLeafIndex;
        uint32 nextHypertreeLayer;
        uint32 currentAuthPathLevel;
        uint32 currentWotsCounter;
        bytes32 currentLayerSeed;
        bytes32 currentLayerSkSeed;
        bytes32 currentLayerPkHash;
        bytes32 currentLayerRandomizer;
        SPHINCSPlusCCore.StatelessSignature signature;
    }

    uint256 internal nextSessionNonce;
    mapping(bytes32 sessionId => Session session) internal sessions;

    function beginSessionFromSeed(
        bytes memory seedMaterial,
        uint32 maxStatefulSignatures,
        bytes memory message
    ) external returns (bytes32 sessionId, bool ok) {
        SHRINCS.SigningKey memory signingKey;
        SHRINCS.PublicKey memory publicKey;
        (signingKey, publicKey, ok) =
            ShrincsTestSigner.keygen(seedMaterial, maxStatefulSignatures);
        if (!ok) return (bytes32(0), false);
        return beginSession(signingKey, publicKey, message);
    }

    function beginSession(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes memory message
    ) public returns (bytes32 sessionId, bool ok) {
        sessionId = keccak256(
            abi.encodePacked(address(this), msg.sender, nextSessionNonce)
        );
        unchecked {
            ++nextSessionNonce;
        }

        Session storage session = sessions[sessionId];
        session.active = true;
        session.signingKey = signingKey;
        session.publicKey = publicKey;
        session.message = message;

        bytes32 randomizer = keccak256(
            abi.encodePacked(
                "fors-randomizer", signingKey.statelessPrfSeed, message
            )
        );
        uint256 signedTrees = uint256(ShrincsParams.NUM_FORS_TREES) - 1;
        for (uint32 counter = 0; counter < MAX_GRIND_COUNTER;) {
            bytes memory digest;
            uint64 treeIndex;
            uint32 leafIndex;
            (digest, treeIndex, leafIndex) = forsDigest(
                signingKey.pkSeed,
                signingKey.hypertreeRoot,
                message,
                randomizer,
                counter
            );
            if (
                readBits32Memory(
                        digest,
                        signedTrees * ShrincsParams.FORS_TREE_HEIGHT,
                        ShrincsParams.FORS_TREE_HEIGHT
                    ) == 0
            ) {
                session.signature.fors.randomizer =
                    abi.encodePacked(randomizer);
                session.signature.fors.counter = counter;
                session.forsDigest = digest;
                session.bottomTreeIndex = treeIndex;
                session.bottomLeafIndex = leafIndex;
                session.forsPrepared = true;
                return (sessionId, true);
            }
            unchecked {
                ++counter;
            }
        }

        delete sessions[sessionId];
        return (bytes32(0), false);
    }

    function stepFors(bytes32 sessionId, uint32 maxTrees)
        external
        returns (uint32 processed, bool done)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.forsPrepared, "fors not prepared");
        require(!session.forsFinalized, "fors finalized");

        uint32 signedTrees = ShrincsParams.NUM_FORS_TREES - 1;
        while (processed < maxTrees && session.nextForsTree < signedTrees) {
            uint32 forsTree = session.nextForsTree;
            uint32 leaf = readBits32Memory(
                session.forsDigest,
                uint256(forsTree) * ShrincsParams.FORS_TREE_HEIGHT,
                ShrincsParams.FORS_TREE_HEIGHT
            );
            // line-length: allow — fmt canonical tuple head exceeds cap
            (bytes32 root, bytes32[] memory authPath) = forsTreeRootAndAuthPath(
                session.signingKey.pkSeed,
                session.signingKey.statelessSkSeed,
                session.bottomTreeIndex,
                session.bottomLeafIndex,
                forsTree,
                leaf
            );
            session.forsRoots.push(root);
            FORSMinusC.ForsEntry storage entry =
                session.signature.fors.entries.push();
            entry.secretLeaf = abi.encodePacked(
                forsLeafSecret(
                    session.signingKey.pkSeed,
                    session.signingKey.statelessSkSeed,
                    session.bottomTreeIndex,
                    session.bottomLeafIndex,
                    forsTree,
                    leaf
                )
            );
            for (uint256 i = 0; i < authPath.length;) {
                entry.authPath.push(abi.encodePacked(authPath[i]));
                unchecked {
                    ++i;
                }
            }
            unchecked {
                ++processed;
                ++session.nextForsTree;
            }
        }

        done = session.nextForsTree == signedTrees;
    }

    function finalizeFors(bytes32 sessionId)
        external
        returns (bytes32 forsRoot)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.forsPrepared, "fors not prepared");
        require(!session.forsFinalized, "fors finalized");
        require(
            session.nextForsTree == ShrincsParams.NUM_FORS_TREES - 1,
            "fors incomplete"
        );

        bytes memory roots = new bytes(session.forsRoots.length * 32);
        for (uint256 i = 0; i < session.forsRoots.length;) {
            setSlice32(roots, session.forsRoots[i], i * 32);
            unchecked {
                ++i;
            }
        }

        forsRoot = keccak256(
            abi.encodePacked("fors-pk", session.signingKey.pkSeed, roots)
        );
        session.currentHypertreeRoot = forsRoot;
        session.currentHypertreeTreeIndex = session.bottomTreeIndex;
        session.currentHypertreeLeafIndex = session.bottomLeafIndex;
        session.forsFinalized = true;
    }

    function stepHypertree(bytes32 sessionId, uint32 maxLayers)
        external
        returns (uint32 processed, bool done)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.forsFinalized, "fors not finalized");
        require(!session.signatureFinalized, "signature finalized");

        while (
            processed < maxLayers
                && session.nextHypertreeLayer < NUM_HYPERTREE_LAYERS
        ) {
            if (!session.hypertreeLayerStarted) {
                this.startHypertreeLayer(sessionId);
            }
            if (!session.hypertreeWotsDone) {
                bool wotsDone =
                    this.stepHypertreeWots(sessionId, MAX_GRIND_COUNTER);
                require(wotsDone, "wots incomplete");
            }
            if (!session.hypertreeAuthPathDone) {
                uint32 subtreeHeight = uint32(
                    ShrincsParams.HYPERTREE_HEIGHT
                        / ShrincsParams.NUM_HYPERTREE_LAYERS
                );
                (, bool authDone) =
                    this.stepHypertreeAuthPath(sessionId, subtreeHeight);
                require(authDone, "auth incomplete");
            }
            this.finalizeHypertreeLayer(sessionId);
            unchecked {
                ++processed;
            }
        }

        done = session.nextHypertreeLayer == NUM_HYPERTREE_LAYERS;
    }

    function startHypertreeLayer(bytes32 sessionId)
        external
        returns (bool started)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.forsFinalized, "fors not finalized");
        require(!session.signatureFinalized, "signature finalized");
        require(
            session.nextHypertreeLayer < NUM_HYPERTREE_LAYERS,
            "hypertree complete"
        );
        require(!session.hypertreeLayerStarted, "layer started");

        uint32 layer = session.nextHypertreeLayer;
        uint64 tree = session.currentHypertreeTreeIndex;
        uint32 leaf = session.currentHypertreeLeafIndex;
        // casting to 'uint8' is safe because layer is bounded by
        // NUM_HYPERTREE_LAYERS (8)
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 layerByte = uint8(layer);
        bytes32 layerSeed = hypertreeLayerSeed(
            session.signingKey.statelessSkSeed, layerByte
        );
        bytes32 leafSeed = keccak256(
            abi.encodePacked("hypertree-leaf-seed", layerSeed, tree, leaf)
        );
        bytes32 skSeed =
            keccak256(abi.encodePacked("hypertree-wots-sk-seed", leafSeed));
        bytes32 pkHash = statelessWotsCPublicKey(
            session.signingKey.pkSeed, skSeed, layer, tree, leaf
        );

        session.currentLayerSeed = layerSeed;
        session.currentLayerSkSeed = skSeed;
        session.currentLayerPkHash = pkHash;
        session.currentLayerRandomizer = keccak256(
            abi.encodePacked(
                "wots-c-randomizer",
                session.signingKey.statelessPrfSeed,
                session.currentHypertreeRoot
            )
        );
        session.currentWotsCounter = 0;
        session.currentAuthPathLevel = 0;
        session.hypertreeLayerStarted = true;
        session.hypertreeWotsDone = false;
        session.hypertreeAuthPathDone = false;

        Hypertree.HypertreeLayerSignature storage layerSig =
            session.signature.hypertree.push();
        layerSig.treeIndex = tree;
        layerSig.leafIndex = leaf;
        layerSig.wotsCPkHash = abi.encodePacked(pkHash);

        return true;
    }

    function stepHypertreeWots(bytes32 sessionId, uint32 maxCounters)
        external
        returns (bool done)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.hypertreeLayerStarted, "layer not started");
        require(!session.hypertreeWotsDone, "wots finalized");

        uint32 layer = session.nextHypertreeLayer;
        uint64 tree = session.currentHypertreeTreeIndex;
        uint32 leaf = session.currentHypertreeLeafIndex;
        uint32 limit = session.currentWotsCounter + maxCounters;
        if (limit < session.currentWotsCounter || limit > MAX_GRIND_COUNTER)
        {
            limit = MAX_GRIND_COUNTER;
        }

        for (uint32 counter = session.currentWotsCounter; counter < limit;) {
            bytes32 fullDigest = keccak256(
                abi.encodePacked(
                    "wots-c-msg",
                    session.signingKey.pkSeed,
                    session.currentLayerPkHash,
                    session.currentLayerRandomizer,
                    counter,
                    session.currentHypertreeRoot
                )
            );
            // line-length: allow — fmt canonical tuple head exceeds cap
            (bytes32[] memory chains, uint32 digitSum) = buildStatelessWotsChains(
                session.signingKey.pkSeed,
                session.currentLayerSkSeed,
                layer,
                tree,
                leaf,
                fullDigest
            );
            if (digitSum == ShrincsParams.WOTS_TARGET_SUM_STATEFUL) {
                Hypertree.HypertreeLayerSignature storage layerSig =
                    session.signature.hypertree[session.nextHypertreeLayer];
                layerSig.wotsCSignature.randomizer =
                    abi.encodePacked(session.currentLayerRandomizer);
                layerSig.wotsCSignature.counter = counter;
                for (uint256 i = 0; i < chains.length;) {
                    layerSig.wotsCSignature.chains
                        .push(abi.encodePacked(chains[i]));
                    unchecked {
                        ++i;
                    }
                }
                session.currentWotsCounter = counter;
                session.hypertreeWotsDone = true;
                return true;
            }
            unchecked {
                ++counter;
            }
        }

        session.currentWotsCounter = limit;
        return false;
    }

    function stepHypertreeAuthPath(bytes32 sessionId, uint32 maxLevels)
        external
        returns (uint32 processed, bool done)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.hypertreeLayerStarted, "layer not started");
        require(session.hypertreeWotsDone, "wots incomplete");
        require(!session.hypertreeAuthPathDone, "auth finalized");

        uint32 subtreeHeight = uint32(
            ShrincsParams.HYPERTREE_HEIGHT
                / ShrincsParams.NUM_HYPERTREE_LAYERS
        );
        uint32 layer = session.nextHypertreeLayer;
        uint64 tree = session.currentHypertreeTreeIndex;
        uint32 leaf = session.currentHypertreeLeafIndex;
        Hypertree.HypertreeLayerSignature storage layerSig =
            session.signature.hypertree[session.nextHypertreeLayer];

        while (
            processed < maxLevels
                && session.currentAuthPathLevel < subtreeHeight
        ) {
            uint32 level = session.currentAuthPathLevel;
            uint32 sibling = (leaf >> level) ^ 1;
            bytes32 node = hypertreeVirtualNode(
                session.signingKey.pkSeed,
                session.currentLayerSeed,
                layer,
                tree,
                level,
                sibling
            );
            layerSig.authPath.push(abi.encodePacked(node));
            unchecked {
                ++processed;
                ++session.currentAuthPathLevel;
            }
        }

        if (session.currentAuthPathLevel == subtreeHeight) {
            session.hypertreeAuthPathDone = true;
            return (processed, true);
        }
        return (processed, false);
    }

    function finalizeHypertreeLayer(bytes32 sessionId)
        external
        returns (bool moreLayers)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.hypertreeLayerStarted, "layer not started");
        require(session.hypertreeWotsDone, "wots incomplete");
        require(session.hypertreeAuthPathDone, "auth incomplete");

        uint32 subtreeHeight = uint32(
            ShrincsParams.HYPERTREE_HEIGHT
                / ShrincsParams.NUM_HYPERTREE_LAYERS
        );
        uint64 tree = session.currentHypertreeTreeIndex;
        uint32 nextLayer = session.nextHypertreeLayer + 1;
        uint64 leafMask = uint64((uint256(1) << subtreeHeight) - 1);
        bytes32 nextRoot = hypertreeVirtualNode(
            session.signingKey.pkSeed,
            session.currentLayerSeed,
            session.nextHypertreeLayer,
            tree,
            subtreeHeight,
            0
        );

        session.currentHypertreeRoot = nextRoot;
        // Deviates from [FIPS205 §8.2]: SHRINCS chains the hypertree
        // coordinates sequentially per layer instead of the FIPS-205 index
        // recurrence. The next layer's leaf index is the low
        // subtree-height bits of the current tree index, and the next
        // tree index is the remaining high bits. This must stay in lockstep
        // with Hypertree.verifyHypertree.
        // casting to 'uint32' is safe because leafMask keeps only the low
        // subtree-height bits
        // forge-lint: disable-next-line(unsafe-typecast)
        session.currentHypertreeLeafIndex = uint32(tree & leafMask);
        session.currentHypertreeTreeIndex = tree >> subtreeHeight;
        session.nextHypertreeLayer = nextLayer;
        session.hypertreeLayerStarted = false;
        session.hypertreeWotsDone = false;
        session.hypertreeAuthPathDone = false;
        session.currentAuthPathLevel = 0;
        session.currentWotsCounter = 0;
        session.currentLayerSeed = bytes32(0);
        session.currentLayerSkSeed = bytes32(0);
        session.currentLayerPkHash = bytes32(0);
        session.currentLayerRandomizer = bytes32(0);
        return nextLayer < NUM_HYPERTREE_LAYERS;
    }

    function finalizeSignature(bytes32 sessionId)
        external
        returns (bytes memory encodedSignature)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        require(session.forsFinalized, "fors not finalized");
        require(
            session.nextHypertreeLayer == NUM_HYPERTREE_LAYERS,
            "hypertree incomplete"
        );
        session.signatureFinalized = true;
        encodedSignature =
            abi.encode(copyStatelessSignature(session.signature));
    }

    function sessionPublicKey(bytes32 sessionId)
        external
        view
        returns (SHRINCS.PublicKey memory publicKey)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        publicKey = copyPublicKey(session.publicKey);
    }

    function sessionMessage(bytes32 sessionId)
        external
        view
        returns (bytes memory message)
    {
        Session storage session = sessions[sessionId];
        require(session.active, "unknown session");
        message = session.message;
    }

    function sessionProgress(bytes32 sessionId)
        external
        view
        returns (
            bool active,
            bool forsPrepared,
            bool forsFinalized,
            uint32 nextForsTree,
            uint32 nextHypertreeLayer
        )
    {
        Session storage session = sessions[sessionId];
        return (
            session.active,
            session.forsPrepared,
            session.forsFinalized,
            session.nextForsTree,
            session.nextHypertreeLayer
        );
    }

    function copyPublicKey(SHRINCS.PublicKey storage publicKey)
        internal
        view
        returns (SHRINCS.PublicKey memory out)
    {
        out.statefulPublicKey = publicKey.statefulPublicKey;
        out.publicKeyCommitment = publicKey.publicKeyCommitment;
        out.pkSeed = publicKey.pkSeed;
        out.hypertreeRoot = publicKey.hypertreeRoot;
    }

    function copyStatelessSignature(
        SPHINCSPlusCCore.StatelessSignature storage signature
    )
        internal
        view
        returns (SPHINCSPlusCCore.StatelessSignature memory out)
    {
        out.fors.randomizer = signature.fors.randomizer;
        out.fors.counter = signature.fors.counter;
        out.fors.entries =
            new FORSMinusC.ForsEntry[](signature.fors.entries.length);
        for (uint256 i = 0; i < signature.fors.entries.length;) {
            out.fors.entries[i].secretLeaf =
            signature.fors.entries[i].secretLeaf;
            out.fors.entries[i].authPath =
                new bytes[](signature.fors.entries[i].authPath.length);
            for (
                uint256 j = 0;
                j < signature.fors.entries[i].authPath.length;

            ) {
                out.fors.entries[i].authPath[j] =
                    signature.fors.entries[i].authPath[j];
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        out.hypertree = new Hypertree
            .HypertreeLayerSignature[](signature.hypertree.length);
        for (uint256 i = 0; i < signature.hypertree.length;) {
            out.hypertree[i].treeIndex = signature.hypertree[i].treeIndex;
            out.hypertree[i].leafIndex = signature.hypertree[i].leafIndex;
            out.hypertree[i].wotsCPkHash = signature.hypertree[i].wotsCPkHash;
            out.hypertree[i].wotsCSignature.randomizer =
            signature.hypertree[i].wotsCSignature.randomizer;
            out.hypertree[i].wotsCSignature.counter =
            signature.hypertree[i].wotsCSignature.counter;
            out.hypertree[i].wotsCSignature.chains = new bytes[](
                signature.hypertree[i].wotsCSignature.chains.length
            );
            for (
                uint256 j = 0;
                j < signature.hypertree[i].wotsCSignature.chains.length;

            ) {
                out.hypertree[i].wotsCSignature.chains[j] =
                    signature.hypertree[i].wotsCSignature.chains[j];
                unchecked {
                    ++j;
                }
            }
            out.hypertree[i].authPath =
                new bytes[](signature.hypertree[i].authPath.length);
            for (uint256 j = 0; j < signature.hypertree[i].authPath.length;) {
                out.hypertree[i].authPath[j] =
                    signature.hypertree[i].authPath[j];
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    function forsDigest(
        bytes32 pkSeed,
        bytes32 hypertreeRoot,
        bytes memory message,
        bytes32 randomizer,
        uint32 counter
    )
        internal
        pure
        returns (bytes memory digest, uint64 treeIndex, uint32 leafIndex)
    {
        uint32 indexBits = uint32(ShrincsParams.NUM_FORS_TREES)
            * uint32(ShrincsParams.FORS_TREE_HEIGHT);
        uint32 subtreeHeight = uint32(
            ShrincsParams.HYPERTREE_HEIGHT
                / ShrincsParams.NUM_HYPERTREE_LAYERS
        );
        uint32 treeBits =
            uint32(ShrincsParams.HYPERTREE_HEIGHT) - subtreeHeight;
        uint256 digestBytes =
            (uint256(indexBits)
                    + uint256(ShrincsParams.HYPERTREE_HEIGHT)
                    + 7) / 8;
        digest = forsDigestBytes(
            pkSeed, hypertreeRoot, randomizer, counter, message, digestBytes
        );
        uint256 cursor = indexBits;
        treeIndex = readBits64Memory(digest, cursor, treeBits);
        leafIndex =
            readBits32Memory(digest, cursor + treeBits, subtreeHeight);
    }

    function forsDigestBytes(
        bytes32 pkSeed,
        bytes32 hypertreeRoot,
        bytes32 randomizer,
        uint32 counter,
        bytes memory message,
        uint256 digestBytes
    ) internal pure returns (bytes memory out) {
        bytes memory base = abi.encodePacked(
            "fors-digest",
            pkSeed,
            hypertreeRoot,
            randomizer,
            counter,
            message
        );
        if (digestBytes <= 32) {
            out = new bytes(digestBytes);
            bytes32 digestWord = keccak256(base);
            SHRINCSHash.setHashChunk(out, digestWord, 0, digestBytes);
            return out;
        }

        out = new bytes(digestBytes);
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            bytes32 digestWord =
                keccak256(abi.encodePacked(base, blockCounter));
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            SHRINCSHash.setHashChunk(out, digestWord, offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
    }

    function forsTreeRootAndAuthPath(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTree,
        uint32 leaf
    ) internal pure returns (bytes32, bytes32[] memory) {
        uint32 height = ShrincsParams.FORS_TREE_HEIGHT;
        uint256 leafCount = uint256(1) << height;
        bytes32[] memory levelNodes = new bytes32[](leafCount);
        for (uint32 index = 0; index < leafCount;) {
            levelNodes[index] = forsLeafHash(
                pkSeed, skSeed, treeIndex, leafIndex, forsTree, index
            );
            unchecked {
                ++index;
            }
        }
        uint256 nodeIndex = leaf;
        bytes32[] memory authPath = new bytes32[](height);

        for (uint32 nodeHeight = 1; nodeHeight <= height;) {
            authPath[nodeHeight - 1] = levelNodes[nodeIndex ^ 1];
            bytes32[] memory parents = new bytes32[](levelNodes.length / 2);
            for (uint256 parentIndex = 0; parentIndex < parents.length;) {
                uint64 shiftedTree =
                    uint64(forsTree) << (height - nodeHeight);
                // casting to 'uint64' is safe because parentIndex ranges
                // over a FORS subtree level, well within uint64
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64 parentLowIndex = shiftedTree + uint64(parentIndex);
                bytes32 addressWord = forsAddressWord(
                    treeIndex, leafIndex, nodeHeight, parentLowIndex
                );
                parents[parentIndex] = keccak256(
                    abi.encodePacked(
                        "fors-node",
                        pkSeed,
                        addressWord,
                        levelNodes[parentIndex * 2],
                        levelNodes[parentIndex * 2 + 1]
                    )
                );
                unchecked {
                    ++parentIndex;
                }
            }
            levelNodes = parents;
            nodeIndex >>= 1;
            unchecked {
                ++nodeHeight;
            }
        }
        return (levelNodes[0], authPath);
    }

    function forsLeafSecret(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTree,
        uint32 leaf
    ) internal pure returns (bytes32) {
        uint64 treeLeaf =
            (uint64(forsTree) << ShrincsParams.FORS_TREE_HEIGHT)
                + uint64(leaf);
        bytes32 addressWord =
            forsAddressWord(treeIndex, leafIndex, 0, treeLeaf);
        return
            keccak256(
                abi.encodePacked("fors-sk", skSeed, pkSeed, addressWord)
            );
    }

    function forsLeafHash(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 forsTree,
        uint32 leaf
    ) internal pure returns (bytes32) {
        bytes32 secret = forsLeafSecret(
            pkSeed, skSeed, treeIndex, leafIndex, forsTree, leaf
        );
        uint64 treeLeaf = (uint64(forsTree)
                    << ShrincsParams.FORS_TREE_HEIGHT) + uint64(leaf);
        bytes32 addressWord =
            forsAddressWord(treeIndex, leafIndex, 0, treeLeaf);
        return keccak256(
            abi.encodePacked("fors-leaf", pkSeed, addressWord, secret)
        );
    }

    function forsAddressWord(
        uint64 treeIndex,
        uint32 leafIndex,
        uint32 nodeHeight,
        uint64 lowIndex
    ) internal pure returns (bytes32 out) {
        assembly {
            out := shl(128, treeIndex)
            out := or(out, shl(96, 3))
            out := or(out, shl(64, leafIndex))
            out := or(out, or(shl(32, nodeHeight), lowIndex))
        }
    }

    function signStatelessWotsC(
        bytes32 pkSeed,
        bytes32 skSeed,
        bytes32 statelessPrfSeed,
        bytes32 pkHash,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes32 message
    )
        internal
        pure
        returns (
            bytes32 randomizer,
            uint32 counter,
            bytes32[] memory chains,
            bool ok
        )
    {
        randomizer = keccak256(
            abi.encodePacked("wots-c-randomizer", statelessPrfSeed, message)
        );
        for (counter = 0; counter < MAX_GRIND_COUNTER;) {
            bytes32 fullDigest = keccak256(
                abi.encodePacked(
                    "wots-c-msg",
                    pkSeed,
                    pkHash,
                    randomizer,
                    counter,
                    message
                )
            );
            uint32 digitSum;
            (chains, digitSum) = buildStatelessWotsChains(
                pkSeed, skSeed, layer, tree, keypair, fullDigest
            );
            if (digitSum == ShrincsParams.WOTS_TARGET_SUM_STATEFUL) {
                return (randomizer, counter, chains, true);
            }
            unchecked {
                ++counter;
            }
        }
        return (randomizer, counter, chains, false);
    }

    function buildStatelessWotsChains(
        bytes32 pkSeed,
        bytes32 skSeed,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes32 digest
    ) internal pure returns (bytes32[] memory chains, uint32 digitSum) {
        chains = new bytes32[](ShrincsParams.NUM_WOTS_CHAINS);
        for (uint32 chain = 0; chain < ShrincsParams.NUM_WOTS_CHAINS;) {
            uint32 digit = baseW16Digit(digest, chain);
            digitSum += digit;
            bytes32 secret = statelessWotsCSecret(skSeed, chain);
            chains[chain] = statelessWotsCChain(
                pkSeed, layer, tree, keypair, chain, secret, 0, digit
            );
            unchecked {
                ++chain;
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
            uint32(ShrincsParams.HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
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
            layerSeeds[layer] = hypertreeLayerSeed(statelessSkSeed, layer);
            unchecked {
                ++layer;
            }
        }
    }

    function hypertreeLayerSeed(bytes32 statelessSkSeed, uint8 layer)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "hypertree-layer-seed", statelessSkSeed, bytes1(layer)
            )
        );
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
        return keccak256(
            abi.encodePacked(
                "hypertree-node", pkSeed, addressWord, left, right
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
            uint256(ShrincsParams.NUM_WOTS_CHAINS) * 32
        );
        for (uint32 chain = 0; chain < ShrincsParams.NUM_WOTS_CHAINS;) {
            bytes32 secret = statelessWotsCSecret(skSeed, chain);
            bytes32 endpoint = statelessWotsCChain(
                pkSeed,
                layer,
                tree,
                keypair,
                chain,
                secret,
                0,
                ShrincsParams.WOTS_CHAIN_LEN - 1
            );
            setSlice32(endpoints, endpoint, uint256(chain) * 32);
            unchecked {
                ++chain;
            }
        }
        return keccak256(abi.encodePacked("wots-c-pk", pkSeed, endpoints));
    }

    function hypertreeAuthPath(
        bytes32 pkSeed,
        bytes32 layerSeed,
        uint32 layer,
        uint64 tree,
        uint32 leaf
    ) internal pure returns (bytes32[] memory path) {
        uint32 subtreeHeight = uint32(
            ShrincsParams.HYPERTREE_HEIGHT
                / ShrincsParams.NUM_HYPERTREE_LAYERS
        );
        path = new bytes32[](subtreeHeight);
        for (uint32 level = 0; level < subtreeHeight;) {
            uint32 sibling = (leaf >> level) ^ 1;
            path[level] = hypertreeVirtualNode(
                pkSeed, layerSeed, layer, tree, level, sibling
            );
            unchecked {
                ++level;
            }
        }
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
            bytes32 addressWord = SHRINCSHash.addressWord32(
                layer, tree, UXMSS.AddressTypeWotsHash, keypair, chain, step
            );
            out = keccak256(
                abi.encodePacked("wots-c-chain", pkSeed, addressWord, out)
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
    ) internal pure returns (bytes32 out) {
        assembly {
            out := or(shl(224, layer), shl(128, treeIndex))
            out := or(out, shl(96, 2))
            out := or(out, or(shl(32, nodeHeight), parentIndex))
        }
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
        returns (uint32)
    {
        uint8 packedByte = uint8(digest[index >> 1]);
        return
            index & 1 == 0
                ? uint32(packedByte >> 4)
                : uint32(packedByte & 0x0f);
    }

    function readBits32Memory(
        bytes memory input,
        uint256 startBit,
        uint32 bitLen
    ) internal pure returns (uint32) {
        return uint32(readBitsMemory(input, startBit, bitLen));
    }

    function readBits64Memory(
        bytes memory input,
        uint256 startBit,
        uint32 bitLen
    ) internal pure returns (uint64) {
        return uint64(readBitsMemory(input, startBit, bitLen));
    }

    function readBitsMemory(
        bytes memory input,
        uint256 startBit,
        uint32 bitLen
    ) internal pure returns (uint64 out) {
        for (uint256 bit = 0; bit < bitLen;) {
            uint256 absolute = startBit + bit;
            uint8 byteValue = uint8(input[absolute >> 3]);
            uint256 bitInByte = 7 - (absolute & 7);
            out = (out << 1) | uint64((byteValue >> bitInByte) & 1);
            unchecked {
                ++bit;
            }
        }
    }
}
