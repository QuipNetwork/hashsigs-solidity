// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessTypes } from "./ShrincsStatelessTypes.sol";

abstract contract ShrincsStatelessPorsFp is ShrincsStatelessTypes {
    // PORS-FP is addressed like FORS at layer 0, but it uses one large PORS tree
    // instead of k separate FORS trees. The digest-derived tau chooses the bottom
    // XMSS tree/keypair whose WOTS-C signature authenticates this PORS public key.
    struct PorsAddressContext {
        uint64 xmssTree;
        uint32 xmssKeypair;
    }

    // Output of the PORS-FP message hash. It is Algorithm-1 shaped:
    // first h bits encode tau, and the remaining blocks encode k distinct leaves.
    struct PorsDigest {
        PorsAddressContext addressContext;
        uint32[] leaves;
    }

    function verifyPorsFpAndReturnRoot(
        ParamsView memory params,
        PublicKey calldata publicKey,
        bytes calldata message,
        PorsFpSignature calldata signature,
        uint64 xmssTree,
        uint32 xmssKeypair
    ) internal pure returns (bytes memory) {
        if (signature.randomizer.length != params.nBytes || signature.leaves.length != params.k) return "";
        if (signature.authSet.length > params.porsMaxAuth) return "";

        // Recompute H(s, m): this determines both the bottom hypertree address
        // and the exact sorted set of PORS leaves that must be revealed
        PorsDigest memory digest = porsDigest(params, publicKey, message, signature.randomizer, signature.counter);
        if (digest.leaves.length != params.k) return "";

        //digest.addressContext.xmssTree is the hypertree/XMSS tree selected by the message digest
        // digest.addressContext.xmssKeypair is the WOTS-C leaf/keypair selected inside that XMSS tree
        // xmssTree and xmssKeypair are the tree/leaf claimed by the first hypertree signature layer
        if (digest.addressContext.xmssTree != xmssTree || digest.addressContext.xmssKeypair != xmssKeypair) return "";

        // The signature leaves must be in digest order. Since `porsDigest` sorts
        // this also fixes a canonical encoding for the revealed subset
        for (uint256 i = 0; i < signature.leaves.length;) {
            if (signature.leaves[i].leafIndex != digest.leaves[i] || signature.leaves[i].sk.length != params.nBytes) {
                return "";
            }
            unchecked {
                ++i;
            }
        }
        for (uint256 i = 0; i < signature.authSet.length;) {
            if (signature.authSet[i].value.length != params.nBytes) return "";
            unchecked {
                ++i;
            }
        }

        // Rebuild the PORS root from revealed secrets plus the shared Octopus
        // authentication set, then compare against the PORS public root
        bytes memory computedRoot = porsRootFromAuthSet(
            params, publicKey.messagePkSeed, signature, PorsAddressContext({ xmssTree: xmssTree, xmssKeypair: xmssKeypair })
        );
        return eq(computedRoot, publicKey.messageRoot) ? computedRoot : bytes("");
    }

    //--- PORS-FP helper functions ---
    function porsRootFromAuthSet(
        ParamsView memory params,
        bytes calldata pkSeed,
        PorsFpSignature calldata signature,
        PorsAddressContext memory addressContext
    ) internal pure returns (bytes memory) {
        uint32[] memory indices = new uint32[](signature.leaves.length);
        bytes[] memory nodes = new bytes[](signature.leaves.length);
        for (uint256 i = 0; i < signature.leaves.length;) {
            // Start the Octopus reconstruction frontier at the revealed leaves
            // Each leaf is F/PORS-leaf(pkSeed, ADRS(height=0,index), sk)
            indices[i] = signature.leaves[i].leafIndex;
            nodes[i] = porsLeafHash(params.nBytes, pkSeed, addressContext, indices[i], signature.leaves[i].sk);
            unchecked {
                ++i;
            }
        }
        // PORS-FP uses one larger Merkle tree with t leaves, not k separate FORS trees.
        // This implementation chooses t = k * 2^a to reuse the existing FORS-shaped parameters.
        uint32 treeHeight = porsTreeHeight(params);

        // The Octopus set contains exactly the siblings that are not already
        // derivable from another active path. This rejects both missing nodes
        // and padded/extra auth nodes.
        if (signature.authSet.length != octopusAuthNodeCount(indices, treeHeight)) return "";
        //climb the pors tree one level at a time
        // indices are the revealed leaf indices and nodes are the corresponding leaf hashes
        for (uint32 level = 0; level < treeHeight;) {
            (indices, nodes) = porsAscendLevel(params.nBytes, pkSeed, signature, level, indices, nodes, addressContext);
            if (nodes.length == 0) return "";
            unchecked {
                ++level;
            }
        }
        return nodes.length == 1 ? nodes[0] : bytes(""); // The final node is the computed PORS root
    }

    function porsAscendLevel(
        uint16 nBytes,
        bytes calldata pkSeed,
        PorsFpSignature calldata signature,
        uint32 level,
        uint32[] memory indices,
        bytes[] memory nodes,
        PorsAddressContext memory addressContext
    ) internal pure returns (uint32[] memory, bytes[] memory) {
        uint32[] memory nextIndices = new uint32[](indices.length);
        bytes[] memory nextNodes = new bytes[](indices.length);
        uint256 nextLen;

        for (uint256 i = 0; i < indices.length;) {
            uint32 index = indices[i];
            uint32 sibling = index ^ 1;

            // Prefer a sibling that is already in the active frontier. If it is
            // absent, it must be supplied by the shared Octopus authentication set.
            bytes memory siblingNode = findNode(indices, nodes, sibling); // check if sibling is already selected as an active node at this level
            if (siblingNode.length == 0) {
                // if not, look for it in the auth set
                siblingNode = findAuth(signature.authSet, level, sibling);
            }
            if (siblingNode.length == 0) return (new uint32[](0), new bytes[](0)); // if neither, then the auth set is incomplete

            if (index < sibling || findNode(indices, nodes, sibling).length == 0) {
                // Hash each sibling pair once into its parent, then deduplicate
                // parents so the next level has one node per active subtree.
                // e.g. if indices 2 and 3 are active, they share sibling 0 and parent 1, so we only need one hash of (2,0) and one parent node 1.
                (bytes memory left, bytes memory right) = index & 1 == 0 ? (nodes[i], siblingNode) : (siblingNode, nodes[i]); // if even then left=sk and right=sibling, else left=sibling and right=sk
                uint32 parent = index >> 1; // parent = index / 2
                if (!hasIndex(nextIndices, nextLen, parent)) {
                    // if parent not already in nextIndices, add it along with the hash of the pair
                    nextIndices[nextLen] = parent;
                    nextNodes[nextLen] = porsNodeHash(nBytes, pkSeed, addressContext, level + 1, parent, left, right);
                    unchecked {
                        ++nextLen;
                    }
                }
            }
            unchecked {
                ++i;
            }
        }

        return shrink(nextIndices, nextNodes, nextLen); // trims to contain only nextLen entries
    }

    function porsLeafHash(
        uint16 nBytes,
        bytes calldata pkSeed,
        PorsAddressContext memory addressContext,
        uint32 leafIndex,
        bytes calldata sk
    ) internal pure returns (bytes memory) {
        // PORS-FP custom address type, but FIPS FORS field layout:
        // layer=0, tree=tau tree, keypair=tau leaf, height=0, index=leaf.
        return domainKeccakBytes(
            "pors-fp-leaf",
            pkSeed,
            abi.encodePacked(forsAddress(PORS_TREE_TYPE, addressContext.xmssTree, addressContext.xmssKeypair, 0, leafIndex), sk),
            nBytes
        );
    }

    function porsNodeHash(
        uint16 nBytes,
        bytes calldata pkSeed,
        PorsAddressContext memory addressContext,
        uint32 height,
        uint32 index,
        bytes memory left,
        bytes memory right
    ) internal pure returns (bytes memory) {
        // Internal PORS nodes use the same address context, with nonzero height
        // and the parent index at that height.
        return domainKeccakBytes(
            "pors-fp-node",
            pkSeed,
            abi.encodePacked(forsAddress(PORS_TREE_TYPE, addressContext.xmssTree, addressContext.xmssKeypair, height, index), left, right),
            nBytes
        );
    }

    function porsDigest(
        ParamsView memory params,
        PublicKey calldata publicKey,
        bytes calldata message,
        bytes calldata randomizer,
        uint32 counter
    ) internal pure returns (PorsDigest memory out) {
        // Algorithm 1 style digest:
        // y = H(s, m), tau = first h bits, remaining blocks are candidate leaves.
        uint32 treeHeight = porsTreeHeight(params);
        uint256 digestBytes = (uint256(params.h) + uint256(params.k) * treeHeight + 7) / 8; // tree height is bits per leaf, so k*treeHeight bits for the candidate leaves, plus h bits for tau
        bytes memory digest =
            domainKeccakBytes("pors-fp-msg", publicKey.messagePkSeed, abi.encodePacked(randomizer, counter, message), digestBytes);

        // tau identifies the bottom hypertree WOTS-C key that must sign this PORS root.
        uint64 tau = readBits64(digest, 0, params.h);
        uint64 leafCount = uint64(1) << uint32(params.h / params.d); // number of leaves in one bottom hypertree
        // get the hypertree index and then the leaf index within that hypertree from tau
        out.addressContext = PorsAddressContext({ xmssTree: tau / leafCount, xmssKeypair: uint32(tau % leafCount) });

        // Read ceil(log2(t))-bit candidates, accept only distinct values in [0,t).
        uint32[] memory leaves = new uint32[](params.k);
        uint256 count;
        uint256 cursor = params.h;
        uint32 totalLeaves = porsLeafCount(params);
        while (count < params.k && cursor + treeHeight <= digest.length * 8) {
            // cursor bit start pos + treeHeight bits for leaf index must be within digest
            uint32 candidate = readBits(digest, cursor, treeHeight);
            cursor += treeHeight;
            if (candidate < totalLeaves && !hasIndex(leaves, count, candidate)) {
                //choose candidate only if it's a valid leaf index and not already chosen
                leaves[count] = candidate;
                unchecked {
                    ++count;
                }
            }
        }
        if (count != params.k) {
            out.leaves = new uint32[](0);
            return out;
        }

        // Canonical subset order for signing and verification.
        sortUint32(leaves);
        out.leaves = leaves;
    }

    function findNode(uint32[] memory indices, bytes[] memory nodes, uint32 index) internal pure returns (bytes memory) {
        for (uint256 i = 0; i < indices.length;) {
            if (indices[i] == index) return nodes[i]; // if index is in the active frontier, return the corresponding node
            unchecked {
                ++i;
            }
        }
        return "";
    }

    function findAuth(PorsAuthNode[] calldata authSet, uint32 level, uint32 index) internal pure returns (bytes memory) {
        for (uint256 i = 0; i < authSet.length;) {
            if (authSet[i].level == level && authSet[i].index == index) return authSet[i].value;
            unchecked {
                ++i;
            }
        }
        return "";
    }

    function hasIndex(uint32[] memory values, uint256 len, uint32 needle) internal pure returns (bool) {
        for (uint256 i = 0; i < len;) {
            if (values[i] == needle) return true;
            unchecked {
                ++i;
            }
        }
        return false;
    }

    function octopusAuthNodeCount(uint32[] memory leafIndices, uint32 treeHeight) internal pure returns (uint256 count) {
        // Count the exact Octopus authentication set size for this subset:
        // at each level, every active node whose sibling is not active needs
        // one auth node; active siblings are merged for free.
        uint32[] memory active = leafIndices;
        for (uint32 level = 0; level < treeHeight;) {
            uint32[] memory parents = new uint32[](active.length); // hold active nodes for next level
            // there can't be more active nodes than the current level
            uint256 parentLen;
            for (uint256 i = 0; i < active.length;) {
                uint32 sibling = active[i] ^ 1;
                if (!hasIndex(active, active.length, sibling)) {
                    unchecked {
                        ++count; // if sibling not active, we need an auth node for this pair, so increase count
                    }
                }
                uint32 parent = active[i] >> 1;
                if (!hasIndex(parents, parentLen, parent)) {
                    parents[parentLen] = parent;
                    unchecked {
                        ++parentLen;
                    }
                }
                unchecked {
                    ++i;
                }
            }
            active = shrinkIndices(parents, parentLen);
            unchecked {
                ++level;
            }
        }
    }

    function porsLeafCount(ParamsView memory params) internal pure returns (uint32) {
        // One PORS tree with t leaves. This code chooses t = k * 2^a.
        return uint32(params.k) * (uint32(1) << params.a); // pg 37 of 2025-2203.pdf
    }

    function porsTreeHeight(ParamsView memory params) internal pure returns (uint32) {
        // Height of the single PORS tree. If t is not a power of two, this is
        // the height of the next power-of-two Merkle tree.
        return log2ceil(porsLeafCount(params));
    }

    function sortUint32(uint32[] memory values) internal pure {
        // insertion sort, small enough array
        for (uint256 i = 1; i < values.length;) {
            uint32 value = values[i];
            uint256 j = i;
            while (j > 0 && values[j - 1] > value) {
                values[j] = values[j - 1];
                unchecked {
                    --j;
                }
            }
            values[j] = value;
            unchecked {
                ++i;
            }
        }
    }

    function shrinkIndices(uint32[] memory indices, uint256 len) internal pure returns (uint32[] memory) {
        uint32[] memory out = new uint32[](len);
        for (uint256 i = 0; i < len;) {
            out[i] = indices[i];
            unchecked {
                ++i;
            }
        }
        return out;
    }

    function shrink(uint32[] memory indices, bytes[] memory nodes, uint256 len) internal pure returns (uint32[] memory, bytes[] memory) {
        uint32[] memory outIndices = new uint32[](len);
        bytes[] memory outNodes = new bytes[](len);
        for (uint256 i = 0; i < len;) {
            outIndices[i] = indices[i];
            outNodes[i] = nodes[i];
            unchecked {
                ++i;
            }
        }
        return (outIndices, outNodes);
    }
}
