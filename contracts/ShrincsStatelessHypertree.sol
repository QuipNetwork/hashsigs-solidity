// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsStatelessMerkle } from './ShrincsStatelessMerkle.sol';
import { ShrincsStatelessWotsC } from './ShrincsStatelessWotsC.sol';

abstract contract ShrincsStatelessHypertree is ShrincsStatelessMerkle, ShrincsStatelessWotsC {
    function verifyHypertree(
        ParamsView memory params,
        PublicKey calldata publicKey,
        bytes memory messageRoot,
        HypertreeLayerSignature[] calldata layers
    ) internal pure returns (bool) {
        if (layers.length != params.d) return false;
        uint32 subtreeHeight = uint32(params.h / params.d); // h is total height and d is number of layers
        uint32 leafCount = uint32(1) << subtreeHeight; // each XMSS subtree has 2^(h / d) WOTS-C keypairs

        // The bottom layer signs the message-layer root. Each later layer signs
        // the XMSS root produced by the layer below it.
        bytes32 current;
        assembly {
            current := mload(add(messageRoot, 32))
        }

        for (uint256 layer = 0; layer < layers.length; ) {
            HypertreeLayerSignature calldata layerSig = layers[layer];

            // The WOTS-C keypair must be a valid leaf inside this layer's XMSS subtree,
            // and its claimed public-key hash/auth path must have the expected sizes.
            if (layerSig.leafIndex >= leafCount || layerSig.wotsCPkHash.length != params.nBytes) return false;
            if (layerSig.authPath.length != subtreeHeight) return false;

            // Verify that the WOTS-C signature at this layer signs `current`.
            // At layer 0, `current` is the FORS-C/PORS-FP message root. After that,
            // `current` is the root reconstructed from the previous XMSS subtree.
            if (
                !verifyWotsC32(
                    params,
                    publicKey.hypertreePkSeed,
                    uint32(layer),
                    layerSig.treeIndex,
                    layerSig.leafIndex,
                    layerSig.wotsCPkHash,
                    current,
                    layerSig.wotsCSignature
                )
            ) return false;

            // Per SPHINCS+/SLH-DSA, the XMSS leaf is the compressed WOTS-C public key
            // reconstructed from the WOTS-C signature. Internal XMSS nodes are hashed
            // by `hypertreeRootFromPath`; the leaf itself is not hashed again.
            bytes calldata wotsPkHash = layerSig.wotsCPkHash;
            bytes32 leaf;
            assembly {
                leaf := calldataload(wotsPkHash.offset)
            }

            (bytes32 nextRoot, bool ok) = hypertreeRootFromPath32(
                subtreeHeight, publicKey.hypertreePkSeed, uint32(layer), layerSig.treeIndex, layerSig.leafIndex, leaf, layerSig.authPath
            );
            if (!ok) return false;
            current = nextRoot;
            unchecked {
                ++layer;
            }
        }

        // The final reconstructed root must match the public hypertree root.
        bytes calldata expectedRootBytes = publicKey.hypertreeRoot;
        bytes32 expectedRoot;
        assembly {
            expectedRoot := calldataload(expectedRootBytes.offset)
        }
        return current == expectedRoot;
    }
}
