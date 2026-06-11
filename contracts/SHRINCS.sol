// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ShrincsType } from "./ShrincsTypes.sol";

library SHRINCS {
    // Stateful path:
    // 1. Validate the composite SHRINCS public key and embedded stateful key bytes.
    // 2. Recover the compact WOTS-C public key hash from the signature and message.
    // 3. Verify the unbalanced XMSS authentication path to the stateful root.
    function verifyStatefulUnsafeRaw(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        if (!_validParameterSetBinding(p, parameterSetId, publicKey.parameterSetId)) return false;
        if (!_matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        if (!_validStatefulCompositePublicKey(publicKey)) return false;
        (ShrincsType.StatefulPublicKey memory statefulKey, bool ok) = _decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok) return false;

        uint32 leafIndex = uint32(signature.authPath.length);
        if (leafIndex == 0 || leafIndex > statefulKey.maxSignatures) return false;
        if (signature.chains.length != ShrincsType.WOTS_CHAINS_STATEFUL) return false;

        (bytes32 pkHash, bool validWots) =
            _compactStatefulWotsPublicKeyFromSignature(statefulKey.pkSeed, leafIndex, message, signature);
        if (!validWots) return false;

        (bytes32 root, bool validPath) = _rootFromUnbalancedPath(statefulKey.pkSeed, leafIndex, pkHash, signature.authPath);
        return validPath && statefulKey.root == root;
    }

    function verifyStateful(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        ShrincsType.ActionContext calldata context,
        ShrincsType.StatefulSignature calldata signature
    ) internal pure returns (bool) {
        bytes memory message = abi.encodePacked(
            statefulActionMessageHash(parameterSetId, expectedCompositePublicKey, context)
        );
        return verifyStatefulUnsafeRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    function verifyStatelessUnsafeRaw(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        if (!_validParameterSetBinding(p, parameterSetId, publicKey.parameterSetId)) return false;
        if (!_matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        return _verifyStatelessMemory(parameterSetId, publicKey, message, signature);
    }

    function verifyStateless(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        ShrincsType.ActionContext calldata context,
        ShrincsType.StatelessSignature calldata signature
    ) internal pure returns (bool) {
        bytes memory message = abi.encodePacked(
            statelessActionMessageHash(parameterSetId, expectedCompositePublicKey, context)
        );
        return _verifyStatelessRawMemory(parameterSetId, expectedCompositePublicKey, publicKey, message, signature);
    }

    // Placeholder for a future on-chain flow where a stateless signature authorizes
    // replacement of only the stateful SHRINCS component.
    function rotateStatefulViaStateless(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext calldata context,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32 nextStatefulKeyCommitment) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        if (!_validParameterSetBinding(p, parameterSetId, currentPublicKey.parameterSetId)) return bytes32(0);
        if (!_matchesExpectedCompositePublicKey(currentPublicKey, expectedCompositePublicKey)) return bytes32(0);
        if (!_validParams(p, currentPublicKey)) return bytes32(0);
        if (!_validParameterSetBinding(p, parameterSetId, nextStatefulKey.parameterSetId)) return bytes32(0);
        if (nextStatefulKey.statefulPublicKey.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES) return bytes32(0);
        bytes memory recoveryMessage = abi.encodePacked(
            statefulRotationMessageHash(parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextStatefulKey)
        );
        if (!_verifyStatelessRawMemory(parameterSetId, expectedCompositePublicKey, currentPublicKey, recoveryMessage, recoverySignature)) return bytes32(0);

        return _compositePublicKeyCommitment(
            nextStatefulKey.statefulPublicKey,
            currentPublicKey.messagePkSeed,
            currentPublicKey.messageRoot,
            currentPublicKey.hypertreePkSeed,
            currentPublicKey.hypertreeRoot
        );
    }

    // Placeholder for a future on-chain flow where a stateless signature authorizes
    // a full SHRINCS key rotation to a fresh composite public key.
    function rotateFullShrincsKey(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext calldata context,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) internal pure returns (bytes32 nextCompositePublicKey) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        if (!_validParameterSetBinding(p, parameterSetId, currentPublicKey.parameterSetId)) return bytes32(0);
        if (!_matchesExpectedCompositePublicKey(currentPublicKey, expectedCompositePublicKey)) return bytes32(0);
        if (!_validParams(p, currentPublicKey)) return bytes32(0);
        if (!_validParameterSetBinding(p, parameterSetId, nextKey.parameterSetId)) return bytes32(0);
        if (
            nextKey.statefulPublicKey.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES
                || nextKey.compositePublicKey.length != 32
                || nextKey.messagePkSeed.length != 32
                || nextKey.messageRoot.length != 32
                || nextKey.hypertreePkSeed.length != 32
                || nextKey.hypertreeRoot.length != 32
        ) return bytes32(0);

        nextCompositePublicKey = _compositePublicKeyCommitment(
            nextKey.statefulPublicKey,
            nextKey.messagePkSeed,
            nextKey.messageRoot,
            nextKey.hypertreePkSeed,
            nextKey.hypertreeRoot
        );

        bytes32 nextCompositePublicKeyWord;
        bytes calldata compositePublicKey = nextKey.compositePublicKey;
        assembly {
            nextCompositePublicKeyWord := calldataload(compositePublicKey.offset)
        }
        if (nextCompositePublicKey != nextCompositePublicKeyWord) return bytes32(0);

        bytes memory recoveryMessage =
            abi.encodePacked(fullRotationMessageHash(parameterSetId, expectedCompositePublicKey, currentPublicKey, context, nextKey));
        if (!_verifyStatelessRawMemory(parameterSetId, expectedCompositePublicKey, currentPublicKey, recoveryMessage, recoverySignature)) return bytes32(0);
    }

    // Resolve explicit params or fall back to the defaults registered in ShrincsType
    // for the selected parameter set and hash suite.
    function _paramsView(ShrincsType.ParameterSetId parameterSetId) private pure returns (ShrincsType.ParamsView memory) {
        return ShrincsType.defaultParamsView(parameterSetId);
    }

    function statefulActionMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.ActionContext calldata context
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_VERIFY_STATEFUL,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    function statelessActionMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.ActionContext calldata context
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_VERIFY_STATELESS,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                context.actionType,
                context.payloadHash
            )
        );
    }

    // Compute the canonical hash that a stateless recovery signature must cover when
    // authorizing replacement of only the stateful SHRINCS component.
    function statefulRotationMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext calldata context,
        ShrincsType.StatefulRotationTarget calldata nextStatefulKey
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_ROTATE_STATEFUL,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.compositePublicKey,
                nextStatefulKey.statefulPublicKey
            )
        );
    }

    // Compute the canonical hash that a stateless recovery signature must cover when
    // authorizing a full next SHRINCS key bundle.
    function fullRotationMessageHash(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.RotationContext calldata context,
        ShrincsType.RotationTarget calldata nextKey
    ) internal pure returns (bytes32) {
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        bytes32 nextKeyBundleHash = keccak256(
            abi.encodePacked(
                nextKey.compositePublicKey,
                nextKey.statefulPublicKey,
                nextKey.messagePkSeed,
                nextKey.messageRoot,
                nextKey.hypertreePkSeed,
                nextKey.hypertreeRoot
            )
        );
        return keccak256(
            abi.encodePacked(
                ShrincsType.OP_ROTATE_FULL,
                uint8(parameterSetId),
                p.hashSuiteId,
                expectedCompositePublicKey,
                context.domainSeparator,
                context.nonce,
                context.keyVersion,
                currentPublicKey.compositePublicKey,
                nextKeyBundleHash
            )
        );
    }

    // Enforce the parameter/profile invariants expected by this verifier and check
    // that the public key declares the same parameter-set identity.
    function _validParams(ShrincsType.ParamsView memory params, ShrincsType.PublicKey calldata publicKey)
        private
        pure
        returns (bool)
    {
        if (params.nBytes != 32) return false;
        if (params.parameterSetId != publicKey.parameterSetId) return false;
        if (params.h == 0 || params.d == 0 || params.h % params.d != 0) return false;
        if (params.a == 0 || params.k < 2 || params.l == 0) return false;
        if (params.h > 64 || params.a >= 32 || params.h / params.d >= 32) return false;
        if (params.w != 16 && params.w != 256) return false;
        if (!_validStatefulCompositePublicKey(publicKey)) return false;
        if (uint256(params.k) * (uint256(1) << params.a) > type(uint32).max) return false;
        return true;
    }

    function _validParameterSetBinding(
        ShrincsType.ParamsView memory params,
        ShrincsType.ParameterSetId requestedParameterSetId,
        ShrincsType.ParameterSetId declaredParameterSetId
    ) private pure returns (bool) {
        return params.parameterSetId == requestedParameterSetId && declaredParameterSetId == requestedParameterSetId
            && params.hashSuiteId == ShrincsType.HASH_SUITE_KECCAK_256;
    }

    // Shared stateless verification core that accepts either calldata messages from
    // external callers or canonical in-memory rotation messages built by this library.
    function _verifyStatelessMemory(
        ShrincsType.ParameterSetId parameterSetId,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatelessSignature calldata signature
    ) private pure returns (bool) {
        return _verifyStatelessRawMemory(
            parameterSetId,
            _compositePublicKeyWord(publicKey.compositePublicKey),
            publicKey,
            message,
            signature
        );
    }

    function _verifyStatelessRawMemory(
        ShrincsType.ParameterSetId parameterSetId,
        bytes32 expectedCompositePublicKey,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.StatelessSignature calldata signature
    ) private pure returns (bool) {
        if (!_matchesExpectedCompositePublicKey(publicKey, expectedCompositePublicKey)) return false;
        ShrincsType.ParamsView memory p = _paramsView(parameterSetId);
        if (!_validParams(p, publicKey)) return false;
        if (signature.hypertree.length == 0) return false;

        bytes memory messageRoot = _verifyForsCAndReturnRoot(
            p, publicKey, message, signature.fors, signature.hypertree[0].treeIndex, signature.hypertree[0].leafIndex
        );
        if (messageRoot.length == 0) return false;
        return _verifyHypertree(p, publicKey, messageRoot, signature.hypertree);
    }

    // Verify each hypertree XMSS layer in sequence, carrying the reconstructed root
    // from one layer into the next until the public hypertree root is reached.
    function _verifyHypertree(
        ShrincsType.ParamsView memory params,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory messageRoot,
        ShrincsType.HypertreeLayerSignature[] calldata layers
    ) private pure returns (bool) {
        if (layers.length != params.d) return false;
        uint32 subtreeHeight = uint32(params.h / params.d);
        uint32 leafCount = uint32(1) << subtreeHeight;

        bytes32 current;
        assembly {
            current := mload(add(messageRoot, 32))
        }

        for (uint256 layer = 0; layer < layers.length;) {
            ShrincsType.HypertreeLayerSignature calldata layerSig = layers[layer];
            if (layerSig.leafIndex >= leafCount || layerSig.wotsCPkHash.length != params.nBytes) return false;
            if (layerSig.authPath.length != subtreeHeight) return false;
            if (
                !_verifyWotsC32(
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

            bytes calldata wotsPkHash = layerSig.wotsCPkHash;
            bytes32 leaf;
            assembly {
                leaf := calldataload(wotsPkHash.offset)
            }

            (bytes32 nextRoot, bool ok) = _hypertreeRootFromPath32(
                subtreeHeight, publicKey.hypertreePkSeed, uint32(layer), layerSig.treeIndex, layerSig.leafIndex, leaf, layerSig.authPath
            );
            if (!ok) return false;
            current = nextRoot;
            unchecked {
                ++layer;
            }
        }

        bytes calldata expectedRootBytes = publicKey.hypertreeRoot;
        bytes32 expectedRoot;
        assembly {
            expectedRoot := calldataload(expectedRootBytes.offset)
        }
        return current == expectedRoot;
    }

    // Rebuild the WOTS-C public-key hash for one hypertree layer and compare it to
    // the expected leaf commitment carried in the layer signature.
    function _verifyWotsC32(
        ShrincsType.ParamsView memory params,
        bytes calldata pkSeedBytes,
        uint32 layer,
        uint64 tree,
        uint32 keypair,
        bytes calldata expectedPkHashBytes,
        bytes32 message,
        ShrincsType.WotsCSignature calldata signature
    ) private pure returns (bool) {
        uint256 chainCount = uint256(params.l);
        if (signature.randomizer.length != 32 || signature.chains.length != chainCount || expectedPkHashBytes.length != 32) return false;

        bytes calldata randomizerBytes = signature.randomizer;
        bytes32 pkSeed;
        bytes32 expectedPkHash;
        bytes32 randomizer;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            expectedPkHash := calldataload(expectedPkHashBytes.offset)
            randomizer := calldataload(randomizerBytes.offset)
        }

        bytes memory digest = _wotsDigest32(pkSeed, expectedPkHash, randomizer, signature.counter, message, _wotsDigestBytes(params));
        uint256 pkInputLen = 41 + chainCount * 32;
        uint256 pkInput;
        assembly {
            pkInput := mload(0x40)
            mstore(pkInput, "wots-c-pk")
            mstore(add(pkInput, 9), pkSeed)
            mstore(0x40, add(pkInput, and(add(pkInputLen, 31), not(31))))
        }

        uint256 addressBase = (uint256(layer) << 224) | (uint256(tree) << 128) | (uint256(keypair) << 64);
        uint32 digitSum;
        for (uint256 i = 0; i < chainCount;) {
            bytes calldata chain = signature.chains[i];
            if (chain.length != 32) return false;
            uint32 digit = _baseWDigit(params.w, digest, i);
            digitSum += digit;
            bytes32 segment = _wotsChain32NoMaskBase(params.w, pkSeed, addressBase, uint32(i), chain, digit);
            assembly {
                mstore(add(add(pkInput, 41), mul(i, 32)), segment)
            }
            unchecked {
                ++i;
            }
        }
        if (digitSum != params.wotsTargetSum) return false;

        bytes32 computedPkHash;
        assembly {
            computedPkHash := keccak256(pkInput, pkInputLen)
        }
        return computedPkHash == expectedPkHash;
    }

    // Derive the WOTS-C message digest bytes from the public seed, randomizer,
    // counter, expected public-key hash, and message.
    function _wotsDigest32(
        bytes32 pkSeed,
        bytes32 expectedPkHash,
        bytes32 randomizer,
        uint32 counter,
        bytes32 message,
        uint256 outLen
    ) private pure returns (bytes memory out) {
        out = new bytes(outLen);
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "wots-c-msg")
            mstore(add(ptr, 10), pkSeed)
            mstore(add(ptr, 42), expectedPkHash)
            mstore(add(ptr, 74), randomizer)
            mstore(add(ptr, 106), shl(224, counter))
            mstore(add(ptr, 110), message)
            let digestWord := keccak256(ptr, 142)
            mstore(add(out, 32), digestWord)
            mstore(0x40, add(ptr, 160))
        }
    }

    // Finish a stateless WOTS-C chain from the received signature element to its
    // terminal value using compact per-step addressing.
    function _wotsChain32NoMaskBase(uint16 w, bytes32 pkSeed, uint256 addressBase, uint32 chainIdx, bytes calldata value, uint32 digit)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            out := calldataload(value.offset)
        }
        uint256 steps = uint256(w - 1) - digit;
        for (uint256 j = 0; j < steps;) {
            out = _hashStatelessWotsCChainNoMask32(pkSeed, bytes32(addressBase | (uint256(chainIdx) << 32) | (uint256(digit) + j)), out);
            unchecked {
                ++j;
            }
        }
    }

    // Finish a stateless WOTS-C chain using the structured WOTS context variant.
    // This helper remains available for paths that use full address composition.
    function _wotsChain32NoMask(
        ShrincsType.WotsContext memory ctx,
        bytes calldata pkSeedBytes,
        uint32 chainIdx,
        bytes calldata value,
        uint32 digit
    ) private pure returns (bytes32 out) {
        bytes32 pkSeed;
        assembly {
            pkSeed := calldataload(pkSeedBytes.offset)
            out := calldataload(value.offset)
        }
        uint32 steps = uint32(ctx.w - 1) - digit;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord =
                _addressWord32(ctx.layer, ctx.tree, ShrincsType.WOTS_HASH_TYPE, ctx.keypair, chainIdx, digit + j);
            out = _hashStatelessWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    // Hash one stateless WOTS-C chain step under the chain domain separator and
    // encoded address word.
    function _hashStatelessWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "wots-c-chain")
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), segment)
            out := keccak256(ptr, 108)
        }
    }

    // Return the number of digest bytes needed to encode all base-W WOTS digits for
    // the current stateless parameter set.
    function _wotsDigestBytes(ShrincsType.ParamsView memory params) private pure returns (uint256) {
        uint256 bitsPerDigit = params.w == 256 ? 8 : 4;
        return (uint256(params.l) * bitsPerDigit + 7) / 8;
    }

    // Verify the FORS-C portion of the stateless signature and return the message
    // root that seeds the first hypertree layer on success.
    function _verifyForsCAndReturnRoot(
        ShrincsType.ParamsView memory params,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        ShrincsType.ForsSignature calldata signature,
        uint64 xmssTree,
        uint32 xmssKeypair
    ) private pure returns (bytes memory) {
        uint256 signedTrees = uint256(params.k) - 1;
        if (signature.randomizer.length != 32 || signature.entries.length != signedTrees) return "";

        ShrincsType.ForsDigest memory digest =
            _forsDigest(params, publicKey, message, signature.randomizer, signature.counter);
        uint256 a = uint256(params.a);
        if (_readBits32Fast(digest.digest, signedTrees * a, params.a) != 0) return "";
        if (digest.xmssTree != xmssTree || digest.xmssKeypair != xmssKeypair) return "";

        bytes calldata pkSeed = publicKey.messagePkSeed;
        uint256 forsPkInputLen = 39 + signedTrees * 32;
        uint256 forsPkInput;
        assembly {
            forsPkInput := mload(0x40)
            mstore(forsPkInput, "fors-pk")
            calldatacopy(add(forsPkInput, 7), pkSeed.offset, 32)
            mstore(0x40, add(forsPkInput, and(add(forsPkInputLen, 31), not(31))))
        }

        for (uint256 tree = 0; tree < signedTrees;) {
            ShrincsType.ForsEntry calldata entry = signature.entries[tree];
            if (entry.sk.length != 32 || entry.auth.length != a) return "";
            uint32 leafIndex = _readBits32Fast(digest.digest, tree * a, params.a);
            bytes32 root = _forsEntryRoot32(uint32(a), pkSeed, xmssTree, xmssKeypair, uint32(tree), leafIndex, entry);
            if (root == bytes32(0)) return "";
            assembly {
                mstore(add(add(forsPkInput, 39), mul(tree, 32)), root)
            }
            unchecked {
                ++tree;
            }
        }

        bytes32 computedRoot32;
        assembly {
            computedRoot32 := keccak256(forsPkInput, forsPkInputLen)
        }
        bytes calldata expectedRootBytes = publicKey.messageRoot;
        bytes32 expectedRoot;
        assembly {
            expectedRoot := calldataload(expectedRootBytes.offset)
        }
        return computedRoot32 == expectedRoot ? abi.encodePacked(computedRoot32) : bytes("");
    }

    // Reconstruct one FORS tree root from the revealed secret leaf and its
    // authentication path.
    function _forsEntryRoot32(
        uint32 height,
        bytes calldata pkSeed,
        uint64 xmssTree,
        uint32 xmssKeypair,
        uint32 tree,
        uint32 leafIndex,
        ShrincsType.ForsEntry calldata entry
    ) private pure returns (bytes32 node) {
        uint256 addressBase = _forsAddressBase(xmssTree, xmssKeypair);
        node = _hashForsLeaf32(pkSeed, bytes32(addressBase | ((uint256(tree) << height) + uint256(leafIndex))), entry.sk);
        uint256 index = leafIndex;
        for (uint256 level = 0; level < height;) {
            bytes calldata authNode = entry.auth[level];
            if (authNode.length != 32) return bytes32(0);
            bytes32 sibling;
            assembly {
                sibling := calldataload(authNode.offset)
            }
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            uint256 nodeHeight = level + 1;
            node = _hashForsNode32(
                pkSeed,
                bytes32(addressBase | (nodeHeight << 32) | ((uint256(tree) << (height - nodeHeight)) + (index >> 1))),
                left,
                right
            );
            index >>= 1;
            unchecked {
                ++level;
            }
        }
    }

    // Build the common high bits of a FORS address from the XMSS tree and keypair
    // coordinates.
    function _forsAddressBase(uint64 xmssTree, uint32 xmssKeypair) private pure returns (uint256) {
        return (uint256(xmssTree) << 128) | (uint256(ShrincsType.FORS_TREE_TYPE) << 96) | (uint256(xmssKeypair) << 64);
    }

    // Hash one FORS secret value into its leaf under the FORS leaf domain.
    function _hashForsLeaf32(bytes calldata pkSeed, bytes32 addressWord, bytes calldata sk) private pure returns (bytes32 out) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "fors-leaf")
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            mstore(add(ptr, 41), addressWord)
            calldatacopy(add(ptr, 73), sk.offset, 32)
            out := keccak256(ptr, 105)
            mstore(0x40, add(ptr, 128))
        }
    }

    // Hash two FORS child nodes into their parent under the FORS node domain.
    function _hashForsNode32(bytes calldata pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "fors-node")
            calldatacopy(add(ptr, 9), pkSeed.offset, 32)
            mstore(add(ptr, 41), addressWord)
            mstore(add(ptr, 73), left)
            mstore(add(ptr, 105), right)
            out := keccak256(ptr, 137)
            mstore(0x40, add(ptr, 160))
        }
    }

    // Derive the FORS message digest and split out the hypertree coordinates used
    // by the first XMSS layer.
    function _forsDigest(
        ShrincsType.ParamsView memory params,
        ShrincsType.PublicKey calldata publicKey,
        bytes memory message,
        bytes calldata randomizer,
        uint32 counter
    ) private pure returns (ShrincsType.ForsDigest memory out) {
        uint32 indexBits = uint32(params.k) * uint32(params.a);
        uint32 subtreeHeight = uint32(params.h / params.d);
        uint32 treeBits = uint32(params.h) - subtreeHeight;
        uint256 digestBytes = (uint256(indexBits) + uint256(params.h) + 7) / 8;
        bytes memory digest = _forsDigestBytes(publicKey.messagePkSeed, publicKey.hypertreeRoot, randomizer, counter, message, digestBytes);

        uint256 cursor = indexBits;
        out.xmssTree = _readBits64Fast(digest, cursor, treeBits);
        cursor += treeBits;
        out.xmssKeypair = _readBits32Fast(digest, cursor, subtreeHeight);
        out.digest = digest;
    }

    // Hash the message, randomizer, and public context into the variable-length byte
    // string consumed by FORS digit extraction.
    function _forsDigestBytes(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        bytes calldata randomizer,
        uint32 counter,
        bytes memory message,
        uint256 digestBytes
    ) private pure returns (bytes memory out) {
        out = new bytes(digestBytes);
        uint256 messageLen = message.length;
        uint256 baseLen = 111 + messageLen;
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(ptr, "fors-digest")
            calldatacopy(add(ptr, 11), pkSeed.offset, 32)
            calldatacopy(add(ptr, 43), hypertreeRoot.offset, 32)
            calldatacopy(add(ptr, 75), randomizer.offset, 32)
            mstore(add(ptr, 107), shl(224, counter))
            let src := add(message, 32)
            let dst := add(ptr, 111)
            for { let end := add(src, messageLen) } lt(src, end) { src := add(src, 32) dst := add(dst, 32) } {
                mstore(dst, mload(src))
            }
        }
        if (digestBytes <= 32) {
            bytes32 digestWord;
            assembly {
                digestWord := keccak256(ptr, baseLen)
                mstore(add(out, 32), digestWord)
                mstore(0x40, add(ptr, and(add(baseLen, 31), not(31))))
            }
            return out;
        }
        uint256 totalLen = baseLen + 4;
        uint256 offset;
        uint32 blockCounter;
        while (offset < digestBytes) {
            bytes32 digestWord;
            uint256 chunk = digestBytes - offset;
            if (chunk > 32) chunk = 32;
            assembly {
                mstore(add(ptr, baseLen), shl(224, blockCounter))
                digestWord := keccak256(ptr, totalLen)
            }
            _setHashChunk(out, digestWord, offset, chunk);
            offset += chunk;
            unchecked {
                ++blockCounter;
            }
        }
        assembly {
            mstore(0x40, add(ptr, and(add(totalLen, 31), not(31))))
        }
    }

    // Rebuild one hypertree XMSS root from a leaf and its authentication path using
    // compact Keccak-based node hashing.
    function _hypertreeRootFromPath32(
        uint32 height,
        bytes calldata pkSeed,
        uint32 layer,
        uint64 treeIndex,
        uint32 leafIndex,
        bytes32 leaf,
        bytes[] calldata authPath
    ) private pure returns (bytes32 node, bool ok) {
        if (authPath.length != height) return (bytes32(0), false);
        bytes32 pkSeedWord;
        assembly {
            pkSeedWord := calldataload(pkSeed.offset)
        }
        uint256 addressBase =
            (uint256(layer) << 224) | (uint256(treeIndex) << 128) | (uint256(ShrincsType.TREE_TYPE) << 96);
        node = leaf;
        uint256 index = leafIndex;
        for (uint256 level = 0; level < height;) {
            bytes calldata authNode = authPath[level];
            if (authNode.length != 32) return (bytes32(0), false);
            bytes32 sibling;
            assembly {
                sibling := calldataload(authNode.offset)
            }
            (bytes32 left, bytes32 right) = index & 1 == 0 ? (node, sibling) : (sibling, node);
            uint256 nodeHeight = level + 1;
            node = _hashHypertreeNode32(pkSeedWord, bytes32(addressBase | (nodeHeight << 32) | (index >> 1)), left, right);
            index >>= 1;
            unchecked {
                ++level;
            }
        }
        ok = true;
    }

    // Hash two hypertree child nodes into their parent under the hypertree node
    // domain separator.
    function _hashHypertreeNode32(bytes32 pkSeed, bytes32 addressWord, bytes32 left, bytes32 right)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "hypertree-node")
            mstore(add(ptr, 14), pkSeed)
            mstore(add(ptr, 46), addressWord)
            mstore(add(ptr, 78), left)
            mstore(add(ptr, 110), right)
            out := keccak256(ptr, 142)
        }
    }

    // Extract one base-W digit from the packed digest bytes used by stateless WOTS-C.
    function _baseWDigit(uint16 w, bytes memory digest, uint256 index) private pure returns (uint32) {
        if (w == 256) return uint8(digest[index]);
        uint8 b = uint8(digest[index >> 1]);
        return index & 1 == 0 ? b >> 4 : b & 0x0f;
    }

    // Copy a partial 32-byte hash block into an output byte string at the requested
    // offset.
    function _setHashChunk(bytes memory out, bytes32 blockHash, uint256 offset, uint256 chunk) private pure {
        for (uint256 i = 0; i < chunk;) {
            out[offset + i] = blockHash[i];
            unchecked {
                ++i;
            }
        }
    }

    // Read up to 32 bits from a packed big-endian bitstring without branching over
    // byte boundaries.
    function _readBits32Fast(bytes memory input, uint256 startBit, uint32 bitLen) private pure returns (uint32) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 32 ? type(uint32).max : (uint256(1) << bitLen) - 1;
        return uint32(shifted & mask);
    }

    // Read up to 64 bits from a packed big-endian bitstring without materializing
    // intermediate slices.
    function _readBits64Fast(bytes memory input, uint256 startBit, uint32 bitLen) private pure returns (uint64) {
        uint256 byteOffset = startBit >> 3;
        uint256 bitOffset = startBit & 7;
        uint256 word;
        assembly {
            word := mload(add(add(input, 32), byteOffset))
        }
        uint256 shifted = word >> (256 - bitOffset - bitLen);
        uint256 mask = bitLen == 64 ? type(uint64).max : (uint256(1) << bitLen) - 1;
        return uint64(shifted & mask);
    }

    function _matchesExpectedCompositePublicKey(ShrincsType.PublicKey calldata publicKey, bytes32 expectedCompositePublicKey)
        private
        pure
        returns (bool)
    {
        return _compositePublicKeyWord(publicKey.compositePublicKey) == expectedCompositePublicKey;
    }

    function _compositePublicKeyWord(bytes calldata compositePublicKey) private pure returns (bytes32 word) {
        if (compositePublicKey.length != 32) return bytes32(0);
        assembly {
            word := calldataload(compositePublicKey.offset)
        }
    }

    // Check the composite public-key layout and recompute its commitment from the
    // embedded stateful and stateless public components.
    function _validStatefulCompositePublicKey(ShrincsType.PublicKey calldata publicKey) private pure returns (bool) {
        if (publicKey.compositePublicKey.length != 32) return false;
        if (publicKey.statefulPublicKey.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES) return false;
        if (publicKey.messagePkSeed.length != 32) return false;
        if (publicKey.messageRoot.length != 32) return false;
        if (publicKey.hypertreePkSeed.length != 32) return false;
        if (publicKey.hypertreeRoot.length != 32) return false;

        bytes32 expected;
        bytes calldata compositePublicKey = publicKey.compositePublicKey;
        assembly {
            expected := calldataload(compositePublicKey.offset)
        }
        return _compositePublicKeyCommitment(
            publicKey.statefulPublicKey,
            publicKey.messagePkSeed,
            publicKey.messageRoot,
            publicKey.hypertreePkSeed,
            publicKey.hypertreeRoot
        ) == expected;
    }

    // Recompute the composite SHRINCS public-key commitment from one stateful key
    // and the fixed stateless public components.
    function _compositePublicKeyCommitment(
        bytes calldata statefulPublicKey,
        bytes calldata messagePkSeed,
        bytes calldata messageRoot,
        bytes calldata hypertreePkSeed,
        bytes calldata hypertreeRoot
    ) private pure returns (bytes32 computed) {
        uint256 statefulPkLen = ShrincsType.STATEFUL_PUBLIC_KEY_BYTES;
        uint256 compositeInputLen = 18 + statefulPkLen + 32 + 32 + 32 + 32;

        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "shrincs-public-key")
            calldatacopy(add(ptr, 18), statefulPublicKey.offset, statefulPkLen)
            calldatacopy(add(ptr, add(18, statefulPkLen)), messagePkSeed.offset, 32)
            calldatacopy(add(ptr, add(50, statefulPkLen)), messageRoot.offset, 32)
            calldatacopy(add(ptr, add(82, statefulPkLen)), hypertreePkSeed.offset, 32)
            calldatacopy(add(ptr, add(114, statefulPkLen)), hypertreeRoot.offset, 32)
            computed := keccak256(ptr, compositeInputLen)
            mstore(0x40, add(ptr, 224))
        }
    }

    // Decode the packed stateful public key bytes into the typed `pkSeed`, `root`,
    // and `maxSignatures` fields expected by the stateful verifier path.
    function _decodeStatefulPublicKey(bytes calldata encoded)
        private
        pure
        returns (ShrincsType.StatefulPublicKey memory publicKey, bool ok)
    {
        if (encoded.length != ShrincsType.STATEFUL_PUBLIC_KEY_BYTES) return (publicKey, false);
        assembly {
            publicKey := mload(0x40)
            mstore(publicKey, calldataload(encoded.offset))
            mstore(add(publicKey, 0x20), calldataload(add(encoded.offset, 32)))
            mstore(add(publicKey, 0x40), shr(224, calldataload(add(encoded.offset, 64))))
            mstore(0x40, add(publicKey, 0x60))
        }
        return (publicKey, true);
    }

    // Rebuild the compact stateful WOTS-C public-key hash from the signature chains
    // and the message-derived base-16 digits.
    function _compactStatefulWotsPublicKeyFromSignature(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes memory message,
        ShrincsType.StatefulSignature calldata signature
    ) private pure returns (bytes32 pkHash, bool ok) {
        bytes32 digest = keccak256(
            abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, signature.randomizer, signature.counter, message)
        );

        uint32 digitSum;
        bytes memory segments = new bytes(ShrincsType.WOTS_CHAINS_STATEFUL * 32);
        for (uint256 i = 0; i < ShrincsType.WOTS_CHAINS_STATEFUL;) {
            uint32 digit = _baseW16Digit(digest, i);
            digitSum += digit;
            bytes32 segment = _statefulChainNoMask(
                pkSeed,
                leafIndex,
                uint32(i),
                signature.chains[i],
                digit,
                ShrincsType.WOTS_BASE_STATEFUL - 1 - digit
            );
            _setSlice32(segments, segment, i * 32);
            unchecked {
                ++i;
            }
        }

        if (digitSum != ShrincsType.WOTS_TARGET_SUM_STATEFUL) return (bytes32(0), false);
        return (keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, segments)), true);
    }

    // Verify the unbalanced XMSS-style authentication path used by the SHRINCS
    // stateful path.
    function _rootFromUnbalancedPath(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] calldata authPath
    ) private pure returns (bytes32 root, bool ok) {
        if (authPath.length != leafIndex || authPath.length == 0) return (bytes32(0), false);
        root = _statefulParentHash(pkSeed, leafIndex, leaf, authPath[0]);
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            root = _statefulParentHash(pkSeed, leafIndex - uint32(offset) - 1, authPath[offset + 1], root);
            unchecked {
                ++offset;
            }
        }
        ok = true;
    }

    // Hash two stateful XMSS nodes into their parent under the unbalanced XMSS node
    // domain.
    function _statefulParentHash(bytes32 pkSeed, uint32 leftLeafIndex, bytes32 left, bytes32 right)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "uxmss-node")
            mstore(add(ptr, 10), pkSeed)
            mstore(add(ptr, 42), shl(224, leftLeafIndex))
            mstore(add(ptr, 46), left)
            mstore(add(ptr, 78), right)
            out := keccak256(ptr, 110)
        }
    }

    // Finish one stateful WOTS-C chain from its signed digit to the chain endpoint
    // used in the compact public-key hash.
    function _statefulChainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIdx,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) private pure returns (bytes32 out) {
        out = value;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord =
                _addressWord32(0, 0, ShrincsType.WOTS_HASH_TYPE, leafIndex, chainIdx, start + j);
            out = _hashStatefulWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked {
                ++j;
            }
        }
    }

    // Hash one stateful WOTS-C chain step under the shared WOTS chain domain.
    function _hashStatefulWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        private
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "wots-c-chain")
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), segment)
            out := keccak256(ptr, 108)
        }
    }

    // Extract one base-16 digit from the packed stateful WOTS digest.
    function _baseW16Digit(bytes32 digest, uint256 index) private pure returns (uint32 digit) {
        assembly {
            let b := byte(shr(1, index), digest)
            digit := and(b, 0x0f)
            if iszero(and(index, 1)) { digit := shr(4, b) }
        }
    }

    // Store one 32-byte segment into a byte buffer at a fixed offset.
    function _setSlice32(bytes memory dst, bytes32 src, uint256 offset) private pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    // Pack the compact 32-byte address word used by the stateful and stateless
    // Keccak-based hash domains in this verifier.
    function _addressWord32(uint32 layer, uint64 tree, uint32 addressType, uint32 keypair, uint32 chain, uint32 step)
        private
        pure
        returns (bytes32)
    {
        return bytes32(
            (uint256(layer) << 224) | (uint256(tree) << 128) | (uint256(addressType) << 96) | (uint256(keypair) << 64)
                | (uint256(chain) << 32) | uint256(step)
        );
    }
}
