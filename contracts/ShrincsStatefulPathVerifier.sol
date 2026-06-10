// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ShrincsStatefulPathVerifier {
    uint16 internal constant N_BYTES = 32;
    uint16 internal constant WOTS_CHAINS = 64;
    uint16 internal constant WOTS_BASE = 16;
    uint32 internal constant WOTS_TARGET_SUM = 480;
    uint32 internal constant WOTS_HASH_TYPE = 0;

    struct PublicKey {
        bytes32 pkSeed;
        bytes32 root;
        uint32 maxSignatures;
    }

    struct Signature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[WOTS_CHAINS] chains;
        bytes32[] authPath;
    }

    // verify signatures without masking
    function verify(PublicKey calldata publicKey, bytes calldata message, Signature calldata signature)
        external
        pure
        returns (bool)
    {
        uint32 leafIndex = uint32(signature.authPath.length);
        if (leafIndex == 0 || leafIndex > publicKey.maxSignatures) return false;
        // Step 1: Recover the WOTS-C public key (leaf node) from the signature and message.
        // This reconstructs the public key by completing all WOTS-C chains.
        // Returns empty if the checksum validation fails.
        (bytes32 pkHash, bool validWots) = compactWotsPublicKeyFromSignature(publicKey.pkSeed, leafIndex, message, signature);
        if (!validWots) return false;

        // Step 2: Compute the root by hashing up the unbalanced binary tree.
        // Starting from the recovered leaf (pkHash), combine with each sibling in authPath
        // to recompute the parent node, repeatedly up to the tree root.
        (bytes32 root, bool validPath) = rootFromUnbalancedPath(publicKey.pkSeed, leafIndex, pkHash, signature.authPath);

        // Step 3: Verify that the recomputed root matches the stored public key root.
        return validPath && publicKey.root == root;

    }

    // Reconstructs the WOTS-C public key from the signature and message using unmasked chain hashing.
    // - pkSeed: public seed used for keyed hashing
    // - leafIndex: index of the WOTS-C keypair (used in address words)
    // - message, signature: inputs used to derive the digest and starting chain values
    // Returns the compacted public-key bytes (concatenated chain outputs) or empty bytes on checksum failure.
    function compactWotsPublicKeyFromSignature(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes calldata message,
        Signature calldata signature
    ) internal pure returns (bytes32 pkHash, bool ok) {
        // Domain-separated digest used to produce base-W digits.
        bytes32 digest = keccak256(abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, signature.randomizer, signature.counter, message));

        uint32 digitSum;
        // Allocate storage for WOTS_CHAINS concatenated 32-byte segments.
        bytes memory segments = new bytes(WOTS_CHAINS * 32);

        // For each chain: extract digit, advance chain the remaining steps, store result.
        for (uint256 i = 0; i < WOTS_CHAINS;) {
            uint32 digit = baseW16Digit(digest, i);
            digitSum += digit;
            bytes32 segment = chainNoMask(pkSeed, leafIndex, uint32(i), signature.chains[i], digit, WOTS_BASE - 1 - digit);
            setSlice32(segments, segment, i * 32);
            unchecked { ++i; }
        }

        // Checksum-like sum validation; reject if mismatch.
        if (digitSum != WOTS_TARGET_SUM) return (bytes32(0), false);
        return (keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, segments)), true);
    }

    // Derives the WOTS-C public key from signature and message using masked chain hashing (side-channel resistant).
    function compactWotsPublicKeyFromSignatureMasked(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes calldata message,
        Signature calldata signature
    ) public pure returns (bytes32 pkHash, bool ok) {
        // Domain-separated digest used to produce base-W digits.
        bytes32 digest = keccak256(abi.encodePacked("uxmss-wots-digits", pkSeed, leafIndex, signature.randomizer, signature.counter, message));

        uint32 digitSum;
        bytes memory segments = new bytes(WOTS_CHAINS * 32);

        // For each chain: extract digit, advance chain using masked hashing, store result.
        for (uint256 i = 0; i < WOTS_CHAINS;) {
            uint32 digit = baseW16Digit(digest, i);
            digitSum += digit;
            bytes32 segment = chainMasked(pkSeed, leafIndex, uint32(i), signature.chains[i], digit, WOTS_BASE - 1 - digit);
            setSlice32(segments, segment, i * 32);
            unchecked { ++i; }
        }

        // Checksum-like sum validation; reject if mismatch.
        if (digitSum != WOTS_TARGET_SUM) return (bytes32(0), false);
        return (keccak256(abi.encodePacked("uxmss-wots-pk", pkSeed, leafIndex, segments)), true);
    }

    //verifies signature using masked chain hashing for side-channel resistance
    function verifyMasked(PublicKey calldata publicKey, bytes calldata message, Signature calldata signature)
        external
        pure
        returns (bool)
    {
        uint32 leafIndex = uint32(signature.authPath.length);
        if (leafIndex == 0 || leafIndex > publicKey.maxSignatures) return false;

        // Step 1: Recover the WOTS-C public key (leaf node) from the signature and message.
        // Uses masked chain hashing for resistance against side-channel attacks.
        // Returns empty bytes if checksum validation fails.
        (bytes32 pkHash, bool validWots) = compactWotsPublicKeyFromSignatureMasked(publicKey.pkSeed, leafIndex, message, signature);
        if (!validWots) return false;

        // Step 2: Compute the tree root by hashing up the authentication path.
        // Starting from the recovered leaf (pkHash), combine with each sibling to rebuild the root.
        (bytes32 root, bool validPath) = rootFromUnbalancedPath(publicKey.pkSeed, leafIndex, pkHash, signature.authPath);

        // Step 3: Verify that the recomputed root matches the stored public key root.
        return validPath && publicKey.root == root;

    }


    function rootFromUnbalancedPath(
        bytes32 pkSeed,
        uint32 leafIndex,
        bytes32 leaf,
        bytes32[] calldata authPath
    ) internal pure returns (bytes32 root, bool ok) {
        // authPath must have exactly leafIndex elements and be non-empty
        if (authPath.length != leafIndex || authPath.length == 0) return (bytes32(0), false);
        // First parent: combine (leaf, first sibling)
        root = parentHash(pkSeed, leafIndex, leaf, authPath[0]);

        // Iterate remaining siblings: each step combines sibling (left) with current node (right)
        for (uint256 offset = 0; offset < authPath.length - 1;) {
            // sibling corresponds to index: leafIndex - (offset + 1)
            root = parentHash(pkSeed, leafIndex - uint32(offset) - 1, authPath[offset + 1], root);
            unchecked { ++offset; }
        }
        ok = true;
    }

    // Compute parent hash of two N-byte nodes with domain separation and seed.
    function parentHash(bytes32 pkSeed, uint32 leftLeafIndex, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "uxmss-node")
            mstore(add(ptr, 10), pkSeed)
            mstore(add(ptr, 42), shl(224, leftLeafIndex)) // shifts to the top 32 bits of a 256 bit word
            mstore(add(ptr, 46), left)
            mstore(add(ptr, 78), right)
            out := keccak256(ptr, 110)
        }
    }

    // Finish a WOTS-C chain without masking.
    // - start: starting step index (the signature element corresponds to this step)
    // - steps: number of steps to advance (how many times to hash)
    function chainNoMask(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIdx,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        out = value;
        for (uint32 j = 0; j < steps;) {
            // Build compact address word for this step: packs layer, tree, type, keypair, chain, step.
            bytes32 addressWord = addressWord32(0, 0, WOTS_HASH_TYPE, leafIndex, chainIdx, start + j);
            // Advance one step using the no-mask keccak construct.
            out = hashWotsCChainNoMask32(pkSeed, addressWord, out);
            unchecked { ++j; }
        }
    }

    // Finish a WOTS-C chain using masking (side-channel resistant).
    function chainMasked(
        bytes32 pkSeed,
        uint32 leafIndex,
        uint32 chainIdx,
        bytes32 value,
        uint32 start,
        uint32 steps
    ) internal pure returns (bytes32 out) {
        out = value;
        for (uint32 j = 0; j < steps;) {
            bytes32 addressWord = addressWord32(0, 0, WOTS_HASH_TYPE, leafIndex, chainIdx, start + j);
            out = hashWotsCChainMasked32(pkSeed, addressWord, out);
            unchecked { ++j; }
        }
    }
    // hash for one WOTS-C chain step without masking, using a compact fixed-layout Keccak input for efficiency.
    // Keccak layout: keccak("wots-c-chain" || pkSeed || addressWord || segment)
    // All memory writes are arranged for compact fixed-size inputs (108 bytes total).
    function hashWotsCChainNoMask32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let ptr := mload(0x40)
            // write domain string at ptr (12 bytes including null/length alignment used here)
            mstore(ptr, "wots-c-chain")
            // write pkSeed at ptr+12
            mstore(add(ptr, 12), pkSeed)
            // write addressWord at ptr+44
            mstore(add(ptr, 44), addressWord)
            // write segment at ptr+76
            mstore(add(ptr, 76), segment)
            // keccak over 108 bytes (12 + 32 + 32 + 32)
            out := keccak256(ptr, 108)
        }
    }

    // hash for one WOTS-C chain step with masking, using a compact fixed-layout Keccak input for efficiency.
    // Masked variant: first derive mask = keccak("wots-c-mask" || pkSeed || addressWord)
    // then compute keccak("wots-c-chain" || pkSeed || addressWord || (segment XOR mask))
    function hashWotsCChainMasked32(bytes32 pkSeed, bytes32 addressWord, bytes32 segment)
        internal
        pure
        returns (bytes32 out)
    {
        bytes32 mask;
        assembly {
            let ptr := mload(0x40)
            // derive mask using smaller input (75 bytes)
            mstore(ptr, "wots-c-mask")
            mstore(add(ptr, 11), pkSeed)
            mstore(add(ptr, 43), addressWord)
            mask := keccak256(ptr, 75)

            // compute chain hash with masked segment
            mstore(ptr, "wots-c-chain")
            mstore(add(ptr, 12), pkSeed)
            mstore(add(ptr, 44), addressWord)
            mstore(add(ptr, 76), xor(segment, mask))
            out := keccak256(ptr, 108)
        }
    }

    // Extract base-16 digit from a bytes32 digest: two digits per byte (high nibble then low nibble).
    // index selects which digit (0-63) to extract.
    function baseW16Digit(bytes32 digest, uint256 index) internal pure returns (uint32 digit) {
        assembly {
            let b := byte(shr(1, index), digest) // shr(1,index) <=> index >> 1, divides index by 2 to get byte index
            // byte(pos,digest) extracts the byte at position 'pos' from 'digest'
            digit := and(b, 0x0f) // default to low nibble
            if iszero(and(index, 1)) { digit := shr(4, b) } // if index is even, shift right to get high nibble instead
        }
    }

    // Write a 32-byte word into a byte array at a byte offset.
    function setSlice32(bytes memory dst, bytes32 src, uint256 offset) internal pure {
        assembly {
            mstore(add(add(dst, 32), offset), src)
        }
    }

    // Pack address fields into a 32-byte word:
    // [layer (32)] [tree (96)] [addressType (32)] [keypair (32)] [chain (32)] [step (32)]
    function addressWord32(uint32 layer, uint64 tree, uint32 addressType, uint32 keypair, uint32 chain, uint32 step)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((uint256(layer) << 224) | (uint256(tree) << 128) | (uint256(addressType) << 96)
                | (uint256(keypair) << 64) | (uint256(chain) << 32) | uint256(step)
        );
    }
}
