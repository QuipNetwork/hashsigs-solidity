// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity^0.8.28;

import {console2} from "forge-std/console2.sol";

library WOTSPlus {
    // SignatureSize: The size of the signature in bytes.
    uint8 public constant SignatureSize = NumSignatureChunks * HashLen;
    // PublicKeySize: The size of the public key in bytes.
    uint8 public constant PublicKeySize = HashLen * 2;

    // Hash: The WOTS+ `F` hash function.
    function Hash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    // HashLen: The WOTS+ `n` security parameter which is the size 
    // of the hash function output in bytes.
    // This is 32 for keccak256 (256 / 8 = 32)
    uint8 public constant HashLen = 32;

    // MessageLen: The WOTS+ `m` parameter which is the size 
    // of the message to be signed in bytes 
    // (and also the size of our hash function)
    //
    // This is 32 for keccak256 (256 / 8 = 32)
    //
    // Note that this is not the message length itself as, like 
    // with most signatures, we hash the message and then compute
    // the signature on the hash of the message.
    uint8 public constant MessageLen = 32;

    // ChainLen: The WOTS+ `w`(internitz) parameter. 
    // This corresponds to the number of hash chains for each public
    // key segment and the base-w representation of the message
    // and checksum.
    // 
    // A larger value means a smaller signature size but a longer
    // computation time.
    // 
    // For XMSS (rfc8391) this value is limited to 4 or 16 because
    // they simplify the algorithm and offer the best trade-offs.
    uint8 public constant ChainLen = 16;
    // lg(ChainLen) so we don't calculate it
    uint8 public constant LgChainLen = 4;

    // NumMessageChunks: the `len_1` parameter which is the number of
    // message chunks. This is 
    // ceil(8n / lg(w)) -> ceil(8 * HashLen / lg(ChainLen))
    // or ceil(32*8 / lg(16)) -> 256 / 4 = 64
    // Python:  math.ceil(32*8 / math.log(16,2))
    uint8 public constant NumMessageChunks = 64;

    // NumChecksumChunks: the `len_2` parameter which is the number of
    // checksum chunks. This is
    // floor(lg(len_1 * (w - 1)) / lg(w)) + 1
    // -> floor(lg(NumMessageChunks * (ChainLen - 1)) / lg(ChainLen)) + 1
    // -> floor(lg(64 * 15) / lg(16)) + 1 = 3
    // Python: math.floor(math.log(64 * 15, 2) / math.log(16, 2)) + 1
    uint8 public constant NumChecksumChunks = 3;

    uint8 public constant NumSignatureChunks = NumMessageChunks + NumChecksumChunks;

    // verify: Verify a WOTS+ signature. 
    // 1. The first part of the publicKey is a public seed used to regenerate the randomization elements. (`r` from the paper).
    // 2. The second part of the publicKey is the hash of the NumMessageChunks + NumChecksumChunks public key segments.
    // 3. Convert the Message to "base-w" representation (or base of ChainLen representation).
    // 4. Compute and add the checksum. 
    // 5. Run the chain function on each segment to reproduce each public key segment.
    // 6. Hash all public key segments together to recreate the original public key.
    function verify(
        bytes calldata publicKey, 
        bytes calldata message, 
        bytes32[] memory signature
    ) public pure returns (bool) {
        require(publicKey.length == PublicKeySize, string.concat("public key length must be ", "64", " bytes"));
        require(message.length == MessageLen, string.concat("message length must be ", "32", " bytes"));
        require(signature.length == NumSignatureChunks, "Invalid signature length");
        
        // Immediately log received signature values
        console2.log("Received in verify:");
        for (uint i = 0; i < signature.length; i++) {
            console2.log("Signature chunk %d:", i);
            console2.logBytes32(signature[i]);
            require(uint256(signature[i]) != 0, "Signature segment is zero in verify");
        }
        
        bytes32 publicSeed = bytes32(publicKey[0:HashLen]);
        bytes32 publicKeyHash = bytes32(publicKey[HashLen:PublicKeySize]);

        console2.log("Public key seed:");
        console2.logBytes32(publicSeed);
        console2.log("Public key hash:");
        console2.logBytes32(publicKeyHash);
        console2.log("Message:");
        console2.logBytes(message);
        console2.log("Signature:");
        for (uint i = 0; i < signature.length; i++) {
            console2.log("Signature segment %d:", i);
            console2.logBytes32(signature[i]);
        }

        bytes memory publicKeySegments = new bytes(NumMessageChunks + NumChecksumChunks);

        // would it be clearer to compute these together in a subfunction, hiding the checksum details entirely?
        uint8[] memory chainSegments = ComputeMessageHashChainIndexes(message);

        // Compute each public key segment. These are done by taking the signature, which is prevChainOut at chainIdx - 1, 
        // and completing the hash chain via the chain function to recompute the public key segment.
        for (uint8 i = 0; i < chainSegments.length; i++ ) {
            uint8 chainIdx = chainSegments[i];
            uint8 numIterations = ChainLen - chainIdx - 1;
            bytes32 prevChainOut = signature[i];

            bytes32 segment = chain(prevChainOut, publicSeed, chainIdx, numIterations);
            // Debug prints
            console2.log("Starting signature segment %d:", i);
            console2.logBytes32(signature[i]);
            console2.log("Generated public key segment %d:", i);
            console2.logBytes32(segment);

            publicKeySegments = bytes.concat(publicKeySegments, segment);
        }

        // Hash all public key segments together to recreate the original public key.
        bytes32 computedHash = Hash(publicKeySegments);

        // Compare computed hash with stored public key hash
        return computedHash == bytes32(publicKeyHash);
    }

    // sign: Sign a message with a WOTS+ private key. Do not use this, it is present as an example and
    // you should be using a typescript version of this function because it requires your private key.
    function sign(bytes32 privateKey, bytes calldata message) public pure returns (bytes32[NumSignatureChunks] memory) {
        require(privateKey.length == HashLen, string.concat("private key length must be ", "32", " bytes"));
        require(message.length == MessageLen, string.concat("message length must be ", "32", " bytes"));

        bytes32 publicSeed = prf(privateKey, 0);
        bytes32[NumSignatureChunks] memory signature;

        uint8[] memory chainSegments = ComputeMessageHashChainIndexes(message);

        for (uint8 i = 0; i < chainSegments.length; i++ ) {
            uint16 chainIdx = chainSegments[i];
            bytes32 secretKeySegment = prf(privateKey, i + 1);
            signature[i] = chain(secretKeySegment, publicSeed, 0, chainIdx);
            
            // Debug prints
            console2.log("Signature segment %d:", i);
            console2.logBytes32(signature[i]);
        }

        return signature;
    }

    // generateKeyPair: Generate a WOTS+ key pair. Do not use this, it is present as an example and
    // you should be using a typescript version of this function, presumably with better entropy source.
    function generateKeyPair(bytes32 privateSeed) public pure returns (bytes memory, bytes32) {

        bytes32 privateKey = prf(privateSeed, 0);
        bytes32 publicSeed = prf(privateKey, 0);

        bytes32[] memory publicKeySegments = new bytes32[](NumMessageChunks + NumChecksumChunks);
        for (uint8 i = 0; i < publicKeySegments.length; i++) {
            bytes32 secretKeySegment = prf(privateKey, i + 1);
            publicKeySegments[i] = chain(secretKeySegment, publicSeed, 0, ChainLen - 1);

            console2.log("Public key segment %d:", i);
            console2.logBytes32(publicKeySegments[i]);

        }

        bytes memory publicKey = abi.encodePacked(publicSeed, Hash(abi.encodePacked(publicKeySegments)));
        return (publicKey, privateKey);
    }

    // chain is the c_k^i function, 
    // the hash of (prevChainOut XOR randomization element at index).
    // As a practical matter, we generate the randomization elements
    // via a seed like in XMSS(rfc8391) with a defined PRF.
    function chain(bytes32 prevChainOut, bytes32 publicSeed, uint16 index, uint16 steps) private pure returns (bytes32) {
        // fail fast when out of range
        // note: maybe this is wasteful since the functions calling this one should never send it?
        require ((index + steps) < ChainLen, 
            string.concat("steps + index must be less than ", "16"));

        // Skip the functionKey calculation when it is unneeded. 
        if (steps == 0) {
            return prevChainOut;
        }

        // functionKey is `k` from the paper, we define it as the index 0 from the prf, 
        // as the prf output is not used on the first element in the chain function.
        // This is hashed in on each chain iteration along with the randomization element.
        // It is part of the public key, so safe to define it with the public seed.
        // note: maybe worthwhile to calculate this outside this function, e.g., in keygen
        // off the public seed and/or store it
        bytes32 functionKey = prf(publicSeed, 0);
    
        bytes32 chainOut = prevChainOut;
        for (uint8 i = 1; i <= steps; i++) {
            bytes32 randomizationElement = prf(publicSeed, index + i);
            chainOut = Hash(abi.encodePacked(functionKey, xor(chainOut, randomizationElement)));
        }
        return chainOut;
    }

    // xor: XOR two bytes32 values
    function xor(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return bytes32(uint256(a) ^ uint256(b));
    }

    // prf: Generate randomization elements from seed and index
    // Similar to XMSS RFC 8391 section 5.1
    // NOTE: while sha256 and ripemd160 are available in solidity,
    // they are implemented as precompiled contracts and are more expensive for gas. 
    function prf(bytes32 seed, uint16 index) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            bytes1(0x03),  // prefix to domain separate
            seed,          // the seed input
            uint16(index)  // the index/position
        ));
    }

    // ComputeMessageHashChainIndexes: Compute the chain indexes for a message. 
    // We convert the message to base-w representation (or base of ChainLen representation)
    // We attach the checksum, also in base-w representation, to the end of the hash chain index list. 
    function ComputeMessageHashChainIndexes(bytes calldata message) internal pure returns (uint8[] memory) {
        uint8[] memory chainIndexes = new uint8[](NumMessageChunks + NumChecksumChunks);
        toBaseW(message, NumMessageChunks, chainIndexes, 0); 
        checksum(chainIndexes);
        return chainIndexes;
    }

    // checksum: Calculate the checksum of the message and return it in basew
    function checksum(uint8[] memory basew) internal pure {
        uint16 csum = 0;
        for (uint8 i = 0; i < NumMessageChunks; i++ ) {
            csum = csum + ChainLen - 1 - basew[i];
        }

        // this is left-shifting the checksum to ensure proper alignment when 
        // converting to base-w representation.
        // This shift ensures that when we convert to base-w, the least significant
        // bits of the checksum will be properly aligned with the w-bit boundaries.
        // (8 - ((NumChecksumChunks * LgChainLen) % 8)) = 4
        csum = csum << 4;
        // Per XMSS (rfc8391) this is done in big endian...
        // It's 2 bytes because thats ceil( ( len_2 * lg(w) ) / 8 ), technically actually 
        // 12 bits, or 3 basew segments.
        bytes memory csumBytes = new bytes(2);
        csumBytes[0] = bytes1(uint8(csum >> 8));    // Most significant byte
        csumBytes[1] = bytes1(uint8(csum & 0xFF));  // Least significant byte

        // Convert checksum bytes to base-w and append to basew array
        toBaseW(csumBytes, NumChecksumChunks, basew, NumMessageChunks);
    }

    // toBaseW: Convert a message to base-w representation (or base of ChainLen representation)
    // These numbers are used to index into each hash chain which is rooted at a secret key segment and produces
    // a public key segment at the end of the chain. Verification of a signature means using these
    // index into each hash chain to recompute the corresponding public key segment.
    function toBaseW(bytes memory message, uint8 numChunks, uint8[] memory basew, uint8 offset) internal pure {
        // Input message index
        uint8 mIdx = 0;
        // Output basew index
        uint8 oIdx = 0 + offset;
        uint8 total = 0;
        uint8 bits = 0;

        for (uint8 consumed = 0; consumed < numChunks; consumed++) {
            // Consume more bits when we run out
            if (bits == 0) {
                total = uint8(message[mIdx]);
                mIdx++;
                bits += 8;
            }

            // Read lg(ChainLen) bits from the message (lg(w))
            bits -= LgChainLen;
            basew[oIdx] = (total >> bits) & (ChainLen - 1);
            oIdx++;
        }
    }
}