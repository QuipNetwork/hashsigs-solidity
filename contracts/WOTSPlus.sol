// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity^0.8.28;

library WOTSPlus {
    public constant SignatureSize = NumSignatureChunks * HashLen;
    public constant PublicKeySize = HashLen;

    // Hash: The WOTS+ `F` hash function.
    public constant Hash = keccak256;

    // HashLen: The WOTS+ `n` security parameter which is the size 
    // of the `F` hash function output in bytes.
    // This is 32 for keccak256 (256 / 8 = 32)
    public constant uint8 HashLen = Hash.outputLen;

    // MessageLen: The WOTS+ `m` parameter which is the size 
    // of the message to be signed in bytes 
    // (and also the size of our hash function)
    //
    // This is 32 for keccak256 (256 / 8 = 32)
    //
    // Note that this is not the message length itself as, like 
    // with most signatures, we hash the message and then compute
    // the signature on the hash of the message.
    public constant uint8 MessageLen = Hash.outputLen;

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
    public constant uint8 ChainLen = 16;
    // lg(ChainLen) so we don't calculate it
    public constant uint8 LgChainLen = 4;

    // NumMessageChunks: the `len_1` parameter which is the number of
    // message chunks. This is 
    // ceil(8n / lg(w)) -> ceil(8 * HashLen / lg(ChainLen))
    // or ceil(32*8 / lg(16)) -> 256 / 4 = 64
    // Python:  math.ceil(32*8 / math.log(16,2))
    public constant uint8 NumMessageChunks = 64;

    // NumChecksumChunks: the `len_2` parameter which is the number of
    // checksum chunks. This is
    // floor(lg(len_1 * (w - 1)) / lg(w)) + 1
    // -> floor(lg(NumMessageChunks * (ChainLen - 1)) / lg(ChainLen)) + 1
    // -> floor(lg(64 * 15) / lg(16)) + 1 = 3
    // Python: math.floor(math.log(64 * 15, 2) / math.log(16, 2)) + 1
    public constant uint8 NumChecksumChunks = 3;

    public constant uint8 NumSignatureChunks = NumMessageChunks + NumChecksumChunks;

    function verify(bytes memory publicKey, bytes memory message, bytes memory signature) public pure returns (bool) {
        require(publicKey.length == 64, "public key length must be 64 bytes");
        
        bytes publicSeed = publicKey[0:32];
        bytes publicKeyHash = publicKey[32:64];

        bytes[] publicKeySegments = new bytes[](NumMessageChunks + NumChecksumChunks);

        basewMsg = toBaseW(message, NumMessageChunks);
        basewChecksum = checksum(basewMsg);


        for (uint i = 0; i < basewMsg.length; i++ ) {
            uint16 index = basewMsg[i];
            uint16 numIterations = ChainLen - index - 1;
            bytes prevChainOut = signature[i];

            publicKeySegments[index] = chain(prevChainOut, publicSeed, index, numIterations);
        }

        for (uint i = 0; i < basewChecksum.length; i++ ) {
            uint16 index = basewMsg.length + i;
            uint16 numIterations = ChainLen - index - 1;
            bytes prevChainOut = signature[i];

            publicKeySegments[index] = chain(prevChainOut, publicSeed, index, numIterations);
        }

        // Hash all public key segments together
        bytes32 computedHash = Hash(abi.encodePacked(publicKeySegments));

        // Compare computed hash with stored public key hash
        return computedHash == publicKeyHash;
    }

    function generateKeyPair(bytes memory privateSeed) public pure returns (bytes memory, bytes memory) {
        bytes privateKey = prf(privateSeed, 0);
        bytes publicKey = chain(bytes("0"), privateSeed, 0, ChainLen);
        return (publicKey, privateKey);
    }

    function sign(bytes memory privateKey, bytes memory message) public pure returns (bytes memory) {
        return bytes("signature");
    }

    // chain is the c_k^i function, 
    // the hash of (prevChainOut XOR randomization element at index).
    // As a practical matter, we generate the randomization elements
    // via a seed like in XMSS(rfc8391) with a defined PRF.
    function chain(bytes memory prevChainOut, bytes memory publicSeed, uint16 index, uint16 numIterations) public pure returns (bytes memory chainOut) {

        // functionKey is `k` from the paper, we define it as the index 0 from the prf, 
        // as the prf output is not used on the first element in the chain function.
        // This is hashed in on each chain iteration along with the randomization element.
        // It is part of the public key, so safe to define it with the public seed.
        bytes functionKey = prf(publicSeed, 0);
    
        bytes chainOut = prevChainOut;
        for (uint16 i = 1; i <= numIterations; i++) {
            bytes32 randomizationElement = prf(publicSeed, index + i);
            chainOut = abi.encodePacked(Hash(xor(chainOut, randomizationElement)));
        }
        return chainOut;
    }

    // xor xors 2 byte arrays
    function xor(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        require(a.length == b.length, "Length must be equal");
        bytes memory result = new bytes(a.length);
        for (uint i = 0; i < a.length; i++) {
            result[i] = bytes1(uint8(a[i]) ^ uint8(b[i]));
        }
        return result;
    }    

    // prf: Generate randomization elements from seed and index
    // Similar to XMSS RFC 8391 section 5.1
    // NOTE: while sha256 and ripemd160 are available in solidity,
    // they are implemented as precompiled contracts and are more expensive for gas. 
    function prf(bytes memory seed, uint16 index) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            bytes1(0x03),  // prefix to domain separate
            seed,          // the seed input
            uint16(index)  // the index/position
        ));
    }

    // checksum: Calculate the checksum of the message and return it in basew
    function checksum(uint16[] memory basewMsg) public pure returns (uint16[] memory checksum) {
        uint16 csum = 0;
        for ( i = 0; i < basewMsg.length; i++ ) {
            csum = csum + ChainLen - 1 - basewMsg[i];
        }
        return toBaseW(csum, NumChecksumChunks);
    }    

    function toBaseW(bytes memory message, uint16 numChunks) public pure returns (uint16[] memory basew) {
        uint16[] memory basew = new uint16[](numChunks);
        uint16 in = 0;
        uint16 out = 0;
        uint16 total = 0;
        uint16 bits = 0;

        for (uint16 consumed = 0; consumed < numChunks; consumed++) {
            if (bits == 0) {
                total = message[in];
                in++;
                bits += 8;
            }
            bits -= LgChainLen;
            basew[out] = (total >> bits) & (ChainLen - 1);
            out++;
        }
        return basew;
    }
}