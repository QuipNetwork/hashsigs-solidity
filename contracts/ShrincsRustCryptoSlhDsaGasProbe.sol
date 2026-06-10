// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Gas probe for RustCrypto SLH-DSA-SHAKE-128f artifacts.
/// @dev This does not implement FIPS-205 verification on-chain. RustCrypto
/// verifies off-chain in the gas runner; this contract measures the calldata,
/// decoding, length checks, and full-payload hashing cost for the real artifact
/// shape.
contract ShrincsRustCryptoSlhDsaGasProbe {
    uint256 public constant SHAKE_128F_PUBLIC_KEY_BYTES = 32;
    uint256 public constant SHAKE_128F_SIGNATURE_BYTES = 17088;

    bytes32 internal constant DOMAIN = keccak256("rustcrypto-slh-dsa-shake-128f");

    function verify(bytes calldata publicKey, bytes calldata message, bytes calldata signature, bytes32 expectedDigest)
        external
        pure
        returns (bool)
    {
        if (publicKey.length != SHAKE_128F_PUBLIC_KEY_BYTES) return false;
        if (signature.length != SHAKE_128F_SIGNATURE_BYTES) return false;

        return digest(publicKey, message, signature) == expectedDigest;
    }

    function digest(bytes calldata publicKey, bytes calldata message, bytes calldata signature) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(DOMAIN, publicKey, message, signature));
    }
}
