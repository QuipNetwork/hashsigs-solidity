// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library WotsTypes {
    uint8 internal constant WOTS_PLUS_LEN = 67;
    uint8 internal constant WOTS_C_LEN = 64;

    struct AddressContext {
        uint32 layer;
        bytes12 tree;
        uint32 keypair;
    }

    // struct WotsPlusPublicKey {
    //     bytes32 publicSeed;
    //     bytes32 publicKeyHash;
    // }

    // struct WotsPlusMessage {
    //     bytes32 messageHash;
    // }

    // struct WotsPlusSignature {
    //     bytes32[WOTS_PLUS_LEN] elements;
    // }

    struct WotsCPublicKey {
        bytes32 pkSeed;
        bytes32 pkHash;
    }

    struct WotsCSignature {
        bytes32 randomizer;
        uint32 counter;
        bytes32[WOTS_C_LEN] chains;
    }
}
