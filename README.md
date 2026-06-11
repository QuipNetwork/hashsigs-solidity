# SHRINCS Solidity Verifier

This repository contains a Solidity verifier-oriented implementation of the SHRINCS signature construction.

The current code is focused on on-chain verification behavior. It does not implement signer-side recovery state, seed restore logic, or wallet lifecycle management.

## What SHRINCS Is

In this codebase, SHRINCS is a two-path signature design:

- a **stateful path**
  - cheap normal-case verification
  - based on compact `WOTS-C` plus an unbalanced XMSS-style authentication path
- a **stateless path**
  - fallback / recovery verification path
  - based on a SPHINCS-style `FORS-C + hypertree + WOTS-C` structure

The high-level idea is:

- normal operation uses the cheaper stateful path
- a restored or degraded signer can use the stateless path
- the verifier only checks signatures and rotation authorizations; it does not track signer state

## Repository Shape

Main contracts:

- [contracts/SHRINCS.sol](./contracts/SHRINCS.sol)
  - main verifier library
- [contracts/ShrincsTypes.sol](./contracts/ShrincsTypes.sol)
  - shared enums, structs, and predefined parameter-set defaults

Tests:

- [test/ShrincsSphincs256sVectors.t.sol](./test/ShrincsSphincs256sVectors.t.sol)
  - vector-backed verification and rotation-authorization tests

Test vectors:

- [test/test_vectors/shrincs_sphincs_256s_keccak.json](./test/test_vectors/shrincs_sphincs_256s_keccak.json)

## Available Verifier Paths

### 1. Stateful verification

```solidity
SHRINCS.verifyStatefulUnsafeRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature)
SHRINCS.verifyStateful(parameterSetId, expectedCompositePublicKey, publicKey, actionContext, signature)
```

`verifyStatefulUnsafeRaw(...)` verifies an arbitrary caller-provided message.
It is meant for vectors, compatibility checks, and tightly controlled integrations.

`verifyStateful(...)` is the account-style path. It computes a canonical hash from `ActionContext`:

- `domainSeparator`
- `nonce`
- `keyVersion`
- `actionType`
- `payloadHash`

`payloadHash` should be the hash of a typed action payload. The verifier does not accept free-form account-operation bytes on this path.

The account-style path also rejects invalid contexts:

- `expectedCompositePublicKey == 0`
- `domainSeparator == 0`
- `actionType == 0`
- `payloadHash == 0`

Both forms verify:

- the provided `expectedCompositePublicKey` matches `publicKey.compositePublicKey`
- the composite SHRINCS public key commitment
- the embedded stateful public key
- compact `WOTS-C` reconstruction
- the unbalanced XMSS-style authentication path

### 2. Stateless verification

```solidity
SHRINCS.verifyStatelessUnsafeRaw(parameterSetId, expectedCompositePublicKey, publicKey, message, signature)
SHRINCS.verifyStateless(parameterSetId, expectedCompositePublicKey, publicKey, actionContext, signature)
```

`verifyStatelessUnsafeRaw(...)` verifies an arbitrary caller-provided message.
It is meant for vectors, compatibility checks, and tightly controlled integrations.

`verifyStateless(...)` is the account-style path. It computes a canonical hash from `ActionContext`.

`payloadHash` should be the hash of a typed action payload.

The account-style path also rejects invalid contexts:

- `expectedCompositePublicKey == 0`
- `domainSeparator == 0`
- `actionType == 0`
- `payloadHash == 0`

Both forms verify:

- the provided `expectedCompositePublicKey` matches `publicKey.compositePublicKey`
- parameter-set compatibility
- `FORS-C`
- hypertree layer traversal
- stateless `WOTS-C`
- final hypertree root against the public key

### 3. Stateful-key rotation authorization

```solidity
SHRINCS.rotateStatefulViaStateless(
    parameterSetId,
    expectedCompositePublicKey,
    currentPublicKey,
    rotationContext,
    recoverySignature,
    nextStatefulKey
)
```

This is a verifier-side authorization helper, not signer recovery logic.

It:

- computes a canonical rotation message hash from:
  - `parameterSetId`
  - `expectedCompositePublicKey`
  - `currentPublicKey.compositePublicKey`
  - `rotationContext`
  - `nextStatefulKey`
- verifies a stateless recovery signature over that canonical hash under the current key
- validates a proposed next stateful public key
- decodes the next stateful key and rejects `maxSignatures == 0`
- rejects zero `domainSeparator`
- rejects mismatched rotation target `parameterSetId`
- returns the next composite public-key commitment on success
- returns `bytes32(0)` on failure

### 4. Full SHRINCS-key rotation authorization

```solidity
SHRINCS.rotateFullShrincsKey(
    parameterSetId,
    expectedCompositePublicKey,
    currentPublicKey,
    rotationContext,
    recoverySignature,
    nextKey
)
```

This verifies a stateless recovery signature authorizing a full next SHRINCS key bundle.

It:

- computes a canonical full-rotation message hash from:
  - `parameterSetId`
  - `expectedCompositePublicKey`
  - `currentPublicKey.compositePublicKey`
  - `rotationContext`
  - the full `nextKey` bundle
- verifies the current stateless recovery signature over that canonical hash
- validates the full next key payload
- decodes the next stateful key and rejects `maxSignatures == 0`
- rejects zero `domainSeparator`
- rejects mismatched rotation target `parameterSetId`
- recomputes the next composite public-key commitment
- checks that it matches `nextKey.compositePublicKey`
- returns `bytes32(0)` on failure

## Parameter Sets

The verifier currently accepts only predefined parameter sets selected by enum:

```solidity
ShrincsType.ParameterSetId.Sphincs256sKeccak
```

There is also a reserved `ShrincsType.ParameterSetId.Unsupported` enum value used only for negative tests. It is not a valid production profile and is rejected by the library.

The concrete values are resolved internally in [ShrincsTypes.sol](./contracts/ShrincsTypes.sol). Callers do not supply arbitrary numeric parameter tuples anymore.

The hash suite is currently implied by the parameter set. The canonical account-action and rotation hashes also bind the resolved `hashSuiteId`, so the signed message shape stays stable if more parameter sets are added later.

The current verifier is intentionally pinned to exactly one production profile:

- `parameterSetId = ShrincsType.ParameterSetId.Sphincs256sKeccak`
- `hashSuiteId = HASH_SUITE_KECCAK_256`
- `nBytes = 32`
- `h = 64`
- `d = 8`
- `a = 14`
- `k = 22`
- `w = 16`
- `l = 64`
- `wotsTargetSum = 480`

This is deliberate. The library does not currently claim support for arbitrary future parameter tuples even if they are superficially shape-compatible.

## On-Chain Integration State

The `SHRINCS` library is only responsible for signature verification and rotation-authorization checking.

It does **not** manage surrounding account or protocol state such as:

- the currently active on-chain SHRINCS public key
- the selected parameter set for an account
- nonces / sequence numbers
- key version / rotation epoch
- recovery policy flags
- pending rotation state
- balances, permissions, or other account logic

So a real on-chain verifier or account contract usually needs an initialization step that stores at least:

- `currentShrincsPublicKey`
- `parameterSetId`

and usually also:

- `nonce`
- `keyVersion`

This is outside the SHRINCS library itself. The library only checks whether the provided signature or rotation authorization is valid for the provided inputs.

The integrating contract should pass its stored `currentShrincsPublicKey` into the library as `expectedCompositePublicKey`. The library enforces that the provided `publicKey` bundle is pinned to that expected key.

For rotation flows, the integrating contract should also supply a `rotationContext` carrying at least:

- `domainSeparator`
- `nonce`
- `keyVersion`

The library uses that context to build the canonical rotation message hash that must be signed by the stateless recovery path.

## Example Wrapper Contract

The library is intentionally storage-free. A real on-chain verifier or account contract must own the account state and feed that state into the library on every call.

Example shape:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SHRINCS} from "./contracts/SHRINCS.sol";
import {ShrincsType} from "./contracts/ShrincsTypes.sol";

contract ShrincsAccountVerifier {
    bytes32 public currentShrincsPublicKey;
    ShrincsType.ParameterSetId public parameterSetId;
    uint256 public nonce;
    uint256 public keyVersion;

    bytes32 internal constant DOMAIN_SEPARATOR = keccak256("shrincs-account-v1");

    constructor(bytes32 initialShrincsPublicKey, ShrincsType.ParameterSetId initialParameterSetId) {
        currentShrincsPublicKey = initialShrincsPublicKey;
        parameterSetId = initialParameterSetId;
    }

    function verifyStatefulAction(
        ShrincsType.PublicKey calldata publicKey,
        bytes32 actionType,
        bytes32 payloadHash,
        ShrincsType.StatefulSignature calldata signature
    ) external returns (bool) {
        ShrincsType.ActionContext memory context = ShrincsType.ActionContext({
            domainSeparator: DOMAIN_SEPARATOR,
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });

        bool ok = SHRINCS.verifyStateful(
            parameterSetId,
            currentShrincsPublicKey,
            publicKey,
            context,
            signature
        );
        if (!ok) return false;

        nonce += 1;
        return true;
    }

    function rotateFullKey(
        ShrincsType.PublicKey calldata currentPublicKey,
        ShrincsType.StatelessSignature calldata recoverySignature,
        ShrincsType.RotationTarget calldata nextKey
    ) external returns (bool) {
        ShrincsType.RotationContext memory context = ShrincsType.RotationContext({
            domainSeparator: DOMAIN_SEPARATOR,
            nonce: nonce,
            keyVersion: keyVersion
        });

        bytes32 nextCompositePublicKey = SHRINCS.rotateFullShrincsKey(
            parameterSetId,
            currentShrincsPublicKey,
            currentPublicKey,
            context,
            recoverySignature,
            nextKey
        );
        if (nextCompositePublicKey == bytes32(0)) return false;

        currentShrincsPublicKey = nextCompositePublicKey;
        parameterSetId = nextKey.parameterSetId;
        nonce += 1;
        keyVersion += 1;
        return true;
    }
}
```

What the wrapper must handle:

- store `currentShrincsPublicKey`
- store the active `parameterSetId`
- store and increment `nonce`
- store and increment `keyVersion`
- define a stable `domainSeparator`
- define the typed action payloads whose hash becomes `payloadHash`
- decide which path is allowed for which operation
- update stored key state only after successful rotation authorization

What the wrapper should not delegate to users:

- choosing `expectedCompositePublicKey`
- choosing the stored `nonce`
- choosing the stored `keyVersion`
- choosing an empty `domainSeparator`
- bypassing the typed `payloadHash` flow for normal account operations

## Test Coverage

Current tests cover:

### Stateful path

- valid stateful signature verifies
- wrong message is rejected
- wrong public key is rejected
- wrong expected composite public key is rejected
- zero expected composite public key is rejected
- unsupported requested parameter set is rejected
- mismatched declared parameter set is rejected
- corrupted stateful signature is rejected
- canonical action hash changes when payload changes
- zeroed account-style action context is rejected

### Stateless path

- valid stateless signature verifies
- wrong message is rejected
- tampered `FORS` data is rejected
- tampered hypertree `WOTS-C` public-key hash is rejected
- tampered hypertree authentication path is rejected
- wrong expected composite public key is rejected
- zero expected composite public key is rejected
- unsupported requested parameter set is rejected
- mismatched declared parameter set is rejected
- malformed `compositePublicKey` length is rejected
- malformed `messagePkSeed` length is rejected
- malformed `messageRoot` length is rejected
- malformed `hypertreePkSeed` length is rejected
- malformed `hypertreeRoot` length is rejected
- canonical action hash changes when nonce changes
- zeroed account-style action context is rejected

### Rotation authorization helpers

- `rotateStatefulViaStateless(...)`
  - canonical rotation hash changes when the next stateful key changes
  - rejects legacy stateless signatures that were not signed over the canonical rotation hash
  - rejects malformed next stateful public key
  - rejects next stateful keys with `maxSignatures == 0`
  - rejects unsupported next parameter set
  - rejects zero `domainSeparator`

- `rotateFullShrincsKey(...)`
  - canonical rotation hash changes when the next key bundle changes
  - rejects legacy stateless signatures that were not signed over the canonical rotation hash
  - rejects mismatched supplied composite commitment
  - rejects next stateful keys with `maxSignatures == 0`
  - rejects unsupported next parameter set
  - rejects zero `domainSeparator`

## Development

This project uses Foundry for Solidity build and test work.

### Prerequisites

1. Install Foundry:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

2. Install Node.js dependencies if you also need the Hardhat side:

```bash
npm install
```

## Build

The current verifier path is compiled with IR enabled:

```bash
forge build --contracts contracts --skip test --via-ir
```

## Test

Run the full verifier test suite:

```bash
forge test --via-ir
```

Current expected result:

- `38 passed, 0 failed`

## Notes

- `lib/forge-std/src/Test.sol` is provided locally in this repository so tests do not depend on fetching the `forge-std` submodule.
- `foundry.toml` still contains a legacy `src = "src"` setting and a couple of nonstandard `production` profile keys, so you may still see harmless config warnings from Foundry.

## License

Copyright (C) 2024 quip.network

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
