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
SHRINCS.verifyStateful(parameterSetId, publicKey, message, signature)
```

This verifies:

- the composite SHRINCS public key commitment
- the embedded stateful public key
- compact `WOTS-C` reconstruction
- the unbalanced XMSS-style authentication path

### 2. Stateless verification

```solidity
SHRINCS.verifyStateless(parameterSetId, publicKey, message, signature)
```

This verifies:

- parameter-set compatibility
- `FORS-C`
- hypertree layer traversal
- stateless `WOTS-C`
- final hypertree root against the public key

### 3. Stateful-key rotation authorization

```solidity
SHRINCS.rotateStatefulViaStateless(parameterSetId, currentPublicKey, recoveryMessage, recoverySignature, nextStatefulKey)
```

This is a verifier-side authorization helper, not signer recovery logic.

It:

- verifies a stateless recovery signature under the current key
- validates a proposed next stateful public key
- returns the next composite public-key commitment on success
- returns `bytes32(0)` on failure

### 4. Full SHRINCS-key rotation authorization

```solidity
SHRINCS.rotateFullShrincsKey(parameterSetId, currentPublicKey, recoveryMessage, recoverySignature, nextKey)
```

This verifies a stateless recovery signature authorizing a full next SHRINCS key bundle.

It:

- verifies the current stateless recovery signature
- validates the full next key payload
- recomputes the next composite public-key commitment
- checks that it matches `nextKey.compositePublicKey`
- returns `bytes32(0)` on failure

## Parameter Sets

The verifier currently accepts only predefined parameter sets selected by enum:

```solidity
ShrincsType.ParameterSetId.Sphincs256sKeccak
```

The concrete values are resolved internally in [ShrincsTypes.sol](./contracts/ShrincsTypes.sol). Callers do not supply arbitrary numeric parameter tuples anymore.

## Test Coverage

Current tests cover:

### Stateful path

- valid stateful signature verifies
- wrong message is rejected
- wrong public key is rejected
- corrupted stateful signature is rejected

### Stateless path

- valid stateless signature verifies
- wrong message is rejected
- tampered `FORS` data is rejected
- tampered hypertree `WOTS-C` public-key hash is rejected
- tampered hypertree authentication path is rejected

### Rotation authorization helpers

- `rotateStatefulViaStateless(...)`
  - returns next composite commitment on valid recovery authorization
  - rejects wrong recovery message
  - rejects malformed next stateful public key

- `rotateFullShrincsKey(...)`
  - returns next composite commitment on valid full-key rotation authorization
  - rejects wrong recovery message
  - rejects mismatched supplied composite commitment

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

- `15 passed, 0 failed`

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
