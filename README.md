# hashsigs-solidity

Solidity verification code for the current SHRINCS account surface:

- a stateless SHRINCS path using `FORS-C + hypertree + WOTS-C`
- a compact JARDIN-style path using compact `FORS-C` plus a small Merkle auth path
- an example account wrapper that exposes only stateless and compact actions

The older stateful WOTS-C / unbalanced-XMSS action path has been removed from the production surface. The standalone stateful ERC-7913 verifier and stateful account policy examples were removed with it.

## Contracts

- [contracts/SHRINCS.sol](./contracts/SHRINCS.sol)
  - facade for stateless verification, compact verification, compact slot hashes, and full stateless rotation hashes
- [contracts/ShrincsForsC.sol](./contracts/ShrincsForsC.sol)
  - stateless `FORS-C` digest extraction and root reconstruction
- [contracts/ShrincsHypertree.sol](./contracts/ShrincsHypertree.sol)
  - stateless hypertree verification, including the WOTS-C layer signatures used inside the stateless construction
- [contracts/ShrincsCompact.sol](./contracts/ShrincsCompact.sol)
  - JARDIN-style compact `FORS-C` verifier
- [contracts/examples/ShrincsAccountVerifierExample.sol](./contracts/examples/ShrincsAccountVerifierExample.sol)
  - example wrapper with nonce/key-version binding, ERC-1271, stateless usage accounting, full key rotation, and compact slots
- [contracts/WOTSPlus.sol](./contracts/WOTSPlus.sol)
  - legacy standalone WOTS+ implementation retained outside the SHRINCS account surface

## Public Key Shape

The Solidity public key now exposes only the stateless bundle:

```solidity
PublicKey = (pkSeed, hypertreeRoot)
```

The account stores `currentPkSeed` and `currentHypertreeRoot` directly. There is
no global public-key commitment in the wrapper storage or public-key ABI.

## Verification Paths

### Stateless

```solidity
SHRINCS.verifyStateless(expectedPkSeed, expectedHypertreeRoot, publicKey, actionContext, signature)
```

The stateless path:

1. validates the account action context
2. hashes the stateless action message with the installed `pkSeed`/`hypertreeRoot`
3. verifies the `FORS-C` signature
4. carries the reconstructed root through the hypertree to `hypertreeRoot`

The raw helper is:

```solidity
SHRINCS.verifyStatelessUncheckedMessage(expectedPkSeed, expectedHypertreeRoot, publicKey, message, signature)
```

### Compact

```solidity
SHRINCS.verifyCompact(subPkSeed, subPkRoot, actionContext, signature)
```

The compact path verifies a fixed 10,053-byte JARDIN Type 2 signature:

```text
R32 || counter4 || openedFORS[51] || q1 || merkleAuth[7]
```

Account wrappers authorize compact slots with stateless signatures over:

- `SHRINCS.compactSlotRegistrationMessageHash(...)`
- `SHRINCS.compactSlotRevocationMessageHash(...)`

After a slot is registered, compact actions are verified against:

```solidity
SHRINCS.compactActionMessageHash(context)
```

### Full Rotation

```solidity
SHRINCS.statelessRotate(
    expectedPkSeed,
    expectedHypertreeRoot,
    currentPublicKey,
    rotationContext,
    recoverySignature,
    nextKey
)
```

Full rotation is authorized by the current stateless key and installs a new
`pkSeed`/`hypertreeRoot` pair.

## Example Account Wrapper

`ShrincsAccountVerifierExample` exposes:

- `verifyStatelessAction(...)`
- `verifyCompactAction(...)`
- `registerCompactSlot(...)`
- `revokeCompactSlot(...)`
- `rotateFullKey(...)`
- `isValidSignature(...)`

Wrapper state:

- `currentPkSeed`
- `currentHypertreeRoot`
- `nonce`
- `keyVersion`
- `statelessSignaturesUsed`
- `compactSlots`

ERC-1271 mode bytes:

- `0x02`: stateless action envelope
- `0x03`: compact action envelope

Mode `0x01` is no longer accepted.

## Parameters

Main stateless profile:

- `HASH_LEN = 32`
- `HYPERTREE_HEIGHT = 64`
- `NUM_HYPERTREE_LAYERS = 8`
- `FORS_TREE_HEIGHT = 14`
- `NUM_FORS_TREES = 22`
- `NUM_WOTS_CHAINS = 64`
- `WOTS_CHAIN_LEN = 16`
- `STATELESS_SIGNATURE_LIMIT = 1,048,576`

Compact profile:

- `COMPACT_FORS_TREE_HEIGHT = 5`
- `COMPACT_NUM_FORS_TREES = 52`
- `COMPACT_OPEN_FORS_TREES = 51`
- `COMPACT_MERKLE_HEIGHT = 7`
- `COMPACT_Q_MAX = 128`

## Tests

Run:

```bash
forge test
```

The test suite covers:

- stateless vector verification and malformed signature rejection
- compact raw/action vector verification
- compact slot registration, revocation, and action checks
- ERC-1271 stateless and compact snapshots
- full stateless rotation
- gas measurements for stateless and compact paths
- standalone `WOTSPlus`

## Account Vectors

Regenerate account wrapper vectors with:

```bash
dev/export-account-vectors.sh
```

The generated file is:

```text
test/test_vectors/shrincs_account_wrapper_vectors.json
```

It now contains stateless action and full-rotation wrapper vectors only.
