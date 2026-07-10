# Deployment registry

This repo owns the canonical deployments of the SHRINCS verifiers and
the WOTS+ library. SHRINCS is testnet-only. Consumers pin the published
`(address, runtime codehash)` pairs below; they never deploy their own
copy and never derive these values from a local rebuild.

All deploys use CREATE3 (maintainer decision, 2026-07-10). A CREATE3
child address depends only on `(factory, salt)`, not on the child's init
code, so a recompile or a profile change doesn't move the address.

## How a deploy is produced

1. Deploy the CREATE3 factory once per chain. The deploy scripts do this
   automatically on first use: `Create3Factory` is deployed through the
   canonical CREATE2 proxy (`0x4e59b44847b379578588920cA78FbF26c0B4956C`)
   under salt `keccak256("QUIP:Create3Factory:V1.0")`, so its address is
   the same on every chain.
2. From the release commit, on each target chain, run the profile's
   deploy script under its required build profile. Each script asserts
   `FOUNDRY_PROFILE` and refuses to run under the wrong one.

   ```bash
   FOUNDRY_PROFILE=production forge script \
       script/DeployShrincsVerifier256s.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q18 forge script \
       script/DeployShrincsVerifier128sQ18.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q20 forge script \
       script/DeployShrincsVerifier128sQ20.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production forge script \
       script/DeployWOTSPlus.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
   ```

3. Capture the codehash from the on-chain deployment with
   `cast codehash <address> --rpc-url $RPC`, never from a local rebuild:
   solc appends a metadata hash that drifts with compiler version,
   settings, and source paths.
4. Record the row below and confirm `cast codehash` returns the same
   value on every listed chain.

A new verifier version is a new salt, a new address, and a new row.
Deployed artifacts are immutable; nothing is upgraded in place.

## Current registry (CREATE3)

The `production` solc pin fixes each verifier's runtime codehash across
chains. The addresses below are pre-release predictions from a local
simulation at the current commit through the factory above. They match
what a real deploy produces from this commit as long as the factory
bytecode is unchanged. No chain has a deployment yet.

Shared CREATE3 factory (all rows): predicted
`0xBF3af840d7523547C358976697E82f9Ebcb7a801`
(salt `keccak256("QUIP:Create3Factory:V1.0")`).

### SHRINCS verifiers

| Field | 256s | 128s-q18 | 128s-q20 |
|---|---|---|---|
| Contract | `ShrincsVerifier256s` | `ShrincsVerifier128sQ18` | `ShrincsVerifier128sQ20` |
| Build profile | `production` | `production-128s-q18` | `production-128s-q20` |
| CREATE3 salt string | `QUIP:ShrincsVerifier256s:V1.0` | `QUIP:ShrincsVerifier128sQ18:V1.0` | `QUIP:ShrincsVerifier128sQ20:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s")` | `keccak256("shrincs-128s-q18")` | `keccak256("shrincs-128s-q20")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | same | same |
| Predicted address | `0x435e55c7a9BA8DF02E2C1bAc9daacC732f4F9568` | `0x65E1A21B69658Ae37Dab2Ac1E483306C04b14b06` | `0xDb182Cf4A8726C8816A7F77e345Ad75f417b5968` |
| Runtime codehash | *(capture on first deploy)* | *(capture on first deploy)* | *(capture on first deploy)* |
| Chains deployed | *(none yet)* | *(none yet)* | *(none yet)* |

The 128s-q20 stateless budget (2^20) wants profile security-analysis
backing before production use; 128s-q18 is the conservative sibling.
The 128s verifiers verify against the regenerated 128s vectors, which
land with the Rust-signer coordination (tracked as T6); don't treat a
128s deploy as production-ready until those vectors exist.

### WOTS+ library

| Field | Value |
|---|---|
| Contract | `WOTSPlus` (library) |
| Build profile | `production` |
| CREATE3 salt string | `QUIP:WOTSPlus:V1.0` |
| Predicted address | `0x628bCbF1A1dfE63cad765012DD20e1dFD4461585` |
| Runtime codehash | *(capture on first deploy)* |
| Chains deployed | *(none yet)* |

WOTS+ is profile-independent (its parameters are its own constants, not
`ShrincsParams`), so its bytecode and CREATE3 address are the same under
any build profile.

## Historical mechanisms (recorded, replaced)

These are the pre-CREATE3 mechanisms, kept for the record. Neither had a
canonical on-chain deployment.

### SHRINCS verifier — CREATE2

Before the profile split, a single `ShrincsVerifier` deployed through the
canonical CREATE2 proxy `0x4e59b44847b379578588920cA78FbF26c0B4956C`.

| Field | Value |
|---|---|
| Salt | `keccak256("QUIP:ShrincsVerifier:V1.0")` |
| `VERSION_TAG()` | `0x064b5b1b1f5d6dc3d38c8ed9f38fd24f68628329f9329a54b8e8c53e3b06da58` |
| Predicted address | `0x560Ea50c83AB3952587fa3C7b9250c045cfA1252` (pre-release rehearsal) |
| Predicted codehash | `0x8553890af0b7136ccf8993d2d691c492618150ee85f028892f285ccb6682a5ff` (pre-release rehearsal) |
| Chains deployed | none |

CREATE2 ties the address to the init code, so any recompile moved it.
CREATE3 removes that coupling, so the profile split adopts it.
The old `ShrincsVerifier` is now the abstract base of the three concrete
per-profile verifiers, so this exact artifact is no longer deployable;
the address above was never used on any chain.

### WOTS+ — Hardhat Ignition

WOTS+ deployed through Hardhat Ignition (`ignition/modules/WOTSPlus.ts`,
`WOTSPlusModule`) with Ignition's default CREATE strategy: a plain
nonce-based deploy from the deployer account, with no CREATE2 salt and no
fixed factory. It produced no deterministic, chain-invariant address, and
no address was recorded. The Hardhat path is removed; WOTS+ now deploys
through the CREATE3 script above.
