# Deployment registry

This repo owns the canonical deployments of the SHRINCS verifiers, their
SPHINCSPlusC stateless delegates, and the WOTS+ library. SHRINCS is
testnet-only. Consumers pin the published `(address, runtime codehash)`
pairs below; they never deploy their own copy and never derive these
values from a local rebuild.

All deploys use CREATE3 (maintainer decision, 2026-07-10). A CREATE3
child address depends only on `(factory, salt)`, not on the child's init
code, so a recompile or a profile change doesn't move the address.

Solc metadata is disabled for every build (`bytecode_hash = "none"`,
`cbor_metadata = false` in `foundry.toml`). This makes the
`Create3Factory` creation code — and with it the factory address —
identical across the three production profiles, so one factory serves
every suite. It also drops the metadata tail from each runtime codehash.
No chain has a deployment yet, so nothing is burned.

## How a deploy is produced

1. Deploy the CREATE3 factory once per chain. The deploy scripts do this
   automatically on first use: `Create3Factory` is deployed through the
   canonical CREATE2 proxy (`0x4e59b44847b379578588920cA78FbF26c0B4956C`)
   under salt `keccak256("QUIP:Create3Factory:V1.0")`, so its address is
   the same on every chain: `0xcE8dAc13593a359d961F91c35F8694cb2A03D005`.
2. Deploy in dependency order on each target chain, from the release
   commit, each script under its required build profile (the script
   asserts `FOUNDRY_PROFILE` and refuses to run under the wrong one).
   Deploy each SPHINCSPlusC verifier BEFORE its SHRINCS sibling: CREATE3
   fixes the address either way, but `SHRINCSVerifier.verifyStateless`
   reverts on empty code, and each SHRINCS deploy script asserts its
   sibling is already deployed at the pinned address.

   ```bash
   FOUNDRY_PROFILE=production forge script \
       script/DeploySPHINCSPlusC256sKeccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production forge script \
       script/DeploySHRINCS256sKeccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q18 forge script \
       script/DeploySPHINCSPlusC128sQ18Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q18 forge script \
       script/DeploySHRINCS128sQ18Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q20 forge script \
       script/DeploySPHINCSPlusC128sQ20Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q20 forge script \
       script/DeploySHRINCS128sQ20Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify

   FOUNDRY_PROFILE=production forge script \
       script/DeployWOTSPlus.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify
   ```

3. Capture the codehash from the on-chain deployment with
   `cast codehash <address> --rpc-url $RPC`, never from a local rebuild.
   With metadata disabled the codehash is the plain runtime-code hash, so
   it no longer drifts with source paths; it still depends on the compiler
   version and optimizer settings, which the production profiles pin.
4. Record the row below and confirm `cast codehash` returns the same
   value on every listed chain.

A new verifier version is a new salt, a new address, and a new row.
Deployed artifacts are immutable; nothing is upgraded in place.

## Current registry (CREATE3)

The `production` solc pin fixes each verifier's runtime codehash across
chains. The addresses below are pre-release predictions from a local
simulation at the current commit through the factory below. They match
what a real deploy produces from this commit as long as the factory
creation code is unchanged. No chain has a deployment yet.

Shared CREATE3 factory (all rows): predicted
`0xcE8dAc13593a359d961F91c35F8694cb2A03D005`
(salt `keccak256("QUIP:Create3Factory:V1.0")`, creation-code hash
`0xbe6eb1cac061b12187ed962ba44e19142929386dd027feee67ed5ea587777f05`).

### SHRINCS verifiers

| Field | 256s | 128s-q18 | 128s-q20 |
|---|---|---|---|
| Contract | `SHRINCS256sKeccak` | `SHRINCS128sQ18Keccak` | `SHRINCS128sQ20Keccak` |
| Build profile | `production` | `production-128s-q18` | `production-128s-q20` |
| CREATE3 salt string | `QUIP:SHRINCS256sKeccak:V1.0` | `QUIP:SHRINCS128sQ18Keccak:V1.0` | `QUIP:SHRINCS128sQ20Keccak:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | same | same |
| Predicted address | `0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A` | `0x1bcb84Bd8BcB0038Ad601405e693c2B326b0967a` | `0x48ccFf174F6e5CdabD1e0CC0f769068E3E806816` |
| Stateless delegate | `SPHINCSPlusC256sKeccak` (below) | `SPHINCSPlusC128sQ18Keccak` (below) | `SPHINCSPlusC128sQ20Keccak` (below) |
| Runtime codehash | *(capture on first deploy)* | *(capture on first deploy)* | *(capture on first deploy)* |
| Chains deployed | *(none yet)* | *(none yet)* | *(none yet)* |

Each SHRINCS verifier's `verifyStateless` delegates to the pinned
SPHINCSPlusC sibling in the next table; deploy the sibling first (step 2).
The stateful `verify` path uses no sibling.

The 128s-q20 stateless budget (2^20) wants profile security-analysis
backing before production use; 128s-q18 is the conservative sibling.
The 128s verifiers verify against the regenerated 128s vectors, which
land with the Rust-signer coordination (tracked as T6); don't treat a
128s deploy as production-ready until those vectors exist.

### SPHINCSPlusC verifiers

The stateless delegates. Each SHRINCS verifier pins its profile's sibling
address (its `SPHINCS_PLUS_C_VERIFIER` constant) and forwards stateless
verification to it. A SPHINCSPlusC verifier is also usable on its own as
a bare ERC-7913 stateless verifier: `key` is
`abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot)` and the signature
envelope is `abi.encode(StatelessSignature)`, with no commitment logic.

| Field | 256s | 128s-q18 | 128s-q20 |
|---|---|---|---|
| Contract | `SPHINCSPlusC256sKeccak` | `SPHINCSPlusC128sQ18Keccak` | `SPHINCSPlusC128sQ20Keccak` |
| Build profile | `production` | `production-128s-q18` | `production-128s-q20` |
| CREATE3 salt string | `QUIP:SPHINCSPlusC256sKeccak:V1.0` | `QUIP:SPHINCSPlusC128sQ18Keccak:V1.0` | `QUIP:SPHINCSPlusC128sQ20Keccak:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.sphincsplusc-verifier.v1")` | same | same |
| Predicted address | `0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A` | `0xBc7Fefc3D757Fa81E3C7d65905e32722b1a044A6` | `0x7C30ef553deE8F6DF59eE1FF4477f382607d330f` |
| Key format | `abi.encode(pkSeed, hypertreeRoot)` | same | same |
| Signature envelope | `abi.encode(StatelessSignature)` | same | same |
| Runtime codehash | *(capture on first deploy)* | *(capture on first deploy)* | *(capture on first deploy)* |
| Chains deployed | *(none yet)* | *(none yet)* | *(none yet)* |

### SHA-256 suite (256s-sha2)

The SHA-256 twin of the 256s profile: identical parameters, SHA-256 in
place of keccak-256 as the scheme hash. Its own CREATE3 salts and
addresses, served by the same shared factory (the metadata-stripped
factory creation code is suite-independent). Predicted addresses below are
derived and pinned by `test/SHRINCSPinned256sSha2.t.sol`. The 256s-sha2
stateless signature vector verifies end-to-end through the production
verifier (`SHRINCSSphincs256sSha2Vectors`); per-helper coverage is the
`HashSuiteKat` sha2 KATs. The in-Solidity test signers route their scheme
hashes through the hash-suite seam, so the sha2 leg also self-signs: the
keygen goldens are anchored to the Rust sha2 signer, and the stateful and
stateless produce-then-verify suites run under this profile. No bytes are
deployed yet — SHRINCS is testnet-only — so runtime codehashes are captured
on first deploy.

| Field | SHRINCS256sSha2 | SPHINCSPlusC256sSha2 |
|---|---|---|
| Build profile | `production-256s-sha2` | `production-256s-sha2` |
| CREATE3 salt string | `QUIP:SHRINCS256sSha2:V1.0` | `QUIP:SPHINCSPlusC256sSha2:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-sha2")` | `keccak256("shrincs-256s-sha2")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | `keccak256("quip.sphincsplusc-verifier.v1")` |
| Predicted address | `0x47C7041BcABc941764D59cb3e973e7e77a46b76f` | `0x4634950D028606e7E0db97FC3CEd91511DAdE6cb` |
| Stateless delegate | `SPHINCSPlusC256sSha2` (right) | — |
| Runtime codehash | *(capture on first deploy)* | *(capture on first deploy)* |
| Chains deployed | *(none yet)* | *(none yet)* |

### WOTS+ library

| Field | Value |
|---|---|
| Contract | `WOTSPlus` (library) |
| Build profile | `production` |
| CREATE3 salt string | `QUIP:WOTSPlus:V1.0` |
| Predicted address | `0xe440897Eb9Df111FA48b0d62f7093BDe9a5B5dC7` |
| Runtime codehash | *(capture on first deploy)* |
| Chains deployed | *(none yet)* |

WOTS+ is profile-independent (its parameters are its own constants, not
`SHRINCSParams`), so its bytecode and CREATE3 address are the same under
any build profile. Its salt and deploy script are unchanged; the
predicted address moved only because disabling solc metadata moved the
shared factory (see the top of this file), and every CREATE3 child
address is a function of that factory.

## Historical mechanisms (recorded, replaced)

These are the superseded names and mechanisms, kept for the record. None
had a canonical on-chain deployment.

### Pre-release SHRINCS names and predictions

Earlier drafts named the concrete verifiers `ShrincsVerifier256s`,
`ShrincsVerifier128sQ18`, and `ShrincsVerifier128sQ20`, salted them
`QUIP:ShrincsVerifier256s:V1.0` (and the q18/q20 forms), and predicted
their addresses through the pre-metadata-strip factory
`0xBF3af840d7523547C358976697E82f9Ebcb7a801`. None were deployed. They
are replaced by the `SHRINCS*Keccak` rows above — new names, new salts,
new factory, new addresses — plus the new `SPHINCSPlusC*Keccak` stateless
delegates.

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
CREATE3 removes that coupling, so the profile split adopts it. That
single verifier is now the abstract `SHRINCSVerifier` base
(contracts/SHRINCSVerifier.sol) of the concrete per-profile verifiers,
so this exact artifact is no longer deployable; the address above was
never used on any chain.

### WOTS+ — Hardhat Ignition

WOTS+ deployed through Hardhat Ignition (`ignition/modules/WOTSPlus.ts`,
`WOTSPlusModule`) with Ignition's default CREATE strategy: a plain
nonce-based deploy from the deployer account, with no CREATE2 salt and no
fixed factory. It produced no deterministic, chain-invariant address, and
no address was recorded. The Hardhat path is removed; WOTS+ now deploys
through the CREATE3 script above.
