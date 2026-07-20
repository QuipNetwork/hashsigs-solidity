# Deployment registry

This repo owns the canonical deployments of the SHRINCS verifiers, their
SPHINCSPlusC stateless delegates, and the WOTS+ library. SHRINCS is
testnet-only. Consumers pin the published `(address, runtime codehash)`
pairs below; they never deploy their own copy and never derive these
values from a local rebuild.

All deploys use CREATE3 through the canonical CreateX singleton
(`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`,
github.com/pcaversaccio/createx; maintainer decisions: CREATE3
2026-07-10, CreateX as the deployer 2026-07-21). A CREATE3 child address
depends only on `(CreateX, salt)`, not on the child's init code, so a
recompile or a profile change doesn't move the address — and because
CreateX is pre-deployed at the same address on every supported chain,
nothing this repo compiles is address-load-bearing at all.

Salts: the deploy scripts pass their raw `keccak256("QUIP:...")` salts
to `deployCreate3`. CreateX guards a salt whose first 20 bytes are
neither the caller nor zero (every QUIP salt) to
`guardedSalt = keccak256(abi.encode(salt))` — its permissionless mode:
any funded account produces the same child address. All address
predictions (`DeployBase._addressOf`, the pin tests, the tables below)
apply the same guard, `_deploy` cross-checks the local derivation
against CreateX's `computeCreate3Address` before broadcasting, and
`test/CreateXCreate3.t.sol` anchors the math to a real on-chain CreateX
deployment.

Solc metadata is disabled for every build (`bytecode_hash = "none"`,
`cbor_metadata = false` in `foundry.toml`) so each artifact's runtime
codehash is chain- and source-path-invariant. No chain has a deployment
yet, so nothing is burned.

CreateX's permissionless mode is exactly that — permissionless: anyone
can call `deployCreate3` first with a documented salt and deploy
arbitrary code at the advertised address, permanently capturing it on a
chain (the CREATE3 proxy at the guarded salt is then occupied and cannot
be redeployed). This is a griefing vector, not a wrong-accept one, and
the tooling fails closed against it. Each deploy script pins its
artifact's expected runtime codehash (`RUNTIME_CODEHASH`);
`DeployBase._deploy` reverts if the target address is already occupied by
code whose hash differs from the pin — a squatted salt or a stale pin —
instead of skipping it as "already deployed", and it also asserts a fresh
deploy's codehash matches the pin. Consumers verify the published runtime
codehash below against the on-chain code and never trust a squatted
address.

Recovering a squatted (or otherwise burned) salt: bump the salt version
constant in the deploy script. A new salt is a new, unoccupied address,
exactly as a new artifact version already is; the old salt is abandoned.

## How a deploy is produced

1. Confirm CreateX exists on the target chain:
   `cast code 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed --rpc-url $RPC`
   must return code. It is an OP-stack genesis preinstall and deployed on
   100+ chains (deployments list in pcaversaccio/createx). The scripts
   cannot bootstrap it (`_requireCreateX` fails closed); on a chain that
   lacks it, first land CreateX at the same address via its published
   presigned deployment transactions (pcaversaccio/createx), then re-run.
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

### Regenerating a script's `RUNTIME_CODEHASH` pin

Each deploy script pins the expected runtime codehash of its artifact so
`_deploy` can fail closed on a squatted or drifted address (see above). The
deployables carry no immutables, so the pin equals `keccak256` of the
compiled runtime bytecode and is knowable before any deploy. Regenerate it
after any change to the artifact's source or its build settings, two ways:

1. Build the script's profile, then hash the artifact's deployed bytecode,
   e.g. for the 256s keccak verifier:

   ```bash
   FOUNDRY_PROFILE=production /opt/homebrew/bin/forge build
   cast keccak "$(jq -r .deployedBytecode.object \
       out/SHRINCS256sKeccak.sol/SHRINCS256sKeccak.json)"
   ```

   Use the profile's `out` dir (`out` for `production`,
   `out-128s-q18-prod`, `out-128s-q20-prod`, `out-256s-sha2-prod`).
2. Or read it from a deploy run: `_deploy` logs the value on the
   `runtime codehash (record in DEPLOYMENTS.md)` line (fresh deploy) or the
   `already occupied; runtime codehash` line (occupied address). Both are
   logged before the pin assert, so a first run with a placeholder pin
   still prints the value to record.

Copy the value into the script's `RUNTIME_CODEHASH` constant and the
matching registry row below.

## Current registry (CREATE3 via CreateX)

The `production` solc pin fixes each verifier's runtime codehash across
chains. The addresses below derive from the pinned salts through the
canonical CreateX singleton; they are chain-invariant and independent of
anything this repo compiles. No chain has a deployment yet. The runtime
codehashes below are the pinned `RUNTIME_CODEHASH` values from the deploy
scripts (keccak256 of each artifact's compiled runtime bytecode at this
commit); confirm each with `cast codehash <address>` on first deploy.

CREATE3 deployer (all rows): CreateX at
`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`. Each address is the
CREATE3 child of `(CreateX, guardedSalt)` where
`rawSalt = keccak256(saltString)` and
`guardedSalt = keccak256(abi.encode(rawSalt))` (CreateX's permissionless
salt guard). Both forms are recorded below so nobody re-derives them
wrongly: predict with the GUARDED salt
(`computeCreate3Address(guardedSalt)`), deploy with the RAW salt
(`deployCreate3(rawSalt, initCode)`).

| Salt string | Guarded salt | Address |
|---|---|---|
| `QUIP:SPHINCSPlusC256sKeccak:V1.0` | `0xf8c807b1f4f2bfa3549b25264873c7f7a79fcbebddc4b38a2a2f2df406e6a913` | `0x9b62Fd54D8a1EDF39EF07A13A20b2E453cB1D732` |
| `QUIP:SPHINCSPlusC128sQ18Keccak:V1.0` | `0xeb1249ea424db6d70e4857297db8a440e2942b295c6769bcb5581763e2bc5545` | `0xbA920B0e1ba05E9F909c43d1f0d6818F5ED2aEf6` |
| `QUIP:SPHINCSPlusC128sQ20Keccak:V1.0` | `0x58bdd8aa5e2e3b18a2bd5f5b790f43adff9bbd2943ef60692b7321d09e2a2dcb` | `0xfB8722b28d27F0272578e4FdaBf9619B9970c083` |
| `QUIP:SPHINCSPlusC256sSha2:V1.0` | `0x2a05ebda9cbb0a51ff6fc692600b6cd0c8dc59b1974c5ca5c6d23526074c86f8` | `0xa4eB2dEF6eE29C5cf337E9ff5712E95F400A6650` |
| `QUIP:SHRINCS256sKeccak:V1.0` | `0x0939717cfb5c4a8733d30f03f927530fa07b9533c20d62e376c0b078e135be9a` | `0x9154dA0BA19600C543a8c5ed1B1c44af415B5688` |
| `QUIP:SHRINCS128sQ18Keccak:V1.0` | `0x40adfebc3fe1c2e40e07808830fa746f0e66daff4074855a62846b382aac88ef` | `0x26a7D084e543F01Fe9233B152e942477D8c96E2a` |
| `QUIP:SHRINCS128sQ20Keccak:V1.0` | `0xab47405d20c88e450a97af5655e8de529be3477bdba3984a1352eaf59bc37640` | `0x8E7B1C5b206054Dd307Ad5Bdb0669e8Cc2dC2077` |
| `QUIP:SHRINCS256sSha2:V1.0` | `0x52611b3c711230e673773141103c1d1ba27397eaf76456d6a43582b6332c3d4a` | `0x94E02751D093c77687874f1F075B8151ef4721C8` |
| `QUIP:WOTSPlus:V1.0` | `0x93be132d2fb970301e56504dd46373fdf30bc28b21d5fcc5ee92e2a215ae2763` | `0xe8A4C40A2Ca198e1b787431382D025097864A5c6` |

### SHRINCS verifiers

| Field | 256s | 128s-q18 | 128s-q20 |
|---|---|---|---|
| Contract | `SHRINCS256sKeccak` | `SHRINCS128sQ18Keccak` | `SHRINCS128sQ20Keccak` |
| Build profile | `production` | `production-128s-q18` | `production-128s-q20` |
| CREATE3 salt string | `QUIP:SHRINCS256sKeccak:V1.0` | `QUIP:SHRINCS128sQ18Keccak:V1.0` | `QUIP:SHRINCS128sQ20Keccak:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | same | same |
| Predicted address | `0x9154dA0BA19600C543a8c5ed1B1c44af415B5688` | `0x26a7D084e543F01Fe9233B152e942477D8c96E2a` | `0x8E7B1C5b206054Dd307Ad5Bdb0669e8Cc2dC2077` |
| Stateless delegate | `SPHINCSPlusC256sKeccak` (below) | `SPHINCSPlusC128sQ18Keccak` (below) | `SPHINCSPlusC128sQ20Keccak` (below) |
| Runtime codehash | `0x82e5e0727823ed856db249d3d64484f6b4c53efe4b64bcbd7e104f537d79ec90` | `0x41de0f0626072b44e34db37bc4266c9e42705ce065ca6bb89eb9c16d44e4a606` | `0x5ab4bda8779521f2b4784e324d49a18602ade71bc0ba0b05a6e0d50d34496087` |
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
| Predicted address | `0x9b62Fd54D8a1EDF39EF07A13A20b2E453cB1D732` | `0xbA920B0e1ba05E9F909c43d1f0d6818F5ED2aEf6` | `0xfB8722b28d27F0272578e4FdaBf9619B9970c083` |
| Key format | `abi.encode(pkSeed, hypertreeRoot)` | same | same |
| Signature envelope | `abi.encode(StatelessSignature)` | same | same |
| Runtime codehash | `0x998bb84a9cf85aeca5dfaffd88edbe1d62aa5b7fac9d9229b0a437f5c9a91e70` | `0xf6ad5f990d817ed947a152e54135324a90aa1b3bd1104bcdc99a4ddb4cd866a3` | `0xb9dc1b3ddc6fe633051b27a67322c4a72536d1cd668c4332ec4f104a1518f2e4` |
| Chains deployed | *(none yet)* | *(none yet)* | *(none yet)* |

### SHA-256 suite (256s-sha2)

The SHA-256 twin of the 256s profile: identical parameters, SHA-256 in
place of keccak-256 as the scheme hash. Its own CREATE3 salts and
addresses, derived through the same CreateX singleton as every other
row. Predicted addresses below are
derived and pinned by `test/SHRINCSPinned256sSha2.t.sol`. The 256s-sha2
stateless signature vector verifies end-to-end through the production
verifier (`SHRINCSSphincs256sSha2Vectors`); per-helper coverage is the
`HashSuiteKat` sha2 KATs. The in-Solidity test signers route their scheme
hashes through the hash-suite seam, so the sha2 leg also self-signs: the
keygen goldens are anchored to the Rust sha2 signer, and the stateful and
stateless produce-then-verify suites run under this profile. No bytes are
deployed yet — SHRINCS is testnet-only — so the runtime codehashes below
are the pinned `RUNTIME_CODEHASH` predictions at this commit, confirmed on
first deploy.

| Field | SHRINCS256sSha2 | SPHINCSPlusC256sSha2 |
|---|---|---|
| Build profile | `production-256s-sha2` | `production-256s-sha2` |
| CREATE3 salt string | `QUIP:SHRINCS256sSha2:V1.0` | `QUIP:SPHINCSPlusC256sSha2:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-sha2")` | `keccak256("shrincs-256s-sha2")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | `keccak256("quip.sphincsplusc-verifier.v1")` |
| Predicted address | `0x94E02751D093c77687874f1F075B8151ef4721C8` | `0xa4eB2dEF6eE29C5cf337E9ff5712E95F400A6650` |
| Stateless delegate | `SPHINCSPlusC256sSha2` (right) | — |
| Runtime codehash | `0x7ef9a4bd76dbe9a23a139abef8169c41dd898da60629cb61a421f511a45831ab` | `0x6f609f9d426a1d54c6f578ecb8518185c2623574829a3abeb4998352ed2ca9bd` |
| Chains deployed | *(none yet)* | *(none yet)* |

### WOTS+ library

| Field | Value |
|---|---|
| Contract | `WOTSPlus` (library) |
| Build profile | `production` |
| CREATE3 salt string | `QUIP:WOTSPlus:V1.0` |
| Predicted address | `0xe8A4C40A2Ca198e1b787431382D025097864A5c6` |
| Runtime codehash | `0x0efb1b18e06862b6b16d6b9fdb0563c5ceaf435af928034cbdb94af18ae2e683` |
| Chains deployed | *(none yet)* |

WOTS+ is profile-independent (its parameters are its own constants, not
`SHRINCSParams`), so its bytecode and CREATE3 address are the same under
any build profile. Its salt and deploy script are unchanged; the
predicted address moved only because the CREATE3 deployer changed to
CreateX (see the top of this file), and every CREATE3 child address is a
function of its deployer.

## Historical mechanisms (recorded, replaced)

These are the superseded names and mechanisms, kept for the record. None
had a canonical on-chain deployment.

### Own Create3Factory (CREATE2-proxy-bootstrapped)

Before CreateX, the scripts deployed a repo-owned `Create3Factory`
through the canonical CREATE2 proxy
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt
`keccak256("QUIP:Create3Factory:V1.0")`), predicted at
`0xcE8dAc13593a359d961F91c35F8694cb2A03D005` with production
creation-code hash
`0xbe6eb1cac061b12187ed962ba44e19142929386dd027feee67ed5ea587777f05`,
and every artifact was that factory's CREATE3 child (raw salt, no
guard). The factory address depended on the factory's own compiled
creation code, which made metadata stripping and cross-profile bytecode
identity address-load-bearing and required pinning the factory init-code
hash against source drift (the removed `test/Create3FactoryDrift.t.sol`).
CreateX removes that coupling: the deployer is pre-deployed, so no
compiled artifact influences any address. Same raw salt strings, new
deployer and salt guard, new child addresses (rows above). No chain ever
had a deployment through this factory.

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
