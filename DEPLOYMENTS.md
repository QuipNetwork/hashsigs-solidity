# Deployment registry

This repo owns the canonical deployments of the SHRINCS verifiers, their
SPHINCSPlusC stateless delegates, and the WOTS+ library. Consumers pin
the published `(address, runtime codehash)` pairs below; they never
deploy their own copy and never derive these values from a local
rebuild.

All deploys use CREATE3 through the canonical CreateX singleton
(`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`,
github.com/pcaversaccio/createx; maintainer decisions: CREATE3
2026-07-10, CreateX as the deployer 2026-07-21, permissioned
sender-scoped salts 2026-08-03). A CREATE3 child address depends only on
`(CreateX, guarded salt)`, not on the child's init code, so a recompile
or a profile change doesn't move the address — and because CreateX is
pre-deployed at the same address on every supported chain, nothing this
repo compiles is address-load-bearing.

## Salts: permissioned, sender-scoped

Every canonical salt is laid out the way CreateX's **permissioned** mode
requires:

```
[20 bytes DEPLOYER][1 byte 0x00 flag][11 bytes entropy]
 └ 0xc68B6477…6A26  └ no chain scoping └ leading 11 bytes of
                                          keccak256("QUIP:<label>")
```

Because the leading 20 bytes equal the caller, CreateX guards the salt to
`guardedSalt = keccak256(abi.encode(DEPLOYER, rawSalt))`. Two
consequences, and both are the point:

- **Only `DEPLOYER` can reach these addresses.** Anyone else calling
  `deployCreate3` with a published raw salt fails the sender match, so
  CreateX applies its *permissionless* guard instead and lands them at an
  unrelated address. Squatting is prevented, not merely detected.
- **The addresses are still identical on every chain.** The `0x00` flag
  byte keeps `block.chainid` out of the guard. (`0x01` would scope them
  per chain; `script/CreateXSalt.sol` rejects it.)

The canonical deployer is
**`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`**. This is
address-load-bearing and permanent: every address below is a function of
it, and losing its key makes those addresses permanently unreachable on
any chain not already deployed to.

`script/CreateXSalt.sol` is the single implementation of the layout, the
guard, and the derivation. All address predictions (`DeployBase`, the pin
tests, the tables below) go through it. Three things keep it honest:

- `_deploy` cross-checks the local derivation against CreateX's own
  `computeCreate3Address` before broadcasting;
- `test/CreateXCreate3.t.sol` anchors the guard-independent CREATE3
  proxy math to a real on-chain CreateX deployment, and — with
  `CREATEX_FORK_RPC_URL` set — anchors the **permissioned guard itself**
  against live CreateX bytecode, asserting both that `DEPLOYER` reaches
  the predicted address and that a non-deployer does not;
- `test/CreateXSaltInvariants.t.sol` pins the salt layout, the nine
  advertised addresses, and the squat closure, under every CI profile.

Solc metadata is disabled for every build (`bytecode_hash = "none"`,
`cbor_metadata = false` in `foundry.toml`) so each artifact's runtime
codehash is chain- and source-path-invariant.

### Why the codehash pin still exists

Each deploy script pins its artifact's expected runtime codehash
(`RUNTIME_CODEHASH`), and `DeployBase._deploy` reverts if the target
address is already occupied by code whose hash differs, instead of
skipping it as "already deployed". Under permissioned salts this is
defense in depth rather than the primary squat guard: it now catches a
stale pin, a drifted artifact, or a genuine re-run, and `_deploy` also
asserts a fresh deploy's codehash matches. Consumers still verify the
published codehash against the on-chain code.

### Deploy-time guards

`_deploy` fails closed on three things before it broadcasts:

| Check | Catches |
|---|---|
| `_requireProfile` | wrong `FOUNDRY_PROFILE` → wrong parameter set |
| `_requireBroadcaster` | wrong signer → CreateX would silently take its permissionless branch and deploy at a different, squattable address |
| `CreateXSalt.requireWellFormed` | stale/mistyped sender field, or a `0x01` flag byte that would silently break chain-invariance |

None of these revert inside CreateX itself, which is why they are
asserted locally. **Always pass an explicit `--sender` alongside
`--private-key`, and never use `--resume` or `--skip-simulation`** —
both bypass the script body and therefore these guards.

### Recovering a burned salt

Bump the salt version in the label (`:V1.0` → `:V1.1`). That changes the
11-byte entropy, hence the salt, hence the address. A new salt is a new,
unoccupied address, exactly as a new artifact version already is; the old
salt is abandoned. Squatting can no longer burn a salt, so this now
covers only our own mistakes (e.g. deploying a wrong artifact).

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

   The broadcaster MUST be the canonical deployer; pass it explicitly
   so the simulation pins the sender rather than inferring it:

   ```bash
   export DEPLOYER=0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26
   ```

   Confirm the permissioned guard against live CreateX first (no gas,
   no key needed) — this is the gate, not a formality:

   ```bash
   CREATEX_FORK_RPC_URL=$RPC forge test \
       --match-contract CreateXPermissionedGuardFork
   ```

   ```bash
   FOUNDRY_PROFILE=production forge script \
       script/DeploySPHINCSPlusC256sKeccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify

   FOUNDRY_PROFILE=production forge script \
       script/DeploySHRINCS256sKeccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q18 forge script \
       script/DeploySPHINCSPlusC128sQ18Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q18 forge script \
       script/DeploySHRINCS128sQ18Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q20 forge script \
       script/DeploySPHINCSPlusC128sQ20Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify

   FOUNDRY_PROFILE=production-128s-q20 forge script \
       script/DeploySHRINCS128sQ20Keccak.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify

   FOUNDRY_PROFILE=production forge script \
       script/DeployWOTSPlus.s.sol \
       --rpc-url $RPC --private-key $DEPLOYER_PK \
       --sender $DEPLOYER --broadcast --verify
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
`_deploy` can fail closed on a stale pin or a drifted artifact (see
above). The
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
anything this repo compiles. The runtime codehashes below are the pinned
`RUNTIME_CODEHASH` values from the deploy scripts (keccak256 of each
artifact's compiled runtime bytecode at this commit); confirm each with
`cast codehash <address>` on first deploy. The 256s keccak pair is live on
Base mainnet and confirmed against its pins (see Deployed transactions);
the other seven are not deployed anywhere yet.

CREATE3 deployer (all rows): CreateX at
`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`, called by
`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`. Each address is the CREATE3
child of `(CreateX, guardedSalt)` where the raw salt is
`[20B DEPLOYER][0x00][11B of keccak256(label)]` and
`guardedSalt = keccak256(abi.encode(DEPLOYER, rawSalt))` (CreateX's
permissioned salt guard). Rows are keyed on the **raw salt**, which is
the unambiguous identity — the label is an input to it, and the same
label produced different addresses under the superseded permissionless
scheme (see below). Predict with the GUARDED salt
(`computeCreate3Address(guardedSalt)`), deploy with the RAW salt
(`deployCreate3(rawSalt, initCode)`).

| Label | Raw salt | Guarded salt |
|---|---|---|
| `QUIP:SPHINCSPlusC256sKeccak:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a2600646ccb7479803c0f6dcd6b` | `0x970d41c1b7c30a8a3e9eff3ff6bbe4dd33b56b6775a6461ebea0d92da624235e` |
| `QUIP:SPHINCSPlusC128sQ18Keccak:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a2600c103b4836148f7cfd0915f` | `0x0f6f40632cf5d8667a0e713fc30e8052040e9829a9d89f93c2f6d3c6b42a2a19` |
| `QUIP:SPHINCSPlusC128sQ20Keccak:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a2600b2f54c4aed263fa5a0a4e2` | `0x845bc567f0b8ecc250aa34032ba7550733f09133332dc0c0325bcc9272c0ce8b` |
| `QUIP:SPHINCSPlusC256sSha2:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a2600f8cf84956b2af62074d56b` | `0x93147de612c33a3a0aec9c904a9a2a68d3c7a15e5d4b4de94718303d12108b75` |
| `QUIP:SHRINCS256sKeccak:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26004289c748f2bf48bb1ee562` | `0x3ddfd11b1a8c90adffb425027e36250fed0e33c6e1487355b34eb3a650de6639` |
| `QUIP:SHRINCS128sQ18Keccak:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26008d1935d25a649a1fb9a23a` | `0x246f7f27a5c3e6ed6a5737b0c47d830d2a7c1e43a39e554a70fcf5f82378b568` |
| `QUIP:SHRINCS128sQ20Keccak:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26005ecf2cbb0748f5a7c9b715` | `0xf54e1e7db76ab79776d17794ea406147bde1899ca999c55e44b706e4ac7bf23b` |
| `QUIP:SHRINCS256sSha2:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a260036f59a74cc43a5f8773947` | `0x24c2bd4f32652b992eb8749fb320954670fd1fe4c64a3bc0d51a934e85766bb5` |
| `QUIP:WOTSPlus:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26006a0bc5ee9251a176011a94` | `0x6dec99ce43a5bbb090010ff191badca24996ac21dd07edd7a25770a1cda2a0a6` |

| Label | Address |
|---|---|
| `QUIP:SPHINCSPlusC256sKeccak:V1.0` | `0x97B3726F44e3B7521199CE4e0fC160A32A597d31` |
| `QUIP:SPHINCSPlusC128sQ18Keccak:V1.0` | `0xF4f47272350af70D9735FDBf42d398D17470c2f0` |
| `QUIP:SPHINCSPlusC128sQ20Keccak:V1.0` | `0x0A218Bf4A264B00c89883b2A780478627a0C7E08` |
| `QUIP:SPHINCSPlusC256sSha2:V1.0` | `0x8F477848aC34523095F68f60C5d5eFa21a491fCA` |
| `QUIP:SHRINCS256sKeccak:V1.0` | `0xE6F2970bA30d59e8288b7007bA755828372457c3` |
| `QUIP:SHRINCS128sQ18Keccak:V1.0` | `0xDA52530D9027bea659d8458e1128a566B43C8c69` |
| `QUIP:SHRINCS128sQ20Keccak:V1.0` | `0x4f78F04b9C496749972afcb0ad5C114326De5086` |
| `QUIP:SHRINCS256sSha2:V1.0` | `0x31F7262Db25b5F16ddfA4A995FfB298386BB57D8` |
| `QUIP:WOTSPlus:V1.0` | `0xef0CbdEC1ed6Db29F44030Bc22e4BD1D19898208` |

These nine addresses are pinned in
`test/CreateXSaltInvariants.t.sol::testAdvertisedAddressesMatchRegistry`,
so a drift between this table and the code fails CI.

An address here is determined by its salt whether or not code exists at it
yet — that is what CREATE3 buys. The per-artifact tables below therefore
list the address unconditionally, and the `Chains deployed` row is what
says where bytes actually are.

### Deployed transactions

Confirmed on-chain, `cast codehash` matching the pinned `RUNTIME_CODEHASH`
in each deploy script. Deployed by
`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26` through CreateX's permissioned
mode, so these addresses were reachable by no other account.

| Chain | Artifact | Address | Tx | Block | Gas |
|---|---|---|---|---|---|
| Base mainnet (8453) | `SPHINCSPlusC256sKeccak` | `0x97B3726F44e3B7521199CE4e0fC160A32A597d31` | `0xb92149af0104c0858659297878c090c2b13bd6510a5c1ffe3049d6c294b7e0e3` | 49480565 | 937,092 |
| Base mainnet (8453) | `SHRINCS256sKeccak` | `0xE6F2970bA30d59e8288b7007bA755828372457c3` | `0x2bceb96406945f000688be44f95a75ef8f740bce8aeec9e060aa852bdd2c4b28` | 49480603 | 980,942 |

The delegate was deployed first, as required: `SHRINCS256sKeccak` forwards
stateless verification to it and reverts on empty code, and its deploy
script asserts the sibling is present before broadcasting.

### SHRINCS verifiers

| Field | 256s | 128s-q18 | 128s-q20 |
|---|---|---|---|
| Contract | `SHRINCS256sKeccak` | `SHRINCS128sQ18Keccak` | `SHRINCS128sQ20Keccak` |
| Build profile | `production` | `production-128s-q18` | `production-128s-q20` |
| CREATE3 salt label | `QUIP:SHRINCS256sKeccak:V1.0` | `QUIP:SHRINCS128sQ18Keccak:V1.0` | `QUIP:SHRINCS128sQ20Keccak:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | same | same |
| Address | `0xE6F2970bA30d59e8288b7007bA755828372457c3` | `0xDA52530D9027bea659d8458e1128a566B43C8c69` | `0x4f78F04b9C496749972afcb0ad5C114326De5086` |
| Stateless delegate | `SPHINCSPlusC256sKeccak` (below) | `SPHINCSPlusC128sQ18Keccak` (below) | `SPHINCSPlusC128sQ20Keccak` (below) |
| Runtime codehash | `0xc104068546743a66b687cf2f8d23cca22e14d793158993efa525dac7fc15f646` | `0xd9be437b3616cc77aeb66caf4edc44954ec4b2fae85df2e5c346bdc82060812d` | `0xc1af8915b7fadf95ad558e2992c40ae6ae2a87c1991a552ae5d2a79377da4e0d` |
| Chains deployed | Base mainnet (8453) | *(none yet)* | *(none yet)* |

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
| CREATE3 salt label | `QUIP:SPHINCSPlusC256sKeccak:V1.0` | `QUIP:SPHINCSPlusC128sQ18Keccak:V1.0` | `QUIP:SPHINCSPlusC128sQ20Keccak:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.sphincsplusc-verifier.v1")` | same | same |
| Address | `0x97B3726F44e3B7521199CE4e0fC160A32A597d31` | `0xF4f47272350af70D9735FDBf42d398D17470c2f0` | `0x0A218Bf4A264B00c89883b2A780478627a0C7E08` |
| Key format | `abi.encode(pkSeed, hypertreeRoot)` | same | same |
| Signature envelope | `abi.encode(StatelessSignature)` | same | same |
| Runtime codehash | `0x998bb84a9cf85aeca5dfaffd88edbe1d62aa5b7fac9d9229b0a437f5c9a91e70` | `0xf6ad5f990d817ed947a152e54135324a90aa1b3bd1104bcdc99a4ddb4cd866a3` | `0xb9dc1b3ddc6fe633051b27a67322c4a72536d1cd668c4332ec4f104a1518f2e4` |
| Chains deployed | Base mainnet (8453) | *(none yet)* | *(none yet)* |

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
deployed at these addresses yet, so the runtime codehashes below are the
pinned `RUNTIME_CODEHASH` predictions at this commit, confirmed on first
deploy.

| Field | SHRINCS256sSha2 | SPHINCSPlusC256sSha2 |
|---|---|---|
| Build profile | `production-256s-sha2` | `production-256s-sha2` |
| CREATE3 salt label | `QUIP:SHRINCS256sSha2:V1.0` | `QUIP:SPHINCSPlusC256sSha2:V1.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-sha2")` | `keccak256("shrincs-256s-sha2")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v1")` | `keccak256("quip.sphincsplusc-verifier.v1")` |
| Address | `0x31F7262Db25b5F16ddfA4A995FfB298386BB57D8` | `0x8F477848aC34523095F68f60C5d5eFa21a491fCA` |
| Stateless delegate | `SPHINCSPlusC256sSha2` (right) | — |
| Runtime codehash | `0x75a544f812cd75691e2ef8f132c6bf80ef5504e43750cb55cd05191e6c1cdbcd` | `0x6f609f9d426a1d54c6f578ecb8518185c2623574829a3abeb4998352ed2ca9bd` |
| Chains deployed | *(none yet)* | *(none yet)* |

### WOTS+ library

| Field | Value |
|---|---|
| Contract | `WOTSPlus` (library) |
| Build profile | `production` |
| CREATE3 salt label | `QUIP:WOTSPlus:V1.0` |
| Address | `0xef0CbdEC1ed6Db29F44030Bc22e4BD1D19898208` |
| Runtime codehash | `0x0efb1b18e06862b6b16d6b9fdb0563c5ceaf435af928034cbdb94af18ae2e683` |
| Chains deployed | *(none yet)* |

WOTS+ is profile-independent (its parameters are its own constants, not
`SHRINCSParams`), so its bytecode and CREATE3 address are the same under
any build profile. Its salt label and deploy script are unchanged; the
predicted address has moved twice for reasons outside its own source —
first when the CREATE3 deployer became CreateX, then when the salts
became sender-scoped (see the top of this file). Every CREATE3 child
address is a function of its deployer and its guarded salt.

## Superseded: permissionless-salt deployments

These are real, live deployments made under the previous permissionless
salt scheme (raw salt `keccak256("QUIP:<label>")`, guarded to
`keccak256(abi.encode(salt))`). The permissioned scheme moves every
address, so **these are abandoned**: they are recorded here so the same
label string cannot be mistaken for the same address, and so nobody reads
their on-chain presence as a current endorsement. They are not upgraded,
not referenced by the tables above, and receive no further deploys. The
bytecode at them is genuine (deployed by
`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`), it is simply superseded.

| Artifact | Address | Chains | Runtime codehash |
|---|---|---|---|
| `SPHINCSPlusC256sKeccak` | `0x9b62Fd54D8a1EDF39EF07A13A20b2E453cB1D732` | Base Sepolia (84532), OP Sepolia (11155420) | `0x998bb84a9cf85aeca5dfaffd88edbe1d62aa5b7fac9d9229b0a437f5c9a91e70` |
| `SHRINCS256sKeccak` | `0x9154dA0BA19600C543a8c5ed1B1c44af415B5688` | Base Sepolia (84532), OP Sepolia (11155420) | `0x82e5e0727823ed856db249d3d64484f6b4c53efe4b64bcbd7e104f537d79ec90` |

Deploy transactions:

| Chain | Artifact | Tx |
|---|---|---|
| Base Sepolia | `SPHINCSPlusC256sKeccak` | `0xe902f4ebaf147a674bef4e84eb28dcc78ad4454366e5f37813da21fec0382bf5` |
| Base Sepolia | `SHRINCS256sKeccak` | `0x15d9225e53a8b8a6b0c5fdbe65465db3595f9268398d15832460913a996bbf43` |
| OP Sepolia | `SPHINCSPlusC256sKeccak` | `0x5f562f0e4bff16431b8055917a7a7d6ef87a7e02926d034363d3bc3a1a7dc85c` |
| OP Sepolia | `SHRINCS256sKeccak` | `0x26a265eb03c4554876af9bc1f1a7cc2a328083528822b2b0ad8f216d8eb684b2` |

Note the codehashes above are the pre-change values: `SHRINCS256sKeccak`'s
runtime bytecode embeds its sibling's address, so moving the sibling moved
that artifact's codehash too. The `SPHINCSPlusC256sKeccak` codehash is
unchanged by the salt scheme (it embeds no address) and appears in both
this table and the current registry.

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
