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

## V1 to V2 signature migration

V2 changes the FORS digest to bind the compiled profile identifier. A V1
stateless signature is therefore intentionally invalid under a V2 verifier,
and a V2 stateless signature is intentionally invalid under a V1 verifier.
Stateful signature mathematics is unchanged, but integrations should use the
verifier version tag and address as the authoritative protocol identity rather
than assuming compatibility from the profile name alone.

Before switching an account or recovery flow to V2:

1. Upgrade every signer to a Rust build containing the profile-bound FORS
digest and regenerate any queued, cached, or pre-authorized stateless
signatures.
2. Deploy the matching V2 SPHINCSPlusC sibling first, verify its runtime
codehash, then deploy the V2 SHRINCS verifier that pins it.
3. Update verifier allowlists/registries to the V2 address and require the V2
`VERSION_TAG`. Keep a separately labelled V1 verifier only while legacy
signatures still need verification.
4. Exercise recovery and stateless rotation end to end before retiring V1.
Never route a V1 signature to V2, or a V2 signature to V1; retrying cannot make
those signatures valid.

## Current registry (CREATE3 via CreateX)

The `production` solc pin fixes each verifier's runtime codehash across
chains. The addresses below derive from the pinned salts through the
canonical CreateX singleton; they are chain-invariant and independent of
anything this repo compiles. The runtime codehashes below are the pinned
`RUNTIME_CODEHASH` values from the deploy scripts (keccak256 of each
artifact's compiled runtime bytecode at this commit); confirm each with
`cast codehash <address>` on first deploy. Base mainnet currently has only the historical V1 256s-keccak pair recorded
below; no V2 verifier is live. All eight V2 verifier addresses are currently
undeployed.

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
| `QUIP:SPHINCSPlusC256sKeccak:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26008fab73914675dd06dd5c26` | `0xb84e7391fd0abeaf34ab294f392152fb4d3be8fac708c5fe8e098ad98f900206` |
| `QUIP:SPHINCSPlusC128sQ18Keccak:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26003f16e25dc83414a291bf60` | `0x6297c889d4c09ea675e4c9f41e287f34c2ab974b64d909291adb2766f4c09421` |
| `QUIP:SPHINCSPlusC128sQ20Keccak:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a2600ba927d29ca7ad9c4b736cf` | `0xaf794fd7ca6bcd7b7dc439bd51da0600639420ea703d34877fed61c25c1b5551` |
| `QUIP:SPHINCSPlusC256sSha2:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26000164dffc9f1057e03308fa` | `0x05c8a826fa1073f9f514686172e8624c87da1c2e08125f3283f2e83960d7f767` |
| `QUIP:SHRINCS256sKeccak:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26006da0942490e15e10effd64` | `0xb01dbde9c09a8b828b15e49874765badc36eff41e51be734679fbc0907cd2784` |
| `QUIP:SHRINCS128sQ18Keccak:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a260024538a70f3120fe15c56ef` | `0x8411a603b3b36acf7c9be2fe61851dd9856cb2618a0bcbd4ee38dc3228200bf0` |
| `QUIP:SHRINCS128sQ20Keccak:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a2600eba9a74c56498197b7bf55` | `0xe33e5dbac44637fb67d99a719ffa5c2303d3596c2fcd57944612722b89283829` |
| `QUIP:SHRINCS256sSha2:V2.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a260022739ec9ea90a95c66ee69` | `0xdf9118b99bc05a38f1acb9ad46a83c1c7fdc309d726fdc543a17e288f17fe404` |
| `QUIP:WOTSPlus:V1.0` | `0xc68b64770da7914deb0ef238b048a0bf3b5f6a26006a0bc5ee9251a176011a94` | `0x6dec99ce43a5bbb090010ff191badca24996ac21dd07edd7a25770a1cda2a0a6` |

| Label | Address |
|---|---|
| `QUIP:SPHINCSPlusC256sKeccak:V2.0` | `0x9aA24A7FFA5476765a3eea18E7d42dB637c67715` |
| `QUIP:SPHINCSPlusC128sQ18Keccak:V2.0` | `0x55DE18D3dab9eaCdd75Dc4ce53E1EbBd1c4331B8` |
| `QUIP:SPHINCSPlusC128sQ20Keccak:V2.0` | `0xa78ECdac7BA78E99a6865eE61c808497bdc7Ae3b` |
| `QUIP:SPHINCSPlusC256sSha2:V2.0` | `0xAa504387af27bEF16544Cc7e465271D5f8C8c8ee` |
| `QUIP:SHRINCS256sKeccak:V2.0` | `0x2274a20acD927b24FC130e5673F010c2846F90cb` |
| `QUIP:SHRINCS128sQ18Keccak:V2.0` | `0xCfDbbe2eA27ab6A37E442fe7027e3D4eD8686260` |
| `QUIP:SHRINCS128sQ20Keccak:V2.0` | `0xdC836F601A4efB46b8B50874C065dEFfc8a7149B` |
| `QUIP:SHRINCS256sSha2:V2.0` | `0x7eB0CB2c257715DCe91c750f308a398d17511cd5` |
| `QUIP:WOTSPlus:V1.0` | `0xef0CbdEC1ed6Db29F44030Bc22e4BD1D19898208` |

These nine addresses are pinned in
`test/CreateXSaltInvariants.t.sol::testAdvertisedAddressesMatchRegistry`,
so a drift between this table and the code fails CI.

An address here is determined by its salt whether or not code exists at it
yet — that is what CREATE3 buys. The per-artifact tables below therefore
list the address unconditionally, and the `Chains deployed` row is what
says where bytes actually are.

### Historical V1 deployed transactions

These immutable V1 deployments remain on-chain for legacy verification. Their code hashes matched the V1 pins
in each deploy script. Deployed by
`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26` through CreateX's permissioned
mode, so these addresses were reachable by no other account.

| Chain | Artifact | Address | Tx | Block | Gas |
|---|---|---|---|---|---|
| Base mainnet (8453) | `SPHINCSPlusC256sKeccak` | `0x97B3726F44e3B7521199CE4e0fC160A32A597d31` | `0xb92149af0104c0858659297878c090c2b13bd6510a5c1ffe3049d6c294b7e0e3` | 49480565 | 937,092 |
| Base mainnet (8453) | `SHRINCS256sKeccak` | `0xE6F2970bA30d59e8288b7007bA755828372457c3` | `0x2bceb96406945f000688be44f95a75ef8f740bce8aeec9e060aa852bdd2c4b28` | 49480603 | 980,942 |

The V1 delegate was deployed first, as required: `SHRINCS256sKeccak` forwards
stateless verification to it and reverts on empty code, and its deploy
script asserts the sibling is present before broadcasting.

### SHRINCS verifiers

| Field | 256s | 128s-q18 | 128s-q20 |
|---|---|---|---|
| Contract | `SHRINCS256sKeccak` | `SHRINCS128sQ18Keccak` | `SHRINCS128sQ20Keccak` |
| Build profile | `production` | `production-128s-q18` | `production-128s-q20` |
| CREATE3 salt label | `QUIP:SHRINCS256sKeccak:V2.0` | `QUIP:SHRINCS128sQ18Keccak:V2.0` | `QUIP:SHRINCS128sQ20Keccak:V2.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v2")` | same | same |
| Address | `0x2274a20acD927b24FC130e5673F010c2846F90cb` | `0xCfDbbe2eA27ab6A37E442fe7027e3D4eD8686260` | `0xdC836F601A4efB46b8B50874C065dEFfc8a7149B` |
| Stateless delegate | `SPHINCSPlusC256sKeccak` (below) | `SPHINCSPlusC128sQ18Keccak` (below) | `SPHINCSPlusC128sQ20Keccak` (below) |
| Runtime codehash | `0x7cf65cd72815deb21a5601047b7578f63366ca8087331e6cfdf4de014faab089` | `0xb5a93d4e8c2c198138022507c1967ac1657ae14ceb4bb18f55308c81da6ca0a9` | `0xb1ac645f62424942efadbc598e0579c4e029f90e77c51ab95f92927e2e0a30df` |
| Chains deployed | *(none yet)* | *(none yet)* | *(none yet)* |

Each SHRINCS verifier's `verifyStateless` delegates to the pinned
SPHINCSPlusC sibling in the next table; deploy the sibling first (step 2).
The stateful `verify` path uses no sibling.

The 128s-q20 stateless budget (2^20) wants profile security-analysis
backing before production use; 128s-q18 is the conservative sibling.
The 128s verifiers verify against regenerated, profile-bound Rust vectors, which
now exist; do not treat a
128s deploy as production-ready without running the profile matrix.

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
| CREATE3 salt label | `QUIP:SPHINCSPlusC256sKeccak:V2.0` | `QUIP:SPHINCSPlusC128sQ18Keccak:V2.0` | `QUIP:SPHINCSPlusC128sQ20Keccak:V2.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-keccak")` | `keccak256("shrincs-128s-q18-keccak")` | `keccak256("shrincs-128s-q20-keccak")` |
| `VERSION_TAG()` | `keccak256("quip.sphincsplusc-verifier.v2")` | same | same |
| Address | `0x9aA24A7FFA5476765a3eea18E7d42dB637c67715` | `0x55DE18D3dab9eaCdd75Dc4ce53E1EbBd1c4331B8` | `0xa78ECdac7BA78E99a6865eE61c808497bdc7Ae3b` |
| Key format | `abi.encode(pkSeed, hypertreeRoot)` | same | same |
| Signature envelope | `abi.encode(StatelessSignature)` | same | same |
| Runtime codehash | `0x19bef5459a4a8696b23a0c00449f5dbb5a4d65458a7c3474937507775b2ceca6` | `0xf1bb001ed74ecf528028cd290a82f8b7e816b8b875805f4f5168ef3802dfcacf` | `0x2c36eeed143cdb2175f293609e82623b1f2eb894b98f69101bb9a453ab11167b` |
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
deployed at these addresses yet, so the runtime codehashes below are the
pinned `RUNTIME_CODEHASH` predictions at this commit, confirmed on first
deploy.

| Field | SHRINCS256sSha2 | SPHINCSPlusC256sSha2 |
|---|---|---|
| Build profile | `production-256s-sha2` | `production-256s-sha2` |
| CREATE3 salt label | `QUIP:SHRINCS256sSha2:V2.0` | `QUIP:SPHINCSPlusC256sSha2:V2.0` |
| `PROFILE_TAG()` | `keccak256("shrincs-256s-sha2")` | `keccak256("shrincs-256s-sha2")` |
| `VERSION_TAG()` | `keccak256("quip.shrincs-verifier.v2")` | `keccak256("quip.sphincsplusc-verifier.v2")` |
| Address | `0x7eB0CB2c257715DCe91c750f308a398d17511cd5` | `0xAa504387af27bEF16544Cc7e465271D5f8C8c8ee` |
| Stateless delegate | `SPHINCSPlusC256sSha2` (right) | — |
| Runtime codehash | `0x64b5b22ae1cc4d8c3d901b70289f3093d14607269e9c5d5b9e97d3679763ec52` | `0xe0c51e6011b22501fa26ce9a326ad688eba3e5f46a26e4d4542beaddc3e0b52d` |
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

The codehashes above are the bytes actually deployed under the historical V1
semantics. They are intentionally different from the current V2 registry:
the profile-bound digest changed SPHINCSPlusC runtime bytecode, while the
SHRINCS runtime also changed and pins a different sibling address.

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
