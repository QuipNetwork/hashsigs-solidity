# Changelog

## Unreleased

Package version is 0.4.0. The stateless verifier signature format
changes incompatibly, a breaking change under CODINGSTANDARDS section 7.
The pre-1.0 minor version advances from 0.3.0.

### Changed
- Breaking: `SHRINCSVerifier.verifyStateless` and
  `SPHINCSPlusCVerifier.verify` now take the fixed-layout stateless
  signature instead of the ABI envelope (QUI-1328). The ABI envelope was
  91,680 bytes on 256s and exceeded the WalletConnect relay payload cap.
  The fixed layout is 29,256 bytes on 256s (`PK || PQ`) and 29,092 bytes
  for the SPHINCSPlusC signature (`PQ`). `contracts/StatelessLayout.sol`
  defines it and every size derives from `SHRINCSParams`. See
  `docs/compact-stateless-encoding.md`.
- Revert model on both stateless entry points: a wrong signature
  length, a malformed key, or a failed check returns `0xffffffff`. Only
  out-of-gas reverts, and `verifyStateless` still reverts on an
  undeployed sibling. The ABI envelope's framing malleability, including
  the masked-profile tail truncation, is gone.
- `SHRINCS.prepareStatelessDelegation` takes the fixed-layout payload
  and returns `(ok, pkSeed, hypertreeRoot, signature)` with the PQ section
  as a calldata slice.
- `VERSION_TAG` is `quip.shrincs-verifier.v5` and
  `quip.sphincsplusc-verifier.v4`. Runtime codehash pins for the four
  256s verifiers changed (deploy scripts and `DEPLOYMENTS.md`). CREATE3
  salts and addresses did not change; no V3/V4 address is deployed.
- Measured on 256s keccak with forge 1.7.1, the version CI pins: the
  `stateless.verify_stateless_delegation_gas` measurement fell from
  1,660,710 to 1,453,718 gas. That is execution only. Including the base
  transaction and calldata cost, it fell from 2,433,134 to 1,945,126 gas
  (forge 1.8.1, which isolates calls by default).
  Production runtime is 4,685 bytes (SHRINCS)
  and 3,720 bytes (SPHINCSPlusC), from 4,581 and 4,148.

- Breaking: the `SHRINCS` library stateless functions
  (`verifyStateless`, `rotateStatefulViaStateless`, `statelessRotate`,
  `verifyStatelessUncheckedMessage`) take the fixed-layout signature as
  `bytes calldata`. The example wallet's `verifyStatelessAction`,
  `rotateToFreshKey`, and `rotateFullKey` follow, and its stateless
  ERC-1271 action envelope carries the signature as a trailing `bytes`
  field. `SHRINCS.statelessActionEnvelope` re-tags that field in place
  with the same unvalidated safety story as `statefulActionEnvelope`.
- `SPHINCSPlusC.verify`, `FORSMinusC.verifyForsCAndReturnRoot` and
  `forsEntryRoot32`, and `Hypertree.verifyHypertree` read the fixed
  layout.
- Breaking: `Hypertree.verifyWotsC32` and `hypertreeRootFromPath32` are
  now `private` (`_verifyWotsC32`, `_hypertreeRootFromPath32`). They rely
  on `verifyHypertree`'s length check and do not check lengths themselves.
  See `DECISIONS_REQUIRED.md`.

### Added
- Golden vectors `test/test_vectors/stateless-compact-256s.json` for
  the SDK encoder. Test-only struct types
  `test/helpers/StatelessSignatureTypes.sol` and encoders
  `SHRINCSTestCodec.encodeCompactPayload` and `encodeCompactSignature`.

### Removed
- Every struct-typed stateless type and code path:
  `SPHINCSPlusC.Signature`, `FORSMinusC.ForsSignature` and `ForsEntry`,
  `Hypertree.HypertreeLayerSignature`, `WOTSPlusC.WotsCSignature`, the
  struct-typed FORS-C and hypertree loops, `SHRINCS.statelessEnvelope`,
  `SHRINCS.sliceStatelessSignatureEnvelope` and its
  `InvalidStatelessSignatureSlice` error, and
  `SPHINCSPlusC.signatureEnvelope`, `statelessSignatureEnvelope`, and
  `encodeStatelessSignatureEnvelope`.
- Tests that covered only removed code: `Issue10SliceBounds`,
  `Issue11SliceAlignment`, `SHRINCSStatelessSliceCopy`, the struct
  hypertree-path cases in `Issue05HelperValidation`, and the stateless and
  signature-only ABI re-tag cases in `SHRINCSCalldataRetag`.

## 0.3.0 - 2026-10-31

Package version is 0.3.0. Removing public library functions is a
breaking change under CODINGSTANDARDS section 7. The pre-1.0 minor
version advances from 0.2.0.

### Added
- Transient attestation on the SHRINCS ERC-7913 verifier
  (`IERC7913TransientAttestation`). `verifyAndAttest` runs the same
  stateful path as `verify` (shared `_verifyStateful`). On success it
  writes 1 to the ERC-7562 associated transient slot
  `keccak256(abi.encode(msg.sender, keccak256(key), hash))`.
  `wasVerified(account, keyHash, hash)` reads that slot. Nothing is
  written on failure. Failure values and reverts match `verify`. The
  attestation clears when the transaction ends. The `view` `verify`
  never attests. Callers need Cancun (EIP-1153). `verifyAndAttest`
  reverts under `staticcall` on a valid signature. Measured overhead
  versus `verify` is about 0.8k gas on the test profile (warm).
- Compile-time profile selection. Per-profile `SHRINCSParams` libraries
  live under `contracts/profiles/<profile>/`. A `shrincs-profile/`
  Foundry remapping selects the active library. Profiles: 256s (default
  keccak), 128s-q18, 128s-q20, and 256s-sha2. The 256s keccak production
  build stayed byte-identical to the pre-split verifier
  (metadata-stripped deployed bytecode compared before and after).
- `Hash.maskHash` high-aligned hash truncation at the eight
  hash-producing sites in each hash suite. A truncated profile emits
  high-aligned, zero-padded node values. The mask is all-ones (no-op)
  for the 256s keccak profile.
- `test/SHRINCSProfileInvariants.t.sol`: structural invariants and a
  profile-identity guard that fails closed on a wrong-profile or
  `remappings.txt`-shadowed build. CI adds a `remappings.txt` guard and
  a build, lint, and test matrix over the four profiles.
- Concrete per-profile verifiers `SHRINCS256sKeccak`,
  `SHRINCS128sQ18Keccak`, `SHRINCS128sQ20Keccak`, `SHRINCS256sSha2`,
  and the matching SPHINCSPlusC siblings, each with a `PROFILE_TAG`.
  CREATE3 deploy scripts (per-profile salts) for the verifiers and
  WOTS+, plus `DEPLOYMENTS.md`.

### Changed
- Deploys use CREATE3 through CreateX permissioned (sender-scoped) salt
  mode. A CREATE3 child address depends only on factory and salt, not
  init code. This replaces the CREATE2 verifier script, the
  Hardhat-Ignition WOTS+ deploy, and the earlier permissionless CREATE3
  salts. Those older mechanisms stay recorded in `DEPLOYMENTS.md`.
  Each raw salt is `[20B DEPLOYER][0x00][11B of
  keccak256("QUIP:<label>")]`. CreateX guards that salt to
  `keccak256(abi.encode(DEPLOYER, salt))`. Only
  `0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26` can deploy at an
  advertised address. The `0x00` flag byte keeps addresses
  chain-invariant. `script/CreateXSalt.sol` holds the layout, the guard,
  and the derivation. `DeployBase._deploy` asserts the broadcaster is
  the canonical deployer and that the salt is well-formed. CreateX
  itself does not revert on either check. It deploys elsewhere instead.
  All nine advertised addresses move. The four SHRINCS runtime
  codehashes move with them, because each embeds its sibling address.
  The four SPHINCSPlusC codehashes and the WOTS+ codehash stay the same.
  Salt labels stay the same. `DEPLOYMENTS.md` now keys its registry on
  the raw salt and records the superseded Base Sepolia and OP Sepolia
  deploys made under the old scheme. Deploys require an explicit
  `--sender` and must not use `--resume` or `--skip-simulation`.
- `SHRINCSVerifier` is now an abstract base. Deploy one of the concrete
  per-profile subclasses. The ERC-7913 function ABI (`verify`) stays
  the same. `VERSION_TAG` remains a public constant. Its value changed
  (see below).
- Hash-construction wire format is incompatible with 0.1.0 signatures.
  `fors-digest` now binds `PROFILE_ID` after the domain tag. WOTS-C and
  FORS-C compression preimages now bind a 32-byte ADRS word. The SHRINCS
  ERC-7913 raw adapters now bind the 32-byte message hash to the
  installed bundle commitment (`statefulRawMessageHash` and
  `statelessRawMessageHash`). A 0.1.0 signature does not verify under
  this code.
- `SHRINCSVerifier.VERSION_TAG` is now
  `keccak256("quip.shrincs-verifier.v4")`. The 0.1.0 value was
  `keccak256("quip.shrincs-verifier.v1")`. v2 binds `PROFILE_ID` in
  `fors-digest`. v3 binds ADRS words in compression preimages. v4
  binds the raw ERC-7913 message to the bundle commitment.
  `SPHINCSPlusCVerifier.VERSION_TAG` is now
  `keccak256("quip.sphincsplusc-verifier.v3")`. The initial value was
  `keccak256("quip.sphincsplusc-verifier.v1")`. SPHINCSPlusCVerifier
  did not exist at 0.1.0. That tag follows the same v2 and v3
  hash-construction bumps. It does not bump to v4. The
  bundle-commitment binding lives only on the SHRINCS adapter path.
  `SPHINCSPlusCVerifier` still verifies the caller-supplied 32-byte
  hash.

### Removed
- Hardhat: `hardhat.config.ts`, `ignition/`, `tsconfig.json`,
  `package-lock.json`, and the hardhat devDependencies. The project is
  Foundry-only. Deploys go through the CREATE3 scripts.
- Production library functions `WOTSPlus.sign`,
  `WOTSPlus.generateKeyPair`, `Hash.addressWord32`,
  `SHRINCS.encodeStatefulEnvelope`, and
  `SHRINCS.encodeStatelessEnvelope`. Test-only replacements live in
  `test/helpers/WOTSPlusTestSigner.sol` (`sign`, `generateKeyPair`) and
  `test/helpers/SHRINCSTestCodec.sol` (`encodeStatefulEnvelope`,
  `encodeStatelessEnvelope`, `addressWord32`).

## 0.1.0 - 2026-07-10

### Added
- SHRINCS verifier library (`contracts/SHRINCS.sol`) with shared
  `ShrincsTypes` data model, pinned to a SPHINCS+-256s-style keccak-256
  parameter set (`h = 64`, `d = 8`, `a = 14`, `k = 22`) with a 2^20
  stateless-signature budget.
- Stateful verification path (`ShrincsStateful.sol`) and stateless
  recovery/rotation path (`ShrincsForsC.sol`, `ShrincsHypertree.sol`).
- Example account wrapper
  (`contracts/examples/ShrincsAccountVerifierExample.sol`) with
  MonotonicIndex, RecoveryRotation, and LeafBitmap policies and an
  ERC-1271 view adapter.
- ERC-1271 envelope canonicity validation: stateful envelopes must
  re-encode to their exact input bytes; stateless envelopes are checked
  by a structural calldata walk
  (`contracts/examples/ShrincsAccountEnvelope.sol`) pinned against the
  re-encode reference by differential fuzz tests.
- ERC-7913 raw verifier surface (`ShrincsVerifier.sol`,
  `ShrincsCodec.sol`) with a CREATE2-deterministic deployment script
  and pinned `[profile.production]` solc 0.8.35.
- Test-only Solidity SHRINCS signer, SPHINCS+ cross-check vectors, gas
  measurement tests, and account-vector export tooling
  (`dev/export-account-vectors.sh`).
- `CODINGSTANDARDS.md`, the repo-local `solidity-standards` Claude Code
  skill, and `scripts/check-line-length.sh`; GitLab CI runs the four
  standards gates (format, lint-on-build, hard line cap, tests).

### Changed
- `via_ir`, optimizer settings, test-vector `fs_permissions`, and the
  78-char `forge fmt` width are now set in `foundry.toml`.
- `contracts/WOTSPlus.sol` reformatted to the repo coding standards; its
  `internal` helper functions were renamed for clarity (§7
  internal-rename). The public API (`verify`,
  `verifyWithRandomizationElements`, `sign`, `generateKeyPair`,
  `generateRandomizationElements`, `chain`, and the public constants)
  is unchanged.

### Removed
- `ignition/modules/Lock.ts` sample Hardhat Ignition module.
