# Changelog

## Unreleased

### Added
- Compile-time profile selection. Per-profile `ShrincsParams` libraries
  under `contracts/profiles/<profile>/`, chosen by a `shrincs-profile/`
  Foundry remapping and re-exported as aliases in `ShrincsTypes`.
  Profiles: `256s` (default), `128s-q18`, `128s-q20`.
- `ShrincsUtils.maskHash` high-aligned hash truncation, applied at the
  nine hash-producing sites so a truncated profile emits high-aligned,
  zero-padded node values. All-ones (no-op) for 256s.
- `test/ShrincsProfileInvariants.t.sol`: structural invariants and a
  profile-identity guard that fails closed on a wrong-profile or
  `remappings.txt`-shadowed build. CI adds a `remappings.txt` guard and
  a build/lint/test matrix over the three profiles.
- Concrete per-profile verifiers `ShrincsVerifier256s`,
  `ShrincsVerifier128sQ18`, `ShrincsVerifier128sQ20`, each with a
  `PROFILE_TAG`. CREATE3 deploy scripts (per-profile salts) for the
  verifiers and WOTS+, plus `DEPLOYMENTS.md`.

### Changed
- `ShrincsVerifier` is now an abstract base; deploy one of the concrete
  per-profile subclasses. The ABI surface (`verify`, `VERSION_TAG`) is
  unchanged. No chain had a `ShrincsVerifier` deployment (pre-release).
- Deploys use CREATE3 (address depends only on factory + salt, not init
  code), replacing the CREATE2 verifier script and the Hardhat-Ignition
  WOTS+ deploy; both historical mechanisms are recorded in
  `DEPLOYMENTS.md`.

## 0.1.0 - 2026-07-10

### Added
- SHRINCS verifier library (`contracts/SHRINCS.sol`) with shared `ShrincsTypes` data model,
  pinned to the Sphincs256sKeccakQ20 profile with a 2^20 stateless-signature budget.
- Stateful verification path (`ShrincsStateful.sol`) and stateless recovery/rotation path.
- Example account wrapper (`contracts/examples/ShrincsAccountVerifierExample.sol`) with
  MonotonicIndex and RecoveryRotation policies and an ERC-1271 view adapter.
- ERC-7913 raw verifier surface (`ShrincsVerifier.sol`, `ShrincsCodec.sol`) with a
  CREATE2-deterministic deployment script and pinned `[profile.production]` solc 0.8.35.
- Test-only Solidity SHRINCS signer, SPHINCS+ cross-check vectors, and gas measurement tests.

### Changed
- `via_ir`, optimizer settings, and test-vector `fs_permissions` are now set in `foundry.toml`.
- `contracts/WOTSPlus.sol` reformatted to the repo coding standards; its
  `internal` helper functions were renamed for clarity (§7 internal-rename).
  The public API (`verify`, `verifyWithRandomizationElements`, `sign`,
  `generateKeyPair`, `generateRandomizationElements`, `chain`, and the public
  constants) is unchanged.

### Removed
- `ignition/modules/Lock.ts` sample Hardhat Ignition module.
