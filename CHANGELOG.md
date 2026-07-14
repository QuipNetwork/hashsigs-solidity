# Changelog

## Unreleased

### Added
- Transient attestation registry on the SHRINCS ERC-7913 verifier
  (`IERC7913TransientAttestation`): `verifyAndAttest` runs the exact
  stateful `verify` path (shared `_verifyStateful`) and, on success,
  TSTOREs 1 at `keccak256(abi.encode(msg.sender, keccak256(key),
  hash))` — an ERC-7562 *associated* transient slot (address-first) so
  ERC-4337 accounts may attest during validation; `wasVerified(account,
  keyHash, hash)` TLOADs it. Nothing is written on failure; failure
  values and reverts mirror `verify`; the attestation clears when the
  transaction ends. The `view` `verify` is unchanged and never attests.
  Requires Cancun (EIP-1153); `verifyAndAttest` reverts under
  `staticcall` on a valid signature. Measured overhead vs `verify` is
  ~0.8k gas (test profile, warm).
- Compile-time profile selection. Per-profile `ShrincsParams` libraries
  under `contracts/profiles/<profile>/`, chosen by a `shrincs-profile/`
  Foundry remapping and re-exported as aliases in `ShrincsTypes`.
  Profiles: `256s` (default), `128s-q18`, `128s-q20`. The 256s
  production build stayed byte-identical to the pre-split verifier
  (metadata-stripped deployed bytecode compared before/after).
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

### Removed
- Hardhat: `hardhat.config.ts`, `ignition/`, `tsconfig.json`,
  `package-lock.json`, and the hardhat devDependencies. The project is
  Foundry-only; deploys go through the CREATE3 scripts.

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
