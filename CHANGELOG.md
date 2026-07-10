# Changelog

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

### Removed
- Legacy WOTS+ and intermediate verifier fragments, replaced by the unified SHRINCS library.
