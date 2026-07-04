# ShrincsVerifier release registry

This repo OWNS the canonical ShrincsVerifier deployment (the EntryPoint/Multicall3
pattern): each release is deployed deterministically once per chain by
`script/DeployShrincsVerifier.s.sol`, and consumers (e.g. quip-swap-solidity) pin
the published `(address, runtime codehash)` pair below — they never deploy their
own copy and never derive these values from a local rebuild.

## How a release is produced

1. From the release commit, on EVERY target chain:
   `FOUNDRY_PROFILE=production forge script script/DeployShrincsVerifier.s.sol --rpc-url $RPC --private-key $DEPLOYER_PK --broadcast --verify`
   (the `production` profile pins solc + via-ir + optimizer runs — the CREATE2
   address is a function of the init code, so byte-identical builds are what make
   the address chain-invariant; the verifier has no constructor args and no
   immutables, so the runtime codehash is chain-invariant too).
2. Capture the codehash **from the canonical deployment** with
   `cast codehash <address> --rpc-url $RPC` — NEVER from a local rebuild (solc's
   appended metadata hash drifts with compiler version, settings, and paths).
3. Record the row below and cross-check `cast codehash` returns the same value on
   every listed chain.

A new verifier version is a NEW salt → new address → new row. Deployed artifacts
are immutable; nothing is ever upgraded in place.

## Releases

### v1 — stateful SHRINCS verifier (ERC-7913)

| Field | Value |
|---|---|
| Salt | `keccak256('QUIP:ShrincsVerifier:V1.0')` |
| `VERSION_TAG()` | `0x064b5b1b1f5d6dc3d38c8ed9f38fd24f68628329f9329a54b8e8c53e3b06da58` (`keccak256("quip.shrincs-verifier.v1")`) |
| CREATE2 factory | `0x4e59b44847b379578588920cA78FbF26c0B4956C` (canonical deterministic-deployment proxy) |
| Address | `0x560Ea50c83AB3952587fa3C7b9250c045cfA1252` ⚠️ pre-release prediction — see note |
| Runtime codehash | `0x8553890af0b7136ccf8993d2d691c492618150ee85f028892f285ccb6682a5ff` ⚠️ pre-release prediction — see note |
| Chains deployed | *(none yet)* |

> ⚠️ **Pre-release note (2026-07-04):** the address/codehash above were derived
> from a deterministic LOCAL REHEARSAL (anvil, `production` profile, solc 0.8.35,
> this commit) — they are what the canonical deploy WILL produce if run from this
> exact commit and profile through the canonical CREATE2 factory. On the first
> real per-chain deploy: run step 1, confirm the script lands on this address,
> capture the codehash per step 2, replace this note with the verified values, and
> fill in the chain list. Any drift means the build is not byte-identical to this
> commit — STOP and reconcile before publishing.
