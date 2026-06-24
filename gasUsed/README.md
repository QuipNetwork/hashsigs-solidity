# SHRINCS gasUsed harness

This folder measures successful SHRINCS verification `receipt.gasUsed` without modifying WOTS+ code.

Start Anvil, then run from `hashsigs-solidity`:

```sh
anvil
node gasUsed/receiptGas.js
```

The harness uses Foundry FFI to call `gasUsed/shrincs-gas-vector`, which depends on the sibling `../hashsigs-rs` checkout for key generation and signing. Make sure the Rust checkout is on a branch with SHRINCS parameters matching the Solidity branch being measured.

For audited-v2 Solidity, use the sibling Rust checkout on:

```sh
git -C ../hashsigs-rs switch remove-parameter-set-rust-on-mr2
```

For q20 Solidity parameters on `parameter-gas`, use the sibling Rust checkout on:

```sh
git -C ../hashsigs-rs switch test_gas_reduction
```

The q20 signer uses `gasUsed/.shrincs-tree-cache` for generated hypertree material. The receipt runner passes this path into the Rust vector helper automatically.

Measurements emitted:

- `receipt gas stateless account verifyStatelessAction success`
- `receipt gas stateless SHRINCS.verifyStateless success`
- `receipt gas stateless SHRINCS.verifyStatelessUncheckedMessage success`

The receipt measurement deploys fresh contracts to Anvil, sends real transactions with the generated SHRINCS calldata, and reads `receipt.gasUsed`.
