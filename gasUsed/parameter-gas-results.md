# SHRINCS Parameter Gas Results

Measured from `parameter-gas` with `node gasUsed/receiptGas.js` against local Anvil.

## SPHINCS+-256s-shaped baseline

Parameters:

- `n = 32`
- `h = 64`
- `d = 8`
- `b = 14`
- `k = 22`
- `w = 16`

Receipt gas:

- `stateless account verifyStatelessAction`: `2,804,000`
- `stateless SHRINCS.verifyStateless`: `2,711,759`
- `stateless SHRINCS.verifyStatelessUncheckedMessage`: `2,710,144`

## SPHINCS+-256s-q20-shaped stateless

Parameters:

- `n = 32`
- `h = 19`
- `d = 1`
- `b = 21`
- `k = 14`
- `w = 16`

Receipt gas:

- `stateless account verifyStatelessAction`: `902,036`
- `stateless SHRINCS.verifyStateless`: `861,099`
- `stateless SHRINCS.verifyStatelessUncheckedMessage`: `859,521`

The q20 measurement uses the sibling Rust checkout on `test_gas_reduction` for q20 vector generation, with tree material cached at `gasUsed/.shrincs-tree-cache`.

## SPHINCS+-128s-q20-shaped stateful and stateless

Parameters:

- `n = 16`
- `h = 18`
- `d = 1`
- `b = 24`
- `k = 6`
- `w = 16`

Receipt gas:

- `stateful account verifyStatefulAction`: `236,048`
- `stateful SHRINCS.verifyStateful`: `202,166`
- `stateful SHRINCS.verifyStatefulUncheckedMessage`: `200,594`
- `stateless account verifyStatelessAction`: `441,969`
- `stateless SHRINCS.verifyStateless`: `408,247`
- `stateless SHRINCS.verifyStatelessUncheckedMessage`: `406,738`

The 128s-q20 measurement uses true `HASH_LEN = 16`, dynamic hash-width stateful fields, and branch-local cached calldata at `gasUsed/.vector-cache/128s-q20-shrincs-measurements-v3`.
