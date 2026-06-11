# SHRINCS SPHINCS-256s Vector Generator

This Rust helper regenerates `../test_vectors/shrincs_sphincs_256s_keccak.json`.

Run it from the repository root:

```sh
cargo run --manifest-path test/shrincs_vector_generator/Cargo.toml -- test/test_vectors/shrincs_sphincs_256s_keccak.json
```

The generated fixture uses the default `sphincs-256s` parameters:

- `h = 64`
- `d = 8`
- subtree height `8`
- `a = 14`
- `k = 22`
- `N_BITS = 256`
- `WOTS_W = 16`
- `l = 64`
- `target_sum = 480`
