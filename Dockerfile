# Reproducible build/test environment for the hashsigs-solidity contracts.
# Pinned Foundry toolchain (forge/cast/anvil) so workloads run identically
# regardless of host tooling. Driven via ./run.
FROM ghcr.io/foundry-rs/foundry:stable

WORKDIR /work
