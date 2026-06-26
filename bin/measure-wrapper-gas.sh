#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

forge test --match-contract ShrincsMeasurementsTest -vv \
  | {
    if command -v rg >/dev/null 2>&1; then
      rg 'canonical_wrapper_call_gas|erc1271_call_gas'
    else
      grep -E 'canonical_wrapper_call_gas|erc1271_call_gas'
    fi
  }
