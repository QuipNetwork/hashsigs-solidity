---
name: solidity-standards
description: Use when writing, editing, or reviewing any Solidity
  (.sol) file in this repo (contracts/, test/), or when reviewing a
  Solidity diff or MR here. Covers the repo's 78-char line limit,
  source-document citations (WOTS+, RFC 8391, SPHINCS+, FIPS 205),
  paper-symbol naming, fail-closed verifiers, and assembly layout
  comments defined in CODINGSTANDARDS.md.
---

# Solidity Coding Standards (hashsigs-solidity)

`CODINGSTANDARDS.md` at the repo root is the source of truth.
**Read it first**; this skill is the workflow, not the rules. Each
checklist item points to the section that defines it. Open that
section rather than working from memory.

## Writing or editing Solidity

Apply while writing, then verify before presenting the change:

1. Line length: every line, comments included (§3).
2. Naming: `mixedCase` functions including `internal`/`private`;
   no single-letter or paper-symbol identifiers except loop `i`/`j`;
   math-derived names use the mapping notation (§2).
3. Citations: cite the source document for anything from the math;
   deliberate departures start `Deviates from [KEY ...]:` (§1).
4. Computed constants: derivation comment with formula and a Python
   one-liner reproducing the value (§4).
5. Verifiers fail closed: return false/zero, never revert;
   length-check `bytes` before assembly reads; a calldata read used
   only in a compare-against-constant/cursor may skip the check
   under the narrow framing-read exception with a fail-closed site
   comment (§5).
6. Assembly: buffer-layout comment above every block; free-memory
   pointer handled; tags noted (§6).
7. Lint suppressions: justification line then directive line, never
   a bare disable (§5).
8. No new commented-out code and no new `// DEBUG:` blocks (§4).
9. ABI stability: never rename `public` library functions or
   constants without a deliberate breaking-change decision (§7).

## Verification commands (all must pass)

`forge` on PATH may be an unrelated tool, so check `forge --version`
before you run anything. If the output does not name Foundry, call the
Foundry binary by its full path: `~/.foundry/bin/forge` after
`foundryup`, or `/opt/homebrew/bin/forge` after Homebrew. Builds and
tests require `via_ir`. The default `foundry.toml` profile already
sets it, so run the bare commands:

```bash
forge fmt --check
forge build   # runs forge lint; zero warnings
scripts/check-line-length.sh
forge test
FOUNDRY_PROFILE=ci forge test  # fuzz/invariant gate
slither . --config-file slither.config.json --fail-medium
```

## Reviewing Solidity (diffs, MRs)

Walk the numbered checklist above against each hunk, and also check:

- Comment headers must name the item they document. Flag
  copy-pasted or stale headers describing another function (§4).
- New or changed domain-separation tag strings are review-blocking
  unless called out in the MR description (§6).
- Every new numeric literal is either structural (offset/mask,
  checkable from the adjacent comment) or needs a named constant
  with a derivation comment (§1, §4).
- If the diff adds or changes a state machine (nonces, key versions,
  budgets, consumption tracking) or an envelope format, check the
  same MR adds fuzz/invariant properties for it: state-machine
  invariants or decode-canonicity plus mutation rejection (§8).
- New Slither findings are fixed or suppressed inline with a
  justification (`// slither-disable-next-line`, mirroring §5), never
  left to gate the pipeline (§8).
- Per repo practice, findings on others' MRs are delivered as a
  remediation-plan comment, not pushed fixes.
