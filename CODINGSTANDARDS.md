# Coding Standards

Standards for all Solidity in this repository (`contracts/`, `test/`).
This is production cryptographic code: the primary audience is auditors
and reviewers checking the code against the source documents.
Optimize for spec-to-code traceability, not brevity.

Enforcement commands are in [§8](#8-enforcement). The repo-local Claude
Code skill `.claude/skills/solidity-standards/` walks this document.

## 1. Source documents and citations

Canonical citation keys:

- `WOTSPLUS` — A. Hülsing, *W-OTS+: Shorter Signatures for Hash-Based
  Signature Schemes*, AFRICACRYPT 2013.
  <https://eprint.iacr.org/2017/965>
- `RFC8391` — *XMSS: eXtended Merkle Signature Scheme*, IETF RFC 8391.
  <https://www.rfc-editor.org/rfc/rfc8391>
- `SPHINCSPLUS` — *SPHINCS+ Specification v3.1*, 2022.
  <https://sphincs.org/data/sphincs+-r3.1-specification.pdf>
- `FIPS205` — NIST FIPS 205, *Stateless Hash-Based Digital Signature
  Standard (SLH-DSA)*, 2024. <https://doi.org/10.6028/NIST.FIPS.205>
- `SHRINCS` — M. Kudinov, J. Nick, *Hash-based Signature Schemes for
  Bitcoin*, Cryptology ePrint Archive 2025/2203, 2025; SHRINCS is
  specified in the appendix.
  <https://eprint.iacr.org/2025/2203>

Cite as `[KEY §x.y]`, `[KEY Alg n]`, `[KEY Eq n]`, `[KEY p. n]`.
Examples: `[RFC8391 §5.1]`, `[FIPS205 Alg 19]`, `[WOTSPLUS §3]`.

Rules:

- Any identifier naming a quantity, function, or algorithm from a
  source document carries a citation at its declaration.
- Any function implementing a spec algorithm cites that algorithm in
  its header comment.
- Numeric literals derived from the math are banned inline ("no magic
  numbers"): give them a named constant with a derivation comment
  (§4). Structural literals (memory offsets, bit masks, `32` for a
  hash word) are fine when the surrounding comment or context makes
  them checkable.
- **Documented deviations:** where this code deliberately departs
  from a source document, the comment must begin
  `Deviates from [KEY ...]:` and state what differs and why.
  Example: SHRINCS hypertree index derivation is sequential per
  layer and does not follow the `[FIPS205 §8.2]` recurrence.

## 2. Naming

- **Mapping notation** (paper symbol ↔ code name). The first line of
  the declaration comment for any math-derived identifier is:

  ```solidity
  // <Name>: the <KEY> `<symbol>` parameter [<KEY> §<loc>] — <meaning>.
  ```

  Example:

  ```solidity
  // ChainLen: the WOTSPLUS `w` (Winternitz) parameter
  // [WOTSPLUS §3] — hash-chain length and base of the
  // message/checksum representation.
  uint8 public constant ChainLen = 16;
  ```

- **No single-character or bare-symbol names**, including locals and
  parameters. Never `w`, `n`, `a`, `p`, `k`. Loop counters `i`, `j`
  over a local range are the only exception.
- **Constants, two tiers:**
  - Spec-derived parameters: `PascalCase` (`ChainLen`, `HashLen`,
    `AddressTypeForsTree`) with the mapping comment above. This
    deliberately overrides the Solidity style guide's
    UPPER_CASE_WITH_UNDERSCORES; the `screaming-snake-case-const`
    lint is disabled in `foundry.toml`.
  - Repo-defined protocol constants (domain-separation tags, opcode
    hashes, encoding sizes): `SCREAMING_SNAKE_CASE`
    (`OP_VERIFY_STATEFUL`, `STATEFUL_PUBLIC_KEY_BYTES`).
- **Functions:** `mixedCase`, including `internal` and `private`
  functions. `private` functions take a leading underscore
  (`_verifyStatelessRawMemory`). `internal` library functions are
  unprefixed — in an `internal` library they are the API.
- **Structs, enums, libraries, contracts:** `CapWords`.
- **Imports:** explicit named imports only:
  `import {ShrincsTypes} from "./ShrincsTypes.sol";`

## 3. Layout and formatting

- **Maximum line length: 78 characters.** Applies to every line of
  every `.sol` file, comments included. `forge fmt` wraps code;
  comments are wrapped by hand (see §8 for the checker).
  `foundry.toml` sets `line_length = 77` to compensate for fmt's
  width accounting (it excludes the trailing token); the enforced
  cap stays 78.
- **Line-cap escape hatches**, both rare and justified inline:
  - fmt re-joins a manual wrap it should keep: put
    `// forgefmt: disable-next-line` directly above and wrap by
    hand. Safe only on simple declarations — fmt 1.7.1 corrupts
    tuple destructures, `using` directives, and struct fields
    under this directive; use the `allow` form for those.
  - A single unbreakable token (long name, string, or `hex`
    literal) or fmt's own canonical output exceeds 78: exempt
    exactly one line with `// line-length: allow — <reason>` on
    the line directly above it. Reserved for unbreakable tokens
    and fmt-canonical overflow, never convenience.
- `forge fmt` settings in `foundry.toml` are authoritative for
  everything else: 4-space indent, double quotes, long int types,
  `attributes_first` function headers, no bracket spacing.
- Solidity style-guide ordering: pragma → imports → types → constants
  → state → functions (external → public → internal → private,
  `view`/`pure` last within each group).
- **License header:** every `.sol` file starts with the repo's
  15-line AGPL-3.0 notice (copy it from an existing file — do not
  retype), then `// SPDX-License-Identifier: AGPL-3.0-or-later`,
  then `pragma solidity ^0.8.28;`. Copyright year is the file's
  creation year.

## 4. Comments and documentation

- **Computed constants** carry a derivation comment: the formula in
  source-document symbols, the same formula restated in code names,
  the evaluated result, and a Python one-liner reproducing it:

  ```solidity
  // NumMessageChunks: the WOTSPLUS `len_1` parameter
  // [WOTSPLUS §3]: ceil(8n / lg(w))
  // -> ceil(8 * HashLen / lg(ChainLen)) = ceil(256 / 4) = 64
  // Python: math.ceil(32*8 / math.log(16, 2))
  uint8 public constant NumMessageChunks = 64;
  ```

- **NatSpec:** new ABI-visible items (`public`/`external` functions,
  `public` constants) use `///` NatSpec: `@notice` for behavior,
  `@param`/`@return` for every parameter and return value, `@dev`
  for citations, caveats, and security notes. Existing plain `//`
  headers are grandfathered until the NatSpec retrofit (tracked as
  future work).
- A header comment must name the item it documents. Copy-pasted
  headers describing a different function are review-blocking.
- **No commented-out code.** The `// DEBUG:` blocks in
  `WOTSPlus.sol` are grandfathered; do not add new ones anywhere.
  Delete debug scaffolding before requesting review.

## 5. Verifier safety idioms

- **Fail closed, never revert.** Verification and rotation functions
  return `false` (or `bytes32(0)`) on any malformed input, unknown
  parameter set, or failed check. They must not revert: reverting
  verifiers leak check ordering and enable griefing when embedded in
  account-abstraction flows. Each early return corresponds to one
  named check.
  Exception: example/reference code that is documented "do not use
  on-chain" (the WOTSPlus signer/keygen) may use `require`.
- **Validate lengths before assembly reads.** Every `calldataload`/
  `calldatacopy` of a `bytes` value is preceded by an explicit
  `.length` check in Solidity.
- **Calldata framing reads (narrow exception).** A `calldataload`
  whose result is used *only* as an operand of an equality/comparison
  against an expected constant or a running cursor — never in
  arithmetic, indexing, loop bounds, lengths, or as returned data —
  may be read without a prior bounds check. The justification, which
  the site comment must state, is that `calldataload` past
  `calldatasize` returns zero, and a zero read must fail the
  comparison (fail closed) rather than pass it. This applies to
  **calldata only** (`returndatacopy`/`mload` past their region do
  not return a safe zero and are out of scope). Every value that
  feeds arithmetic, a loop bound, an index, or a length keeps the
  strict pre-check above. Each exception site carries a comment
  citing this rule and stating why an out-of-bounds zero fails the
  specific comparison closed.
- `unchecked` blocks need a comment stating why overflow/underflow
  is impossible, unless the block is the bare loop-increment idiom
  `unchecked { ++i; }` under a bounded loop.
- **Lint suppressions** use exactly this two-line form — a
  justification, then the directive:

  ```solidity
  // casting to 'uint32' is safe because the mask bounds the
  // result to at most 32 bits
  // forge-lint: disable-next-line(unsafe-typecast)
  return uint32(shifted & mask);
  ```

  A bare disable with no justification is review-blocking.

## 6. Assembly

- Assembly is a last resort for gas-critical hashing and calldata
  slicing (per Trail of Bits guidance). Keep blocks small and
  single-purpose.
- **Every assembly block is preceded by a comment giving the buffer
  layout**: each field's offset and length, the total hashed length,
  and the source-document encoding it implements, e.g.:

  ```solidity
  // keccak256 input ("fors-leaf" tag [§1 tags]):
  //   [0..9)    "fors-leaf"
  //   [9..41)   pkSeed
  //   [41..73)  addressWord
  //   [73..105) secret leaf
  ```

- Restore or advance the free-memory pointer (`0x40`) correctly;
  annotate blocks `assembly ("memory-safe")` when they qualify.
- **Domain-separation tags** (`"shrincs-public-key"`, `"fors-leaf"`,
  `"fors-node"`, `"fors-digest"`, `"fors-pk"`, …) are protocol
  constants: any new tag or change to an existing tag must be
  called out in the MR description, and the tag's byte length must
  appear in the adjacent layout comment.

## 7. ABI and source compatibility

- `public` library functions and `public` constants are external
  ABI (deployed-library linkage): renaming or retyping them is a
  breaking change requiring a version bump and changelog entry.
  ABI-visible symbols are never renamed to satisfy this document.
- `internal` library functions are source-level API for npm
  dependents: renames need at least a minor (pre-1.0: patch) bump
  and a changelog entry. Internal renames to meet §2 are approved.
- When the standard conflicts with an existing exported (`public` or
  `external`) name, the name wins until a deliberate breaking
  release: codify, don't churn.

## 8. Enforcement

- **Format** — `forge fmt --check`: indentation, wrapping, quotes,
  and code lines over 78 characters.
- **Lint** — `forge build` (lint runs on build) or `forge lint`:
  unsafe casts, naming lints, unused imports.
- **Hard line cap** — `scripts/check-line-length.sh`: any line over
  78 characters, comments included. Honors the
  `// line-length: allow` directive (§3) on the preceding line.
- **Tests** — `forge test`: behavior.
- **Static analysis** — `slither . --config-file slither.config.json
  --fail-medium`: the pinned Slither 0.11.5 analyzer. Fix a finding,
  suppress it inline (`// slither-disable-next-line <detector>` with a
  justification comment on the line above, mirroring the §5 form), or
  exclude it in `slither.config.json` with a comment in the MR
  description. `dead-code` stays enabled and surfaces in the SARIF
  report (F-15).
- **Fuzz and invariant properties** — `FOUNDRY_PROFILE=ci forge test`:
  bounded, deterministic fuzz and invariant runs are part of the test
  gate. The per-MR seed is pinned in `.gitlab-ci.yml`; nightly pipelines
  run randomized deep campaigns whose counterexamples persist into
  `cache/fuzz`/`cache/invariant` and fail later MR runs until fixed.
  Never delete a persisted counterexample to turn CI green.
- **New state machines and envelope formats ship with properties** — an
  MR that adds or changes a stateful flow (nonces, key versions,
  budgets, consumption tracking) or a serialized envelope format
  includes fuzz/invariant properties for it in the same MR:
  state-machine invariants for the former, decode canonicity plus
  mutation rejection for the latter.

Note: `forge` on some dev machines is shadowed by an unrelated
tool — confirm `forge --version` reports Foundry (Homebrew installs
to `/opt/homebrew/bin/forge`). Builds and tests require `via_ir`;
the default `foundry.toml` profile already sets it.

All six must pass before requesting review; merges to main require the
full pipeline to pass. Zero warnings: a lint finding is either fixed or
suppressed with the §5 two-line form.
