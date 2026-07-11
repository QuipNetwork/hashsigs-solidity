# SHRINCS profile parameterization design

Scope: compile/deploy-time profile selection for the SHRINCS verifier
(256s baseline plus the 128s-q18/128s-q20 profiles). This is the
committed design reference for the profile mechanics, hazards, and
decisions that the verifier source cites as `[DESIGN §x]`.

## Recommendation (summary)

Hybrid of options (d′) and (b):

- **Counts** (h, d, a, k, len, target sums, signature limit): per-profile
  `ShrincsParams` library selected by **Foundry build-profile
  remappings**, re-exported through constant aliases in `ShrincsTypes`
  so all ~113 existing `ShrincsTypes.X` references compile unchanged.
- **Hash width** (HASH_LEN): keep every `bytes32` type, every 32-byte
  calldata slot, and every 32-byte-aligned assembly preimage layout.
  128s means `Trunc16(keccak256(...))`, high-aligned, zero-padded to a
  32-byte word. One `& HASH_MASK` per hash-producing site (9 sites);
  the 256s mask is all-ones and compiles to a no-op (verified).
- **Deployment**: distinct contracts `ShrincsVerifier256s` /
  `ShrincsVerifier128sQ20`, one per build profile, each with its own
  CREATE2 salt and production profile.

All 34 hand-verified assembly blocks keep their preimage offsets,
lengths, and §6 offset-table comments. The whole-core diff is ~30
functional lines plus one constants-file split.

## 1. Requirements extracted from MR !7

Separate what 128s-q20 must mean from how her branch implements it.

### 1.1 The parameter tuple (requirements)

| Constant | 256s (today) | 128s-q20 | Notes |
|---|---|---|---|
| HASH_LEN (n) | 32 | 16 | [FIPS205 §11] |
| HYPERTREE_HEIGHT (h) | 64 | 18 | |
| NUM_HYPERTREE_LAYERS (d) | 8 | 1 | subtree height h/d = 18 |
| FORS_TREE_HEIGHT (a) | 14 | 24 | |
| NUM_FORS_TREES (k) | 22 | 6 | FORS-C reveals k−1 = 5 |
| WOTS_CHAIN_LEN (w) | 16 | 16 | unchanged |
| NUM_WOTS_CHAINS (len) | 64 | 32 | = 2n for w=16 (no checksum chains; WOTS-C) |
| WOTS_CHAINS_STATEFUL | 64 | 32 | stateful side follows n |
| WOTS_TARGET_SUM_STATEFUL | 480 | 240 | len·(w−1)/2 |
| STATELESS_SIGNATURE_LIMIT | 2^20 | 2^18 in her code | **name says q20 = 2^20; see open question Q1** |
| STATEFUL_PUBLIC_KEY_BYTES | 68 | 36 in her code | this design keeps 68 (padded); see §3.2 |

Derived values that must stay consistent: `wotsDigestBytes()` = 16;
FORS digest bytes = (k·a + h + 7)/8 = 21 (single-block path);
treeBits = h − h/d = 0 (d=1 ⇒ treeIndex always 0).

Her measured result (gasUsed/parameter-gas-results.md): stateless
verify drops from ~2.71M gas (256s) to ~408k (128s-q20); stateful to
~202k. Most of the cut comes from the counts (d 8→1, k 22→6, len
64→32), not from the byte width — relevant to §2.

### 1.2 Her implementation choices (rejectable)

- `bytes`-typed stateful fields (`StatefulPublicKey.pkSeed/root`,
  `StatefulSignature.randomizer/chains/authPath` → `bytes`).
- Tight n-byte packing inside hash preimages: every assembly block
  gains `n`-dependent offsets (`add(add(ptr, 41), n)` style), and the
  §6 constant offset tables become symbolic.
- `loadHash`/`loadHashMemory`/`truncateHash` helpers, duplicated in
  ShrincsUtils and ShrincsStateful; per-byte `setHashSlice` copy loop.
- n-byte blocks in the FORS digest expansion (`chunk > n`).
- Deletes `ShrincsTypes.SigningKey` (breaks the in-repo Solidity test
  signer; her tests replace it with FFI vectors + caches).

These rewrite the hot paths and forfeit the review evidence. The
requirement they serve — smaller signatures — is not actually served
on-chain: the ERC-7913 envelope is `abi.encode`d (ShrincsCodec), and
ABI encoding pads every `bytes` element to a 32-byte word. A tight
16-byte field and a padded 32-byte field with a zero low half occupy
identical calldata bytes at identical zero/nonzero cost. Verified
against ShrincsCodec.sol:63-84 and the ABI spec; see §2 option (b).

## 2. Options evaluated

Empirical results below come from a via-ir 0.8.35 experiment
mimicking one WOTS pk reconstruction (64 chains × ~16 chain hashes,
two internal-call levels deep), scratchpad `viair-exp/`.

### (a) Constants passed down as a params struct — rejected

Concrete per-profile contracts bind a `Params` struct; core libs take
it as an argument.

**Measured**: via-ir does NOT constant-fold the struct. The
params-bound variant costs 347,081 gas vs 339,186 for constant-bound
(+2.3%) and +130 bytes runtime code. Loop bounds stay memory loads;
buffer sizes stay runtime arithmetic. Extrapolated to a 2.7M-gas 256s
stateless verify: ~50-60k gas of pure overhead, paid by the *existing*
profile too.

Also the largest diff of any option: every internal function signature
in ShrincsUtils/ShrincsForsC/ShrincsHypertree/ShrincsStateful/SHRINCS
changes, which re-opens review of every call site. Violates both the
no-runtime-dispatch intent (params live in memory at runtime) and the
lightweight constraint.

### (b) 32-byte-padded truncated hashes — adopted for HASH_LEN

Keep `bytes32` everywhere. Define the 128s tweakable hash as
`Trunc16(keccak256(preimage))`, stored high-aligned in a `bytes32`
with a zero low half; preimages keep their 32-byte slot layout (the
low 16 bytes of each hash slot are zero for 128s).

- **Calldata**: zero delta vs her tight encoding (§1.2). The 16
  padding bytes are zeros the ABI encoder emits either way.
- **Execution**: preimages are 32-byte-slot sized, so keccak word
  counts are higher than tight packing: chain-step hash 108 B (4
  words) vs 76 B (3 words) = +6 gas/step; FORS node 137 vs 89 B = +12
  gas/node. Over a 128s stateless verify (~240 chain steps + ~120 FORS
  nodes + 18 hypertree nodes + per-chain pk inputs) this is ~3-4k gas,
  under 1% of the 408k total. Her per-byte `setHashSlice` loop is
  likely more expensive than that. **Conclusion: ≥99% of the measured
  128s-q20 gas/calldata benefit survives, because that benefit comes
  from the counts.**
- **Mask cost for 256s**: the all-ones mask folds away under via-ir
  1000000-runs (measured: 344,291 vs 344,352 gas, bytecode delta 2
  bytes of metadata). The 256s artifact is behaviorally unchanged.
- **Review evidence**: all preimage offsets, lengths, and §6 offset
  tables unchanged. The diff per assembly block is at most one
  trailing `out = out & HASH_MASK;` (or `and(...)` on the existing
  keccak line) — 9 sites total (§3.3).
- **Fail-closed property**: high-aligned truncation makes profile
  confusion fail structurally. A 256s key material presented to the
  128s verifier reconstructs truncated (zero-low-half) node values
  that cannot equal the full-width committed root; comparisons fail.
- **Canonicality/malleability**: no masking on *load*. Every
  calldata-supplied hash field is bound either by the public-key
  commitment (exact bytes hashed) or by a downstream hash comparison,
  so mutated low bytes make verification fail rather than open a
  second accepted encoding. (Contrast: her `truncateHash`-on-load
  *accepts* non-canonical low bytes, which is a malleability
  regression vs the C6 "exactly one accepted encoding" property.)
- **Rust signer**: must hash padded 32-byte-slot preimages and emit
  padded fields. Her gas-vector tool (`gasUsed/shrincs-gas-vector`)
  shells out to `cast abi-encode` with `hex(field)` — emitting padded
  vectors is a formatting change there, but the hashing change lands
  in hashsigs-rs itself (§5).

### (c) Her approach (bytes-typed + dynamic offsets) — rejected

Full flexibility, but every one of the 34 assembly blocks changes
shape: symbolic offsets, `mload(pkSeed)` length reads inside assembly,
overlapping-mstore packing tricks. The just-completed review's
hand-computed offset tables become invalid; effectively a full
re-review of the crypto core. Gains vs (b): ~1% execution gas, zero
calldata (§1.2). Also currently *loses* gas to per-byte copy loops and
adds malleability on load. Not justified.

### (d) Codegen (template → ShrincsTypes256s.sol / …128sQ20.sol) — rejected in favor of (d′)

Zero runtime cost, but: a generator script becomes security-critical
build infrastructure; generated library *sets* (the whole core must be
duplicated per profile, since imports bind at compile time) double the
audit surface; CI must prove generated == template; Etherscan
verification shows generated sources. All of that buys nothing over
(d′), which gets identical artifacts from a single source tree.

### (d′) Build-profile selection via Foundry remappings — adopted for counts

One source tree. Per-profile constants live in
`contracts/profiles/<profile>/ShrincsParams.sol`; `ShrincsTypes`
imports it through a remappable path and re-exports every constant as
an alias (`uint16 internal constant HASH_LEN = ShrincsParams.HASH_LEN;`),
so no reference site changes. Each Foundry profile sets the remapping
and a `skip` list for the other profile's verifier/deploy/test files.

**All mechanisms verified** on forge 1.7.1 / solc 0.8.35 via-ir
(scratchpad `remap-exp/`):

- constant-from-constant aliasing across libraries compiles and folds
  (per-profile PUSH constants confirmed in both artifacts);
- per-profile `remappings = [...]` + `skip = [...]` in foundry.toml
  produce correct, disjoint artifact sets under separate `out` dirs;
- dashed profile names (`FOUNDRY_PROFILE=128s-q20`) work.

**Verified hazard**: a `remappings.txt` file silently overrides
per-profile TOML remappings — with one present, the 128s build
compiled with 256s constants and still succeeded. Mitigations in §3.5
(profile identity test + CI guard). This is the one sharp edge of
(d′); it converts to a red test, not a wrong deploy.

### Comparison

| | (a) params struct | (b) padded hashes | (c) her bytes/dynamic | (d) codegen | (d′) remap profiles |
|---|---|---|---|---|---|
| Runtime gas | +2.3% measured, both profiles | ~+1% vs tight, 128s only; 256s unchanged | baseline tight (but per-byte loops) | 0 | 0 |
| Calldata | 0 | 0 vs (c) (ABI padding) | 0 | 0 | 0 |
| Diff vs reviewed tree | every core fn signature | 9 mask lines + guards | all 34 asm blocks | generator + dup tree | constants split + import |
| Review evidence | forfeits call sites | preserved | forfeited | preserved but doubled surface | preserved |
| Vector regen | none extra | padded preimages (once, with F-08) | tight preimages | n/a (carrier) | n/a (carrier) |
| Maintenance (per new profile) | 1 contract | 1 mask constant | — | regenerate tree | 1 params file + toml section |
| Runtime dispatch | memory reads (violates intent) | none | none | none | none |

Applicability per parameter class: counts need (a)/(d)/(d′) (they size
arrays and bound loops — cannot be a mask); HASH_LEN is the only
parameter with assembly-layout blast radius, and (b) neutralizes it.
So: hybrid.

## 3. Design detail

### 3.1 File/library layout

```
contracts/
  profiles/
    256s/ShrincsParams.sol        # library ShrincsParams (256s values)
    128s-q20/ShrincsParams.sol    # library ShrincsParams (128s-q20 values)
  ShrincsTypes.sol                # structs (unchanged) + constant aliases
  ShrincsUtils.sol … SHRINCS.sol  # core: unchanged references
  ShrincsVerifier.sol             # becomes `abstract contract ShrincsVerifier`
  ShrincsVerifier256s.sol         # contract ShrincsVerifier256s is ShrincsVerifier
  ShrincsVerifier128sQ20.sol      # contract ShrincsVerifier128sQ20 is ShrincsVerifier
```

`ShrincsParams` per profile holds, with §1/§2/§4 citations and Python
derivation one-liners (extends F-13's fix): HASH_LEN, HASH_MASK,
HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS, FORS_TREE_HEIGHT,
NUM_FORS_TREES, WOTS_CHAIN_LEN, NUM_WOTS_CHAINS, WOTS_CHAINS_STATEFUL,
WOTS_BASE_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
STATELESS_SIGNATURE_LIMIT, STATEFUL_PUBLIC_KEY_BYTES, and a
`PROFILE_ID` string/bytes32 (e.g. `keccak256("shrincs-256s")`).

`ShrincsTypes` keeps every struct byte-for-byte and re-exports the
constants as aliases. Two library declarations named `ShrincsParams`
in different files are legal Solidity (per-file namespacing) and only
one is ever imported per build.

HASH_MASK values:

- 256s: `bytes32(type(uint256).max)` (folds to no-op, measured);
- 128s-q20: `bytes32(uint256(type(uint128).max) << 128)` (high 16
  bytes).

### 3.2 Types and calldata shapes (unchanged)

- All stateless signature fields stay `bytes` with `length == 32`
  checks, exactly as reviewed. For 128s the low 16 bytes are zero.
- `StatefulPublicKey`/`StatefulSignature`/`SigningKey` keep `bytes32`
  fields. The in-repo Solidity test signer keeps compiling.
- `STATEFUL_PUBLIC_KEY_BYTES` stays 68 for both profiles (32-byte
  pkSeed slot ‖ 32-byte root slot ‖ 4-byte maxSignatures);
  `decodeStatefulPublicKey`'s assembly block is untouched. This
  deliberately diverges from her 36-byte packing (costs 32 zero
  calldata bytes ≈ 128 gas; buys an unchanged decoder and one key
  encoding shape across profiles).
- Length checks against literal `32` stay literal `32`. Only the one
  existing `ShrincsTypes.HASH_LEN` check
  (ShrincsHypertree.sol:81, wotsCPkHash) needs its meaning pinned:
  redefine it as the 32-byte slot check (i.e. change to literal 32 or
  keep HASH_LEN and document that fields are slot-width; pick literal
  32 for uniformity).

### 3.3 Mask hook sites (the entire hash-width diff)

Add `function maskHash(bytes32 h) internal pure returns (bytes32)`
(`h & ShrincsParams.HASH_MASK`) in ShrincsUtils and apply at the 9
hash-*producing* sites:

| # | Site | Form |
|---|---|---|
| 1 | ShrincsForsC.verifyForsCAndReturnRoot — "fors-pk" root | wrap after asm keccak |
| 2 | ShrincsForsC.hashForsLeaf32 | wrap |
| 3 | ShrincsForsC.hashForsNode32 | wrap |
| 4 | ShrincsHypertree.verifyWotsC32 — "wots-c-pk" | wrap |
| 5 | ShrincsHypertree.hashStatelessWotsCChainNoMask32 | wrap |
| 6 | ShrincsHypertree.hashHypertreeNode32 | wrap |
| 7 | ShrincsStateful — "uxmss-wots-pk" (Solidity keccak) | wrap |
| 8 | ShrincsStateful.statefulParentHash | wrap |
| 9 | ShrincsStateful.hashStatefulWotsCChainNoMask32 | wrap |

Not masked (deliberate, must be pinned in the spec and mirrored by the
Rust signer):

- **Digit-selection digests** ("wots-c-msg", "uxmss-wots-digits"):
  full keccak output; digits read from the first `len/2` bytes
  (existing `baseW16Digit*` readers already do this for len=32).
  Relaxes ShrincsHypertree's `wotsDigestBytes() != 32` guard to a
  profile-invariant test (§3.5) plus `wotsDigestBytes() <= 32`.
- **FORS digest expansion** ("fors-digest"): stays 32-byte blocks
  (`chunk > 32`), an XOF-style expansion where n does not apply.
  Divergence from her n-byte blocks — spec decision, see Q3.
- **Message hashes, OP_* action/rotation hashes, publicKeyCommitment,
  envelope hashes**: full 32-byte keccak in every profile (these are
  the ERC-7913/account-layer surface, not the SPHINCS hash family).

Comment updates ride along: each §6 offset table gains one line
("output truncated to HASH_LEN bytes, high-aligned"); stale
profile-literal prose in cast-safety comments ("fixed 8-layer
hypertree", "height is 14 bits", "64 chains") is generalized.

### 3.4 foundry.toml, deploy, CI

Profiles (per-profile `out` dirs so artifacts never collide):

```toml
[profile.default]            # 256s, developer default
remappings = ["shrincs-profile/=contracts/profiles/256s/"]
skip = ["contracts/ShrincsVerifier128sQ20.sol",
        "script/DeployShrincsVerifier128sQ20.s.sol",
        "test/profiles/128s-q20/**"]

[profile.128s-q20]
out = "out-128s-q20"
remappings = ["shrincs-profile/=contracts/profiles/128s-q20/"]
skip = ["contracts/ShrincsVerifier256s.sol",
        "script/DeployShrincsVerifier256s.s.sol",
        "test/ShrincsSphincs256sVectors.t.sol",
        "test/profiles/256s/**"]

[profile.production]         # 256s canonical build (existing pin)
solc = "0.8.35"  # via-ir, 1_000_000 runs, as today
[profile.production-128s-q20]
solc = "0.8.35"  # same pin + 128s remapping/skip + out-128s-q20-prod
```

Both production profiles pin the same solc 0.8.35/via-ir/runs; they
differ only in remapping, skip, and `out`. Two artifacts, two init
codes, two CREATE2 addresses — deterministic per profile.

Deploy: split `DeployShrincsVerifier.s.sol` into
`DeployShrincsVerifier256s.s.sol` (salt
`keccak256("QUIP:ShrincsVerifier256s:V1.0")`, requires
`FOUNDRY_PROFILE=production`) and `DeployShrincsVerifier128sQ20.s.sol`
(salt `...128sQ20:V1.0`, requires
`FOUNDRY_PROFILE=production-128s-q20`). Keep the F-17 profile
assertion pattern in both. The existing V1.0 salt has not been burned
on-chain (pre-release), so renaming the contract is safe; if any chain
already has a deployment, keep the old salt string for the 256s
contract — decision Q5. RELEASES.md records (profile, version, tag,
address, codehash, chain).

Verifier contracts: `ShrincsVerifier` becomes `abstract` (one-line
diff; prevents deploying the unsuffixed artifact). Each thin subclass
adds `bytes32 public constant PROFILE_TAG` (constants cannot be
`virtual`/`override`, so the base keeps VERSION_TAG as the
format-family tag and the profile tag lives on the subclass). Empty
subclass bodies otherwise — the reviewed verifier logic is untouched.

CI: matrix the verify job over `FOUNDRY_PROFILE ∈ {default, 128s-q20}`
for `forge build`, `forge lint --deny warnings`, `forge test`; run
`forge fmt --check` and the line-length script once. Add a guard step:
`test ! -f remappings.txt` (see hazard, §2(d′)).

Hardhat: hardhat.config.ts cannot resolve the `shrincs-profile/`
import (v2, no remapping support), and adding `remappings.txt` for it
would trip the verified precedence hazard. Options: add
`@nomicfoundation/hardhat-foundry` (resolves via `forge remappings`,
default profile = 256s), or drop the hardhat/ignition path (it only
deploys WOTSPlus and the example today). Decision Q4; default
recommendation: add hardhat-foundry, pin ignition to 256s.

### 3.5 Profile invariants and identity tests (new, small)

`test/ShrincsProfileInvariants.t.sol`, compiled under every profile:

- structural: `h % d == 0`; `wotsDigestBytes() <= 32`;
  `NUM_WOTS_CHAINS == 2 * HASH_LEN` (w = 16);
  `WOTS_TARGET_SUM_STATEFUL == WOTS_CHAINS_STATEFUL * (w-1) / 2`;
  FORS digest bytes + 32-byte slack sane; `treeBits <= 64`;
  `k*a + h` bit-reads within `readBits32/64` limits;
  FORS leaf/parent low-index fits 32 bits (`k << a` bound);
  `HASH_MASK` is exactly HASH_LEN high bytes of ones.
- identity (kills the remappings.txt hazard and wrong-profile builds):
  read `FOUNDRY_PROFILE` via `vm.envOr` and assert the compiled
  (PROFILE_ID, HASH_LEN, h, d, a, k, len, limit) tuple matches the
  expected table for that profile name.

### 3.6 Tests and vectors per profile

- Profile-agnostic tests (codec, verifier envelope handling, account
  example, stateful signer round-trips with small maxSignatures, toy
  stateless profile) run under both profiles unchanged — the Solidity
  test signer derives everything from ShrincsTypes constants.
  Exception to verify during implementation: stateless
  keygen/sign in the Solidity signer is computationally infeasible at
  128s-q20 (FORS trees of 2^24 leaves; FORS-C grind expects ~2^24
  attempts because the omitted tree must select leaf 0 with a = 24).
  Stateless round-trip tests must be vector-driven at
  128s-q20, exactly as her branch concluded (FFI + cache). The 256s
  profile already uses Rust-anchored JSON vectors
  (shrincs_sphincs_256s_keccak.json) — same pattern, so this is
  precedent, not new machinery.
- Rust-anchored JSON vectors per profile:
  `test/test_vectors/shrincs_sphincs_256s_keccak.json` (regenerated,
  see §5) and `shrincs_sphincs_128s_q20_keccak.json` (new). Vector
  tests live in per-profile test dirs covered by `skip`.
- Her gasUsed/ harness ports directly: `ShrincsReceiptProbe` compiles
  per profile as-is; `receiptGas.js` gains a `FOUNDRY_PROFILE` knob
  and per-profile vector cache dirs. Her `ShrincsMeasurements.t.sol`
  is already merged at 6aae97e and is profile-agnostic (all counts
  come from ShrincsTypes) — it runs under both profiles unchanged.

## 4. Interaction with F-08 (domain-tag split)

Vectors regenerate once, covering both changes. Bundle into the same
Rust-coordination window:

1. **F-08**: stateful chain tag `"wots-c-chain"` → `"uxmss-wots-chain"`
   (preimage length shifts 108 → 112; §6 tables at the two chain-hash
   sites update; this is the only preimage-layout change in the whole
   plan and it is the already-agreed F-08 one).
2. **This design**: padded-slot preimages + Trunc16 for the 128s
   profile; 256s preimages are byte-identical to today except the
   F-08 tag.
3. **Recommended rider (Q2)**: bind the profile into key commitments
   while vectors are already breaking — e.g.
   `"shrincs-public-key" → "shrincs-public-key/" ‖ PROFILE_ID` — so a
   key bundle can never be presented cross-profile even if a future
   profile reuses field shapes. Today the mismatch fails structurally
   (truncation, §2(b)), but an explicit binding is cheap now and
   impossible later.

## 5. What the Rust signer (hashsigs-rs) must provide per profile

- A profile module/feature per parameter tuple (256s, 128s-q20) — her
  `test_gas_reduction` branch already forks constants; it needs the
  padded-preimage hash layout instead of tight packing for n=16, plus
  the F-08 tag.
- Emit all hash-valued fields as 32-byte padded (high-aligned) hex in
  vector JSON/calldata; keep the 68-byte stateful pk encoding.
- Regenerate, per profile: `shrincs_sphincs_<profile>_keccak.json`,
  `shrincs_account_wrapper_vectors.json`, stateful keygen anchors, and
  the gasUsed vector caches. One regeneration event total (F-08 +
  padding + profile split).
- 128s-q20 signing-cost note for tooling: FORS tree build ≈ 6·2^25
  hashes per fresh (key, hypertree-leaf) and FORS-C grinding ~2^24
  digest attempts per signature; keep her tree/vector caches.

## 7. Open questions for the maintainer

- **Q1 — q20 vs 2^18.** Her branch sets STATELESS_SIGNATURE_LIMIT =
  2^18 (= 2^h leaves) while the profile name says q20 (= 2^20
  signatures, i.e. ~4 FORS reuses per leaf on average). Which budget
  is the security target for (a=24, k=6, h=18)? Needs the profile's
  security analysis, and possibly a rename (128s-q18) if 2^18 stands.
- **Q2 — Profile binding in commitments.** Approve the
  `"shrincs-public-key/" ‖ PROFILE_ID` domain rider in the F-08
  vector-breaking window (§4)? Recommended: yes.
- **Q3 — FORS digest expansion block size.** This design keeps
  32-byte XOF blocks for all profiles; her branch used n-byte blocks.
  Signer must match — confirm 32.
- **Q4 — Hardhat.** Keep (via hardhat-foundry, pinned 256s) or drop
  the hardhat/ignition path?
- **Q5 — Salt continuity.** Confirm no chain has a canonical
  ShrincsVerifier deployment yet, so the per-profile salt strings
  (`...ShrincsVerifier256s:V1.0`) can replace `...ShrincsVerifier:V1.0`.
- **Q6 — 128s-q20 stateful counts.** Confirm the stateful subsystem
  follows n (32 chains, target 240) as in her branch, rather than
  staying at 64 chains for defense margin. Her measurements assume 32.

## Appendix: evidence log

- ABI padding equivalence: ShrincsCodec.sol:63-84 (abi.encode
  envelope + canonicity re-encode); ABI spec pads `bytes` to 32-byte
  words. Zero-byte calldata cost identical either way.
- via-ir params-struct test: scratchpad `viair-exp/` — ParamsBound
  347,081 gas / 555 B deployed vs ConstBound 339,186 / 425 B; masked
  all-ones ConstBound 344,291 vs 344,352 unmasked (noise).
- Remapping/alias/skip/dash test: scratchpad `remap-exp/` — per-profile
  PUSH2 0x0800 / 0x0200 confirmed in respective artifacts;
  `remappings.txt` present ⇒ 128s artifact silently built with 256s
  constants (hazard confirmed).
- Assembly block count: review-findings F-12 (34 blocks); §6 offset
  tables present at 6aae97e (e.g. ShrincsForsC.sol:82-90,
  ShrincsHypertree.sol:311-317, ShrincsStateful.sol:221-227).
- Her branch diff studied: contracts (805-line diff) + tooling
  (1,375-line diff incl. shrincs-gas-vector/src/main.rs emitters and
  gasUsed/parameter-gas-results.md measurements).

## Maintainer decisions (2026-07-10, answers to Q1-Q6)
- Q1: THREE profiles. 128s ships as 128s-q18 (STATELESS_SIGNATURE_LIMIT
  2^18, matching her code) AND a 128s-q20 mode (2^20) — same (a=24, k=6,
  h=18) constants, differing only in the limit. q20's budget still wants
  security-analysis backing before production use; name both honestly.
- Q2: YES — bind profile ID into the public-key commitment tag
  ("shrincs-public-key/<profile>") during the single vector-regeneration
  event, bundled with the F-08 tag split.
- Q3: default confirmed — FORS digest expansion stays 32-byte-block.
- Q4: DROP hardhat entirely (replace, don't deprecate).
- Q5 (amended): SHRINCS is testnet-only; CREATE3 for ALL deploys moving
  forward — SHRINCS (per-profile salts) AND WOTS+. The historical WOTS+
  CREATE2 deployment (factory, salt, init-code pinning, per-chain
  addresses) must be documented in committed docs (DEPLOYMENTS.md or
  README section) as part of T5, extracted from git history, before the
  CREATE2 path is removed. Update T5/deploy script to match.
- Q6: default confirmed — stateful side follows n (32 chains, target 240).
