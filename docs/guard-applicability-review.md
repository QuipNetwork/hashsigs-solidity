# Guard applicability review — SHRINCS verify paths

This is the ratified input-guard applicability review (decision record) for
the SHRINCS verify paths, including the ratified Addendum below.

Repo: /Users/carback1/Code/quip/hashsigs-solidity, branch shrincs-main,
HEAD e4002d5. Scope: every input guard on the verify paths (adapters,
facade, component libraries, codec, wrapper ERC-1271 path). Rotation
guards and test code excluded. Spike project:
`scratchpad/guard-spike/` (solc 0.8.28, via-ir, optimizer 200 —
matching the repo's test profile).

Note: `SHRINCSCodec.sol` was dissolved into `SHRINCS.sol` and
`SPHINCSPlusC.sol` in commit `0f190b0` ("Dissolve SHRINCSCodec into
SHRINCS and SPHINCSPlusC"), after this review was ratified at HEAD
e4002d5. The `SHRINCSCodec.sol:<line>` citations throughout this
document are historical, against the pre-dissolution source. The code
moved byte-for-byte under the same function names: 15 codec/decode
functions now live in `SHRINCS.sol`, and the 4 stateless key/message/
signature-envelope helpers (`decodeStatelessKey`, `toMessage`,
`encodeStatelessSignatureEnvelope`, `statelessSignatureEnvelope`) now
live in `SPHINCSPlusC.sol`.

Classes: **S** = soundness (dropping admits a wrong-accept, directly or
under a stated condition), **A** = API contract (non-reverting
0xffffffff model; ERC-7913 permits plain reverts instead), **M** =
canonical-uniqueness / byte-malleability (a second byte-encoding of the
same logical signature verifies), **R** = redundant (another check or a
compared hash already rejects the input).

---

## 1. Empirical results (spike: guard-spike/test/Guard.t.sol)

Setup: a struct `S { uint32 counter; bytes data; bytes32[] words; }`
re-tagged over `abi.encode(S)` bytes exactly as the zero-copy plan's
primitive (`s := add(payload.offset, calldataload(payload.offset))`),
with the offset/length/value words then patched, and members accessed
through solc-generated accessors from a driver via low-level staticcall.

**E1 — malformed offsets into a re-tagged calldata struct:**
- Offset past calldatasize but < 2^64 (`0x10000`): solc's
  `access_calldata_tail` check **reverts** (empty revert data) on slice
  creation, indexed access, and calldata→memory copy alike.
- Offset `2^255`: **NO revert.** solc's tail check uses signed
  comparisons (`slt`/`sgt`); a 2^255 offset is negative as signed, both
  checks pass, `calldataload` of the huge address returns 0, and the
  member silently reads as an **empty `bytes`/array** (length 0, huge
  `.offset`). Indexed access then Panics (0x32) only because length is
  0. A `bytes calldata` slice built from such a member has a huge
  `.offset`; assembly `calldataload(d.offset)` returns zeros.
- Blown-up **length** word (0x10000 or 2^255) with a canonical offset:
  solc **reverts** (short-tail check).
- Raw hand-rolled assembly reads (no solc accessor) never revert and
  see zeros for all out-of-bounds cases.

**E2 — dirty high bits in a uint32 member of a re-tagged struct:**
solc-generated member access **reverts** (validation, same as
abi.decode). The dirty value neither propagates nor gets cleaned.

**E3 — aliased/overlapping in-bounds offsets:** two members pointing at
the same/overlapping tail region read **normally with no objection**,
as long as each member individually passes its own bounds check. A
payload with `data` aliased onto the `words` tail returned consistent
values from both members. (An alias whose reinterpreted count word
implies more bytes than calldatasize reverts on the short-tail check.)

**Consequences for the re-tag design:** solc's generated checks are a
real but **incomplete** backstop. They catch moderate OOB offsets, OOB
lengths, and dirty value-type bits (all as reverts), but (i) 2^255-class
offsets silently alias members to empty values, and (ii) in-bounds
non-canonical framing (aliasing, gaps, non-minimal offsets, trailing
bytes, dirty `bytes` padding) is accepted. Even so, in this codebase
every such silent misread lands in a downstream shape guard (length /
count == profile constant) or a hash comparison and fails closed —
we found **no wrong-accept**. What survives without the walk is
unbounded byte-malleability plus a mixed revert/false failure surface.

**Walk gas (spike: WalkGas.t.sol, 256s shapes):**
- `isCanonicalStatelessEnvelope`: **330,896 gas** over a 92,256-byte
  envelope ≈ **14%** of the documented ~2.41M ERC-1271 stateless check
  (the canonical action entrypoints do not run a walk; baseline
  1,869,500).
- `isCanonicalStatefulEnvelope`: **1,762 gas** over 3,136 bytes ≈ ~1%
  of the ~180k ERC-1271 stateful check.
- The SHRINCSCodec `_isCanonicalEnvelope` walks are the same code
  (copied), so the verifier-adapter walks cost the same order.

---

## 2. Self-authentication traces

Trusted state: the installed 32-byte `publicKeyCommitment`
(SHRINCSVerifier key / wrapper `currentSHRINCSPublicKey`) and, for the
standalone SPHINCSPlusCVerifier, the pinned (pkSeed, hypertreeRoot) key.

**PublicKey bundle.** `statefulPublicKey`, `pkSeed`, `hypertreeRoot`
are hashed into the recomputed commitment
(SHRINCSCodec.sol:250-263) and compared against the installed
commitment (SHRINCSCodec.sol:311,314) → their **bytes** are
self-authenticating. **Critically, their lengths are NOT**: the
commitment preimage is `abi.encodePacked` of three variable-length
`bytes` (SHRINCSCodec.sol:256-262), which drops length separators. Two
different field splits of the same concatenation produce the same
commitment (concatenation ambiguity). The `validPublicKey` length
checks (SHRINCSCodec.sol:330-339) are the only thing pinning the split;
see row table. The `publicKeyCommitment` *field* is compared directly
against trusted state (SHRINCSCodec.sol:311) → self-authenticating
content, unbound length.

**Stateful signature (UXMSS).** `randomizer` and `counter` are bound
into the `uxmss-wots-digits` digest preimage (UXMSS.sol:125-134) whose
output steers chain walks whose endpoints are hashed
(`uxmss-wots-pk`, UXMSS.sol:195-204) into the leaf that must
reconstruct the committed root → self-authenticating. The **leaf
position** (leafIndex = authPath.length, UXMSS.sol:77) is bound into
the digits preimage (:129), the WOTS address base (:151), the
`uxmss-wots-pk` preimage (:199), and every `uxmss-node` parent
preimage via `leftLeafIndex` (UXMSS.sol:229-241, 282) →
position IS bound; a signature for leaf i cannot verify at leaf j
without a preimage break. `chains` **content** is self-authenticating
(endpoints hashed); the chains **count** is not bound (the loop and
the `segments` buffer are fixed at WOTS_CHAINS_STATEFUL; extra array
elements are never read).

**Stateless signature.** FORS `randomizer` bytes: bound into
`fors-digest` (FORSMinusC.sol:495-503) — content self-authenticating,
**length unbound** (exactly 32 bytes are mloaded regardless,
FORSMinusC.sol:501). `counter`: bound (:503). `secretLeaf` /
`authPath` node contents: hashed up to per-tree roots →
self-authenticating; entry count and per-entry path lengths unbound
(fixed loops; `fors-pk` input length is a compile-time constant,
FORSMinusC.sol:116). Hypertree layer coordinates: layer-0
treeIndex/leafIndex are recomputed from the digest and compared
(FORSMinusC.sol:112-113); upper-layer coordinates are chained by
shift/mask recurrence and compared (Hypertree.sol:94-95,158-161) →
self-authenticating through those comparisons. `wotsCPkHash` content:
compared against the reconstruction (Hypertree.sol:337) and used as the
subtree leaf → self-authenticating; length unbound. WOTS chain
contents: self-authenticating (endpoint hash); count unbound. authPath
lengths: unbound (fixed subtreeHeight loop).

**Pattern:** every leaf VALUE is self-authenticating; every LENGTH and
COUNT word is a pure control word — none is bound into any preimage
(preimage layouts are fixed-width; loops iterate profile constants).
The guards on lengths/counts are therefore exactly where scrutiny
belongs, and the classification splits them into: split-pins for the
packed commitment (class S), panic-prevention (class A), and
padded-array/oversized-bytes rejection (class M).

---

## 3. Verdict table

Out of scope (the verification itself, listed once): commitment
declared-and-recompute compares (SHRINCSCodec.sol:311,314); UXMSS root
compare (UXMSS.sol:102); WOTS-C target-sum (UXMSS.sol:189,
Hypertree.sol:324); FORS-C omitted-tree leaf-0 grinding rule
(FORSMinusC.sol:101-109); FORS digest coordinate compares
(FORSMinusC.sol:112-113); hypertree final root compare
(Hypertree.sol:181); WOTS-C pkHash compare (Hypertree.sol:337); wrapper
canonical-hash compares (SHRINCSAccountVerifierExample.sol:629,681).
Wrapper leaf/nonce/budget policy checks are the wrapper's replay layer,
not input guards.

| # | Guard | file:line | Class | Concrete attack if dropped | Verdict |
|---|-------|-----------|-------|----------------------------|---------|
| 1 | ERC-7913 key.length != 32 | SHRINCSCodec.sol:66 | S(cond)+A+M | If a caller ever registers a short/empty key, `calldataload(key.offset)` reads past the key into the **attacker-supplied envelope region** of the same calldata → attacker chooses the "installed" commitment → full forgery against that signer entry | **KEEP** |
| 2 | stateless key.length != 64 | SHRINCSCodec.sol:174 | S(cond)+A+M | Same shape, worse: pkSeed AND root read from attacker-adjacent calldata → attacker substitutes a keypair they own. (On the pinned-delegation path the key is verifier-built, class R there) | **KEEP** |
| 3 | Walk: offset == running cursor (all `word(...)==cursor/const` steps, incl. fixed head sizes) | SHRINCSCodec.sol:406-702; SHRINCSAccountEnvelope.sol:104-315,353-447 | A+M | None found for forgery — with the walk gone, abi.decode (today) or solc accessor checks + shape guards (re-tag world) still end in revert-or-false. What is admitted: unbounded framing malleability (gaps, non-minimal offsets, E3 aliasing) | **DROP-IF**(plain-revert model adopted AND byte-malleability accepted AND the zero-copy re-tag plan is re-based on E1b/E3 reality) |
| 4 | Walk: rdLen bounds (len/count ≤ plen, in-range read) | same, e.g. SHRINCSCodec.sol:460-463 | walk-internal S | Without it the walk's own cursor arithmetic wraps — it is what makes rows 3/5/6/7 sound | **KEEP** (inseparable from the walk while any walk exists) |
| 5 | Walk: `bytes` tail padding must be zero (rdPad) | e.g. SHRINCSCodec.sol:479-484 | M | Dirty padding decodes/reads identically → second encoding | **DROP-IF**(malleability accepted) |
| 6 | Walk: dirty-bit rejects (uint32 counter ×3, uint64 treeIndex, uint32 leafIndex) | SHRINCSCodec.sol:554,567,583-584,648; SHRINCSAccountEnvelope.sol:202,216,231-232,422 | A | abi.decode reverts on these today; E2 shows re-tagged member access also reverts. Guard only converts revert → 0xffffffff | **DROP-IF**(revert model) |
| 7 | Walk: full-consumption anchor (sigEnd == plen) | SHRINCSCodec.sol:678,697; SHRINCSAccountEnvelope.sol:312,444 | M | Trailing garbage → infinite second encodings | **DROP-IF**(malleability accepted) |
| 8 | Wrapper: signature.length < 1 | SHRINCSAccountVerifierExample.sol:136 | A | `signature[0]` on empty bytes reverts anyway (solc bounds check) | **DROP-IF**(revert model) |
| 9 | Wrapper: unknown mode byte → invalid | SHRINCSAccountVerifierExample.sol:194 | A (API) | Not really droppable — it is the mode dispatch's else-branch | **KEEP** |
| 10 | expectedPublicKeyCommitment == 0 reject | SHRINCSCodec.sol:298 | R | None: passing needs the recomputed commitment to equal 0 = keccak preimage of zero. Protects only the aesthetics of the uninstalled-key case, which already fails closed | **DROP** |
| 11 | publicKey.publicKeyCommitment.length != 32 (matchesExpected) | SHRINCSCodec.sol:300 | M, dup of #15 | Longer field with same 32-byte prefix passes; shorter reads adjacent heap (deterministic, no capability). Exact duplicate of validPublicKey:335, and both always run on every verify path | **DROP** (duplicate; keep one instance) |
| 12 | statefulPublicKey.length == 68 | SHRINCSCodec.sol:330-333 | **S**+M | Commitment preimage is length-free `encodePacked`; without split pins one commitment matches many (sPK,seed,root) splits of the same concatenation. Exploiting further needs a signature under a shifted window (second-preimage-hard), but the guard is what keeps the commitment an injective encoding by construction rather than by assumption | **KEEP** |
| 13 | pkSeed.length == 32 | SHRINCSCodec.sol:337 | **S**+M | Same split-pin role (see #12) | **KEEP** (one instance per field per path; see #24) |
| 14 | hypertreeRoot.length == 32 | SHRINCSCodec.sol:339 | **S**+M | Same | **KEEP** |
| 15 | publicKeyCommitment.length == 32 (validPublicKey) | SHRINCSCodec.sol:335 | M | Field is not part of the packed preimage; only its first 32 bytes are compared → longer field = second encoding | **KEEP** (as the surviving instance after #11 drops) |
| 16 | decodeStatefulPublicKey encoded.length != 68 | SHRINCSCodec.sol:363 | R (+memory-safety) | validPublicKey:330 always precedes on verify paths; but this check is the precondition making its own fixed-offset assembly reads in-buffer, and the function is a public library API | **KEEP** |
| 17 | validActionContext: nonzero domainSeparator/actionType/payloadHash | SHRINCS.sol:723-734 (used :273,:299; wrapper :634,:686) | R (policy) | None for forgery: all three are bound into the signed action hash, so a signature only verifies for exactly the values the signer signed. Pure signing-hygiene policy | **DROP-IF**(policy delegated to integrators); otherwise keep as policy, not as a security guard |
| 18 | UXMSS leafIndex == 0 | UXMSS.sol:92 | R (+typed fail-fast) | Explicitly returns false before WOTS work; jointly reviewed with #22, whose helper-level empty-path check remains defense in depth | **KEEP** (maintainer selected typed fail-fast; ground leaf-zero regression pinned) |
| 19 | UXMSS leafIndex > maxSignatures | UXMSS.sol:82 | R-crypto + work-bound | Forgery-wise redundant (position is hash-bound everywhere, §2); but authPath.length is an attacker-chosen loop bound in rootFromUnbalancedPath — this trusted (commitment-bound) cap is the only limit on attacker-forced hashing before rejection | **KEEP** |
| 20 | UXMSS chains.length != WOTS_CHAINS_STATEFUL | UXMSS.sol:84 | A+M | Short array → Panic(0x32) at :176 (revert, fail-closed); long array → extras never read → second encoding verifies | **DROP-IF**(revert model + malleability accepted) |
| 21 | rootFromUnbalancedPath authPath.length != leafIndex | UXMSS.sol:224 | R (tautological) | On the verify path leafIndex := authPath.length (:77), so this compares a value to itself | **DROP** (retain only if the function is kept as a public API with independent callers) |
| 22 | rootFromUnbalancedPath authPath.length == 0 | UXMSS.sol:222 | R (dup of #18 on verify path) | #18 now returns false before WOTS work; retained here as defense in depth for direct internal helper callers and to prevent authPath[0] Panic | **KEEP** (joint failure-policy pair with #18) |
| 23 | SPHINCSPlusC pkSeed/hypertreeRoot length != 32 | SPHINCSPlusC.sol:99,101 | R in-repo (S-twin at boundary) | Every in-repo caller supplies exactly 32 (facade widens bytes32; SHRINCS paths are validPublicKey-checked). At the open library boundary they are the twins of #13/#14 and the precondition of the mload-32 reads below | **DROP-IF**(library documented internal-only; otherwise keep as the boundary instance) |
| 24 | signature.hypertree.length == 0 | SPHINCSPlusC.sol:103 | A (R for rejection) | `hypertree[0]` at :112 Panics; Hypertree.sol:61 would reject the count anyway | **DROP-IF**(revert model) |
| 25 | FORS randomizer.length != 32 | FORSMinusC.sol:80 | M | fors-digest mloads exactly 32 bytes (:501); a 33+-byte randomizer with the same 32-byte prefix passes the walk (framing-canonical) and verifies identically → second encoding. Shorter reads adjacent heap (no capability) | **DROP-IF**(malleability accepted) — else KEEP |
| 26 | FORS entries.length != k-1 | FORSMinusC.sol:83 | A+M | Short → Panic at :144; long → extras never read → second encoding | **DROP-IF**(revert model + malleability) |
| 27 | FORS secretLeaf.length != 32 | FORSMinusC.sol:146 | M | hashForsLeaf32 mloads 32 (:336); length unbound in preimage | **DROP-IF**(malleability) |
| 28 | FORS entry.authPath.length != a | FORSMinusC.sol:149 | A+M | Short → Panic at :241; long → ignored | **DROP-IF**(revert model + malleability) |
| 29 | FORS authNode.length != 32 | FORSMinusC.sol:242 | M | mload-32 read (:247); length unbound | **DROP-IF**(malleability) |
| 30 | FORS root == 0 sentinel propagation | FORSMinusC.sol:177 | plumbing | This IS the error channel for #29's sentinel return; false-negative only on a genuinely zero root (≤2^-128) | **KEEP** (while #29 exists) |
| 31 | Hypertree layers.length != d | Hypertree.sol:61 | A+M+work-bound | Short → coordinate/root mismatch (addresses bind the layer index) or Panic-free false; long → attacker-forced extra WOTS work then guaranteed root mismatch. Also the loop/work anchor | **KEEP** |
| 32 | Hypertree layers.length == 0 | Hypertree.sol:67 | R | Unreachable (own comment: d != 0) | **DROP** |
| 33 | layer treeIndex/leafIndex != expected | Hypertree.sol:94-95 | crypto-structural | Coordinate chaining: with FORSMinusC:112-113 this is what makes every layer's address digest-derived (tautological at layer 0, real for layers ≥1). Dropping it frees upper-layer addresses → breaks the address-uniqueness assumption of the tweakable-hash security argument (splicing then still needs signed-value collisions, but the multi-target structure is weakened) | **KEEP** (equivalent refactor: use derived coords and delete the carried fields) |
| 34 | layer leafIndex >= leafCount | Hypertree.sol:97 | R (provable) | Unreachable: layer-0 leafIndex is a subtreeHeight-bit digest read (FORSMinusC.sol:436) and upper-layer values are masked by leafMask (:158) — both < leafCount by construction, and :94-95 force equality first | **DROP** |
| 35 | wotsCPkHash.length != 32 | Hypertree.sol:103 | M | mload-32 (:131); length unbound; duplicated by :215 | **DROP-IF**(malleability) — keep as the single instance (see #39) |
| 36 | layer authPath.length != subtreeHeight | Hypertree.sol:108 | R (dup of :417) | hypertreeRootFromPath32:417 checks the identical condition on the same value | **DROP** (duplicate; #42 kept) |
| 37 | wotsC randomizer.length != 32 | Hypertree.sol:211 | M | wotsDigest32 loads exactly 32 (:238); unbound length | **DROP-IF**(malleability) |
| 38 | wotsC chains.length != len | Hypertree.sol:213 | A+M | Short → Panic at :282; long → ignored | **DROP-IF**(revert model + malleability) |
| 39 | expectedPkHashBytes.length != 32 | Hypertree.sol:215 | R (dup of #35) | Sole caller passes the :103-checked field | **DROP** (duplicate) |
| 40 | wotsDigestBytes() > 32 | Hypertree.sol:222 | R (compile-time) | Folds to false on every supported profile; the profile-invariants test pins it | **DROP** (or keep per its own deliberate-defense comment — zero runtime cost after folding) |
| 41 | wots chain.length != 32 | Hypertree.sol:284 | M | mload-32 (:294); unbound length | **DROP-IF**(malleability) |
| 42 | hypertreeRootFromPath32 authPath.length != height | Hypertree.sol:417 | A+M | Short → Panic at :440; long → ignored | **KEEP** (as the surviving instance of the #36 pair; then DROP-IF like its class) |
| 43 | Hypertree expectedTreeIndex != 0 (post-loop) | Hypertree.sol:180 | R (provable) | Always false for the balanced layout (uint64 shifted by d·(h/d)=64 bits); own comment says so | **DROP** |

**Counts: KEEP 15 · DROP 8 · DROP-IF 20** (rows with pair-verdicts
counted once per row as listed).

---

## 4. Closing analysis

### (a) Failure surface if ALL class-A guards are dropped

Malformed input then produces **reverts instead of 0xffffffff**:
abi.decode validation reverts (today's pipeline), Panic 0x32 from
fixed-count loops indexing short arrays, or solc calldata-accessor
reverts (re-tag pipeline, E1/E2). No wrong-accept appears in any
combination we traced; the surface is strictly {revert, false, true}.
ERC-7913 explicitly permits this ("SHOULD return 0xffffffff **or**
revert"), so SHRINCSVerifier/SPHINCSPlusCVerifier remain conformant.
Consequences land on consumers: ERC-1271 integrators of the wrapper
that `staticcall` and check the magic value are unaffected (revert ≠
magic); integrators that *propagate* reverts (e.g. OpenZeppelin
`isValidSignatureNow` try/catch is fine, raw calls are not) turn clean
signature-rejection into failed calls, which degrades gas estimation
and batch flows (a 4337 bundler simulating a bad signature sees a
revert deep in validation instead of a false). One caveat from E1b: in
the re-tag world a subset of malformed envelopes does NOT revert (huge
offsets read as empty members) — those need at least the count/length
shape guards to resolve to `false`, so class-A guards cannot all be
dropped *simultaneously with* class-M shape guards without leaving
Panics as the only backstop (still fail-closed, but the revert reasons
become Panic codes rather than clean reverts).

### (b) What breaks if class-M guards are dropped

Forgery resistance: nothing — every M row's second encoding maps to the
**same logical signature** (same preimages, same compared hashes).
Affected parties are exclusively **byte-keyed downstream consumers**.
In THIS repo there are none: the wrapper's replay layer keys on
`leafIndex` (= authPath.length, a decoded scalar), `nonce`,
`keyVersion`, the `usedLeafBitmap[keyVersion][word]` bitmap, and the
stateless-use counter (SHRINCSAccountVerifierExample.sol:53-74,
703-737) — no mapping or event key is a hash of signature bytes.
ERC-4337's userOpHash excludes the signature field, so nonce-based
replay protection is unaffected. Who does break: any external system
that deduplicates, indexes, rate-limits, or replay-guards by
`keccak256(signature bytes)` (mempool rules, monitoring, off-chain
databases, third-party wrappers) silently sees N distinct byte-strings
for one logical signature. Dropping M also forfeits the "walk =
re-encode equality" invariant the differential test battery pins, and
the plan's Z3 slice-copy delegation (contiguous-tail assumption) leans
on canonical framing.

### (c) Gas share of the walks (measured, spike WalkGas.t.sol)

| Path | Walk gas | Path total | Share |
|------|----------|------------|-------|
| Wrapper ERC-1271 stateless (92,256 B envelope) | 330,896 | ~2.41M (NatSpec) | **~14%** |
| Wrapper ERC-1271 stateful (3,136 B envelope) | 1,762 | ~180k (NatSpec) | **~1%** |
| Canonical action entrypoints | 0 (no walk) | 1,869,500 / 264,779 (baseline) | 0% |

Verifier-adapter walks (SHRINCSCodec) are the same copied code, same
order of cost. The stateless walk is expensive in absolute terms but
still ~30% cheaper than the ~491k re-encode check it replaced; if the
maintainer adopts revert-model + accepts malleability, dropping the
stateless walk saves ~331k gas per ERC-1271 stateless check — by far
the largest single guard-cost in the system. Every other guard in the
table is a handful of gas.

### (d) Interaction with the zero-copy re-tag plan (binding finding)

The plan's RE-TAG SAFETY INVARIANT says solc bounds checks "remain as
backstop". E1b/E3 show that backstop is **partial**: 2^255-class
offsets alias silently to empty members, and in-bounds aliased framing
is accepted. Neither yields a wrong-accept *given the shape guards
stay*, but the plan should not describe solc as a completeness
guarantee, and the count/length guards (rows 20, 26, 28, 31, 38, 42)
must be treated as **non-droppable while the re-tag design stands**,
independent of the maintainer's revert-model decision — they are what
turns E1b's silent empty members into `false`.

---

# KEEP deep-dive (four-question analysis of every KEEP row)

New empirical work (spike guard-spike/, same solc 0.8.28 / via-ir /
opt-200 profile):

- **CryptoReject.t.sol** — a constant-bounded reconstruction loop (the
  WOTS-C / FORS / hypertree shape) with the count guard DROPPED, over a
  re-tagged calldata struct: **empty array → PANIC(0x32); short array →
  PANIC(0x32); exact → OK; long → OK (extras ignored).** Same for the
  `bytes[]` (authPath) shape: empty → PANIC(0x32), long → OK. So solc's
  calldata array-index bounds check rejects the E1b silently-empty and
  short cases as reverts; only the LONG (malleability) case survives to
  verify identically.
- **CapValue.t.sol** — per-iteration floor of an array-length-bounded
  loop: **~372 gas** for one keccak-of-64-bytes iteration. A real
  hypertree layer iteration runs a full 64-chain WOTS-C verify plus an
  8-node subtree path (~10^3 keccaks), i.e. **order 10^5 gas/layer**;
  a UXMSS auth-path iteration is ~1 parent-hash (~few hundred gas).

**Check-cost convention:** every length/count/coordinate guard is a
`MLOAD`/`CALLDATALOAD` + compare + `JUMPI` ≈ **~15-20 gas, analytic,
once per call** unless it sits in a loop (noted). None is measurable
against the 180k / 2.41M path totals; the walk-internal row is folded
into the measured walk totals (stateful 1,762 / stateless 330,896).

This finding CORRECTS review-message point 4: the E1b empty-member case
is caught by the crypto loop's solc bounds check (Panic), not only by
the shape guard, so those shape guards are **fail-fast + malleability**,
not the sole soundness mechanism.

## Category A — commitment encoding-injectivity (packed-preimage split-pins)

Commitment preimage is `abi.encodePacked("shrincs-public-key",
statefulPublicKey, pkSeed, hypertreeRoot)` (SHRINCSCodec.sol:256-262):
length-free concatenation.

**Row 12 — statefulPublicKey.length == 68 (Codec:330-333)**
1. Gas: ~19, analytic, once.
2. Outer check: NOT covered. The commitment compare (:314) hashes the
   concatenation; a different (sPK,seed,root) split of the same bytes
   yields the same commitment, so the compare cannot distinguish splits.
   decodeStatefulPublicKey:363 re-checks 68 but runs AFTER this.
3. Damage if dropped: the installed commitment stops being an injective
   encoding of the bundle — one commitment matches many field splits.
   Turning that into a forgery additionally needs a validly-signed
   signature under a shifted-window key (second-preimage-hard on
   keccak), so no realistic direct forgery, but injectivity would rest
   on a hardness assumption instead of on construction. Harmed: the
   signer whose commitment is installed.
4. Drop+pin? **No: guard is the mechanism.** Removing it changes the
   commitment from injective-by-construction to injective-by-assumption;
   fuzzing cannot restore a structural property.

**Rows 13 / 14 — pkSeed.length == 32 (Codec:337) / hypertreeRoot.length
== 32 (Codec:339)**: identical split-pin role for the other two packed
fields. Gas ~19 each, once. Not covered by any outer check (same reason
as 12). **KEEP (mechanism).**

**Row 15 — publicKeyCommitment.length == 32 (validPublicKey, Codec:335)**
1. Gas: ~19, once.
2. Outer check: the direct compare (:311) only reads the first 32 bytes
   (`mload(add(...,32))`); a longer field with the same 32-byte prefix
   is not distinguished. matchesExpected:300 checks the same thing but
   is the duplicate slated to DROP (row 11). So this is the surviving
   instance — NOT otherwise covered.
3. Damage if dropped: a longer `publicKeyCommitment` field re-encodes to
   a distinct envelope that still verifies (malleability); a shorter one
   reads adjacent heap deterministically (no attacker capability). Harm:
   byte-keyed consumers only.
4. Drop+pin? The field is not in the packed preimage, so it is pure
   class-M. **DROP-IF(malleability accepted); else KEEP** as the one
   surviving 32-byte pin. If kept, it is the mechanism for this field's
   uniqueness.

**Row 16 — decodeStatefulPublicKey encoded.length != 68 (Codec:363)**
1. Gas: ~19, once.
2. Outer check: **covered identically** on every verify path —
   validPublicKey:330 (row 12) always precedes and enforces the same 68.
3. Damage if dropped: on the verify path, none (row 12 already rejected).
   As a standalone public-library call it is the precondition making its
   fixed-offset assembly reads (Codec:383-387) stay in-buffer; without
   it a short input reads adjacent memory.
4. Drop+pin? **DROP+PIN** on the verify path: pin with an adversarial
   test asserting every production caller of decodeStatefulPublicKey is
   dominated by a validPublicKey/`== 68` check in the same frame (the
   twin already co-occurs). KEEP only if the library is treated as an
   open API with independent callers (memory-safety precondition).

## Category B — key calldata-window guards

**Row 1 — key.length != 32 (Codec:66)**
1. Gas: ~15, once.
2. Outer check: **not covered.** `calldataload(key.offset)` (:71) has no
   solc bounds check (raw assembly, not a typed accessor — E1 showed raw
   reads never revert).
3. Damage if dropped: with a short/empty registered key, the commitment
   word is read past the key into the **attacker-supplied envelope
   region of the same calldata**, so the attacker chooses the "installed"
   commitment → full forgery against that signer entry. Condition:
   requires an integrator to register a non-32-byte key (a
   misconfiguration ERC-7913 forbids, but the verifier is trustless and
   cannot assume it). Harmed: the misconfigured signer; attacker profits.
4. Drop+pin? **No: guard is the mechanism.** It is the only thing
   binding the commitment read to the key bytes. Not fuzz-substitutable.

**Row 2 — stateless key.length != 64 (Codec:174)**: same shape, both
seed words read from attacker-adjacent calldata if dropped → attacker
substitutes a keypair they control. On the internal pinned-delegation
path the 64-byte key is verifier-built (covered → DROP+PIN there), but
as the SPHINCSPlusCVerifier public entrypoint guard: **KEEP (mechanism).**
Gas ~15, once.

## Category C — structural / crypto-binding / dispatch / plumbing

**Row 4 — walk rdLen in-range/≤plen bounds (Codec:460-463 et al.)**
1. Gas: folded into the walk totals (part of every field read).
2. Outer check: none — it is the walk's own soundness primitive.
3. Damage if dropped: the walk's cursor arithmetic wraps; the offset and
   pad checks (rows 3/5/7) become unsound. Only matters if a walk exists.
4. Drop+pin? **No: guard is the mechanism** (while any walk stands). If
   the whole walk is dropped (rows 3/5/7 DROP-IF), this goes with it.

**Row 33 — layer treeIndex/leafIndex == expected (Hypertree:94-95)**
1. Gas: ~2 compares × d(=8) layers ≈ ~300, per call.
2. Outer check: partially — with FORSMinusC:112-113 pinning layer 0,
   this is tautological at layer 0 but load-bearing for layers ≥1
   (their coordinates are derived by shift/mask, :158-161).
3. Damage if dropped: upper-layer WOTS/subtree addresses become
   signature-chosen, weakening the address-uniqueness the tweakable-hash
   multi-target argument relies on. A concrete splice still needs
   signed-value collisions, so no one-shot forgery, but the security
   margin narrows. Harmed: the signer.
4. Drop+pin? **No: guard is the mechanism** (equivalent refactor: derive
   the coordinates and delete the carried fields — same enforcement, not
   a drop).

**Row 9 — unknown mode byte → invalid (wrapper:194)**: the dispatch
default branch, not a removable guard. Gas ~0. **KEEP (mechanism).**

**Row 18 — UXMSS leafIndex == 0 (UXMSS:92)**
1. Gas: ~15, once.
2. Outer check: **covered, but later.** rootFromUnbalancedPath rejects the
   same empty path only after WOTS reconstruction. Rows 18 and 22 are a
   joint failure-policy pair; neither row relies on the other being absent.
3. Damage if dropped: the helper check still prevents a Panic, but a ground
   leaf-zero signature forces one full WOTS reconstruction before rejection
   and makes the public path depend on a lower-level implementation detail.
4. Drop+pin? **KEEP (typed fail-fast; maintainer ruling for issue 14).** The
   public verify core returns false before chain work. A regression grinds the
   leaf-zero digest to the fixed target sum and requires a clean false return,
   so an earlier target-sum failure cannot make the test vacuous.

**Row 30 — FORS zero-root sentinel propagation (FORSMinusC:177)**
1. Gas: ~15 × signedTrees(=21) ≈ ~300, per call.
2. Outer check: it IS the error channel for the sentinel-returning
   checks (forsEntryRoot32 returns bytes32(0) on a bad authNode length,
   row 29). Not independently coverable.
3. Damage if dropped: a bad-length auth node's zero sentinel would be
   treated as a real root and hashed into the FORS pk → the FORS compare
   almost certainly still fails, but the explicit channel is cleaner.
   False-negative only on a genuinely-zero root (≤2^-128).
4. Drop+pin? **KEEP (plumbing)** while the sentinel pattern (row 29)
   exists; if row 29 is dropped (malleability accepted) this can go too.

## Category D — work-bound gas caps + E1b shape guards

**Row 19 — UXMSS leafIndex > maxSignatures (UXMSS:82)**
1. Gas: ~15, once.
2. Outer check: forgery-redundant (leaf position is hash-bound in every
   uxmss preimage, §2); NOT covered as a work bound.
3. Damage if dropped: leafIndex = authPath.length drives the
   rootFromUnbalancedPath loop (:230). Without the trusted cap
   (maxSignatures is commitment-bound, self-authenticating), a signature
   claiming leaf N forces N-1 parent hashes (~few hundred gas each)
   before failing. N is already bounded by calldata size (32N bytes), so
   this is a caller-paid griefing bound, not unbounded.
4. Drop+pin? **KEEP (gas-cap)**, ~O(authPath.length) parent-hashes
   worth; MAINTAINER-CHOICE if the calldata-size bound is deemed
   sufficient (then pin with an over-budget-leaf test returning false).

**Row 31 — Hypertree layers.length != d (Hypertree:61)**
1. Gas: ~15, once.
2. Outer check: **partially.** Empty layers → `layers[0]` at :79 (pre-
   loop) Panics; the verify loop is bounded by `layers.length` (:84), so
   short/long counts eventually mismatch the root or fail a coordinate
   check. So the SOUNDNESS role is covered (Panic/false) — CORRECTING
   the earlier "turns E1b empties into false" claim.
3. Damage if dropped: the loop runs `layers.length` iterations, each a
   full ~10^5-gas WOTS-C layer verify, and an attacker can make every
   layer's self-contained WOTS verify pass (all inputs attacker-chosen,
   target-sum grindable offline) so rejection only comes at the final
   root compare — **attacker-forced work ≈ layers.length × ~10^5 gas**,
   bounded only by calldata/block gas. Caller-paid, but a relayer/
   sponsor (4337 paymaster) could be the payer.
4. Drop+pin? **KEEP (gas-cap).** Rationale narrowed from injectivity to
   DoS bound. Worth ~10^5 gas per attacker-added layer. (Pinning the
   soundness half is easy — wrong-count → false — but the work bound is
   the guard's real job and is not fuzz-substitutable.)

**Row 42 — hypertreeRootFromPath32 authPath.length != height
(Hypertree:417)**
1. Gas: ~15 × d(=8) calls ≈ ~120, per call.
2. Outer check: **covered (different failure mode) for the danger case.**
   Spike-proven: short/empty authPath → `authPath[level]` at :440 Panics
   (0x32); the loop bound is the constant `height`, not the array
   length. Only a LONG authPath (extras ignored) survives → malleability.
3. Damage if dropped: empty/short → Panic (fail-closed); long → a second
   byte-encoding verifies identically (class M). No wrong-accept.
4. Drop+pin? **MAINTAINER-CHOICE (fail-fast + malleability).** CHANGED
   from KEEP: the crypto/solc bounds check already reverts the dangerous
   short case. Pin with a test: short authPath reverts, long authPath is
   rejected only if malleability-rejection is retained. Worth ~120 gas +
   the malleability property.

## Recommendation matrix

| Guard | file:line | Gas (per call) | Verdict |
|-------|-----------|----------------|---------|
| statefulPublicKey.length==68 | Codec:330 | ~19 | KEEP (mechanism) |
| pkSeed.length==32 | Codec:337 | ~19 | KEEP (mechanism) |
| hypertreeRoot.length==32 | Codec:339 | ~19 | KEEP (mechanism) |
| publicKeyCommitment.length==32 | Codec:335 | ~19 | KEEP (mechanism; DROP-IF malleability) |
| decodeStatefulPublicKey len==68 | Codec:363 | ~19 | DROP+PIN (dominated by Codec:330) |
| key.length==32 | Codec:66 | ~15 | KEEP (mechanism) |
| stateless key.length==64 | Codec:174 | ~15 | KEEP (mechanism) |
| walk rdLen bounds | Codec:460 | in walk total | KEEP (mechanism) |
| layer coord==expected | Hypertree:94 | ~300 (×8) | KEEP (mechanism) |
| unknown-mode dispatch | wrapper:194 | ~0 | KEEP (mechanism) |
| FORS zero-root sentinel | FORS:177 | ~300 (×21) | KEEP (plumbing, tied to FORS:242) |
| UXMSS leafIndex==0 | UXMSS:92 | ~15 | KEEP (typed fail-fast; ground regression pinned) |
| UXMSS leafIndex>maxSignatures | UXMSS:82 | ~15 | KEEP (gas-cap; ~O(authPath) parent-hashes) |
| Hypertree layers.length==d | Hypertree:61 | ~15 | KEEP (gas-cap; ~10^5 gas/attacker-layer) |
| hypertreeRootFromPath authPath==height | Hypertree:417 | ~120 (×8) | MAINTAINER-CHOICE (fail-fast+malleability; ~120 gas) |

**Net: KEEP-mechanism 10 · KEEP-gas-cap 2 · KEEP-failure-policy 1 ·
DROP+PIN 1 · MAINTAINER-CHOICE 1.** No KEEP row hides a wrong-accept; the two S-class rows
(commitment split-pins, key-window) are genuine construction mechanisms,
not fuzz-pinnable.

## Addendum — maintainer rulings 2026-07-12 (post-Z1)

- Hypertree.sol:405 authNode length pin (table gap, twin of row 29):
  DROP for class consistency. Execute as a micro-commit in the Z5
  wave, before Z5's gas re-measurement, with its adversarial case
  added to test/SHRINCSGuardPinning.t.sol ({revert,false} envelope).
- Hypertree wotsDigestBytes()>32 (now :190): KEEP, ruling confirmed.
  Compile-time profile-misconfiguration tripwire, not an input guard;
  outside this review's survivor-list framing.
- Forward note: the Hypertree coordinate-chaining KEEP row is
  scheduled to become moot at T6 — maintainer ruled to bundle the
  coordinate-field wire deletion into the T6 vector regeneration
  (see beads htu.3). The guard stays until T6 lands.
