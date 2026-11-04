# Compact stateless encoding

Linear: QUI-1328. The byte layout is defined in
`contracts/StatelessLayout.sol`. It is a Solidity encoding choice: the Rust
implementation has no encoder for it. The Rust implementation is the
reference for behaviour: `test/SHRINCSCompactDifferential.t.sol` checks the
verifiers against the Rust verdicts, and the sizes follow its profile
constants.

From 0.4.0 this is the only stateless signature encoding in the
repository. The ABI envelope and the struct-typed stateless code are gone.

## Why

Before 0.4.0 the SHRINCS stateless signature was ABI-encoded as
`abi.encode(PublicKey, SPHINCSPlusC.Signature)`. Every `bytes` field and
every array carries an offset word and a length word, and every 32-byte
node is a separate dynamic `bytes`. On the 256s profile that envelope was
91,680 bytes. Per QUI-1328, wrapped for ERC-1271 it exceeded the
WalletConnect relay payload cap, so a wallet could not request a stateless
signature over WalletConnect.

The compact encoding is the same data, with nothing else. It is a flat
concatenation of 32-byte words and two big-endian `uint32` counters. Every
size is a compile-time function of `SHRINCSParams`. On 256s the verifier
payload is 29,256 bytes, 32% of the ABI form.

## Entry points

| Contract | Function | Key | Signature |
| --- | --- | --- | --- |
| `SHRINCSVerifier` | `verifyStateless(key, hash, signature)` | 32-byte commitment | `PK ‖ PQ` (`PAYLOAD_LEN`) |
| `SPHINCSPlusCVerifier` | `verify(key, hash, signature)` | `abi.encode(pkSeed, hypertreeRoot)` | `PQ` (`PQ_LEN`) |

Both return `IERC7913SignatureVerifier.verify.selector` (`0x024ad318`) on
success and `0xffffffff` otherwise. The version tags moved to
`quip.shrincs-verifier.v5` and `quip.sphincsplusc-verifier.v4`.

`verifyStateless` decodes the key, then
`SHRINCS.prepareStatelessDelegation` checks the payload length, the
declared commitment against the key, that the stateful key is canonical
(`validStatefulPublicKeyEncoding`), and the recomputed bundle commitment.
It then derives `statelessRawMessageHash(commitment, hash)` and delegates
to the pinned SPHINCSPlusC sibling's `verify`. The FORS-C and hypertree
cryptography is the same set of hash calls with the same inputs as the
pre-0.4.0 struct-typed loops. Only the calldata reads differ.

The wallet envelope (magic `0x51504353`, encoding version, profile ID,
owner ECDSA) is outside the verifier and this repository; its description
here comes from QUI-1328. The verifier sees the bytes starting at the public
key.

## Layout

```
payload = PK || PQ
  PK                             PK_LEN = STATEFUL_PUBLIC_KEY_BYTES + 96
    statefulPublicKey            STATEFUL_PUBLIC_KEY_BYTES
    publicKeyCommitment          32
    pkSeed                       32
    hypertreeRoot                32
  PQ                             PQ_LEN = FORS_LEN + HYPERTREE_LEN
    FORS                         FORS_LEN = 36 + (k - 1) * FORS_ENTRY_LEN
      randomizer                 32
      counter                    4   (uint32, big-endian)
      entry[k - 1]               FORS_ENTRY_LEN = 32 + a * 32
        secretLeaf               32
        authPath[a]              a * 32
    hypertree                    HYPERTREE_LEN = d * LAYER_LEN
      layer[d]                   LAYER_LEN = 68 + len * 32 + h' * 32
        wotsCPkHash              32
        randomizer               32
        counter                  4   (uint32, big-endian)
        chains[len]              len * 32
        authPath[h']             h' * 32
```

`k` = `NUM_FORS_TREES`, `a` = `FORS_TREE_HEIGHT`, `d` =
`NUM_HYPERTREE_LAYERS`, `len` = `NUM_WOTS_CHAINS`, and `h'` =
`HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS`. Fields are the exact 32-byte
words the ABI path reads. Truncated profiles keep 32-byte words with
canonical low bytes, as in the ABI form.

### Sizes per profile

| Part | 256s (keccak, sha2) | 128s-q18, 128s-q20 |
| --- | --- | --- |
| PK | 164 | 164 |
| FORS entry | 480 | 800 |
| FORS | 36 + 21 × 480 = 10,116 | 36 + 5 × 800 = 4,036 |
| Hypertree layer | 2,372 | 1,668 |
| Hypertree | 8 × 2,372 = 18,976 | 1 × 1,668 = 1,668 |
| PQ | 29,092 | 5,704 |
| Payload (PK ‖ PQ) | 29,256 | 5,868 |
| Wallet envelope (37 + 65 + payload) | 29,358 | 5,970 |

`test/SHRINCSCompactLayout.t.sol` pins the 256s column and checks the
formula under every profile.

### Byte offsets (256s)

| Field | Payload offset | Length |
| --- | --- | --- |
| statefulPublicKey | 0 | 68 |
| publicKeyCommitment | 68 | 32 |
| pkSeed | 100 | 32 |
| hypertreeRoot | 132 | 32 |
| FORS randomizer | 164 | 32 |
| FORS counter | 196 | 4 |
| FORS entry `t` secretLeaf | 200 + 480·t | 32 |
| FORS entry `t` auth node `l` | 232 + 480·t + 32·l | 32 |
| layer `j` wotsCPkHash | 10,280 + 2,372·j | 32 |
| layer `j` randomizer | 10,312 + 2,372·j | 32 |
| layer `j` counter | 10,344 + 2,372·j | 4 |
| layer `j` chain `i` | 10,348 + 2,372·j + 32·i | 32 |
| layer `j` auth node `l` | 12,396 + 2,372·j + 32·l | 32 |

`t` runs over 0..20, `l` over 0..13 for FORS and 0..7 for the hypertree,
`j` over 0..7, and `i` over 0..63.

## Revert model

The fixed layout has no offsets to follow. Each function checks one total
length up front. Every later read is at a constant offset that the length
check proves in bounds. So:

- wrong payload or signature length: `0xffffffff`
- wrong key length: `0xffffffff`
- commitment mismatch, non-canonical stateful key, or failed
  cryptography: `0xffffffff`
- out-of-gas: reverts
- `verifyStateless` with an undeployed sibling: reverts. There is no
  try/catch around the delegate call, so a missing sibling is never
  reported as an invalid signature.

A relying contract that `staticcall`s the stateless path cannot be stopped
by a malformed signature. `test/SHRINCSCompactAdversarial.t.sol` checks
this for truncation, trailing bytes, empty and zeroed payloads, arbitrary
junk, and bad key lengths, all through `staticcall`. Every word is read
inside the signature, never from adjacent calldata, so the ABI envelope's
framing malleability (including the masked-profile tail truncation) is
gone.

The `uint32` counter read loads a full 32-byte word and keeps the top four
bytes. Both counters sit at least 32 bytes before the end of their
section, so the extra bytes come from the next field and are discarded.

## Library and wallet surface

Nothing in `contracts/` takes a struct-typed stateless signature any more.
Every stateless signature is a `bytes calldata` slice in this layout:

- `SPHINCSPlusC.verify(pkSeed, hypertreeRoot, hash | message, signature)`
  takes the PQ section. `FORSMinusC.verifyForsCAndReturnRoot` and
  `Hypertree.verifyHypertree` take its FORS and hypertree slices.
- The `SHRINCS` library stateless functions (`verifyStateless`,
  `rotateStatefulViaStateless`, `statelessRotate`,
  `verifyStatelessUncheckedMessage`) take the PQ section as
  `bytes calldata`. The public key stays an ABI `SHRINCS.PublicKey`.
- The example wallet's stateless ERC-1271 action envelope is
  `abi.encode(PublicKey, bytes32 actionType, bytes32 payloadHash,
  bytes signature)` with `signature` the PQ section.
  `SHRINCS.statelessActionEnvelope` re-tags that field in place from its
  head offset and length word, without validation, with the same safety
  story as `statefulActionEnvelope`: a malformed envelope lands in
  {revert, false}.

The pre-0.4.0 struct types survive only in tests, as
`test/helpers/StatelessSignatureTypes.sol`, because the in-Solidity signers
and the Rust vector decoders still build signatures in that shape.
`SHRINCSTestCodec.encodeCompactSignature` and `encodeCompactPayload` turn
them into this layout.

`test/SHRINCSCompactDifferential.t.sol` checks the deployed verifiers
against the Rust generator's verdict on every stateless vector case, at
both the SHRINCS and SPHINCSPlusC layers, and against an in-Solidity
signed fixture. The Rust vectors are generated independently of this
repository's Solidity, so they are the reference.

## Golden vectors

`test/test_vectors/stateless-compact-256s.json` is written by
`test/SHRINCSCompactVectorExport.t.sol` under the default (256s keccak)
profile. Each vector has `commitment`, `declaredCommitment`, `hash`,
`statelessRawMessageHash`, `abiEnvelope`, `compactPayload`, `valid`, and
`expectedResult`. The deployed verifiers produce every result in that run,
and each result must match the Rust verdict before the file is written. The SDK
encoder must reproduce `compactPayload` byte for byte from the ABI form.
