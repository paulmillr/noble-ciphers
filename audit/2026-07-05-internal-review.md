# Internal review — 2026-07-05

Internal file-by-file review of the library (Claude Fable 5, 2026-07-05),
covering `src/aes.ts`, `src/chacha.ts`, `src/salsa.ts`, `src/_arx.ts`,
`src/_poly1305.ts`, `src/_polyval.ts`, `src/ff1.ts`, `src/utils.ts`,
`src/webcrypto.ts` and `src/index.ts`. Specs used as reference: FIPS 197,
SP 800-38A/D/F/G, SP 800-90A, RFC 3394/4493/5297/5649/8452, RFC 8439,
draft-irtf-cfrg-xchacha, and DJB's Salsa20/XSalsa20 papers; where possible,
behavior was cross-validated empirically against OpenSSL via `node:crypto`.
Not a substitute for the external audits listed in the README.

This document is the merged record of the five per-module review notes. It
keeps only what is actionable: applied fixes and changes, issues and caveats
found, tests added, and performance work (applied and rejected). The
per-module lists of items that were checked and found to conform to spec have
been dropped.

## Summary of changes

| File | Change |
|------|--------|
| `src/aes.ts` | `ctrCounter`/`ctr32` no longer compute one keystream block ahead |
| `src/aes.ts` | Per-block counter increment inlined (no re-validation per block) |
| `src/aes.ts` | `_CMAC.process()` avoids per-block revalidation + allocation |
| `src/aes.ts` | `dbl()` made branchless (removed secret-dependent branch) |
| `src/aes.ts` | ECB/CBC validate inputs before expanding the key |
| `src/_polyval.ts` | Unrolled W=4 / W=8 `_updateBlock` paths (~2× GHASH/POLYVAL) |
| `src/_polyval.ts` | `estimateWindow` W=2→W=4 threshold retuned 1 KiB → 384 B |
| `src/salsa.ts` | Frozen `__TESTS` hook exported (reference core was dead code) |
| `src/webcrypto.ts` | Keys imported as non-extractable |
| `src/webcrypto.ts` | Module docstring fix (`managedNonce`/`randomBytes` moved) |
| `src/utils.ts` | `u64Lengths` doc fix (units are caller-defined, not bits) |

Test suite: 808 → 823, all passing. `npm run check` clean (the pre-existing
`jsr: missing public JS entry ./index.js` warning also appears on a clean tree).

## AES — `src/aes.ts`

Scope: AES core and all modes (ECB, CBC, CFB, CTR, GCM, GCM-SIV, AES-SIV/S2V,
KW, KWP, CMAC, CTR-DRBG).

### Issues found and fixed

1. `dbl()` had a secret-dependent branch (`if (carry) block[15] ^= 0x87`); the
   carry bit derives from `E_K(0)` during CMAC subkey generation. Made
   branchless (`^= 0x87 & -carry`). Consistent with the library's
   "algorithmic constant-timeness" policy.
2. `cbc.encrypt`, `cbc.decrypt`, `ecb.decrypt` expanded the AES key before
   validating inputs/output buffer, so a validation throw left an unwiped
   expanded key for the GC. Reordered to validate first. (`cfb`, `ctr`, `gcm`
   already validated first or clean on all paths.)

### Other changes applied

3. **`ctrCounter` / `ctr32` loop restructure** — both previously computed one
   keystream block *ahead* of consumption, wasting one full AES block
   encryption per call (a call encrypting N whole blocks performed N+1 block
   encryptions). The keystream is now computed at the top of each iteration
   and once in the partial-tail branch. Output bytes, final counter state, and
   the unsafe partial-block-continuation contract are unchanged (pinned by
   existing `unsafe ctrCounter/ctr32` tests). This removes 1 of K+1 AES calls
   per CTR invocation and 3 wasted AES calls per GCM operation
   (H derivation, tag mask, payload).
4. **`ctrCounter` counter increment inlined** — the per-block
   `incBytes(ctr, false, 1)` re-ran `abytes` + `Number.isSafeInteger`
   validation for every 16 bytes of payload. Replaced with the same
   fixed-shape 16-byte carry walk, inlined. `incBytes` itself is unchanged
   (still used by the DRBG per *call*, and exported via `__TESTS`).
5. **CMAC block processing** — `_CMAC.process()` went through
   `encryptBlock()`, which re-validated arguments and allocated a fresh
   `Uint32Array` view per 16-byte block; `update()` also allocated a
   `subarray` per block. `process(data, pos)` now XORs bytes directly and uses
   a cached word view `x32` created once in the constructor.
   `destroy()` semantics unchanged (`x32` aliases `x`).

### Tests added — `test/aes.test.ts` (808 → 810)

1. **`CTR 128-bit counter wraparound (fixed vectors)`** — three
   OpenSSL-derived vectors: full wrap `ff..ff → 00..00` across whole blocks,
   wrap immediately before a final partial block, and carry propagation that
   stops mid-counter. The previous wraparound coverage cross-checked against
   `node:crypto` at runtime and was skipped entirely on Deno; these vectors are
   environment-independent and directly pin the newly inlined increment.
2. **`GCM-SIV AES-192 local extension`** — roundtrip + corrupted-tag rejection
   for 24-byte keys, which no RFC 8452 or Wycheproof vector exercises.

### Observations (not fixed, by design or negligible)

- AES T-tables are cache-timing observable; this is a documented, deliberate
  design choice matching OpenSSL/Go — do not "fix".
- CBC/ECB PKCS#7 unpadding failure is observable as a decrypt error
  (padding-oracle risk if exposed remotely); already documented in TSDoc. The
  unpad check itself runs in constant shape over 16 tail bytes.
- `aessiv`'s RFC limits (`2^132`) exceed `Number.isSafeInteger`, so the
  effective enforced limit is `2^53 - 1`; irrelevant since typed arrays are
  far smaller.

### Known deviations / local extensions (unchanged)

- GCM accepts nonces ≥ 8 bytes (SP 800-38D allows narrowing; OpenSSL accepts
  shorter). Intentional.
- KW rejects 8-byte inputs, disagreeing with Wycheproof; this follows
  SP 800-38F §5.3.1 and is documented in the file.
- GCM-SIV accepts 24-byte (AES-192) keys, a local extension outside RFC 8452;
  now pinned by a test.

### Performance

Node v24.16.0, x86-64 Linux. Baseline vs. after (MiB/s, `benchmark`-style
one-shot encrypt; 64-byte numbers are noisy ±15%, 1 MiB numbers stable ±3%):

| op                | 64 B before | 64 B after | 1 MiB before | 1 MiB after |
|-------------------|------------:|-----------:|-------------:|------------:|
| aes-ctr-256       | 25.5        | 30–37      | 163          | 169–171     |
| aes-gcm-256       | 7.9         | 7.2–8.3    | 101          | 96–100      |
| aes-gcm-siv-256   | 6.1         | 6.2–7.0    | 95           | 94          |
| aes-siv-512       | 7.3         | 6.7–7.5    | 62           | 69–76       |
| cmac-256          | 28.8        | 28         | 104          | **139–141** |
| rngAesCtrDrbg 1KB | —           | —          | 120          | 128–129     |

Robust wins: CMAC +35% at 1 MiB, AES-SIV +11–20% at 1 MiB (it MACs the whole
message via CMAC), CTR +4% at 1 MiB and clearly better at small sizes,
DRBG +7%. GCM/GCM-SIV large-payload throughput is GHASH/POLYVAL-bound and
unchanged (see the `_polyval.ts` section, which addresses this); small-payload
GCM benefits slightly from the removed wasted blocks.

### Speed-ups investigated, not applied

1. **GHASH/POLYVAL window size** (largest lever for GCM) — deferred to the
   `_polyval.ts` review below, where it was applied.
2. **AES-SIV / S2V shared key schedule.** `s2v()` calls the public
   `cmac(msg, key)` once per component (`<zero>`/`<one>`, each AAD, final `T`),
   and every call re-runs `expandKeyLE` + subkey derivation (2 extra AES
   blocks). Letting `s2v` build one `_CMAC`-style context and reuse the
   expanded key/K1/K2 across components would substantially improve
   small-payload `aessiv` (currently ~7 MiB/s at 64 B, i.e. dominated by key
   setup). Requires a private constructor path for `_CMAC`; moderate,
   contained refactor — recommended as the next optimization if `aessiv`
   matters.
3. **Per-block `{s0..s3}` object return from `encrypt()`/`decrypt()`** —
   measured a variant writing to a module-level scratch array: ~1–2% on ECB
   1 MiB, within noise. V8's escape analysis already elides the allocation.
   Not worth the readability cost; keep the current style.
4. **CTR vs ECB gap** (169 vs 309 MiB/s) is mostly inherent: CTR reads the
   source, XORs, and maintains the counter, and sits at the same level as CBC
   encrypt (181). Keeping the counter in u32 words instead of bytes was
   considered; the byte walk costs little (see #3-style measurement) and the
   byte layout is what makes the BE/LE handling auditable.
5. **Fixed-round specializations / loop unrolling** (dedicated AES-128 10-round
   path): expected single-digit gains, hurts bundle size and auditability.
   Skipped.
6. **The real large-payload speed-up already exists**: `webcrypto.ts` delegates
   GCM/CTR/CBC to native code at ~GB/s. For bulk data, users should prefer it;
   the pure-JS path's priority is correctness/auditability, per CLAUDE.md.

## ARX — `src/chacha.ts`, `src/salsa.ts`, `src/_arx.ts`, `src/_poly1305.ts`

Scope: the Salsa20 / ChaCha cores, extended-nonce constructions, Poly1305 and
the two AEADs (`chacha20poly1305` / `xchacha20poly1305`, `xsalsa20poly1305`),
the shared ARX counter machinery.

### Changes applied

`src/salsa.ts` — test hook only, no algorithmic change:

- Exported frozen `__TESTS = { salsaCore_small, salsaCore }`, mirroring
  `chacha.ts`. Previously `salsaCore_small`/`salsa()` were dead code, so the
  "reference implementation matches production" property was only enforced for
  ChaCha. Comments updated to match chacha.ts wording.

No source speed-ups were applied — unlike `aes.ts`, the ARX hot paths contain
no wasted work.

### Tests added — `test/arx.test.ts` (810 → 814)

1. **`salsaCore_small matches salsaCore`** — reference vs unrolled core at
   counters 0, 1, `0xfffffffe`.
2. **`RFC 8439 §2.4.2 with explicit counter=1`** — the sunscreen-text vector,
   which is the only spec vector exercising the *public* `counter` argument of
   `chacha20` (previously nonzero counters were only tested on the throwing
   overflow path; AEAD covers counter=1 only indirectly).
3. **`counter=k continues the stream at block k`** — continuation property for
   all five stream ciphers (`chacha20`, `chacha20orig`, `xchacha20`,
   `salsa20`, `xsalsa20`): the AEAD wrappers rely on exactly this contract.
4. **`last valid counter block 0xfffffffe succeeds`** — success side of the
   overflow boundary. ChaCha20 keystream is pinned to an OpenSSL 3
   cross-checked vector; Salsa20 keystream is pinned and additionally
   cross-checked against the reference core (LE hosts). Also asserts one block
   past the boundary still throws.

### Observations (not fixed, by design or negligible)

- On mid-stream counter overflow, `runCipher` has already XORed earlier blocks
  into `output` before throwing — partial output is observable on the error
  path. Keys are still wiped; the throw-side oracles pin this behavior.
- The in-loop overflow check runs *after* the core computes the to-be-rejected
  block: one wasted permutation on the error path only. Not worth reordering
  audited code.
- `Poly1305.update()` copies the entire input on every call. This is
  deliberate hardening from the March 2026 typed-arrays audit pass (defends
  against exotic/resizable/shared buffers mutating during MAC computation).
  Measured cost: ~3.5% at 1 MiB, ~13% on one-shot 64 B `poly1305()` (copy +
  alloc dominates small inputs). If this ever matters, a maintainer-level
  policy decision could narrow the copy (e.g. skip for plain non-resizable
  `ArrayBuffer`-backed inputs), trading auditability for speed. Left as is.
- The reference helpers (`chacha()`, `salsa()`) share module-level scratch
  (`ctmp`/`stmp`) and are non-reentrant; they are reachable only through the
  frozen test-only `__TESTS` hooks. Comments already state this.
- `_poly1305_aead` and `xsalsa20poly1305` borrow caller key/nonce/AAD by
  reference (mutating them between construction and use changes results);
  documented in source comments.

### Performance

Node v24.16.0, x86-64 Linux (MiB/s, one-shot encrypt; ±3% at 1 MiB):

| op                | 64 B | 1 MiB |
|-------------------|-----:|------:|
| chacha20          | 71.5 |   797 |
| salsa20           | 47   |   849 |
| poly1305          | 114  |   549 |
| chacha20poly1305  | 21.7 |   326 |
| xchacha20poly1305 | 17.4 |   326 |
| xsalsa20poly1305  | 29.6 |   331 |

Numbers are unchanged after this review (no hot-path edits). AEAD cost is
exactly additive: `1/326 ≈ 1/797 + 1/549` — at 1 MiB, **Poly1305 consumes ~59%
of AEAD time**, the stream cipher ~41%.

### Speed-ups investigated, none applied

1. **Poly1305 `5·r` precompute** (the donna-32-style `s` array). Prototyped and
   measured: 1 MiB within noise (V8's GVN already commons the repeated
   `5 * rX` products), 64 B ~9% *slower* (extra constructor work + array
   loads). Rejected.
2. **Removing the `update()` input copy** — measured +3.5% (1 MiB) / +13%
   (64 B), but it is deliberate audit hardening; see observations. Rejected
   here; policy call for the maintainer.
3. **Poly1305 wider limbs** — the largest lever for AEAD throughput at every
   size, since Poly1305 is now slower than ChaCha itself. The current 10×13-bit
   limb schedule does ~100 multiplies per 16-byte block. A double-precision
   6×22-bit schedule (products ≤ 44 bits, sums < 2^53) or a
   `BigUint64Array`-based donna-64 could plausibly reach 1.5–2×, but is a
   full rewrite of the most delicate audited arithmetic in the library
   (`finalize()` carry/select logic included). Only worth it with new external
   review; the constructor comment already notes the BigUint64Array option.
4. **AEAD double key-setup** — each `chacha20poly1305` operation invokes the
   public stream cipher twice (counter 0 for the one-time key, counter 1 for
   payload), so key validation/copy and nonce normalization run twice; for
   `xchacha20poly1305`, **HChaCha runs twice per operation** (~2 extra
   permutations, visible in the 21.7 → 17.4 MiB/s gap at 64 B). A restructure
   could derive the subkey once, or use the secretbox trick (encrypt
   `zeros(64) ‖ plaintext` in one call — RFC 8439's OTK is block 0 and payload
   starts at block 1, so the stream is contiguous; 32 of the 64 prefix bytes
   are wasted by construction). Estimated +15–25% for small payloads, ~0 at
   1 MiB. Requires either an internal `createCipher` entry point taking a
   pre-derived subkey or a changed scratch/output-buffer contract; moderate
   refactor of audited code. Recommended next optimization if small-message
   AEAD throughput matters.
5. **Multi-block core calls / SIMD-style batching** in `runCipher`: JS has no
   SIMD; interleaving two blocks in scalar registers was not attempted — the
   unrolled cores already saturate V8's register allocator (32 live locals),
   and doubling that would spill. Skipped.

## GHASH / POLYVAL — `src/_polyval.ts`

Scope: the table-driven GF(2^128) multiplication (GHASH per NIST SP 800-38D,
POLYVAL per RFC 8452), the key/window precompute. This file was identified as
the AES-GCM bottleneck in the AES review above, which deferred the "window
size" investigation here.

### Changes applied

`src/_polyval.ts`:

1. **Unrolled W=8 and W=4 fast paths in `_updateBlock`** — the generic
   triple-nested walk (word → byte → bit-group, with per-block temporary
   array) is replaced for the two large-message windows by flat sequences of
   16 (W=8) / 32 (W=4) table lookups XORed in wide trees. Identical table,
   identical window order and MSB-first bit consumption — only loop structure
   changed; the generic walk remains as the W=2 / reference path. Measured
   (Node v24, x64): GHASH 16 KiB 160 → 307 MiB/s, 1 MiB 222 → 459 MiB/s;
   POLYVAL 1 MiB 202 → 432 MiB/s.
2. **`estimateWindow` threshold retune** — with the unrolled W=4 path, the
   W=2→W=4 crossover moved from ~1 KiB down to ~384 bytes (measured 384 B:
   tie; 512 B: +15%; 1 KiB: +50% for W=4). Threshold changed from
   `> 1024` to `> 384`. The W=8 threshold (64 KiB) re-measured as still
   reasonable (build-cost crossover in the tens of KiB). Window choice cannot
   affect results (see new test); memory delta is 256 extra table entries.

### Tests added — `test/polyval.test.ts` (814 → 815)

- **`window sizes W=2/4/8 produce identical digests`** — same messages
  (lengths 0..256, crossing block boundaries) hashed under `expectedLength`
  hints selecting each window, for both `ghash` and `polyval`. Previously all
  direct vectors were short enough to exercise only W=2, so the W=4/W=8
  construction+lookup paths were pinned only indirectly via large crosstest
  payloads; with dedicated unrolled code paths this equivalence is now
  load-bearing.

### Observations (not fixed, by design or negligible)

- The shared module-level `ZEROS16`/`ZEROS32` tail-padding scratch is
  non-reentrant by construction but safe in single-threaded JS: it is filled,
  consumed, and wiped within one `update()` call, and `_updateBlock` cannot
  throw. The file already carries a `TODO: rewrite` for it.
- `destroy()` wipes the key-derived table but deliberately leaves the four
  scalar accumulator words (documented in a comment; JS numbers cannot be
  reliably wiped anyway, and the `destroyed` guard blocks further use).
- The constructor's window validation accepts `W = 1` while the error message
  says "expected 2, 4 or 8"; unreachable, since `estimateWindow` only returns
  {2, 4, 8}.
- Table lookups are secret-key-dependent memory accesses (like AES T-tables) —
  consistent with the library's documented "algorithmic constant-timeness
  only" policy. The unrolled paths change loop structure, not the access
  pattern. Do not "fix".

### Performance

Node v24.16.0, x86-64 Linux (MiB/s, one-shot encrypt):

| op                 | before | after | Δ     |
|--------------------|-------:|------:|-------|
| ghash 16 KiB       |    160 |   307 | +92%  |
| ghash 1 MiB        |    222 |   459 | +107% |
| polyval 1 MiB      |    202 |   432 | +114% |
| aes-gcm-256 1 KiB  |   46.4 |  55.5 | +20%  |
| aes-gcm-256 16 KiB |     83 |   109 | +31%  |
| aes-gcm-256 1 MiB  |    101 |   119 | +18%  |
| aes-gcm-siv 1 KiB  |   42.5 |  51.9 | +22%  |
| aes-gcm-siv 16 KiB |   78.6 |   107 | +36%  |
| aes-gcm-siv 1 MiB  |   94.8 |   126 | +33%  |

64-byte one-shot GHASH is unchanged (~14–16 MiB/s): it is dominated by the
per-key precompute (128 doublings), not by block processing.

### Speed-ups investigated, not applied

1. **Flat `Uint32Array` table instead of `{s0,s1,s2,s3}` objects** —
   prototyped and measured: consistently *slower* (−13% at 1 MiB, −23% at
   16 KiB). V8's monomorphic object-shape loads beat bounds-checked typed-array
   indexing here. Rejected; the current object layout is also what the wipe in
   `destroy()` assumes.
2. **Hoisting the per-block `[s0,s1,s2,s3]` array literal into instance
   scratch** — no effect (V8 escape analysis already elides it); the win in
   the applied change comes from the flat unroll, not allocation removal.
3. **Wider windows (W=16)** — table becomes 8 × 65536 entries (~8 MiB per
   key); unacceptable memory and precompute cost. Not viable.
4. **Faster constructor via incremental table build** (`entry[b] =
   entry[b & (b-1)] ⊕ doubles[lowest bit]`, 1 XOR per entry instead of up to
   W) — would cut the per-key precompute roughly in half, helping small
   one-shot messages and per-encrypt GCM setup. Kept out of this change to
   keep the diff auditable; worthwhile follow-up if small-payload GCM matters.
5. **Carry-less multiply tricks** — JS has no CLMUL and 32-bit shift-based
   polynomial multiplication loses to table lookups; WebCrypto (`webcrypto.ts`)
   remains the right path for native-speed GCM.

## FF1 — `src/ff1.ts`

Scope: FPE-FF1 against NIST SP 800-38G (Algorithms 7/8, PRF from §4.3 /
Algorithm 6) and the `BinaryFF1` byte wrapper.

### Changes applied

No source changes: nothing in `ff1.ts` needed fixing, and performance work
would be misdirected (10 short CBC-MACs + BigInt conversions per call; the
in-source note about not inlining the AES helpers is accurate). FPE throughput
is not a goal.

### Tests added — `test/ff1.test.ts` (815 → 822)

1. **NIST AES-192 sample vectors** (FF1samples.pdf samples 4–6: radix 10
   with/without tweak, radix 36) — the 24-byte-key FF1 path had zero coverage;
   the implementation reproduces all three published ciphertexts exactly
   (encrypt + decrypt).
2. **`minLen` boundary test** — radix 10 rejects length 1 / accepts length 2;
   radix 2 rejects 6 digits / round-trips 7 (`2^7 = 128 ≥ 100`); radix 65535
   rejects a single digit.

### Observations (not fixed, by design or negligible)

- **FF1 is not constant-time here**: BigInt arithmetic, digit-dependent loop
  shapes, and value-dependent radix conversions all leak timing about secret
  numeral strings. This is inherent to a JS BigInt implementation and
  consistent with the library's "algorithmic constant-timeness only" policy,
  but FF1 operates on *plaintext-derived* values in every round, so the
  exposure is broader than for the block ciphers. Users with adversarial
  co-tenancy should be aware.
- **Small-domain FPE caveats**: post-2016 research (message-recovery attacks
  on small domains) led NIST's SP 800-38G revision drafts to recommend domains
  of at least one million (radix^n ≥ 10^6). The implementation enforces only
  the spec's original `radix^n ≥ 100`. Callers should keep domains large.
- **Radix bound is stricter than the spec**: `radix ≤ 2^16 − 1` (the spec
  allows 2^16), because the 3-byte radix field of the P block is written as
  `0x00 ‖ uint16_be(radix)`. Documented in-source as pending a real 24-bit
  encoder.
- The `maxLen` guard (`maxLen >= 2**32`) is a tautology over a local constant
  (always false, `maxLen = 2^32 − 1`); only the `minLen > maxLen` disjunct can
  fire (radix 1). Harmless dead code kept for spec-shape readability.
- The `if (b)` guard before writing `[NUM_radix(B)]^b` is dead: `b ≥ 1`
  whenever inputs pass validation (v ≥ 1, radix ≥ 2). Harmless.
- Key and tweak are borrowed by reference into the bound `getRound` closure
  (documented in-source): mutating them after `FF1(...)` changes later
  results.

## utils / webcrypto / index

Scope: the shared validation/endianness/buffer machinery every cipher depends
on, the `wrapCipher` / `managedNonce` / `wrapMacConstructor` wrappers, and the
async WebCrypto delegation layer.

### Changes applied

`src/webcrypto.ts`:

1. **Keys imported as non-extractable** (`importKey(..., false, ...)` in both
   `utils.encrypt` and `utils.decrypt`) — the ephemeral `CryptoKey` never
   needs `exportKey`; defense-in-depth with no behavioral change (nothing in
   the wrapper or in WebCrypto encrypt/decrypt requires extractability).
2. **Module docstring fix** — it claimed the module provides `managedNonce`
   and `randomBytes`, which moved to `utils.ts`; now points there instead.

`src/utils.ts`:

3. **`u64Lengths` doc fix** — parameters were documented as "length in bits",
   but units are caller-defined: GCM passes bit lengths, ChaCha20-Poly1305
   passes byte lengths (RFC 8439 uses octet lengths). The helper writes raw
   values; the doc now says so.

### Tests added — `test/webcrypto.test.ts` (822 → 823)

- **`enforces encrypt-once and rejects tampered GCM ciphertext`** — the
  async wrappers' `consumed` flag and WebCrypto GCM tag rejection had no
  direct coverage.

### Observations (not fixed, by design or negligible)

- `isBytes` accepts cross-realm/Buffer views via the `constructor.name`
  fallback, so a deliberately renamed `Int8Array` subclass could pass the
  check. Only exploitable by the embedding application against itself.
- `wrapCipher`'s short-ciphertext error text says "length bigger than
  tagLength" although length *equal* to tagLength is accepted; the message
  only appears on inputs that are genuinely too short, so it cannot mislead a
  caller whose input was rejected. Cosmetic.
- `clean()` is best-effort zeroization, as its warning states — JS gives no
  guarantees (JIT spills, GC copies). Consistent library-wide.
- `wrapMacConstructor`'s zero-key probe instance (used to read
  `outputLen`/`blockLen`) is never destroyed; it holds no secrets, and the
  cost is one dead allocation per module load.
- `checkOpts` mutates `defaults` by design (documented); the only caller
  (`createCipher`) passes a fresh literal.
- `webcrypto.ts` re-imports the raw key per operation (no `CryptoKey`
  caching), and delegates nonce-length/key-length enforcement to the WebCrypto
  backend; both are documented in-source.

### Performance

Nothing to do: these are cold-path helpers. The only ones reachable per-block
(`swap8IfBE`, `swap32IfBE`, `isAligned32`) are already identity functions or
single comparisons on little-endian hosts, and the hex codecs use engine
builtins when available.
