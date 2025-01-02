# noble-ciphers

Audited & minimal JS implementation of Salsa20, ChaCha and AES.

- 🔒 [**Audited**](#security) by an independent security firm
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🏎 Fast: hand-optimized for caveats of JS engines
- 🔍 Reliable: property-based / cross-library / wycheproof tests ensure correctness
- 💼 AES: ECB, CBC, CTR, CFB, GCM, SIV (nonce misuse-resistant), AESKW, AESKWP
- 💃 Salsa20, ChaCha, XSalsa20, XChaCha, ChaCha8, ChaCha12, Poly1305
- 🥈 Two AES implementations: pure JS or friendly wrapper around webcrypto
- 🪶 29KB (11KB gzipped) for everything, 7KB (3KB gzipped) for ChaCha build

Take a glance at [GitHub Discussions](https://github.com/paulmillr/noble-ciphers/discussions) for questions and support.

### This library belongs to _noble_ cryptography

> **noble cryptography** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds
- All libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [post-quantum](https://github.com/paulmillr/noble-post-quantum),
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)
- [Check out homepage](https://paulmillr.com/noble/)
  for reading resources, documentation and apps built with noble

## Usage

> npm install @noble/ciphers

> deno add jsr:@noble/ciphers

We support all major platforms and runtimes.
For React Native, you may need a
[polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file
[noble-ciphers.js](https://github.com/paulmillr/noble-ciphers/releases) is also available.

```js
// import * from '@noble/ciphers'; // Error: use sub-imports, to ensure small app size
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
```

- [Examples](#examples)
  - [Encrypt with XChaCha20-Poly1305](#encrypt-with-xchacha20-poly1305)
  - [Encrypt with AES-256-GCM](#encrypt-with-aes-256-gcm)
  - [AES: gcm, siv, ctr, cfb, cbc, ecb](#aes-gcm-siv-ctr-cfb-cbc-ecb)
  - [Friendly WebCrypto AES](#friendly-webcrypto-aes)
  - [AESKW and AESKWP](#aeskw-and-aeskwp)
  - [Auto-handle nonces](#auto-handle-nonces)
  - [Reuse array for input and output](#reuse-array-for-input-and-output)
  - [All imports](#all-imports)
- [Internals](#internals)
  - [Implemented primitives](#implemented-primitives)
  - [Which cipher should I pick?](#which-cipher-should-i-pick)
  - [How to encrypt properly](#how-to-encrypt-properly)
  - [Nonces](#nonces)
  - [Encryption limits](#encryption-limits)
  - [AES internals and block modes](#aes-internals-and-block-modes)
- [Security](#security)
- [Speed](#speed)
- [Upgrading](#upgrading)
- [Contributing & testing](#contributing--testing)
- [License](#license)

## Examples

> [!NOTE]
> Use different nonce every time `encrypt()` is done.

#### Encrypt with XChaCha20-Poly1305

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';
const key = randomBytes(32);    // random key
// const key = new Uint8Array([ // existing key
//   169, 88, 160, 139, 168, 29, 147, 196, 14, 88, 237, 76, 243, 177, 109, 140,
//   195, 140, 80, 10, 216, 134, 215, 71, 191, 48, 20, 104, 189, 37, 38, 55,
// ]);
// import { hexToBytes } from '@noble/ciphers/utils'; // hex key
// const key = hexToBytes('4b7f89bac90a1086fef73f5da2cbe93b2fae9dfbf7678ae1f3e75fd118ddf999');
const nonce = randomBytes(24);
const chacha = xchacha20poly1305(key, nonce);
const data = utf8ToBytes('hello, noble');
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext); // utils.bytesToUtf8(data_) === data
```

#### Encrypt with AES-256-GCM

```js
import { gcm } from '@noble/ciphers/aes';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';
const key = randomBytes(32);
const nonce = randomBytes(24);
const data = utf8ToBytes('hello, noble');
const aes = gcm(key, nonce);
const ciphertext = aes.encrypt(data);
const data_ = aes.decrypt(ciphertext); // utils.bytesToUtf8(data_) === data
```

#### AES: gcm, siv, ctr, cfb, cbc, ecb

```js
import { gcm, siv, ctr, cfb, cbc, ecb } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
const plaintext = new Uint8Array(32).fill(16);
for (let cipher of [gcm, siv]) {
  const key = randomBytes(32); // 24 for AES-192, 16 for AES-128
  const nonce = randomBytes(12);
  const ciphertext_ = cipher(key, nonce).encrypt(plaintext);
  const plaintext_ = cipher(key, nonce).decrypt(ciphertext_);
}
for (const cipher of [ctr, cbc, cfb]) {
  const key = randomBytes(32); // 24 for AES-192, 16 for AES-128
  const nonce = randomBytes(16);
  const ciphertext_ = cipher(key, nonce).encrypt(plaintext);
  const plaintext_ = cipher(key, nonce).decrypt(ciphertext_);
}
for (const cipher of [ecb]) {
  const key = randomBytes(32); // 24 for AES-192, 16 for AES-128
  const ciphertext_ = cipher(key).encrypt(plaintext);
  const plaintext_ = cipher(key).decrypt(ciphertext_);
}
```

#### Friendly WebCrypto AES

Noble implements AES. Sometimes people want to use built-in `crypto.subtle` instead. However, it has terrible API. We simplify access to built-ins.

> [!NOTE]
> Webcrypto methods are always async.

```js
import { gcm, ctr, cbc, randomBytes } from '@noble/ciphers/webcrypto';
const plaintext = new Uint8Array(32).fill(16);
const key = randomBytes(32);
for (const cipher of [gcm]) {
  const nonce = randomBytes(12);
  const ciphertext_ = await cipher(key, nonce).encrypt(plaintext);
  const plaintext_ = await cipher(key, nonce).decrypt(ciphertext_);
}
for (const cipher of [ctr, cbc]) {
  const nonce = randomBytes(16);
  const ciphertext_ = await cipher(key, nonce).encrypt(plaintext);
  const plaintext_ = await cipher(key, nonce).decrypt(ciphertext_);
}
```

#### AESKW and AESKWP

```ts
import { aeskw, aeskwp } from '@noble/ciphers/aes';
import { hexToBytes } from '@noble/ciphers/utils';

const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
const keyData = hexToBytes('00112233445566778899AABBCCDDEEFF');
const ciphertext =  aeskw(kek).encrypt(keyData);
```

#### Auto-handle nonces

We provide API that manages nonce internally instead of exposing them to library's user.

For `encrypt`, a `nonceBytes`-length buffer is fetched from CSPRNG and prenended to encrypted ciphertext.

For `decrypt`, first `nonceBytes` of ciphertext are treated as nonce.

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { managedNonce } from '@noble/ciphers/webcrypto';
import { hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
const key = hexToBytes('fa686bfdffd3758f6377abbc23bf3d9bdc1a0dda4a6e7f8dbdd579fa1ff6d7e1');
const chacha = managedNonce(xchacha20poly1305)(key); // manages nonces for you
const data = utf8ToBytes('hello, noble');
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext);
```

#### Reuse array for input and output

To avoid additional allocations, Uint8Array can be reused
between encryption and decryption calls.

> [!NOTE]
> Some ciphers don't support unaligned (`byteOffset % 4 !== 0`) Uint8Array as
> destination. It can decrease performance, making the optimization pointless.

```js
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';

const key = randomBytes(32);
const nonce = randomBytes(12);
const chacha = chacha20poly1305(key, nonce);

const input = utf8ToBytes('hello, noble'); // length == 12
const inputLength = input.length;
const tagLength = 16;

const buf = new Uint8Array(inputLength + tagLength);
const start = buf.subarray(0, inputLength);
start.set(input); // copy input to buf

chacha.encrypt(start, buf); // encrypt into `buf`
chacha.decrypt(buf, start); // decrypt into `start`
```

xsalsa20poly1305 also supports this, but requires 32 additional bytes for encryption / decryption,
due to its inner workings.

#### All imports

```js
import { gcm, siv } from '@noble/ciphers/aes';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { secretbox } from '@noble/ciphers/salsa'; // == xsalsa20poly1305
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';

// Unauthenticated encryption: make sure to use HMAC or similar
import { ctr, cfb, cbc, ecb } from '@noble/ciphers/aes';
import { salsa20, xsalsa20 } from '@noble/ciphers/salsa';
import { chacha20, xchacha20, chacha8, chacha12 } from '@noble/ciphers/chacha';

// KW
import { aeskw, aeskwp } from '@noble/ciphers/aes';

// Utilities
import { bytesToHex, hexToBytes, bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
import { managedNonce, randomBytes } from '@noble/ciphers/webcrypto';
import { poly1305 } from '@noble/ciphers/_poly1305';
import { ghash, polyval } from '@noble/ciphers/_polyval';
```

## Internals

### Implemented primitives

- [Salsa20](https://cr.yp.to/snuffle.html) stream cipher, released in 2005.
Salsa's goal was to implement AES replacement that does not rely on S-Boxes,
which are hard to implement in a constant-time manner.
Salsa20 is usually faster than AES, a big deal on slow, budget mobile phones.
    - [XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), extended-nonce
variant was released in 2008. It switched nonces from 96-bit to 192-bit,
and became safe to be picked at random.
    - Nacl / Libsodium popularized term "secretbox", a simple black-box
authenticated encryption. Secretbox is just xsalsa20-poly1305. We provide the
alias and corresponding seal / open methods. We don't provide "box" or "sealedbox".
    - Check out [PDF](https://cr.yp.to/snuffle/salsafamily-20071225.pdf) and
[wiki](https://en.wikipedia.org/wiki/Salsa20).
- [ChaCha20](https://cr.yp.to/chacha.html) stream cipher, released
  in 2008. Developed after Salsa20, ChaCha aims to increase diffusion per round.
  It was standardized in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
  and is now used in TLS 1.3.
    - [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
      extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
      randomly-generated nonces.
    - Check out [PDF](http://cr.yp.to/chacha/chacha-20080128.pdf) and [wiki](https://en.wikipedia.org/wiki/Salsa20).
- [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
is a variant of Rijndael block cipher, standardized by NIST in 2001.
We provide the fastest available pure JS implementation.
    - We support AES-128, AES-192 and AES-256: the mode is selected dynamically,
      based on key length (16, 24, 32).
    - [AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV)
    nonce-misuse-resistant mode is also provided. It's recommended to use it,
    to prevent catastrophic consequences of nonce reuse. Our implementation of SIV
    has the same speed as GCM: there is no performance hit.
    - We also have AESKW and AESKWP from
      [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394) / [RFC 5649](https://datatracker.ietf.org/doc/html/rfc5649)
    - Check out [AES internals and block modes](#aes-internals-and-block-modes).
- We expose polynomial-evaluation MACs: [Poly1305](https://cr.yp.to/mac.html), AES-GCM's [GHash](https://en.wikipedia.org/wiki/Galois/Counter_Mode) and
AES-SIV's [Polyval](https://en.wikipedia.org/wiki/AES-GCM-SIV).
    - Poly1305 ([PDF](https://cr.yp.to/mac/poly1305-20050329.pdf),
    [wiki](https://en.wikipedia.org/wiki/Poly1305))
    is a fast and parallel secret-key message-authentication code suitable for
    a wide variety of applications. It was standardized in
    [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and is now used in TLS 1.3.
    - Polynomial MACs are not perfect for every situation:
    they lack Random Key Robustness: the MAC can be forged, and can't
    be used in PAKE schemes. See
    [invisible salamanders attack](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/).
    To combat invisible salamanders, `hash(key)` can be included in ciphertext,
    however, this would violate ciphertext indistinguishability:
    an attacker would know which key was used - so `HKDF(key, i)`
    could be used instead.
- Format-preserving encryption algorithm (FPE-FF1) specified in NIST Special Publication 800-38G.
[See more info](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf).

### Which cipher should I pick?

We suggest to use XChaCha20-Poly1305.
If you can't use it, prefer AES-GCM-SIV, or AES-GCM.

### How to encrypt properly

- Use unpredictable key with enough entropy
  - Random key must be using cryptographically secure random number generator (CSPRNG), not `Math.random` etc.
  - Non-random key generated from KDF is fine
  - Re-using key is fine, but be aware of rules for cryptographic key wear-out and [encryption limits](#encryption-limits)
- Use new nonce every time and [don't repeat it](#nonces)
  - chacha and salsa20 are fine for sequential counters that _never_ repeat: `01, 02...`
  - xchacha and xsalsa20 should be used for random nonces instead
  - AES-GCM should use 12-byte nonces: smaller nonces are security risk
- Prefer authenticated encryption (AEAD)
  - chacha20poly1305 / aes-gcm / ChaCha + HMAC / AES + HMAC is good
  - chacha20 / aes-ctr / aes-cbc without poly1305 or hmac is bad
  - Flipping bits or ciphertext substitution won't be detected in unauthenticated ciphers
- Don't re-use keys between different protocols
  - For example, using secp256k1 key in AES can be bad
  - Use hkdf or, at least, a hash function to create sub-key instead
- If you need AES, only use AES-256 for new protocols
  - For post-quantum security

### Nonces

Most ciphers need a key and a nonce (aka initialization vector / IV) to encrypt a data:

    ciphertext = encrypt(plaintext, key, nonce)

Repeating (key, nonce) pair with different plaintexts would allow an attacker to decrypt it:

    ciphertext_a = encrypt(plaintext_a, key, nonce)
    ciphertext_b = encrypt(plaintext_b, key, nonce)
    stream_diff = xor(ciphertext_a, ciphertext_b)   # Break encryption

So, you can't repeat nonces. One way of doing so is using counters:

    for i in 0..:
        ciphertext[i] = encrypt(plaintexts[i], key, i)

Another is generating random nonce every time:

    for i in 0..:
        rand_nonces[i] = random()
        ciphertext[i] = encrypt(plaintexts[i], key, rand_nonces[i])

Counters are OK, but it's not always possible to store current counter value:
e.g. in decentralized, unsyncable systems.

Randomness is OK, but there's a catch:
ChaCha20 and AES-GCM use 96-bit / 12-byte nonces, which implies higher chance of collision.
In the example above, `random()` can collide and produce repeating nonce.
Chance is even higher for 64-bit nonces, which GCM allows - don't use them.

To safely use random nonces, utilize XSalsa20 or XChaCha:
they increased nonce length to 192-bit, minimizing a chance of collision.
AES-SIV is also fine. In situations where you can't use eXtended-nonce
algorithms, key rotation is advised. hkdf would work great for this case.

### Encryption limits

A "protected message" would mean a probability of `2**-50` that a passive attacker
successfully distinguishes the ciphertext outputs of the AEAD scheme from the outputs
of a random function. See [draft-irtf-cfrg-aead-limits](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/) for details.

- Max message size:
  - AES-GCM: ~68GB, `2**36-256`
  - Salsa, ChaCha, XSalsa, XChaCha: ~256GB, `2**38-64`
- Max amount of protected messages, under same key:
  - AES-GCM: `2**32.5`
  - Salsa, ChaCha: `2**46`, but only integrity is affected, not confidentiality
  - XSalsa, XChaCha: `2**72`
- Max amount of protected messages, across all keys:
  - AES-GCM: `2**69/B` where B is max blocks encrypted by a key. Meaning
    `2**59` for 1KB, `2**49` for 1MB, `2**39` for 1GB
  - Salsa, ChaCha, XSalsa, XChaCha: `2**100`

##### AES internals and block modes

`cipher = encrypt(block, key)`. Data is split into 128-bit blocks. Encrypted in 10/12/14 rounds (128/192/256bit). Every round does:

1. **S-box**, table substitution
2. **Shift rows**, cyclic shift left of all rows of data array
3. **Mix columns**, multiplying every column by fixed polynomial
4. **Add round key**, round_key xor i-th column of array

For non-deterministic (not ECB) schemes, initialization vector (IV) is mixed to block/key;
and each new round either depends on previous block's key, or on some counter.

- ECB (Electronic Codebook): Deterministic encryption; identical plaintext blocks yield identical ciphertexts. Insecure due to pattern leakage.
  See [AES Penguin](https://words.filippo.io/the-ecb-penguin/)
- CBC (Cipher Block Chaining): Each plaintext block is XORed with the previous ciphertext block before encryption.
  Hard to use: requires proper padding and an IV. Needs a separate MAC.
- CTR (Counter Mode): Turns a block cipher into a stream cipher using a counter and IV (nonce).
  Efficient and parallelizable. Requires a unique nonce per encryption. Better, but still needs a separate MAC.
- GCM (Galois/Counter Mode): Combines CTR mode with polynomial MAC. Efficient and widely used.
- SIV (Synthetic IV): Nonce-misuse-resistant mode; repeating nonces reveal only if plaintexts are identical.
  Maintains security even if nonces are reused.
- XTS: Designed for disk encryption.
  Similar to ECB (deterministic), but has `[i][j]` tweak arguments corresponding to sector i and 16-byte block (part of sector) j.
  Lacks MAC.

GCM / SIV are not ideal:

- Conservative key wear-out is `2**32` (4B) msgs
- MAC can be forged: see Poly1305 section above. Same for SIV

## Security

The library has been independently audited:

- at version 1.0.0, in Sep 2024, by [cure53](https://cure53.de)
  - PDFs: [website](https://cure53.de/audit-report_noble-crypto-libs.pdf), [in-repo](./audit/2024-09-cure53-audit-nbl4.pdf)
  - [Changes since audit](https://github.com/paulmillr/noble-ciphers/compare/1.0.0..main)
  - Scope: everything
  - The audit has been funded by [OpenSats](https://opensats.org)

It is tested against property-based, cross-library and Wycheproof vectors,
and has fuzzing by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz).

If you see anything unusual: investigate and report.

### Constant-timeness

_JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to
achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

The library uses T-tables for AES, which
[leak access timings](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf).
This is also done in [OpenSSL](https://github.com/openssl/openssl/blob/2f33265039cdbd0e4589c80970e02e208f3f94d2/crypto/aes/aes_core.c#L706) and
[Go stdlib](https://cs.opensource.google/go/go/+/refs/tags/go1.22.6:src/crypto/aes/const.go;l=90) for performance reasons.
The analysis was mentioned in [hal-04652991](https://hal.science/hal-04652991/document).

### Supply chain security

- **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures.
- **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
- **Rare releasing** is followed to ensure less re-audit need for end-users
- **Dependencies** are minimized and locked-down:
  - If your app has 500 dependencies, any dep could get hacked and you'll be downloading
    malware with every install. We make sure to use as few dependencies as possible
  - We prevent automatic dependency updates by locking-down version ranges. Every update is checked with `npm-diff`
- **Dev Dependencies** are only used if you want to contribute to the repo. They are disabled for end-users:
  - scure-base, micro-bmark and micro-should are developed by the same author and follow identical security practices
  - prettier (linter), fast-check (property-based testing) and typescript are used for code quality, vector generation and ts compilation. The packages are big, which makes it hard to audit their source code thoroughly and fully

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.
Implementing a userspace CSPRNG to get resilient to the weakness
is even worse: there is no reliable userspace source of quality entropy.

## Speed

To summarize, noble is the fastest JS implementation of Salsa, ChaCha and AES.

You can gain additional speed-up and
avoid memory allocations by passing `output`
uint8array into encrypt / decrypt methods.

Benchmark results on Apple M2 with node v22:

```
64B
xsalsa20poly1305 x 501,756 ops/sec @ 1μs/op
chacha20poly1305 x 428,082 ops/sec @ 2μs/op
xchacha20poly1305 x 343,170 ops/sec @ 2μs/op
aes-256-gcm x 147,492 ops/sec @ 6μs/op
aes-256-gcm-siv x 122,085 ops/sec @ 8μs/op
# Unauthenticated encryption
salsa20 x 1,288,659 ops/sec @ 776ns/op
xsalsa20 x 1,055,966 ops/sec @ 947ns/op
chacha20 x 1,506,024 ops/sec @ 664ns/op
xchacha20 x 1,064,962 ops/sec @ 939ns/op
chacha8 x 1,683,501 ops/sec @ 594ns/op
chacha12 x 1,628,664 ops/sec @ 614ns/op
aes-ecb-256 x 775,193 ops/sec @ 1μs/op
aes-cbc-256 x 738,552 ops/sec @ 1μs/op
aes-ctr-256 x 737,463 ops/sec @ 1μs/op

1MB
xsalsa20poly1305 x 205 ops/sec @ 4ms/op
chacha20poly1305 x 213 ops/sec @ 4ms/op
xchacha20poly1305 x 213 ops/sec @ 4ms/op
aes-256-gcm x 77 ops/sec @ 12ms/op
aes-256-gcm-siv x 81 ops/sec @ 12ms/op
# Unauthenticated encryption
salsa20 x 498 ops/sec @ 2ms/op
xsalsa20 x 493 ops/sec @ 2ms/op
chacha20 x 506 ops/sec @ 1ms/op
xchacha20 x 506 ops/sec @ 1ms/op
chacha8 x 956 ops/sec @ 1ms/op
chacha12 x 735 ops/sec @ 1ms/op
# Wrapper over built-in webcrypto
webcrypto ctr-256 x 5,068 ops/sec @ 197μs/op
webcrypto cbc-256 x 1,116 ops/sec @ 895μs/op
webcrypto gcm-256 x 4,374 ops/sec @ 228μs/op ± 1.69% [172μs..7ms]
```

Compare to other implementations:

```
xsalsa20poly1305 (encrypt, 1MB)
├─tweetnacl x 108 ops/sec @ 9ms/op
└─noble x 190 ops/sec @ 5ms/op

chacha20poly1305 (encrypt, 1MB)
├─node x 1,360 ops/sec @ 735μs/op
├─stablelib x 117 ops/sec @ 8ms/op
└─noble x 193 ops/sec @ 5ms/op

chacha (encrypt, 1MB)
├─node x 2,035 ops/sec @ 491μs/op
├─stablelib x 206 ops/sec @ 4ms/op
└─noble x 474 ops/sec @ 2ms/op

ctr-256 (encrypt, 1MB)
├─stablelib x 70 ops/sec @ 14ms/op
├─aesjs x 31 ops/sec @ 32ms/op
├─noble-webcrypto x 4,589 ops/sec @ 217μs/op
└─noble x 107 ops/sec @ 9ms/op

cbc-256 (encrypt, 1MB)
├─stablelib x 63 ops/sec @ 15ms/op
├─aesjs x 29 ops/sec @ 34ms/op
├─noble-webcrypto x 1,087 ops/sec @ 919μs/op
└─noble x 110 ops/sec @ 9ms/op

gcm-256 (encrypt, 1MB)
├─stablelib x 27 ops/sec @ 36ms/op
├─noble-webcrypto x 4,059 ops/sec @ 246μs/op
└─noble x 74 ops/sec @ 13ms/op
```

## Contributing & testing

* `npm install && npm run build && npm test` will build the code and run tests.
* `npm run lint` / `npm run format` will run linter / fix linter issues.
* `npm run bench` will run benchmarks, which may need their deps first (`npm run bench:install`)
* `cd build && npm install && npm run build:release` will build single file

Check out [github.com/paulmillr/guidelines](https://github.com/paulmillr/guidelines)
for general coding practices and rules.

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

The MIT License (MIT)

Copyright (c) 2023 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

See LICENSE file.
