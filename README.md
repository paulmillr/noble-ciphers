# noble-ciphers

Auditable & minimal JS implementation of Salsa20, ChaCha & AES

- 🔒 Auditable
- 🔻 Tree-shaking-friendly: use only what's necessary, other code won't be included
- 🏎 [Ultra-fast](#speed), hand-optimized for caveats of JS engines
- 🔍 Unique tests ensure correctness: property-based, cross-library and Wycheproof vectors
- 💼 AES: very fast ECB, CBC, CTR, GCM, SIV (nonce misuse-resistant)
- 💃 Salsa20, ChaCha, XSalsa20, XChaCha, Poly1305, ChaCha8, ChaCha12
- ✍️ FF1 format-preserving encryption
- 🧂 Compatible with NaCl / libsodium secretbox
- 🪶 Just 500 lines / 4KB gzipped for Salsa + ChaCha + Poly build

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds with provenance
- All libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)
- [Check out homepage](https://paulmillr.com/noble/)
  for reading resources, documentation and apps built with noble

## Usage

> npm install @noble/ciphers

We support all major platforms and runtimes.
For [Deno](https://deno.land), ensure to use
[npm specifier](https://deno.land/manual@v1.28.0/node/npm_specifiers).
For React Native, you may need a
[polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file
[noble-ciphers.js](https://github.com/paulmillr/noble-ciphers/releases) is also available.

```js
// import * from '@noble/ciphers'; // Error: use sub-imports, to ensure small app size
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
// import { xchacha20poly1305 } from 'npm:@noble/ciphers@0.2.0/chacha'; // Deno
```

- [Examples](#examples)
  - [Encrypt and decrypt with ChaCha20-Poly1305](#encrypt-and-decrypt-with-chacha20-poly1305)
  - [Encrypt and decrypt text with AES-GCM-256](#encrypt-and-decrypt-text-with-aes-gcm-256)
  - [Securely generate random key and nonce](#securely-generate-random-key-and-nonce)
  - [Use managed nonce](#use-managed-nonce)
- [Implementations](#implementations)
  - [salsa: Salsa20 cipher](#salsa)
  - [chacha: ChaCha cipher](#chacha)
  - [aes: AES cipher](#aes)
  - [ff1: format-preserving encryption](#ff1)
- [Guidance](#guidance)
  - [How to encrypt properly](#how-to-encrypt-properly)
  - [Nonces](#nonces)
  - [Encryption limits](#encryption-limits)
  - [AES internals and block modes](#aes-internals-and-block-modes)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [Resources](#resources)

## Examples

#### Encrypt and decrypt with ChaCha20-Poly1305

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { bytesToHex, hexToBytes, bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
const key = hexToBytes('4b7f89bac90a1086fef73f5da2cbe93b2fae9dfbf7678ae1f3e75fd118ddf999');
const nonce = hexToBytes('9610467513de0bbd7c4cc2c3c64069f1802086fbd3232b13');
const chacha = xchacha20poly1305(key, nonce);
const data = utf8ToBytes('hello, noble');
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext); // bytesToUtf8(data_) === data
```

#### Encrypt and decrypt text with AES-GCM-256

```js
import { gcm } from '@noble/ciphers/aes';
import { bytesToHex, hexToBytes, bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
const key = hexToBytes('5296fb2c5ceab0f59367994e5d81d9014027255f12336fabcd29596c2e9ecd87');
const nonce = hexToBytes('9610467513de0bbd7c4cc2c3c64069f1802086fbd3232b13');
const aes = gcm(key, nonce);
const data = utf8ToBytes('hello, noble');
const ciphertext = aes.encrypt(data);
const data_ = aes.decrypt(ciphertext); // bytesToUtf8(data_) === data
```

#### Use managed nonce

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { managedNonce } from '@noble/ciphers/webcrypto/utils'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
const key = hexToBytes('fa686bfdffd3758f6377abbc23bf3d9bdc1a0dda4a6e7f8dbdd579fa1ff6d7e1');
const chacha = managedNonce(xchacha20poly1305)(key); // manages nonces for you
const data = utf8ToBytes('hello, noble');
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext);
```

#### Securely generate random key and nonce

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';
const rkey = randomBytes(32);
const rnonce = randomBytes(24);
const chacha = xchacha20poly1305(rkey, rnonce);
const data = utf8ToBytes('hello, noble');
const ciphertext = chacha.encrypt(data);
const plaintext = chacha.decrypt(ciphertext);
```

## Implementations

### Salsa

```js
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';
const key = randomBytes(32);
const nonce = randomBytes(24);
const stream_x = xsalsa20poly1305(key, nonce);
const data = utf8ToBytes('hello, noble');
const ciphertext = stream_x.encrypt(data);
const plaintext = stream_x.decrypt(ciphertext);

// `dst` argument to avoid memory allocations: re-use same uint8array
stream_x.decrypt(ciphertext, ciphertext.subarray(-16)); // ciphertext became plaintext

// We provide alias to sodium `secretbox`, which is identical to xsalsa20poly1305
import { secretbox } from '@noble/ciphers/salsa';
const box = secretbox(key, nonce);
const ciphertext = box.seal(plaintext);
const plaintext = box.open(ciphertext);

// Standalone salsa
import { salsa20, xsalsa20 } from '@noble/ciphers/salsa';
const nonce12 = randomBytes(12); // salsa uses 96-bit nonce, xsalsa uses 192-bit
const encrypted_s = salsa20(key, nonce12, data);
const encrypted_xs = xsalsa20(key, nonce, data);
```

Salsa20 stream cipher ([website](https://cr.yp.to/snuffle.html),
[PDF](https://cr.yp.to/snuffle/salsafamily-20071225.pdf),
[wiki](https://en.wikipedia.org/wiki/Salsa20)) was released in 2005.
Salsa's goal was to implement AES replacement that does not rely on S-Boxes,
which are hard to implement in a constant-time manner.
Salsa20 is usually faster than AES, a big deal on slow, budget mobile phones.

[XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), extended-nonce
variant was released in 2008. It switched nonces from 96-bit to 192-bit,
and became safe to be picked at random.

Nacl / Libsodium popularized term "secretbox", a simple black-box
authenticated encryption. Secretbox is just xsalsa20-poly1305. We provide the
alias and corresponding seal / open methods.

### ChaCha

```js
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

const key = randomBytes(32);
const nonce12 = randomBytes(12);
const stream_c = chacha20poly1305(key, nonce12);

const data = utf8ToBytes('hello, noble'); // strings must be converted to Uint8Array
const ciphertext_c = stream_c.encrypt(data);
const plaintext_c = stream_c.decrypt(ciphertext_c); // === data

// `dst` argument to avoid memory allocations: re-use same uint8array
stream_c.decrypt(ciphertext_c, ciphertext_c.subarray(-16));

// xchacha: extended-nonce chacha
const nonce24 = randomBytes(24); // 192-bit nonce
const stream_xc = xchacha20poly1305(key, nonce24);
const ciphertext_xc = stream_xc.encrypt(data);
const plaintext_xc = stream_xc.decrypt(ciphertext_xc); // === data

// Standalone chacha
import { chacha20, xchacha20, chacha8, chacha12 } from '@noble/ciphers/chacha';
const ciphertext_pc = chacha20(key, nonce12, data);
const ciphertext_pxc = xchacha20(key, nonce24, data);
const ciphertext_8 = chacha8(key, nonce12, data);
const ciphertext_12 = chacha12(key, nonce12, data);
```

ChaCha20 stream cipher ([website](https://cr.yp.to/chacha.html),
[PDF](http://cr.yp.to/chacha/chacha-20080128.pdf),
[wiki](https://en.wikipedia.org/wiki/Salsa20)) was released
in 2008. ChaCha aims to increase the diffusion per round, but had slightly less
cryptanalysis. It was standardized in
[RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and is now used in TLS 1.3.

XChaCha20 ([draft RFC](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha))
extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
randomly-generated nonces.

### Poly1305

Poly1305 ([website](https://cr.yp.to/mac.html),
[PDF](https://cr.yp.to/mac/poly1305-20050329.pdf),
[wiki](https://en.wikipedia.org/wiki/Poly1305))
is a fast and parallel secret-key message-authentication code suitable for
a wide variety of applications. It was standardized in
[RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and is now used in TLS 1.3.

Poly1305 is polynomial-evaluation MAC, which is not perfect for every situation:
just like GCM, it lacks Random Key Robustness: the tags can be forged, and can't
be used in PAKE schemes. See
[invisible salamanders attack](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/).
To combat invisible salamanders, `hash(key)` can be included in ciphertext,
however, this would violate ciphertext indistinguishability:
an attacker would know which key was used - so `HKDF(key, i)`
could be used instead.

Even though poly1305 can be imported separately from the library, we suggest
using chacha-poly or xsalsa-poly.

### AES

```js
import { gcm, siv, ctr, cbc, ecb } from '@noble/ciphers/aes';

for (let cipher of [gcm, siv, ctr, cbc]) {
  const stream = cipher(key, nonce);
  const ciphertext_ = stream.encrypt(plaintext);
  const plaintext_ = stream.decrypt(ciphertext_);
}
```

AES ([wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard))
is a variant of Rijndael block cipher, standardized by NIST.

We provide the fastest available pure JS implementation of AES.

Optional [AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV)
nonce-misuse-resistant mode is also provided.

Check out [AES internals and block modes](#aes-internals-and-block-modes).

### Webcrypto AES

```js
// Wrapper over built-in webcrypto. Same API, but async
import { gcm, ctr, cbc } from '@noble/ciphers/webcrypto/aes';
for (let cipher of [gcm, siv, ctr, cbc]) {
  const stream = cipher(key, nonce);
  const ciphertext_ = await stream.encrypt(plaintext);
  const plaintext_ = await stream.decrypt(ciphertext_);
}
```

We also have separate wrapper over asynchronous WebCrypto built-in.

It's the same as using `crypto.subtle`, but with massively simplified API.

### Managed nonces

```js
import { managedNonce } from '@noble/ciphers/webcrypto/utils';
import { gcm, siv, ctr, cbc, ecb } from '@noble/ciphers/aes';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';

const wgcm = managedNonce(gcm);
const wsiv = managedNonce(siv);
const wcbc = managedNonce(cbc);
const wctr = managedNonce(ctr);
const wsalsapoly = managedNonce(xsalsa20poly1305);
const wchacha = managedNonce(chacha20poly1305);
const wxchacha = managedNonce(xchacha20poly1305);

// Now:
const encrypted = wgcm(key).encrypt(data); // no nonces
```

We provide API that manages nonce internally instead of exposing them to library's user.

For `encrypt`, a `nonceBytes`-length buffer is fetched from CSPRNG and prenended to encrypted ciphertext.

For `decrypt`, first `nonceBytes` of ciphertext are treated as nonce.

### FF1

Format-preserving encryption algorithm (FPE-FF1) specified in NIST Special Publication 800-38G.
[See more info](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf).

## Guidance

### How to encrypt properly

1. Use unpredictable key with enough entropy
   - Random key must be using cryptographically secure random number generator (CSPRNG), not `Math.random` etc.
   - Non-random key generated from KDF is fine
   - Re-using key is fine, but be aware of rules for cryptographic key wear-out and [encryption limits](#encryption-limits)
2. Use new nonce every time and [don't repeat it](#nonces)
   - chacha and salsa20 are fine for sequential counters that _never_ repeat: `01, 02...`
   - xchacha and xsalsa20 should be used for random nonces instead
3. Prefer authenticated encryption (AEAD)
   - HMAC+ChaCha / HMAC+AES / chacha20poly1305 / aes-gcm is good
   - chacha20 without poly1305 or hmac / aes-ctr / aes-cbc is bad
   - Flipping bits or ciphertext substitution won't be detected in unauthenticated ciphers
4. Don't re-use keys between different protocols
   - For example, using secp256k1 key in AES is bad
   - Use hkdf or, at least, a hash function to create sub-key instead

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
ChaCha20 and AES-GCM use 96-bit / 12-byte nonces, which implies
higher chance of collision. In the example above,
`random()` can collide and produce repeating nonce.

To safely use random nonces, utilize XSalsa20 or XChaCha:
they increased nonce length to 192-bit, minimizing a chance of collision.
AES-SIV is also fine. In situations where you can't use eXtended-nonce
algorithms, key rotation is advised. hkdf would work great for this case.

### Encryption limits

A "protected message" would mean a probability of `2**-50` that a passive attacker
successfully distinguishes the ciphertext outputs of the AEAD scheme from the outputs
of a random function. See [RFC draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/) for details.

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

- ECB — simple deterministic replacement. Dangerous: always map x to y. See [AES Penguin](https://words.filippo.io/the-ecb-penguin/)
- CBC — key is previous round’s block. Hard to use: need proper padding, also needs MAC
- CTR — counter, allows to create streaming cipher. Requires good IV. Parallelizable. OK, but no MAC
- GCM — modern CTR, parallel, with MAC
- SIV — synthetic initialization vector, nonce-misuse-resistant, 1.5-2x slower than GCM.
  Guarantees that, when a nonce is repeated, the only security loss is that identical
  plaintexts will produce identical ciphertexts.
- XTS — used in hard drives. Similar to ECB (deterministic), but has `[i][j]`
  tweak arguments corresponding to sector i and 16-byte block (part of sector) j. Not authenticated!

GCM / SIV are not ideal:
  - Conservative key wear-out is `2**32` (4B) msgs
  - MAC can be forged: see Poly1305 section above. Same for SIV

## Security

The library has not been independently audited yet.

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

### Supply chain security

* **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures.
* **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
* **Rare releasing** is followed to ensure less re-audit need for end-users
* **Dependencies** are minimized and locked-down:
   - If your app has 500 dependencies, any dep could get hacked and you'll be downloading
     malware with every install. We make sure to use as few dependencies as possible
   - We prevent automatic dependency updates by locking-down version ranges. Every update is checked with `npm-diff`
* **Dev Dependencies** are only used if you want to contribute to the repo. They are disabled for end-users:
   - scure-base, micro-bmark and micro-should are developed by the same author and follow identical security practices
   - prettier (linter), fast-check (property-based testing) and typescript are used for code quality, vector generation and ts compilation. The packages are big, which makes it hard to audit their source code thoroughly and fully

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).
In the past, browsers had bugs that made it weak: it may happen again.

## Speed

To summarize, noble is the fastest JS implementation.

You can gain additional speed-up and
avoid memory allocations by passing `output`
uint8array into encrypt / decrypt methods.

Benchmark results on Apple M2 with node v20:

```
encrypt (64B)
├─xsalsa20poly1305 x 484,966 ops/sec @ 2μs/op
├─chacha20poly1305 x 442,282 ops/sec @ 2μs/op
├─xchacha20poly1305 x 300,842 ops/sec @ 3μs/op
├─gcm-256 x 148,522 ops/sec @ 6μs/op
└─gcm-siv-256 x 118,399 ops/sec @ 8μs/op
encrypt (1KB)
├─xsalsa20poly1305 x 143,905 ops/sec @ 6μs/op
├─chacha20poly1305 x 141,663 ops/sec @ 7μs/op
├─xchacha20poly1305 x 122,639 ops/sec @ 8μs/op
├─gcm-256 x 42,645 ops/sec @ 23μs/op
└─gcm-siv-256 x 40,112 ops/sec @ 24μs/op
encrypt (8KB)
├─xsalsa20poly1305 x 23,373 ops/sec @ 42μs/op
├─chacha20poly1305 x 23,683 ops/sec @ 42μs/op
├─xchacha20poly1305 x 23,066 ops/sec @ 43μs/op
├─gcm-256 x 8,381 ops/sec @ 119μs/op
└─gcm-siv-256 x 8,020 ops/sec @ 124μs/op
encrypt (1MB)
├─xsalsa20poly1305 x 193 ops/sec @ 5ms/op
├─chacha20poly1305 x 196 ops/sec @ 5ms/op
├─xchacha20poly1305 x 195 ops/sec @ 5ms/op
├─gcm-256 x 75 ops/sec @ 13ms/op
└─gcm-siv-256 x 72 ops/sec @ 13ms/op
```

Unauthenticated encryption:

```
encrypt (64B)
├─salsa x 1,272,264 ops/sec @ 786ns/op
├─chacha x 1,526,717 ops/sec @ 655ns/op
├─xsalsa x 847,457 ops/sec @ 1μs/op
└─xchacha x 848,896 ops/sec @ 1μs/op
encrypt (1KB)
├─salsa x 355,492 ops/sec @ 2μs/op
├─chacha x 377,358 ops/sec @ 2μs/op
├─xsalsa x 311,915 ops/sec @ 3μs/op
└─xchacha x 315,457 ops/sec @ 3μs/op
encrypt (8KB)
├─salsa x 56,063 ops/sec @ 17μs/op
├─chacha x 57,359 ops/sec @ 17μs/op
├─xsalsa x 54,848 ops/sec @ 18μs/op
└─xchacha x 55,475 ops/sec @ 18μs/op
encrypt (1MB)
├─salsa x 465 ops/sec @ 2ms/op
├─chacha x 474 ops/sec @ 2ms/op
├─xsalsa x 466 ops/sec @ 2ms/op
└─xchacha x 476 ops/sec @ 2ms/op

AES
encrypt (64B)
├─ctr-256 x 689,179 ops/sec @ 1μs/op
├─cbc-256 x 639,795 ops/sec @ 1μs/op
└─ecb-256 x 668,449 ops/sec @ 1μs/op
encrypt (1KB)
├─ctr-256 x 93,668 ops/sec @ 10μs/op
├─cbc-256 x 94,428 ops/sec @ 10μs/op
└─ecb-256 x 151,699 ops/sec @ 6μs/op
encrypt (8KB)
├─ctr-256 x 13,342 ops/sec @ 74μs/op
├─cbc-256 x 13,664 ops/sec @ 73μs/op
└─ecb-256 x 22,426 ops/sec @ 44μs/op
encrypt (1MB)
├─ctr-256 x 106 ops/sec @ 9ms/op
├─cbc-256 x 109 ops/sec @ 9ms/op
└─ecb-256 x 179 ops/sec @ 5ms/op
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

ctr-256 (encrypt, 64B)
├─node x 640,204 ops/sec @ 1μs/op ± 1.67% (min: 1μs, max: 1ms)
├─stablelib x 484,261 ops/sec @ 2μs/op
└─noble x 685,871 ops/sec @ 1μs/op

cbc-256 (encrypt, 64B)
├─node x 549,450 ops/sec @ 1μs/op ± 2.47% (min: 1μs, max: 3ms)
├─stablelib x 407,166 ops/sec @ 2μs/op ± 1.02% (min: 2μs, max: 3ms)
└─noble x 616,142 ops/sec @ 1μs/op ± 1.19% (min: 1μs, max: 2ms)
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## Resources

Check out [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

The MIT License (MIT)

Copyright (c) 2023 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

See LICENSE file.
