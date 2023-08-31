# noble-ciphers

Auditable & minimal JS implementation of Salsa20, ChaCha, Poly1305 & AES-SIV

- 🔒 Auditable
- 🔻 Tree-shaking-friendly: use only what's necessary, other code won't be included
- 🏎 [Ultra-fast](#speed), hand-optimized for caveats of JS engines
- 🔍 Unique tests ensure correctness: property-based, cross-library and Wycheproof vectors
- 💼 AES: SIV (Nonce Misuse-Resistant encryption), simple GCM/CTR/CBC webcrypto wrapper
- 💃 Salsa20, ChaCha, XSalsa20, XChaCha, Poly1305, ChaCha8, ChaCha12
- ✍️ FF1 format-preserving encryption
- 🧂 Compatible with NaCl / libsodium secretbox
- 🪶 Just 500 lines / 4KB gzipped for Salsa + ChaCha + Poly build

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, protection against supply chain attacks
- Auditable TypeScript / JS code
- Supported on all major platforms
- Releases are signed with PGP keys and built transparently with NPM provenance
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)

## Usage

> npm install @noble/ciphers

We support all major platforms and runtimes.
For [Deno](https://deno.land), ensure to use
[npm specifier](https://deno.land/manual@v1.28.0/node/npm_specifiers).
For React Native, you may need a
[polyfill for crypto.getRandomValues](https://github.com/LinusU/react-native-get-random-values).
If you don't like NPM, a standalone
[noble-ciphers.js](https://github.com/paulmillr/noble-ciphers/releases) is also available.

```js
// import * from '@noble/ciphers'; // Error: use sub-imports, to ensure small app size
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
// import { xchacha20poly1305 } from 'npm:@noble/ciphers@0.2.0/chacha'; // Deno
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';
const key = randomBytes(32);
const data = utf8ToBytes('hello, noble'); // strings must be converted to Uint8Array
const nonce = randomBytes(24);
const stream_x = xchacha20poly1305(key, nonce);
const ciphertext = stream_x.encrypt(data);
const plaintext = stream_x.decrypt(ciphertext);
```

- [Modules](#modules)
  - [Salsa](#salsa)
  - [ChaCha](#chacha)
  - [Poly1305](#poly1305)
  - [AES](#aes)
  - [FF1](#ff1)
- [Guidance](#guidance)
  - [How to encrypt properly](#how-to-encrypt-properly)
  - [Nonces](#nonces)
  - [Encryption limits](#encryption-limits)
  - [AES internals and block modes](#aes-internals-and-block-modes)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [Resources](#resources)
  - [Projects using ciphers](#projects-using-ciphers)
- [License](#license)

## Modules

### Salsa

```js
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

const key = randomBytes(32);
const data = utf8ToBytes('hello, noble'); // strings must be converted to Uint8Array

const nonce = randomBytes(24);
const stream_x = xsalsa20poly1305(key, nonce); // === secretbox(key, nonce)
const ciphertext = stream_x.encrypt(data); // === secretbox.seal(data)
const plaintext = stream_x.decrypt(ciphertext); // === secretbox.open(ciphertext)

// Avoid memory allocations: re-use same uint8array
stream_x.decrypt(ciphertext, ciphertext.subarray(-16));
// ciphertext is now plaintext

// We provide sodium secretbox alias, which is just xsalsa20poly1305
import { secretbox } from '@noble/ciphers/salsa';
const box = secretbox(key, nonce);
const ciphertext = box.seal(plaintext);
const plaintext = box.open(ciphertext);
// secretbox does not manage nonces for you

// Standalone salsa is also available
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
const data = utf8ToBytes('hello, noble'); // strings must be converted to Uint8Array

const nonce12 = randomBytes(12); // chacha uses 96-bit nonce
const stream_c = chacha20poly1305(key, nonce12);
const ciphertext_c = stream_c.encrypt(data);
const plaintext_c = stream_c.decrypt(ciphertext_c); // === data

// Avoid memory allocations: re-use same uint8array
stream_c.decrypt(ciphertext_c, ciphertext_c.subarray(-16));
// ciphertext_c is now plaintext_c

const nonce24 = randomBytes(24); // xchacha uses 192-bit nonce
const stream_xc = xchacha20poly1305(key, nonce24);
const ciphertext_xc = stream_xc.encrypt(data);
const plaintext_xc = stream_xc.decrypt(ciphertext_xc); // === data

// Standalone chacha is also available
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
import { aes_128_gcm, aes_128_ctr, aes_128_cbc } from '@noble/ciphers/webcrypto/aes';
import { aes_256_gcm, aes_256_ctr, aes_256_cbc } from '@noble/ciphers/webcrypto/aes';

for (let cipher of [aes_256_gcm, aes_256_ctr, aes_256_cbc]) {
  const stream_new = cipher(key, nonce);
  const ciphertext_new = await stream_new.encrypt(plaintext);
  const plaintext_new = await stream_new.decrypt(ciphertext);
}

import { aes_256_gcm_siv } from '@noble/ciphers/webcrypto/siv';
const stream_siv = aes_256_gcm_siv(key, nonce);
await stream_siv.encrypt(plaintext, AAD);
```

AES ([wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard))
is a variant of Rijndael block cipher, standardized by NIST.

We don't implement AES in pure JS for now: instead, we wrap WebCrypto built-in
and provide an improved, simple API. There is a reason for this:
webcrypto API is terrible: different block modes require different params.

Optional [AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV)
synthetic initialization vector nonce-misuse-resistant mode is also provided.

Check out [AES internals and block modes](#aes-internals-and-block-modes).

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

As for block modes: we only expose GCM & SIV for now.

- ECB — simple deterministic replacement. Dangerous: always map x to y. See [AES Penguin](https://words.filippo.io/the-ecb-penguin/)
- CBC — key is previous round’s block. Hard to use: need proper padding, also needs MAC
- CTR — counter, allows to create streaming cipher. Requires good IV. Parallelizable. OK, but no MAC
- GCM — modern CTR, parallel, with MAC. Not ideal:
  - Conservative key wear-out is `2**32` (4B) msgs
  - MAC can be forged: see Poly1305 section above
- SIV — synthetic initialization vector, nonce-misuse-resistant
  - Can be 1.5-2x slower than GCM by itself
  - nonce misuse-resistant schemes guarantee that if a
    nonce repeats, then the only security loss is that identical
    plaintexts will produce identical ciphertexts
  - MAC can be forged: see Poly1305 section above
- XTS — used in hard drives. Similar to ECB (deterministic), but has `[i][j]`
  tweak arguments corresponding to sector i and 16-byte block (part of sector) j. Not authenticated!

## Security

The library has not been independently audited yet.

It is tested against property-based, cross-library and Wycheproof vectors,
and has fuzzing by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz).

### Constant-timeness

_JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to
achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

### Supply chain security

1. **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures.
2. **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
3. **Rare releasing** is followed.
   The less often it is done, the less code dependents would need to audit
4. **Dependencies** are minimal:
   - All deps are prevented from automatic updates and have locked-down version ranges. Every update is checked with `npm-diff`
   - Updates themselves are rare, to ensure rogue updates are not catched accidentally
5. devDependencies are only used if you want to contribute to the repo. They are disabled for end-users:
   - scure-base, micro-bmark and micro-should are developed by the same author and follow identical security practices
   - prettier (linter), fast-check (property-based testing) and typescript are used for code quality, vector generation and ts compilation. The packages are big, which makes it hard to audit their source code thoroughly and fully

We consider infrastructure attacks like rogue NPM modules very important;
that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings.
If your app uses 500 dependencies, any dep could get hacked and you'll be
downloading malware with every install. Our goal is to minimize this attack vector.

If you see anything unusual: investigate and report.

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
└─xchacha20poly1305 x 300,842 ops/sec @ 3μs/op
encrypt (1KB)
├─xsalsa20poly1305 x 143,905 ops/sec @ 6μs/op
├─chacha20poly1305 x 141,663 ops/sec @ 7μs/op
└─xchacha20poly1305 x 122,639 ops/sec @ 8μs/op
encrypt (8KB)
├─xsalsa20poly1305 x 23,373 ops/sec @ 42μs/op
├─chacha20poly1305 x 23,683 ops/sec @ 42μs/op
└─xchacha20poly1305 x 23,066 ops/sec @ 43μs/op
encrypt (1MB)
├─xsalsa20poly1305 x 193 ops/sec @ 5ms/op
├─chacha20poly1305 x 196 ops/sec @ 5ms/op
└─xchacha20poly1305 x 195 ops/sec @ 5ms/op
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
```

Compare to other implementations:

```
xsalsa20poly1305 (encrypt, 1MB)
├─tweetnacl x 108 ops/sec @ 9ms/op
├─noble x 190 ops/sec @ 5ms/op
└─micro x 21 ops/sec @ 47ms/op

chacha20poly1305 (encrypt, 1MB)
├─node x 1,360 ops/sec @ 735μs/op
├─stablelib x 117 ops/sec @ 8ms/op
├─noble x 193 ops/sec @ 5ms/op
└─micro x 19 ops/sec @ 50ms/op

chacha (encrypt, 1MB)
├─node x 2,035 ops/sec @ 491μs/op
├─stablelib x 206 ops/sec @ 4ms/op
├─noble x 474 ops/sec @ 2ms/op
└─micro x 61 ops/sec @ 16ms/op
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## Resources

- [Fast-key-erasure random-number generators](https://blog.cr.yp.to/20170723-random.html)
- [The design of Chacha20](https://loup-vaillant.fr/tutorials/chacha20-design)
- [The design of Poly1305](https://loup-vaillant.fr/tutorials/poly1305-design)
- Multi-user / multi-key attacks
  - [Break a dozen secret keys, get a million more for free](https://blog.cr.yp.to/20151120-batchattacks.html)
  - [128 Bits of Security and 128 Bits of Security: Know the Difference](https://loup-vaillant.fr/tutorials/128-bits-of-security)

### Projects using ciphers

- [js-libp2p-noise](https://github.com/ChainSafe/js-libp2p-noise)
- See [full list of projects on GitHub](https://github.com/paulmillr/noble-curves/network/dependents).

## License

The MIT License (MIT)

Copyright (c) 2023 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

See LICENSE file.
