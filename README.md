# noble-ciphers

Auditable & minimal JS implementation of Salsa20, ChaCha, Poly1305 & AES-SIV

- 🔒 Auditable
- 🔻 Tree-shaking-friendly: use only what's necessary, other code won't be included
- 🏎 [Ultra-fast](#speed), hand-optimized for caveats of JS engines
- 🔍 Unique tests ensure correctness: property-based, cross-library and Wycheproof vectors
- 💼 AES: GCM (Galois Counter Mode), SIV (Nonce Misuse-Resistant encryption)
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
// import * from '@noble/ciphers'; // Error
// Use sub-imports for tree-shaking, to ensure small size of your apps
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

const key = randomBytes(32);
const nonce = randomBytes(24);
const data = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 110, 111, 98, 108, 101]);
const stream = xsalsa20poly1305(key, nonce);
const encrypted_s = stream.encrypt(data);
stream.decrypt(encrypted); // === data

// Library works over byte arrays. The data above is the same as:
// import { utf8ToBytes } from '@noble/ciphers/utils';
// const data = utf8ToBytes('hello, noble');

// XChaCha
import { xchacha20poly1305 } from '@noble/ciphers/salsa';
const stream_xc = xchacha20poly1305(key, nonce);
const encrypted_xc = stream_xc.encrypt(data);
stream_xc.decrypt(encrypted_xc); // === data

// ChaCha
import { chacha20poly1305 } from '@noble/ciphers/chacha';
const nonce12 = randomBytes(12);
const stream_c = chacha20poly1305(key, nonce12);
const encrypted_c = stream_c.encrypt(data);
stream_c.decrypt(encrypted_c); // === data

// Webcrypto shortcuts
import {
  aes_128_gcm, aes_128_ctr, aes_128_cbc,
  aes_256_gcm, aes_256_ctr, aes_256_cbc
} from '@noble/ciphers/webcrypto/aes';

const stream_aes = aes_256_gcm(key, nonce);
const ciphertext_aes = await stream_aes.encrypt(data); // async
const plaintext_aes = await stream_a.decrypt(ciphertext_aes); // === data

// AES-SIV, FF1
import { aes_256_gcm_siv } from '@noble/ciphers/webcrypto/siv';
import { FF1, BinaryFF1 } from '@noble/ciphers/webcrypto/ff1';

// All algoritms, written in minimal, auditable way.
// Other files contain unrolled loops, which are 5x faster, but less auditable.
import * as ciphers from '@noble/ciphers/_micro';
```

### How to encrypt properly

1. Use unpredictable, random key; don't re-use keys between different protocols
2. Use new nonce every time and don't repeat it
3. Be aware of rules for cryptographic key wear-out and [encryption limits](#encryption-limits)
4. Prefer authenticated encryption, with MACs like poly1305, GCM, hmac

Most ciphers need a key and a nonce (aka initialization vector / IV) to encrypt a data:

    ciphertext = encrypt(plaintext, key, nonce)

Repeating (key, nonce) pair with different plaintexts would allow an attacker to decrypt it:

    ciphertext_a = encrypt(plaintext_a, key, nonce)
    ciphertext_b = encrypt(plaintext_b, key, nonce)
    stream_diff = xor(ciphertext_a, ciphertext_b) # Break encryption

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

### Salsa

```js
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

const key = randomBytes(32);
const data = utf8ToBytes('hello, noble'); // strings must be converted to Uint8Array

const nonce = randomBytes(24);
const stream_x = xsalsa20poly1305(key, nonce); // === secretbox(key, nonce)
const ciphertext = stream_x.encrypt(data);      // === secretbox.seal(data)
const plaintext = stream_x.decrypt(ciphertext); // === secretbox.open(ciphertext)

// We provide sodium secretbox alias, which is just xsalsa20poly1305
import { secretbox } from '@noble/ciphers/salsa';
const box = secretbox(key, nonce);
const ciphertext = box.seal(plaintext);
const plaintext = box.open(ciphertext);


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
[wiki](https://en.wikipedia.org/wiki/Salsa20),
[blog post](https://loup-vaillant.fr/tutorials/chacha20-design)) was released
in 2008. ChaCha aims to increase the diffusion per round, but had slightly less
cryptanalysis. It was standardized in
[RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and is now used in TLS 1.3.

XChaCha20 ([draft RFC](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha))
extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
randomly-generated nonces.

### Poly1305

Poly1305 ([website](https://cr.yp.to/mac.html),
[PDF](https://cr.yp.to/mac/poly1305-20050329.pdf),
[wiki](https://en.wikipedia.org/wiki/Poly1305),
[blog post](https://loup-vaillant.fr/tutorials/poly1305-design))
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
import {
  aes_128_gcm, aes_128_ctr, aes_128_cbc,
  aes_256_gcm, aes_256_ctr, aes_256_cbc
} from '@noble/ciphers/webcrypto/aes';

for (let cipher of [aes_256_gcm, aes_256_ctr, aes_256_cbc]) {
  const stream_new = cipher(key, nonce);
  const ciphertext_new = await stream_new.encrypt(plaintext);
  const plaintext_new = await stream_new.decrypt(ciphertext);
}

import { aes_256_gcm_siv } from '@noble/ciphers/webcrypto/siv';
const stream_siv = aes_256_gcm_siv(key, nonce)
await stream_siv.encrypt(plaintext, AAD);
```

AES ([wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard))
is a variant of Rijndael block cipher, standardized by NIST.

We don't implement AES in pure JS for now: instead, we wrap WebCrypto built-in
and provide an improved, simple API. There is a simple reason for this:
webcrypto API is terrible: different block modes require different params.

Optional [AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV)
(synthetic initialization vector) nonce-misuse-resistant mode is also provided.

##### How AES works

`cipher = encrypt(block, key)`. Data is split into 128-bit blocks. Encrypted in 10/12/14 rounds (128/192/256bit). Every round does:

1. **S-box**, table substitution
2. **Shift rows**, cyclic shift left of all rows of data array
3. **Mix columns**, multiplying every column by fixed polynomial
4. **Add round key**, round_key xor i-th column of array

For non-deterministic (not ECB) schemes, initialization vector (IV) is mixed to block/key;
and each new round either depends on previous block's key, or on some counter.

##### Block modes

We only expose GCM & SIV for now.

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

### FF1

Format-preserving encryption algorithm (FPE-FF1) specified in NIST Special Publication 800-38G.

More info: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf

## Security

The library is experimental. Use at your own risk.

## Speed

To summarize, noble is the fastest JS implementation.

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
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## License

The MIT License (MIT)

Copyright (c) 2023 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

See LICENSE file.
