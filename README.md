# noble-ciphers

Audited & minimal JS implementation of Salsa20, ChaCha and AES.

- 🔒 [**Audited**](#security) by an independent security firm
- 🪶 Minimal: 3KB (gzipped) ChaCha, unused code is excluded from your builds
- 🏎 Fast: hand-optimized for caveats of JS engines
- 🔍 Reliable: cross-library / wycheproof tests ensure correctness
- 💼 AES: ECB, CBC, CTR, CFB, GCM, GCM-SIV & AES-SIV, AESKW, AESKWP, FF1
- 💃 Salsa20, ChaCha, XSalsa20, XChaCha, ChaCha8, ChaCha12, Poly1305, rngChaCha8
- 🥈 Wrapper with identical API over native WebCrypto

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
  5kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)
- WASM version: [awasm-noble](https://github.com/paulmillr/awasm-noble)
- [Check out the homepage](https://paulmillr.com/noble/)
  for reading resources, documentation, and apps built with noble

## Usage

> `npm install @noble/ciphers`

> `deno add jsr:@noble/ciphers`

We support all major platforms and runtimes.
For React Native, you may need a
[polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file
[noble-ciphers.js](https://github.com/paulmillr/noble-ciphers/releases) is also available.

```js
// import * from '@noble/ciphers'; // Error: use sub-imports, to ensure small app size
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/ciphers/utils.js';
const key = randomBytes(32);
const nonce = randomBytes(24);
const data = new TextEncoder().encode('hello noble');
const ciphertext = xchacha20poly1305(key, nonce).encrypt(data);
```

- [chacha: chacha20poly1305, xchacha20poly1305](#chacha-chacha20poly1305-xchacha20poly1305)
- [salsa: xsalsa20poly1305, secretbox](#salsa-xsalsa20poly1305-secretbox)
- [aes: gcm, gcmsiv, aessiv, ctr, cbc, cfb, ecb, aeskw](#aes-gcm-gcmsiv-aessiv-ctr-cbc-cfb-ecb-aeskw)
- [ff1: format-preserving encryption](#ff1-format-preserving-encryption)
- [webcrypto: friendly wrapper](#webcrypto-friendly-wrapper)
- [utils](#utils)
- [managedNonce: automatic nonce handling](#managednonce-automatic-nonce-handling)
- [Reuse array for input and output](#reuse-array-for-input-and-output)
- [Randomness generation](#randomness-generation)
- [Use password for encryption](#use-password-for-encryption)
- [Internals](#internals):
  [Picking a cipher](#picking-a-cipher) |
  [How to encrypt properly](#how-to-encrypt-properly) |
  [Encryption limits](#encryption-limits)
- [Security](#security) | [Speed](#speed) | [Upgrading](#upgrading) | [Contributing & testing](#contributing--testing) | [License](#license)

### Implementations

- `cipher(key, nonce).encrypt(data)` and `.decrypt(ciphertext)`: receive & return `Uint8Array`
- AEADs (gcm, gcmsiv, aessiv, chacha20poly1305, xchacha20poly1305, xsalsa20poly1305)
  authenticate data: ciphertext includes a 16-byte tag, `decrypt` throws on tampering
- Unauthenticated ciphers (ctr, cbc, cfb, ecb, salsa20, chacha20 & others)
  must be combined with HMAC or similar
- Use a new [nonce](#how-to-encrypt-properly) every time `encrypt()` is done

#### chacha: chacha20poly1305, xchacha20poly1305

```js
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/ciphers/utils.js';
const key = randomBytes(32);
const nonce = randomBytes(24); // 12 bytes for chacha20poly1305
const chacha = xchacha20poly1305(key, nonce);
const data = new TextEncoder().encode('hello noble');
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext); // new TextDecoder().decode(data_) === data

// Unauthenticated stream ciphers
import { chacha20, xchacha20, chacha8, chacha12 } from '@noble/ciphers/chacha.js';
const stream = chacha20(key, randomBytes(12), data);
```

#### salsa: xsalsa20poly1305, secretbox

```js
import { xsalsa20poly1305, secretbox } from '@noble/ciphers/salsa.js';
import { randomBytes } from '@noble/ciphers/utils.js';
const key = randomBytes(32);
const nonce = randomBytes(24);
const data = new TextEncoder().encode('hello noble');
const ciphertext = xsalsa20poly1305(key, nonce).encrypt(data);

// NaCl / libsodium compatibility
const box = secretbox(key, nonce);
const sealed = box.seal(data);
const data_ = box.open(sealed);

// Unauthenticated stream ciphers
import { salsa20, xsalsa20 } from '@noble/ciphers/salsa.js';
const stream = salsa20(key, randomBytes(8), data);
```

xsalsa20poly1305 is also known as NaCl / libsodium "secretbox".
"crypto_box" and "sealedbox" are available in package
[noble-sodium](https://github.com/serenity-kit/noble-sodium).

#### aes: gcm, gcmsiv, aessiv, ctr, cbc, cfb, ecb, aeskw

```js
import { gcm, gcmsiv, aessiv, ctr, cfb, cbc, ecb } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
const key = randomBytes(32); // 24 for AES-192, 16 for AES-128
const nonce = randomBytes(12);
const data = new TextEncoder().encode('hello noble');
const aes = gcm(key, nonce);
const ciphertext = aes.encrypt(data);
const data_ = aes.decrypt(ciphertext);

// Other modes share the same API
const plaintext = new Uint8Array(32).fill(16);
// gcm, gcmsiv, aessiv use 12-byte nonces; ctr, cbc, cfb use 16-byte
const modes = [[gcm, 12], [gcmsiv, 12], [aessiv, 12], [ctr, 16], [cbc, 16], [cfb, 16]];
for (const [cipher, nonceLength] of modes) {
  const nonce_ = randomBytes(nonceLength);
  const ciphertext_ = cipher(key, nonce_).encrypt(plaintext);
  const plaintext_ = cipher(key, nonce_).decrypt(ciphertext_);
}
const ecbCiphertext = ecb(key).encrypt(plaintext); // ecb has no nonce

// AESKW, AESKWP
import { aeskw, aeskwp } from '@noble/ciphers/aes.js';
import { hexToBytes } from '@noble/ciphers/utils.js';
const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
const keyData = hexToBytes('00112233445566778899AABBCCDDEEFF');
const wrapped = aeskw(kek).encrypt(keyData);
```

AES-128, AES-192 and AES-256 are selected dynamically, based on key length (16, 24, 32).

#### ff1: format-preserving encryption

```js
import { FF1, BinaryFF1 } from '@noble/ciphers/ff1.js';
import { randomBytes } from '@noble/ciphers/utils.js';
const key = randomBytes(32);
const radix = 10; // every digit is in 0..9
const ff1 = FF1(radix, key);
const encrypted = ff1.encrypt([9, 4, 1, 0]);
const digits = ff1.decrypt(encrypted);
const bff1 = BinaryFF1(key);
const encrypted2 = bff1.encrypt(Uint8Array.from([5, 6, 7]));
```

#### webcrypto: friendly wrapper

```js
import { gcm, ctr, cbc } from '@noble/ciphers/webcrypto.js';
import { randomBytes } from '@noble/ciphers/utils.js';
const plaintext = new Uint8Array(32).fill(16);
const key = randomBytes(32);
for (const [cipher, nonceLength] of [[gcm, 12], [ctr, 16], [cbc, 16]]) {
  const nonce = randomBytes(nonceLength);
  const ciphertext_ = await cipher(key, nonce).encrypt(plaintext);
  const plaintext_ = await cipher(key, nonce).decrypt(ciphertext_);
}
```

A thin wrapper over built-in `crypto.subtle`, mirroring the noble-ciphers API.
Webcrypto methods are always async.

#### utils

```js
import { bytesToHex as toHex, hexToBytes, randomBytes } from '@noble/ciphers/utils.js';
console.log(toHex(randomBytes(32)));
```

- `bytesToHex`, `hexToBytes` convert between `Uint8Array` and hex string
- `randomBytes(len)` produces cryptographically secure random bytes
- `managedNonce` is described below

#### managedNonce: automatic nonce handling

We provide API that manages nonce internally instead of exposing them to library's user.

For `encrypt`: a `nonceBytes`-length buffer is fetched from CSPRNG and prepended to encrypted ciphertext.

For `decrypt`: first `nonceBytes` of ciphertext are treated as nonce.

> [!NOTE]
> AES-GCM & ChaCha (NOT XChaCha) [limit amount of messages](#encryption-limits)
> encryptable under the same key.

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hexToBytes, managedNonce } from '@noble/ciphers/utils.js';
const key = hexToBytes('fa686bfdffd3758f6377abbc23bf3d9bdc1a0dda4a6e7f8dbdd579fa1ff6d7e1');
const chacha = managedNonce(xchacha20poly1305)(key); // manages nonces for you
const data = new TextEncoder().encode('hello noble');
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
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/ciphers/utils.js';

const key = randomBytes(32);
const nonce = randomBytes(12);
const chacha = chacha20poly1305(key, nonce);

const input = new TextEncoder().encode('hello noble'); // length == 12
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

#### Randomness generation

We provide userspace CSPRNG (cryptographically secure pseudorandom number generator).
It's best to limit their usage to non-production, non-critical cases: for example, test-only usage.
ChaCha-based CSPRNG does not have a specification, which makes it less secure.
The AES factories implement the no-derivation-function CTR_DRBG construction for AES-128 and
AES-256 only; derivation-function mode and an AES-192 factory are not provided.

```js
import { randomBytes } from '@noble/ciphers/utils.js';
import { rngAesCtrDrbg256 } from '@noble/ciphers/aes.js';
import { rngChacha8, rngChacha20 } from '@noble/ciphers/chacha.js';

// 1. Best: WebCrypto
const rnd1 = randomBytes(32);
// 2. AES-CTR DRBG
const seed2 = randomBytes(48);
const rnd2 = rngAesCtrDrbg256(seed2).randomBytes(1024);
// 3. ChaCha8 CSPRNG
const seed3 = randomBytes(32);
const rnd3 = rngChacha8(seed3).randomBytes(1024);
```

#### Use password for encryption

It is not safe to convert password into Uint8Array.
Instead, KDF stretching function like PBKDF2 / Scrypt / Argon2id
should be applied to convert password to AES key.
Make sure to use salt (app-specific secret) in addition to password.

> `npm install @noble/hashes`

```js
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { managedNonce } from '@noble/ciphers/utils.js';
import { scrypt } from '@noble/hashes/scrypt.js';

// Convert password into 32-byte key using scrypt
const PASSWORD = 'correct-horse-battery-staple';
const APP_SPECIFIC_SECRET = 'salt-12345678-secret';
const SECURITY_LEVEL = 2 ** 20; // requires 1GB of RAM to calculate
// sync, but scryptAsync is also available
const key = scrypt(PASSWORD, APP_SPECIFIC_SECRET, {
  N: SECURITY_LEVEL,
  r: 8,
  p: 1,
  dkLen: 32,
  maxmem: 2 ** 30 + 4096,
});

// Use random, managed nonce
const chacha = managedNonce(xchacha20poly1305)(key);

const data = new TextEncoder().encode('hello noble');
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext);
```

### Specs

- Salsa20 & XSalsa20: [website](https://cr.yp.to/snuffle.html), [XSalsa PDF](https://cr.yp.to/snuffle/xsalsa-20110204.pdf)
- ChaCha20 & XChaCha20: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), [website](https://cr.yp.to/chacha.html), [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
- AES: [FIPS 197](https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf)
- AES-GCM: [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- AES-GCM-SIV: [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)
- AES-SIV: [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297)
- AESKW: [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)
- AESKWP: [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649)
- FF1: [NIST SP 800-38G](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
- Poly1305: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), [website](https://cr.yp.to/mac.html)
- GHash: [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- Polyval: [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)

## Internals

### Picking a cipher

We suggest to use **XChaCha20-Poly1305** because it's very fast and allows random nonces.
**AES-GCM-SIV** is also a good idea, because it provides resistance against nonce reuse.
**AES-GCM** is a good option when those two are not available.

### How to encrypt properly

- Use unpredictable key with enough entropy
  - Random key must be using cryptographically secure random number generator (CSPRNG), not `Math.random` etc.
  - Non-random key generated from KDF is fine
  - Re-using key is fine, but be aware of rules for cryptographic key wear-out and [encryption limits](#encryption-limits)
- Use new nonce every time and don't repeat it
  - Nonce (aka initialization vector / IV) must never repeat for the same key:
    an attacker can XOR two ciphertexts encrypted under a repeating (key, nonce) pair
    and break encryption
  - chacha and salsa20 are fine for sequential counters that _never_ repeat: `01, 02...`
    But it's not always possible to store the current counter value:
    e.g. in decentralized, unsyncable systems
  - Random nonces are risky for 96-bit / 12-byte nonces of ChaCha20 and AES-GCM:
    chance of collision is too high. It's even higher for 64-bit nonces,
    which GCM allows - don't use them
  - To safely use random nonces, utilize XSalsa20, XChaCha or AES-SIV:
    192-bit nonces minimize the chance of collision.
    When eXtended-nonce algorithms are not available, rotate keys often:
    hkdf would work great for this case
  - AES-GCM should use 12-byte nonces: smaller nonces are security risk
- Prefer authenticated encryption (AEAD)
  - Good: chacha20poly1305, GCM, GCM-SIV, ChaCha+HMAC, CTR+HMAC, CBC+HMAC
  - Bad: chacha20, raw CTR, raw CBC
  - Flipping bits or ciphertext substitution won't be detected in unauthenticated ciphers
  - Polynomial MACs are not perfect for every situation:
    they lack Random Key Robustness: the MAC can be forged, and can't
    be used in PAKE schemes. See
    [invisible salamanders attack](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/).
    To combat salamanders, `hash(key)` can be included in ciphertext,
    however, this would violate ciphertext indistinguishability:
    an attacker would know which key was used - so `HKDF(key, i)`
    could be used instead.
- Don't re-use keys between different protocols
  - For example, using ECDH key in AES can be bad
  - Use hkdf or, at least, a hash function to create sub-key instead

### Encryption limits

A "protected message" would mean a probability of `2**-50` that a passive attacker
successfully distinguishes the ciphertext outputs of the AEAD scheme from the outputs
of a random function.

- Max message size:
  - AES-GCM: ~68GB, `2**36-256`
  - Salsa, ChaCha, XSalsa, XChaCha: ~256GB, `2**38-64`
- Max amount of protected messages, under same key:
  - AES-GCM: `2**32.5`
  - Salsa, ChaCha: `2**46`, but only integrity (MAC) is affected, not confidentiality (encryption)
  - XSalsa, XChaCha: `2**72`
- Max amount of protected messages, across all keys:
  - AES-GCM: `2**69/B` where B is max blocks encrypted by a key. Meaning
    `2**59` for 1KB, `2**49` for 1MB, `2**39` for 1GB
  - Salsa, ChaCha, XSalsa, XChaCha: `2**100`
- Max amount of protected messages, under same key, using **random nonce**:
  - Relevant for 12-byte nonces with `managedNonce`: AES-GCM, ChaCha
  - `2**23` (8M) messages for `2**-50` chance, `2**32.5` (4B) for `2**-32.5` chance

Check out [draft-irtf-cfrg-aead-limits](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/) for details.

## Security

The library has been audited:

- at version 1.0.0, in Sep 2024, independently, by [cure53](https://cure53.de)
  - PDFs: [website](https://cure53.de/audit-report_noble-crypto-libs.pdf), [in-repo](./audit/2024-09-cure53-audit-nbl4.pdf)
  - [Changes since audit](https://github.com/paulmillr/noble-ciphers/compare/1.0.0..main)
  - Scope: everything
  - The audit has been funded by [OpenSats](https://opensats.org)

We've started regular AI-assisted self-audits in Apr 2026.

It is tested against property-based, cross-library and Wycheproof vectors,
and is being fuzzed in [the separate repo](https://github.com/paulmillr/fuzzing).

If you see anything unusual: investigate and report.

### Constant-timeness

We're targeting algorithmic constant time. _JIT-compiler_ and _Garbage Collector_ make "constant time"
extremely hard to achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages.

The library uses T-tables for AES, which
[leak access timings](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf).
This is also done in [OpenSSL](https://github.com/openssl/openssl/blob/2f33265039cdbd0e4589c80970e02e208f3f94d2/crypto/aes/aes_core.c#L706) and
[Go stdlib](https://cs.opensource.google/go/go/+/refs/tags/go1.22.6:src/crypto/aes/const.go;l=90) for performance reasons.
The analysis was mentioned in [hal-04652991](https://hal.science/hal-04652991/document).

### Supply chain security

- **Commits** are signed with PGP keys to prevent forgery. Be sure to verify the commit signatures
- **Releases** are made transparently through token-less GitHub CI and Trusted Publishing. Be sure to verify the [provenance logs](https://docs.npmjs.com/generating-provenance-statements) for authenticity.
- **Rare releasing** is practiced to minimize the need for re-audits by end-users.
- **Dependencies** are minimized and strictly pinned to reduce supply-chain risk.
  - We use as few dependencies as possible.
  - Version ranges are locked, and changes are checked with npm-diff.
- **Dev dependencies** are excluded from end-user installs; they’re only used for development and build steps.

For this package, there are 0 dependencies; and a few dev dependencies:

- jsbt is used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation

### Randomness

We rely on the built-in
[`crypto.getRandomValues`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues),
which is considered a cryptographically secure PRNG.

Browsers have had weaknesses in the past - and could again - but implementing a userspace CSPRNG is even worse, as there’s no reliable userspace source of high-quality entropy.

### Quantum computers

Cryptographically relevant quantum computer, if built, will allow to
utilize Grover's algorithm to break ciphers in 2^(n/2) operations, instead of 2^n.

This means AES128 should be replaced with AES256. Salsa and ChaCha are already safe.

Australian ASD prohibits AES128 [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

## Speed

```sh
npm run benchmark
```

Benchmarks measured on Apple M4.
If you need truly exemplar performance, switch to [awasm-noble](https://github.com/paulmillr/awasm-noble).

```
# 64B
xsalsa20poly1305 1470 ns
chacha20poly1305 1742 ns
xchacha20poly1305 2306 ns
aes-gcm-256 4605 ns
aes-gcm-siv-256 5846 ns
aes-siv-256 6772 ns
## Unauthenticated encryption
chacha20 468 ns
aes-cbc-256 1019 ns
aes-ctr-256 953 ns
## Random number generator
rngChacha8 479 ns

# 1MB
xsalsa20poly1305 x 341 mib/sec
chacha20poly1305 x 336 mib/sec
xchacha20poly1305 x 340 mib/sec
aes-gcm-256 x 94.8 mib/sec
aes-gcm-siv-256 x 91.4 mib/sec
aes-siv-256 x 78.7 mib/sec
## Unauthenticated encryption
chacha20 x 808 mib/sec
aes-cbc-256 x 117 mib/sec
aes-ctr-256 x 130 mib/sec
## Random number generator
rngChacha8 x 1.49 gib/sec
## Wrapper over built-in webcrypto
webcrypto ctr-256 x 6.91 gib/sec
webcrypto cbc-256 x 1.87 gib/sec
webcrypto gcm-256 x 5.67 gib/sec
```

Compare to other implementations:

```
# type=Basic, algorithm=aes-ctr
node             7,181 mib/sec
noble-webcrypto  6,834 mib/sec · ≈
noble            131 mib/sec · -55x
stablelib        128 mib/sec · -56x
aesjs            55.3 mib/sec · -130x

# type=AEAD, algorithm=AES-GCM
noble-webcrypto  5,979 mib/sec
node             5,056 mib/sec · -1.2x
noble            93.5 mib/sec · -64x
stablelib        47.1 mib/sec · -127x

# type=AEAD, algorithm=xsalsa20poly1305
noble            338 mib/sec
tweetnacl        211 mib/sec · -1.6x
```

## Upgrading

Supported node.js versions:

- v2: v20.19+ (ESM-only)
- v1: v14.21+ (ESM & CJS)

Changelog of v2, when upgrading from ciphers v1:

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
- `.js` extension must be used for all modules
    - Old: `@noble/ciphers/aes`
    - New: `@noble/ciphers/aes.js`
    - This simplifies working in browsers natively without transpilers
- webcrypto: move `randomBytes` and `managedNonce` to `utils.js`
- ghash, poly1305, polyval: only allow Uint8Array as hash inputs, prohibit `string`
- utils: new abytes; remove ahash, toBytes
- Remove modules `_assert` (use `utils`), `_micro` and `crypto` (use `webcrypto`)
- Bump TS compilation target from es2020 to es2022
- Massively improve error messages, make them more descriptive

## Contributing & testing

`npm install && npm run build && npm test` will build the code and run tests.
Slow, multi-hour large-input tests are available separately: `npm run test:slow`.

See [paulmillr.com/noble](https://paulmillr.com/noble/) for useful resources, articles,
documentation and demos related to the library.

## License

The MIT License (MIT)

Copyright (c) 2023 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

See LICENSE file.
