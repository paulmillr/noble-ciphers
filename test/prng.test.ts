import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { rngAesCtrDrbg } from '../src/aes.ts';
import { rngChacha20 } from '../src/chacha.ts';
import { hexToBytes } from '../src/utils.ts';
import { json } from './utils.ts';

const AVCP_VECTORS = json('./vectors/ctrDRBG-1.0/internalProjection.json'); // AES-CTR-DRBG

/**
 * Cryptographically Secure PRNG (CSPRNG) Notes
 *
 * 1. Forward Secrecy
 *    - If an attacker obtains the internal state, they should NOT be able to reconstruct
 *      previously generated values (important for long-running processes).
 *    - Hash-based PRNGs generally only allow predicting future outputs.
 *    - Counter-based ciphers (e.g. AES-CTR) allow recovering past and future values if the key
 *      and counter are known.
 *      • Mitigation: periodic re-keying (e.g. AES-CTR DRBG).
 *      • Reference: [Re-keying in AES-CTR DRBG](https://blog.cr.yp.to/20170723-random.html)
 *    - KeccakPRNG supports a “forget” operation, but this is Keccak-specific:
 *      • Invertibility if state is leaked: [Inverting Keccak-f](https://red0xff.github.io/posts/inverting_keccak_f/)
 *      • Equivalent to XOR’ing in zero entropy, which would not erase state in other designs.
 *
 * 2. Entropy Injection
 *    - Breaking pure determinism is required to prevent unbounded prediction.
 *    - Without fresh entropy, a PRNG degenerates into an XOF hash function.
 *
 * 3. Consistent Read Sizes
 *    - Desirable that read(2) || read(2) === read(4) for test reproducibility.
 *    - AES-CTR DRBG does not guarantee this by default.
 *      • Can be patched via an internal buffer for leftover bytes, but this diverges
 *        from other implementations.
 *
 * 4. Variable-Size Seed / Entropy Support
 *    - Nice to have, but not universally supported.
 *
 * Possible Use Cases
 * -----------------
 * - Testing: generate non-deterministic data + test vectors.
 * - Hardening: improve a biased or faulty random source (e.g. hardware faults).
 *   • Requires entropy injection.
 * - Performance: faster than environment’s randomBytes for high-throughput use.
 * - Auditing: encrypt & record seed to replay outputs exactly.
 *
 * ChaCha20-Based PRNG Landscape
 * -----------------------------
 * There is no single ChaCha20 PRNG standard—numerous incompatible implementations exist:
 *
 *  • [Linux kernel random.c](https://github.com/torvalds/linux/blob/aaf724ed69264719550ec4f194d3ab17b886af9a/drivers/char/random.c)
 *    – ChaCha + BLAKE2 hybrid, no tests, tightly coupled to kernel entropy.
 *
 *  • [OpenBSD arc4random.c](http://bxr.su/OpenBSD/lib/libc/crypt/arc4random.c)
 *    – Clean structure, no tests, unpredictable re-key interval.
 *
 *  • [LibTomCrypt prngs/chacha20.c](https://github.com/libtom/libtomcrypt/blob/develop/src/prngs/chacha20.c)
 *    – Single test, reasonable behavior; used in libtomcrypt.
 *
 *  • [RustCrypto RNG](https://github.com/RustCrypto/stream-ciphers/blob/master/chacha20/src/rng.rs)
 *    – Widely used in Rust; no entropy injection, complex multi-stream logic,
 *      inconsistent read-size behavior.
 *
 *  • [libsodium deterministic randombytes](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/randombytes/randombytes_buf_deterministic)
 *    – Essentially a single-use ChaCha20; no reseeding, nonce = library name.
 *
 *  • [libsodium internal random](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/randombytes/internal/randombytes_internal_random.c)
 *    – Untestable, seeds with current time.
 *
 *  • [Supercop knownrandombytes](https://github.com/jedisct1/supercop/blob/master/knownrandombytes/knownrandombytes.c)
 *    – Generates a large chunk, then uses first 32 bytes as next key.
 *
 *  • [chacha20_drng (smuellerDD)](https://github.com/smuellerDD/chacha20_drng/blob/master/chacha20_drng.c)
 *    – Tests & entropy injection; reseeds every 600 s—breaks determinism.
 *
 *  • [nanorand-rs chacha.rs](https://github.com/Absolucy/nanorand-rs/blob/main/src/rand/chacha.rs)
 *    – Tests; reseed wipes state, no injection.
 *
 * Conclusion
 * ----------
 * Implementing a secure, interoperable ChaCha20 PRNG is surprisingly complex and fragmented.
 * For production use, prefer:
 *    • KeccakPRNG
 *    • NIST-approved hash-based DRBGs
 * Unless you only need a PRNG for testing purposes.
 */

describe('PRNG', () => {
  should('AES', () => {
    for (const g of AVCP_VECTORS.testGroups) {
      if (g.derFunc) continue; // No DF support (for now?)
      if (!g.mode.startsWith('AES-')) continue;
      const bits = +g.mode.slice(4);
      for (const t of g.tests) {
        const drbg = rngAesCtrDrbg(bits)(hexToBytes(t.entropyInput), hexToBytes(t.persoString));
        let lastVal;
        for (const i of t.otherInput) {
          if (i.intendedUse === 'reSeed') {
            drbg.addEntropy(hexToBytes(i.entropyInput), hexToBytes(i.additionalInput));
          } else if (i.intendedUse === 'generate') {
            if (g.predResistance) {
              drbg.addEntropy(hexToBytes(i.entropyInput), hexToBytes(i.additionalInput));
              lastVal = drbg.randomBytes(g.returnedBitsLen / 8);
            } else lastVal = drbg.randomBytes(g.returnedBitsLen / 8, hexToBytes(i.additionalInput));
          } else throw new Error('unkwnon op');
        }
        eql(lastVal, hexToBytes(t.returnedBits));
      }
    }
  });
  // Compatible with: https://github.com/libtom/libtomcrypt/blob/develop/src/prngs/chacha20.c
  // Features:
  // - entropy injection
  // - variable seed/entropy length
  // - no forward secrecy by default (==no re-key)
  // - read(2)||read(2) === read(4)
  should('ChaCha20', () => {
    const ent = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
      0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
      0x2e, 0x2f, 0x30, 0x31, 0x32,
    ]);
    const t1 = new Uint8Array([0x59, 0xb2, 0x26, 0x95, 0x2b, 0x01, 0x8f, 0x05, 0xbe, 0xd8]);
    const t2 = new Uint8Array([0x47, 0xc9, 0x0d, 0x03, 0xe4, 0x75, 0x34, 0x27, 0xbd, 0xde]);
    const t3 = new Uint8Array([0xbc, 0xfa, 0xef, 0x59, 0x37, 0x7f, 0x1a, 0x91, 0x1a, 0xa6]);
    const prng = rngChacha20(ent);
    eql(prng.randomBytes(10), t1, 't1');
    prng.randomBytes(500); // skip(500)
    prng.addEntropy(ent); // rekey
    prng.randomBytes(500); // skip(500)
    const clone = prng.clone();
    prng.randomBytes(500); // skip(500)
    eql(prng.randomBytes(10), t2, 't2');
    clone.randomBytes(500); // skip(500)
    eql(clone.randomBytes(10), t3, 't3');
  });
});

should.runWhen(import.meta.url);
