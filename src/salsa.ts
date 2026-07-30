/**
 * Salsa20 stream cipher, released in 2005.
 * Salsa's goal was to implement AES replacement that does not rely on S-Boxes,
 * which are hard to implement in a constant-time manner.
 * Salsa20 is usually faster than AES, a big deal on slow, budget mobile phones.
 *
 * - {@link https://cr.yp.to/snuffle/xsalsa-20110204.pdf | XSalsa20},
 *   extended-nonce
 *   variant was released in 2008. It extends Salsa20's 64-bit nonce to 192 bits,
 *   and became safe to be picked at random.
 * - Nacl / Libsodium popularized term "secretbox", - which is just xsalsa20poly1305.
 *   We provide the alias and corresponding seal / open methods.
 *   "crypto_box" and "sealedbox" are available in package
 *   {@link https://github.com/serenity-kit/noble-sodium | noble-sodium}.
 * - Check out
 *   {@link https://cr.yp.to/snuffle/salsafamily-20071225.pdf | PDF}
 *   and {@link https://cr.yp.to/snuffle.html | website}.
 * @module
 */
import { createCipher, rotl } from './_arx.ts';
import { poly1305 } from './_poly1305.ts';
import {
  abytes,
  clean,
  equalBytes,
  getOutput,
  isLE,
  swap32IfBE,
  wrapCipher,
  type ARXCipher,
  type CipherWithOutput,
  type TArg,
  type TRet,
  type XorStream,
} from './utils.ts';

/**
 * Salsa20 core function. Uses an unrolled loop (salsaCore, hsalsa) - 4x
 * faster than a simple loop, but larger & harder to read. A simple-loop
 * reference version lives in `test/misc/micro-ciphers.ts`;
 * `test/arx.test.ts` keeps the two aligned.
 * The specific implementation is selected in `createCipher` below.
 * Performance numbers for 1MB inputs:
 * * default x 779 ops/sec @ 1ms/op
 * * if salsa+hsalsa are merged x 459 ops/sec @ 2ms/op
 * * small x 132 ops/sec @ 7ms/op
 */

/** Uses only the low 32 bits of Salsa20's 64-bit counter state. */
// prettier-ignore
function salsaCore(
  s: TArg<Uint32Array>, k: TArg<Uint32Array>, n: TArg<Uint32Array>, out: TArg<Uint32Array>, cnt: number, rounds = 20, cntHi = 0
): void {
  // Public wrappers expose only the low 32 bits of Salsa20's 64-bit counter; y09 stays zero
  // there. hsalsa reuses this core with its input words 2-3 in the counter positions.
  // Based on {@link https://cr.yp.to/salsa20.html | the Salsa20 reference page}.
  let y00 = s[0], y01 = k[0], y02 = k[1], y03 = k[2], // "expa" Key     Key     Key
      y04 = k[3], y05 = s[1], y06 = n[0], y07 = n[1], // Key    "nd 3"  Nonce   Nonce
      y08 = cnt,  y09 = cntHi,    y10 = s[2], y11 = k[4], // Pos.   Pos.    "2-by"	Key
      y12 = k[5], y13 = k[6], y14 = k[7], y15 = s[3]; // Key    Key     Key     "te k"
  // Save state to temporary variables
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0, 9);
    x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18);
    x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0, 9);
    x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18);
    x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0, 9);
    x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18);
    x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0, 9);
    x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18);
    x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0, 9);
    x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18);
    x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0, 9);
    x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18);
    x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0, 9);
    x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18);
    x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0, 9);
    x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18);
  }
  // Write output
  let oi = 0;
  out[oi++] = (y00 + x00) | 0; out[oi++] = (y01 + x01) | 0;
  out[oi++] = (y02 + x02) | 0; out[oi++] = (y03 + x03) | 0;
  out[oi++] = (y04 + x04) | 0; out[oi++] = (y05 + x05) | 0;
  out[oi++] = (y06 + x06) | 0; out[oi++] = (y07 + x07) | 0;
  out[oi++] = (y08 + x08) | 0; out[oi++] = (y09 + x09) | 0;
  out[oi++] = (y10 + x10) | 0; out[oi++] = (y11 + x11) | 0;
  out[oi++] = (y12 + x12) | 0; out[oi++] = (y13 + x13) | 0;
  out[oi++] = (y14 + x14) | 0; out[oi++] = (y15 + x15) | 0;
}

/**
 * hsalsa hashes key and nonce-prefix words into the 32-byte subkey used by XSalsa20.
 * Algorithmically identical to `hsalsa_small` from `test/misc/micro-ciphers.ts`,
 * but this exported path normalizes word order on big-endian hosts.
 * Reuses `salsaCore` and subtracts its feed-forward, keeping the hot per-block
 * path untouched.
 * @param s - Sigma constants as 32-bit words.
 * @param k - Key words.
 * @param i - Nonce-prefix words.
 * @param out - Output buffer for the derived subkey.
 * @example
 * Derives the XSalsa20 subkey from sigma, key, and nonce-prefix words.
 *
 * ```ts
 * const sigma = new Uint32Array(4);
 * const key = new Uint32Array(8);
 * const nonce = new Uint32Array(4);
 * const out = new Uint32Array(8);
 * hsalsa(sigma, key, nonce, out);
 * ```
 */
// prettier-ignore
export function hsalsa(
  s: TArg<Uint32Array>, k: TArg<Uint32Array>, i: TArg<Uint32Array>, out: TArg<Uint32Array>
): void {
  // Runs the shared salsaCore permutation, then subtracts the feed-forward it applies,
  // recovering the raw permutation words hsalsa needs.
  // LE hosts read the caller arrays in place (no copies); BE hosts get
  // byte-swapped scratch copies, wiped before returning.
  const s2 = isLE ? s : swap32IfBE(s.slice(0, 4));
  const k2 = isLE ? k : swap32IfBE(k.slice(0, 8));
  const i2 = isLE ? i : swap32IfBE(i.slice(0, 4));
  const t = new Uint32Array(16);
  salsaCore(s2, k2, i2.subarray(0, 2), t, i2[2], 20, i2[3]);
  let oi = 0;
  // XSalsa20 takes words 0,5,10,15 and 6,7,8,9 as the 32-byte subkey material.
  out[oi++] = (t[0] - s2[0]) | 0; out[oi++] = (t[5] - s2[1]) | 0;
  out[oi++] = (t[10] - s2[2]) | 0; out[oi++] = (t[15] - s2[3]) | 0;
  out[oi++] = (t[6] - i2[0]) | 0; out[oi++] = (t[7] - i2[1]) | 0;
  out[oi++] = (t[8] - i2[2]) | 0; out[oi++] = (t[9] - i2[3]) | 0;
  swap32IfBE(out);
  if (!isLE) clean(s2, k2, i2);
  clean(t);
}

/**
 * Salsa20 from original paper. 8-byte nonce.
 * With smaller nonce, it's not safe to make it random (CSPRNG), due to collision chance.
 * @param key - 16-byte or 32-byte key.
 * @param nonce - 8-byte nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * Only the low 32 bits of Salsa20's 64-bit counter state are exposed here;
 * the high word stays zero and the implementation still caps the public
 * value to 32 bits.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Encrypts bytes with the original 8-byte-nonce Salsa20 stream cipher.
 *
 * ```ts
 * import { salsa20 } from '@noble/ciphers/salsa.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(8);
 * salsa20(key, nonce, new Uint8Array([1, 2, 3, 4]));
 * ```
 */
export const salsa20: TRet<XorStream> = /* @__PURE__ */ createCipher(salsaCore, {
  allowShortKeys: true,
  counterRight: true,
});

/**
 * XSalsa20 extended-nonce salsa.
 * With 24-byte nonce, it's safe to make it random (CSPRNG).
 * @param key - 32-byte key.
 * This XSalsa20 wrapper does not enable Salsa20's 16-byte legacy key mode.
 * @param nonce - 24-byte nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Encrypts bytes with XSalsa20 and a random 24-byte nonce.
 *
 * ```ts
 * import { xsalsa20 } from '@noble/ciphers/salsa.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(24);
 * xsalsa20(key, nonce, new Uint8Array([1, 2, 3, 4]));
 * ```
 */
export const xsalsa20: TRet<XorStream> = /* @__PURE__ */ createCipher(salsaCore, {
  counterRight: true,
  extendNonceFn: hsalsa,
});

// Test-only hook: exposes the unrolled production core so tests can compare it
// with the simple/reference core from `test/misc/micro-ciphers.ts`.
export const __TESTS: {
  salsaCore: typeof salsaCore;
} = /* @__PURE__ */ Object.freeze({ salsaCore });

/**
 * xsalsa20-poly1305 eXtended-nonce (24 bytes) salsa.
 * With 24-byte nonce, it's safe to make it random (CSPRNG).
 * Also known as `secretbox` from libsodium / nacl.
 * No AAD input is supported here. Caller-provided `output` buffers for
 * `encrypt()` / `decrypt()` must be `input.length + 32` bytes because the
 * implementation uses a 32-byte leading scratch area before returning `+16`.
 * @param key - 32-byte key.
 * @param nonce - 24-byte nonce.
 * @param AAD - Must be omitted; XSalsa20-Poly1305 secretbox does not support associated data.
 * @returns AEAD cipher instance.
 * @example
 * Encrypts and authenticates plaintext with XSalsa20-Poly1305.
 *
 * ```ts
 * import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(24);
 * const cipher = xsalsa20poly1305(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const xsalsa20poly1305: TRet<ARXCipher> = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 24, tagLength: 16 },
  (key: TArg<Uint8Array>, nonce: TArg<Uint8Array>): TRet<CipherWithOutput> => {
    // This borrows caller key/nonce buffers by reference; mutating them after construction changes
    // later encrypt/decrypt outputs.
    return {
      encrypt(plaintext: TArg<Uint8Array>, output?: TArg<Uint8Array>): TRet<Uint8Array> {
        // xsalsa20poly1305 optimizes by calculating auth key during the same call as encryption.
        // Unfortunately, makes it hard to separate tag calculation & encryption itself,
        // because 32 bytes is half-block of 64-byte salsa.
        // Need 32 extra bytes up front for the auth-key scratch area described above.
        output = getOutput(plaintext.length + 32, output, false);
        // output[0..32] = Poly1305 auth key, output[32..] = plaintext then ciphertext.
        const authKey = output.subarray(0, 32);
        const ciphPlaintext = output.subarray(32);
        output.set(plaintext, 32);
        // authKey is produced by xoring the first 32 bytes with zeros.
        clean(authKey);
        // output = stream ^ output; authKey = stream ^ zeros(32)
        xsalsa20(key, nonce, output, output);
        const tag = poly1305(ciphPlaintext, authKey);
        output.set(tag, 16);
        // Clean up auth-key remnants and the temporary tag copy.
        clean(output.subarray(0, 16), tag);
        // Return output[16..].
        return output.subarray(16) as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>, output?: TArg<Uint8Array>): TRet<Uint8Array> {
        // tmp part     passed tag    ciphertext
        // [0..32]      [32..48]      [48..]
        // Authenticate the ciphertext before decrypting it; on tag failure the scratch/output
        // buffer may already contain copied ciphertext and derived auth-key material.
        abytes(ciphertext, undefined, 'data');
        output = getOutput(ciphertext.length + 32, output, false);
        // output[0..32] is auth-key scratch, output[32..48] is passed tag,
        // output[48..] is ciphertext then plaintext.
        const tmp = output.subarray(0, 32);
        const passedTag = output.subarray(32, 48);
        const ciphPlaintext = output.subarray(48);
        output.set(ciphertext, 32);
        // authKey is produced by xoring the scratch area with zeros.
        clean(tmp);
        const authKey = xsalsa20(key, nonce, tmp, tmp);
        const tag = poly1305(ciphPlaintext, authKey);
        if (!equalBytes(passedTag, tag)) {
          clean(output);
          throw new Error('invalid tag');
        }
        // output = stream ^ output[16..]
        xsalsa20(key, nonce, output.subarray(16), output.subarray(16));
        clean(tmp, passedTag, tag);
        // Return output[48..], skipping zeroized output[0..48].
        return ciphPlaintext as TRet<Uint8Array>;
      },
    } as TRet<CipherWithOutput>;
  }
);

/**
 * Alias to `xsalsa20poly1305`, for compatibility with libsodium / nacl.
 * Check out {@link https://github.com/serenity-kit/noble-sodium | noble-sodium}
 * for `crypto_box`.
 * @param key - 32-byte key.
 * @param nonce - 24-byte nonce.
 * @returns Wrapper with `seal()` and `open()` helpers.
 * @example
 * Uses the libsodium-style `seal()` and `open()` wrapper.
 *
 * ```ts
 * import { secretbox } from '@noble/ciphers/salsa.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(24);
 * const box = secretbox(key, nonce);
 * box.seal(new Uint8Array([1, 2, 3]));
 * ```
 */
export function secretbox(
  key: TArg<Uint8Array>,
  nonce: TArg<Uint8Array>
): TRet<{
  seal: (plaintext: TArg<Uint8Array>, output?: TArg<Uint8Array>) => TRet<Uint8Array>;
  open: (ciphertext: TArg<Uint8Array>, output?: TArg<Uint8Array>) => TRet<Uint8Array>;
}> {
  const xs = xsalsa20poly1305(key, nonce);
  return { seal: xs.encrypt, open: xs.decrypt } as TRet<{
    seal: (plaintext: TArg<Uint8Array>, output?: TArg<Uint8Array>) => TRet<Uint8Array>;
    open: (ciphertext: TArg<Uint8Array>, output?: TArg<Uint8Array>) => TRet<Uint8Array>;
  }>;
}
