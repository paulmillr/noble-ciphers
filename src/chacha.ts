/**
 * ChaCha stream cipher, released
 * in 2008. Developed after Salsa20, ChaCha aims to increase diffusion per round.
 * It was standardized in
 * {@link https://www.rfc-editor.org/rfc/rfc8439 | RFC 8439} and
 * is now used in TLS 1.3.
 *
 * {@link https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha | XChaCha20}
 * extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
 * randomly-generated nonces.
 *
 * Check out
 * {@link http://cr.yp.to/chacha/chacha-20080128.pdf | PDF},
 * {@link https://en.wikipedia.org/wiki/Salsa20 | wiki}, and
 * {@link https://cr.yp.to/chacha.html | website}.
 *
 * @module
 */
import { type XorPRG, createCipher, createPRG, rotl } from './_arx.ts';
import { poly1305 } from './_poly1305.ts';
import {
  type ARXCipher,
  type CipherWithOutput,
  type TArg,
  type TRet,
  type XorStream,
  abytes,
  clean,
  equalBytes,
  getOutput,
  isLE,
  swap32IfBE,
  u64Lengths,
  wrapCipher,
} from './utils.ts';

/**
 * ChaCha core function. Uses an unrolled loop (chachaCore, hchacha) - 4x
 * faster than a simple loop, but larger & harder to read. A simple-loop
 * reference version lives in `test/misc/micro-ciphers.ts`;
 * `test/arx.test.ts` keeps the two aligned.
 * The specific implementation is selected in `createCipher` below.
 */

/** RFC 8439 §2.3 block core for `state = constants | key | counter | nonce`. */
// prettier-ignore
function chachaCore(
  s: TArg<Uint32Array>, k: TArg<Uint32Array>, n: TArg<Uint32Array>, out: TArg<Uint32Array>, cnt: number, rounds = 20
): void {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], // "expa"   "nd 3"  "2-by"  "te k"
      y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], // Key      Key     Key     Key
      y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], // Key      Key     Key     Key
      y12 = cnt,  y13 = n[0], y14 = n[1], y15 = n[2];  // Counter  Nonce   Nonce   Nonce
  // Save state to temporary variables
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x00 = (x00 + x04) | 0; x12 = rotl(x12 ^ x00, 16);
    x08 = (x08 + x12) | 0; x04 = rotl(x04 ^ x08, 12);
    x00 = (x00 + x04) | 0; x12 = rotl(x12 ^ x00, 8);
    x08 = (x08 + x12) | 0; x04 = rotl(x04 ^ x08, 7);

    x01 = (x01 + x05) | 0; x13 = rotl(x13 ^ x01, 16);
    x09 = (x09 + x13) | 0; x05 = rotl(x05 ^ x09, 12);
    x01 = (x01 + x05) | 0; x13 = rotl(x13 ^ x01, 8);
    x09 = (x09 + x13) | 0; x05 = rotl(x05 ^ x09, 7);

    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^ x02, 16);
    x10 = (x10 + x14) | 0; x06 = rotl(x06 ^ x10, 12);
    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^ x02, 8);
    x10 = (x10 + x14) | 0; x06 = rotl(x06 ^ x10, 7);

    x03 = (x03 + x07) | 0; x15 = rotl(x15 ^ x03, 16);
    x11 = (x11 + x15) | 0; x07 = rotl(x07 ^ x11, 12);
    x03 = (x03 + x07) | 0; x15 = rotl(x15 ^ x03, 8)
    x11 = (x11 + x15) | 0; x07 = rotl(x07 ^ x11, 7);

    x00 = (x00 + x05) | 0; x15 = rotl(x15 ^ x00, 16);
    x10 = (x10 + x15) | 0; x05 = rotl(x05 ^ x10, 12);
    x00 = (x00 + x05) | 0; x15 = rotl(x15 ^ x00, 8);
    x10 = (x10 + x15) | 0; x05 = rotl(x05 ^ x10, 7);

    x01 = (x01 + x06) | 0; x12 = rotl(x12 ^ x01, 16);
    x11 = (x11 + x12) | 0; x06 = rotl(x06 ^ x11, 12);
    x01 = (x01 + x06) | 0; x12 = rotl(x12 ^ x01, 8);
    x11 = (x11 + x12) | 0; x06 = rotl(x06 ^ x11, 7);

    x02 = (x02 + x07) | 0; x13 = rotl(x13 ^ x02, 16);
    x08 = (x08 + x13) | 0; x07 = rotl(x07 ^ x08, 12);
    x02 = (x02 + x07) | 0; x13 = rotl(x13 ^ x02, 8);
    x08 = (x08 + x13) | 0; x07 = rotl(x07 ^ x08, 7);

    x03 = (x03 + x04) | 0; x14 = rotl(x14 ^ x03, 16)
    x09 = (x09 + x14) | 0; x04 = rotl(x04 ^ x09, 12);
    x03 = (x03 + x04) | 0; x14 = rotl(x14 ^ x03, 8);
    x09 = (x09 + x14) | 0; x04 = rotl(x04 ^ x09, 7);
  }
  // RFC 8439 §2.3 / §2.3.1: add the original state words back in state order.
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
 * hchacha hashes key and nonce into key' and nonce' for xchacha20.
 * Algorithmically identical to `hchacha_small` from `test/misc/micro-ciphers.ts`,
 * but this exported path normalizes word order on big-endian hosts.
 * Reuses `chachaCore` and subtracts its feed-forward, keeping the hot per-block
 * path untouched.
 * @param s - Sigma constants as 32-bit words.
 * @param k - Key words.
 * @param i - Nonce-prefix words.
 * @param out - Output buffer for the derived subkey.
 * @example
 * Derives the XChaCha subkey from sigma, key, and nonce-prefix words.
 *
 * ```ts
 * const sigma = new Uint32Array(4);
 * const key = new Uint32Array(8);
 * const nonce = new Uint32Array(4);
 * const out = new Uint32Array(8);
 * hchacha(sigma, key, nonce, out);
 * ```
 */
// prettier-ignore
export function hchacha(
  s: TArg<Uint32Array>, k: TArg<Uint32Array>, i: TArg<Uint32Array>, out: TArg<Uint32Array>
): void {
  // Runs the shared chachaCore permutation, then subtracts the RFC 8439 feed-forward
  // it applies, recovering the raw permutation words hchacha needs.
  // LE hosts read the caller arrays in place (no copies); BE hosts get
  // byte-swapped scratch copies, wiped before returning.
  const s2 = isLE ? s : swap32IfBE(s.slice(0, 4));
  const k2 = isLE ? k : swap32IfBE(k.slice(0, 8));
  const i2 = isLE ? i : swap32IfBE(i.slice(0, 4));
  const t = new Uint32Array(16);
  chachaCore(s2, k2, i2.subarray(1), t, i2[0]);
  let oi = 0;
  out[oi++] = (t[0] - s2[0]) | 0; out[oi++] = (t[1] - s2[1]) | 0;
  out[oi++] = (t[2] - s2[2]) | 0; out[oi++] = (t[3] - s2[3]) | 0;
  out[oi++] = (t[12] - i2[0]) | 0; out[oi++] = (t[13] - i2[1]) | 0;
  out[oi++] = (t[14] - i2[2]) | 0; out[oi++] = (t[15] - i2[3]) | 0;
  swap32IfBE(out);
  if (!isLE) clean(s2, k2, i2);
  clean(t);
}

/**
 * Original, non-RFC chacha20 from DJB. 8-byte nonce, 8-byte counter.
 * The nonce/counter layout still reserves 8 counter bytes internally, but the shared public
 * `counter` argument follows noble's strict non-wrapping 32-bit policy. See `src/_arx.ts`
 * near `MAX_COUNTER` for the full counter-policy rationale.
 * @param key - 16-byte or 32-byte key.
 * @param nonce - 8-byte nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Encrypts bytes with the original 8-byte-nonce ChaCha variant and a fresh key/nonce.
 *
 * ```ts
 * import { chacha20orig } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(8);
 * chacha20orig(key, nonce, new Uint8Array(4));
 * ```
 */
export const chacha20orig: TRet<XorStream> = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 8,
  allowShortKeys: true,
});
/**
 * ChaCha stream cipher. Conforms to RFC 8439 (IETF, TLS). 12-byte nonce, 4-byte counter.
 * With smaller nonce, it's not safe to make it random (CSPRNG), due to collision chance.
 * @param key - 32-byte key.
 * @param nonce - 12-byte nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Encrypts bytes with the RFC 8439 ChaCha20 stream cipher and a fresh key/nonce.
 *
 * ```ts
 * import { chacha20 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(12);
 * chacha20(key, nonce, new Uint8Array(4));
 * ```
 */
export const chacha20: TRet<XorStream> = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false,
});

/**
 * XChaCha eXtended-nonce ChaCha. With 24-byte nonce, it's safe to make it random (CSPRNG).
 * See {@link https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha | the IRTF draft}.
 * The nonce/counter layout still reserves 8 counter bytes internally, but the shared public
 * `counter` argument follows noble's strict non-wrapping 32-bit policy. See `src/_arx.ts`
 * near `MAX_COUNTER` for the full counter-policy rationale.
 * @param key - 32-byte key.
 * @param nonce - 24-byte extended nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Encrypts bytes with XChaCha20 using a fresh key and random 24-byte nonce.
 *
 * ```ts
 * import { xchacha20 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(24);
 * xchacha20(key, nonce, new Uint8Array(4));
 * ```
 */
export const xchacha20: TRet<XorStream> = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 8,
  extendNonceFn: hchacha,
  allowShortKeys: false,
});

/**
 * Reduced 8-round chacha, described in original paper.
 * @param key - 32-byte key.
 * @param nonce - 12-byte nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Uses the reduced 8-round variant for non-critical workloads with a fresh key/nonce.
 *
 * ```ts
 * import { chacha8 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(12);
 * chacha8(key, nonce, new Uint8Array(4));
 * ```
 */
export const chacha8: TRet<XorStream> = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  rounds: 8,
});

/**
 * Reduced 12-round chacha, described in original paper.
 * @param key - 32-byte key.
 * @param nonce - 12-byte nonce.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Initial block counter.
 * @returns Encrypted or decrypted bytes.
 * @example
 * Uses the reduced 12-round variant for non-critical workloads with a fresh key/nonce.
 *
 * ```ts
 * import { chacha12 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(12);
 * chacha12(key, nonce, new Uint8Array(4));
 * ```
 */
export const chacha12: TRet<XorStream> = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  rounds: 12,
});

// Test-only hook: exposes the unrolled production core so tests can compare it
// with the simple/reference core from `test/misc/micro-ciphers.ts`.
export const __TESTS: {
  chachaCore: typeof chachaCore;
} = /* @__PURE__ */ Object.freeze({ chachaCore });

// RFC 8439 §2.8.1 pad16(x): shared zero block for AAD/ciphertext padding.
const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
// RFC 8439 §2.8 / §2.8.1: aligned inputs add nothing, otherwise append 16-(len%16) zero bytes.
const updatePadded = (h: ReturnType<typeof poly1305.create>, msg: TArg<Uint8Array>) => {
  h.update(msg);
  const leftover = msg.length % 16;
  if (leftover) h.update(ZEROS16.subarray(leftover));
};

// RFC 8439 §2.6.1 poly1305_key_gen returns `block[0..31]`, so AEAD key
// generation only needs 32 zero bytes.
const ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
function computeTag(
  fn: TArg<XorStream>,
  key: TArg<Uint8Array>,
  nonce: TArg<Uint8Array>,
  ciphertext: TArg<Uint8Array>,
  AAD?: TArg<Uint8Array>
): TRet<Uint8Array> {
  if (AAD !== undefined) abytes(AAD, undefined, 'AAD');
  // RFC 8439 §2.6 / §2.8: derive the Poly1305 one-time key from counter 0,
  // then MAC AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || len(AAD) || len(ciphertext).
  const authKey = fn(
    key as TRet<Uint8Array>,
    nonce as TRet<Uint8Array>,
    ZEROS32 as TRet<Uint8Array>
  );
  const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0, true);

  // Methods below can be replaced with
  // `return poly1305_computeTag_small(authKey, lengths, ciphertext, AAD)`
  // from `test/misc/micro-ciphers.ts`.
  const h = poly1305.create(authKey);
  if (AAD) updatePadded(h, AAD);
  updatePadded(h, ciphertext);
  h.update(lengths);
  const res = h.digest();
  clean(authKey, lengths);
  return res;
}

/**
 * AEAD algorithm from RFC 8439.
 * Salsa20 and chacha (RFC 8439) use poly1305 differently.
 * We could have composed them, but it's hard because of authKey:
 * In salsa20, authKey changes position in salsa stream.
 * In chacha, authKey can't be computed inside computeTag, it modifies the counter.
 */
export const _poly1305_aead =
  (xorStream: TArg<XorStream>) =>
  (key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>): CipherWithOutput => {
    // This borrows caller key/nonce/AAD buffers by reference; mutating them after construction
    // changes future encrypt/decrypt results.
    const tagLength = 16;
    return {
      encrypt(plaintext: TArg<Uint8Array>, output?: TArg<Uint8Array>): TRet<Uint8Array> {
        const plength = plaintext.length;
        output = getOutput(plength + tagLength, output, false);
        output.set(plaintext);
        const oPlain = output.subarray(0, -tagLength);
        // RFC 8439 §2.8: payload encryption starts at counter 1 because counter 0 produced the OTK.
        xorStream(
          key as TRet<Uint8Array>,
          nonce as TRet<Uint8Array>,
          oPlain as TRet<Uint8Array>,
          oPlain as TRet<Uint8Array>,
          1
        );
        const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
        output.set(tag, plength); // append tag
        clean(tag);
        return output as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>, output?: TArg<Uint8Array>): TRet<Uint8Array> {
        output = getOutput(ciphertext.length - tagLength, output, false);
        const data = ciphertext.subarray(0, -tagLength);
        const passedTag = ciphertext.subarray(-tagLength);
        const tag = computeTag(xorStream, key, nonce, data, AAD);
        // RFC 8439 §2.8 / §4: authenticate ciphertext before decrypting it, and compare tags with
        // the constant-time equalBytes() helper rather than decrypting speculative plaintext first.
        if (!equalBytes(passedTag, tag)) {
          clean(tag);
          throw new Error('invalid tag');
        }
        output.set(ciphertext.subarray(0, -tagLength));
        // Actual decryption
        xorStream(
          key as TRet<Uint8Array>,
          nonce as TRet<Uint8Array>,
          output as TRet<Uint8Array>,
          output as TRet<Uint8Array>,
          1
        ); // start stream with i=1
        clean(tag);
        return output as TRet<Uint8Array>;
      },
    };
  };

/**
 * ChaCha20-Poly1305 from RFC 8439.
 *
 * Unsafe to use random nonces under the same key, due to collision chance.
 * Prefer XChaCha instead.
 * @param key - 32-byte key.
 * @param nonce - 12-byte nonce.
 * @param AAD - Additional authenticated data.
 * @returns AEAD cipher instance.
 * @example
 * Encrypts and authenticates plaintext with a fresh key and nonce.
 *
 * ```ts
 * import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(12);
 * const aad = new TextEncoder().encode('session metadata');
 * const cipher = chacha20poly1305(key, nonce, aad);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const chacha20poly1305: TRet<ARXCipher & { withAAD: true }> = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 12, tagLength: 16, withAAD: true },
  /* @__PURE__ */ _poly1305_aead(chacha20)
);
/**
 * XChaCha20-Poly1305 extended-nonce chacha.
 *
 * Can be safely used with random nonces (CSPRNG).
 * See {@link https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha | the IRTF draft}.
 * @param key - 32-byte key.
 * @param nonce - 24-byte nonce.
 * @param AAD - Additional authenticated data.
 * @returns AEAD cipher instance.
 * @example
 * Encrypts and authenticates plaintext with a fresh key and random 24-byte nonce.
 *
 * ```ts
 * import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const nonce = randomBytes(24);
 * const aad = new TextEncoder().encode('session metadata');
 * const cipher = xchacha20poly1305(key, nonce, aad);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const xchacha20poly1305: TRet<ARXCipher & { withAAD: true }> = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 24, tagLength: 16, withAAD: true },
  /* @__PURE__ */ _poly1305_aead(xchacha20)
);

/**
 * Chacha20 CSPRNG (cryptographically secure pseudorandom number generator).
 * It's best to limit usage to non-production, non-critical cases: for example, test-only.
 * Compatible with libtomcrypt. It does not have a specification, so unclear how secure it is.
 * @param seed - Optional seed bytes mixed into the internal `key || nonce` state. When omitted,
 * only 32 random bytes are mixed into the 40-byte state.
 * @returns Seeded concrete `_XorStreamPRG` instance, including `clone()`.
 * @example
 * Seeds the test-only ChaCha20 DRBG from fresh entropy.
 *
 * ```ts
 * import { rngChacha20 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const seed = randomBytes(32);
 * const prg = rngChacha20(seed);
 * prg.randomBytes(8);
 * ```
 */
export const rngChacha20: TRet<XorPRG> = /* @__PURE__ */ createPRG(chacha20orig, 64, 32, 8);
/**
 * Chacha20/8 CSPRNG (cryptographically secure pseudorandom number generator).
 * It's best to limit usage to non-production, non-critical cases: for example, test-only.
 * Faster than `rngChacha20`.
 * @param seed - Optional seed bytes mixed into the internal `key || nonce` state. When omitted,
 * only 32 random bytes are mixed into the 44-byte state.
 * @returns Seeded concrete `_XorStreamPRG` instance, including `clone()`.
 * @example
 * Seeds the faster test-only ChaCha8 DRBG from fresh entropy.
 *
 * ```ts
 * import { rngChacha8 } from '@noble/ciphers/chacha.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const seed = randomBytes(32);
 * const prg = rngChacha8(seed);
 * prg.randomBytes(8);
 * ```
 */
export const rngChacha8: TRet<XorPRG> = /* @__PURE__ */ createPRG(chacha8, 64, 32, 12);
