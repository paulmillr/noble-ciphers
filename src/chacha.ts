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
  swap8IfBE,
  swap32IfBE,
  u64Lengths,
  wrapCipher,
} from './utils.ts';

/**
 * ChaCha core function. It is implemented twice:
 * 1. Simple loop (chachaCore_small, hchacha_small)
 * 2. Unrolled loop (chachaCore, hchacha) - 4x faster, but larger & harder to read
 * The specific implementation is selected in `createCipher` below.
 */

/** RFC 8439 §2.1 quarter round on words a, b, c, d. */
// prettier-ignore
function chachaQR(x: TArg<Uint32Array>, a: number, b: number, c: number, d: number) {
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 7);
}

/** Repeated ChaCha double rounds; callers are expected to pass an even round count. */
function chachaRound(x: TArg<Uint32Array>, rounds = 20) {
  for (let r = 0; r < rounds; r += 2) {
    // RFC 8439 §2.3 / §2.3.1 inner_block: four column rounds, then four diagonal rounds.
    chachaQR(x, 0, 4, 8, 12);
    chachaQR(x, 1, 5, 9, 13);
    chachaQR(x, 2, 6, 10, 14);
    chachaQR(x, 3, 7, 11, 15);
    chachaQR(x, 0, 5, 10, 15);
    chachaQR(x, 1, 6, 11, 12);
    chachaQR(x, 2, 7, 8, 13);
    chachaQR(x, 3, 4, 9, 14);
  }
}

// Shared scratch for the auditability-only helper below; only the test-only
// __TESTS.chachaCore_small hook reaches it, so production exports stay reentrant.
const ctmp = /* @__PURE__ */ new Uint32Array(16);

/** Small version of chacha without loop unrolling. Unused, provided for auditability. */
// prettier-ignore
function chacha(
  s: TArg<Uint32Array>, k: TArg<Uint32Array>, i: TArg<Uint32Array>, out: TArg<Uint32Array>,
  isHChacha: boolean = true, rounds: number = 20
): void {
  // `i` is either `[counter, nonce0, nonce1, nonce2]` for the ChaCha block
  // function or the full 128-bit nonce prefix for the HChaCha subkey path.
  // Create initial array using common pattern
  const y = Uint32Array.from([
    s[0], s[1], s[2], s[3], // "expa"   "nd 3"  "2-by"  "te k"
    k[0], k[1], k[2], k[3], // Key      Key     Key     Key
    k[4], k[5], k[6], k[7], // Key      Key     Key     Key
    i[0], i[1], i[2], i[3], // Counter  Counter Nonce   Nonce
  ]);
  const x = ctmp;
  x.set(y);
  chachaRound(x, rounds);

  // HChaCha writes words 0..3 and 12..15 after the rounds; the ChaCha
  // block path adds the original state word-by-word.
  if (isHChacha) {
    const xindexes = [0, 1, 2, 3, 12, 13, 14, 15];
    for (let i = 0; i < 8; i++) out[i] = x[xindexes[i]];
  } else {
    for (let i = 0; i < 16; i++) out[i] = (y[i] + x[i]) | 0;
  }
}

/** Identical to `chachaCore`. Reached only through the test-only `__TESTS` export. */
// @ts-ignore
const chachaCore_small: typeof chachaCore = (s, k, n, out, cnt, rounds) =>
  // Keep the reference wrapper on the same [counter, nonce0, nonce1, nonce2] layout as chacha().
  chacha(s, k, Uint32Array.from([cnt, n[0], n[1], n[2]]), out, false, rounds);
/** Identical to `hchacha`. Unused. */
// @ts-ignore
const hchacha_small: typeof hchacha = chacha;

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
 * Algorithmically identical to `hchacha_small`, but this exported path
 * normalizes word order on big-endian hosts.
 * Need to find a way to merge it with `chachaCore` without 25% performance hit.
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
  let x00 = swap8IfBE(s[0]), x01 = swap8IfBE(s[1]), x02 = swap8IfBE(s[2]), x03 = swap8IfBE(s[3]),
      x04 = swap8IfBE(k[0]), x05 = swap8IfBE(k[1]), x06 = swap8IfBE(k[2]), x07 = swap8IfBE(k[3]),
      x08 = swap8IfBE(k[4]), x09 = swap8IfBE(k[5]), x10 = swap8IfBE(k[6]), x11 = swap8IfBE(k[7]),
      x12 = swap8IfBE(i[0]), x13 = swap8IfBE(i[1]), x14 = swap8IfBE(i[2]), x15 = swap8IfBE(i[3]);
  for (let r = 0; r < 20; r += 2) {
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
  // HChaCha derives the subkey from state words 0..3 and 12..15 after 20 rounds.
  let oi = 0;
  out[oi++] = x00; out[oi++] = x01;
  out[oi++] = x02; out[oi++] = x03;
  out[oi++] = x12; out[oi++] = x13;
  out[oi++] = x14; out[oi++] = x15;
  swap32IfBE(out);
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

// Test-only hooks for keeping the simple/reference core aligned with the unrolled production core.
export const __TESTS: {
  chachaCore_small: typeof chachaCore_small;
  chachaCore: typeof chachaCore;
} = /* @__PURE__ */ Object.freeze({ chachaCore_small, chachaCore });

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
  // return poly1305_computeTag_small(authKey, lengths, ciphertext, AAD)
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
 * const cipher = chacha20poly1305(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const chacha20poly1305: TRet<ARXCipher> = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 12, tagLength: 16 },
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
 * const cipher = xchacha20poly1305(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const xchacha20poly1305: TRet<ARXCipher> = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 24, tagLength: 16 },
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
