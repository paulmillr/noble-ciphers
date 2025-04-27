/**
 * [ChaCha20](https://cr.yp.to/chacha.html) stream cipher, released
 * in 2008. Developed after Salsa20, ChaCha aims to increase diffusion per round.
 * It was standardized in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) and
 * is now used in TLS 1.3.
 *
 * [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
 * extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
 * randomly-generated nonces.
 *
 * Check out [PDF](http://cr.yp.to/chacha/chacha-20080128.pdf) and
 * [wiki](https://en.wikipedia.org/wiki/Salsa20).
 * @module
 */
import { createCipher, rotl } from './_arx.ts';
import { poly1305 } from './_poly1305.ts';
import {
  type ARXCipher,
  type CipherWithOutput,
  type XorStream,
  clean,
  equalBytes,
  getOutput,
  u64Lengths,
  wrapCipher,
} from './utils.ts';

/**
 * ChaCha core function. It is implemented twice:
 * 1. Simple loop (chachaCore_small, xchacha_small)
 * 2. Unrolled loop (chachaCore, xchacha)
 * The functions are identical: can be verified by replacing createCipher() calls.
 * Unrolled is 4x faster, but takes more code and is harder to read.
 */

/** quarter-round */
// prettier-ignore
function chachaQR(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 7);
}

/** single round */
function chachaRound(x: Uint32Array, rounds = 20) {
  for (let r = 0; r < rounds; r += 2) {
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

/** Small, internal version of `chachaCore` without loop unrolling. Provided for auditability. */
// @ts-expect-error
// prettier-ignore
function chachaCore_small(
  s: Uint32Array, k: Uint32Array, n: Uint32Array, out: Uint32Array,
  cnt: number, rounds = 20
): void {
  const y = new Uint32Array([
    s[0], s[1], s[2], s[3], // "expa"   "nd 3"  "2-by"  "te k"
    k[0], k[1], k[2], k[3], // Key      Key     Key     Key
    k[4], k[5], k[6], k[7], // Key      Key     Key     Key
    cnt, n[0], n[1], n[2],  // Counter  Counter Nonce   Nonce
  ]);
  const x = y.slice();
  chachaRound(x, rounds);
  for (let i = 0; i < 16; i++) out[i] = (y[i] + x[i]) | 0;
}

/** Small, internal version of `hchacha` without loop unrolling. Provided for auditability. */
// @ts-expect-error
// prettier-ignore
function hchacha_small(
  s: Uint32Array, k: Uint32Array, i: Uint32Array, o32: Uint32Array
): void {
  const x = new Uint32Array([
    s[0], s[1], s[2], s[3],
    k[0], k[1], k[2], k[3],
    k[4], k[5], k[6], k[7],
    i[0], i[1], i[2], i[3],
  ]);
  chachaRound(x, 20);
  let oi = 0;
  o32[oi++] = x[0]; o32[oi++] = x[1];
  o32[oi++] = x[2]; o32[oi++] = x[3];
  o32[oi++] = x[12]; o32[oi++] = x[13];
  o32[oi++] = x[14]; o32[oi++] = x[15];
}

// Same as `chachaCore_small`
// prettier-ignore
function chachaCore(
  s: Uint32Array, k: Uint32Array, n: Uint32Array, out: Uint32Array, cnt: number, rounds = 20
): void {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], // "expa"   "nd 3"  "2-by"  "te k"
      y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], // Key      Key     Key     Key
      y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], // Key      Key     Key     Key
      y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];  // Counter  Counter	Nonce   Nonce
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
 * hchacha hashing function, hashes key and nonce into key' and nonce'.
 * Same as chachaCore, but there doesn't seem to be a way to move the block
 * out without 25% performance hit. Used primarily in xchacha.
 */
// prettier-ignore
export function hchacha(
  s: Uint32Array, k: Uint32Array, i: Uint32Array, o32: Uint32Array
): void {
  let x00 = s[0], x01 = s[1], x02 = s[2], x03 = s[3],
      x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3],
      x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7],
      x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3];
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
  let oi = 0;
  o32[oi++] = x00; o32[oi++] = x01;
  o32[oi++] = x02; o32[oi++] = x03;
  o32[oi++] = x12; o32[oi++] = x13;
  o32[oi++] = x14; o32[oi++] = x15;
}

/**
 * Original, non-RFC chacha20 from DJB. 8-byte nonce, 8-byte counter.
 */
export const chacha20orig: XorStream = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 8,
  allowShortKeys: true,
});
/**
 * ChaCha stream cipher. Conforms to RFC 8439 (IETF, TLS). 12-byte nonce, 4-byte counter.
 * With 12-byte nonce, it's not safe to use fill it with random (CSPRNG), due to collision chance.
 */
export const chacha20: XorStream = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false,
});

/**
 * XChaCha eXtended-nonce ChaCha. 24-byte nonce.
 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
 * See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
 */
export const xchacha20: XorStream = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 8,
  extendNonceFn: hchacha,
  allowShortKeys: false,
});

/**
 * Reduced 8-round chacha, described in original paper.
 */
export const chacha8: XorStream = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  rounds: 8,
});

/**
 * Reduced 12-round chacha, described in original paper.
 */
export const chacha12: XorStream = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  rounds: 12,
});

const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
// Pad to digest size with zeros
const updatePadded = (h: ReturnType<typeof poly1305.create>, msg: Uint8Array) => {
  h.update(msg);
  const leftover = msg.length % 16;
  if (leftover) h.update(ZEROS16.subarray(leftover));
};

const ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
function computeTag(
  fn: XorStream,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  AAD?: Uint8Array
): Uint8Array {
  const authKey = fn(key, nonce, ZEROS32);
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
  (xorStream: XorStream) =>
  (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): CipherWithOutput => {
    const tagLength = 16;
    return {
      encrypt(plaintext: Uint8Array, output?: Uint8Array) {
        const plength = plaintext.length;
        output = getOutput(plength + tagLength, output, false);
        output.set(plaintext);
        const oPlain = output.subarray(0, -tagLength);
        // Actual encryption
        xorStream(key, nonce, oPlain, oPlain, 1);
        const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
        output.set(tag, plength); // append tag
        clean(tag);
        return output;
      },
      decrypt(ciphertext: Uint8Array, output?: Uint8Array) {
        output = getOutput(ciphertext.length - tagLength, output, false);
        const data = ciphertext.subarray(0, -tagLength);
        const passedTag = ciphertext.subarray(-tagLength);
        const tag = computeTag(xorStream, key, nonce, data, AAD);
        if (!equalBytes(passedTag, tag)) throw new Error('invalid tag');
        output.set(ciphertext.subarray(0, -tagLength));
        // Actual decryption
        xorStream(key, nonce, output, output, 1); // start stream with i=1
        clean(tag);
        return output;
      },
    };
  };

/**
 * ChaCha20-Poly1305 from RFC 8439.
 *
 * Unsafe to use random nonces under the same key, due to collision chance.
 * Prefer XChaCha instead.
 */
export const chacha20poly1305: ARXCipher = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 12, tagLength: 16 },
  _poly1305_aead(chacha20)
);
/**
 * XChaCha20-Poly1305 extended-nonce chacha.
 *
 * Can be safely used with random nonces (CSPRNG).
 * See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
 */
export const xchacha20poly1305: ARXCipher = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 24, tagLength: 16 },
  _poly1305_aead(xchacha20)
);
