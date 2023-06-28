import * as utils from './utils.js';
import { poly1305 } from './_poly1305.js';
import { salsaBasic } from './_salsa.js';

// ChaCha20 stream cipher was released in 2008. ChaCha aims to increase
// the diffusion per round, but had slightly less cryptanalysis.
// https://cr.yp.to/chacha.html, http://cr.yp.to/chacha/chacha-20080128.pdf

// Left rotate for uint32
const rotl = (a: number, b: number) => (a << b) | (a >>> (32 - b));

// prettier-ignore
function chachaCore(c: Uint32Array, k: Uint32Array, n: Uint32Array, out: Uint32Array, cnt: number, rounds = 20): void {
  let y00 = c[0], y01 = c[1], y02 = c[2], y03 = c[3]; // "expa"   "nd 3"  "2-by"  "te k"
  let y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3]; // Key      Key     Key     Key
  let y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7]; // Key      Key     Key     Key
  let y12 = cnt,  y13 = n[0], y14 = n[1], y15 = n[2]; // Counter  Counter	Nonce   Nonce
  // Save state to temporary variables
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  // Main loop
  for (let i = 0; i < rounds; i += 2) {
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
    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^x02, 8);
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
// prettier-ignore
export function hchacha(c: Uint32Array, key: Uint8Array, src: Uint8Array, dst: Uint8Array): Uint8Array {
  const k32 = utils.u32(key);
  const i32 = utils.u32(src);
  const o32 = utils.u32(dst);
  let x00 = c[0],   x01 = c[1],   x02 = c[2],   x03 = c[3];
  let x04 = k32[0], x05 = k32[1], x06 = k32[2], x07 = k32[3];
  let x08 = k32[4], x09 = k32[5], x10 = k32[6], x11 = k32[7]
  let x12 = i32[0], x13 = i32[1], x14 = i32[2], x15 = i32[3];
   for (let i = 0; i < 20; i += 2) {
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
  o32[0] = x00;
  o32[1] = x01;
  o32[2] = x02;
  o32[3] = x03;
  o32[4] = x12;
  o32[5] = x13;
  o32[6] = x14;
  o32[7] = x15;
  return dst;
}
// Original DJB ChaCha20, 8 bytes nonce, 8 bytes counter
export const chacha20orig = salsaBasic({ core: chachaCore, counterRight: false, counterLen: 8 });
// Also known as chacha20-tls (IETF), 12 bytes nonce, 4 bytes counter
export const chacha20 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 4,
  allow128bitKeys: false,
});

// xchacha draft RFC https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
export const xchacha20 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 8,
  extendNonceFn: hchacha,
  allow128bitKeys: false,
});

// Reduced-round chacha, described in original paper
export const chacha8 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 4,
  rounds: 8,
});
export const chacha12 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 4,
  rounds: 12,
});

const ZERO = new Uint8Array(16);
// Pad to digest size with zeros
const updatePadded = (h: ReturnType<typeof poly1305.create>, msg: Uint8Array) => {
  h.update(msg);
  const left = msg.length % 16;
  if (left) h.update(ZERO.subarray(left));
};

const computeTag = (
  fn: typeof chacha20,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  AAD?: Uint8Array
) => {
  const authKey = fn(key, nonce, new Uint8Array(32));
  const h = poly1305.create(authKey);
  if (AAD) updatePadded(h, AAD);
  updatePadded(h, data);
  const num = new Uint8Array(16);
  const view = utils.createView(num);
  utils.setBigUint64(view, 0, BigInt(AAD ? AAD.length : 0), true);
  utils.setBigUint64(view, 8, BigInt(data.length), true);
  h.update(num);
  const res = h.digest();
  authKey.fill(0);
  return res;
};

// salsa and chacha (RFC 7539) use poly1305 differently.
// We could have composed them such as in:
// https://github.com/paulmillr/scure-base/blob/b266c73dde977b1dd7ef40ef7a23cc15aab526b3/index.ts#L250
// But authKey construction makes it hard:
// - salsa:  authKey changes position in salsa stream
// - chacha: authKey can't be computed inside computeTag, it modifies the counter
// Algo from RFC 7539.
export const _poly1305_aead =
  (fn: typeof chacha20) =>
  (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): utils.Cipher => {
    const tagLength = 16;
    utils.ensureBytes(key, 32);
    utils.ensureBytes(nonce);
    return {
      tagLength,
      encrypt: (plaintext: Uint8Array) => {
        const res = new Uint8Array(plaintext.length + tagLength);
        fn(key, nonce, plaintext, res, 1);
        const tag = computeTag(fn, key, nonce, res.subarray(0, -tagLength), AAD);
        res.set(tag, plaintext.length); // append tag
        return res;
      },
      decrypt: (ciphertext: Uint8Array) => {
        if (ciphertext.length < tagLength)
          throw new Error(`Encrypted data should be at least ${tagLength}`);
        const realTag = ciphertext.subarray(-tagLength);
        const data = ciphertext.subarray(0, -tagLength);
        const tag = computeTag(fn, key, nonce, data, AAD);
        if (!utils.equalBytes(realTag, tag)) throw new Error('Wrong tag');
        return fn(key, nonce, data, undefined, 1);
      },
    };
  };

export const chacha20_poly1305 = _poly1305_aead(chacha20);
export const xchacha20_poly1305 = _poly1305_aead(xchacha20);
