/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */

// micro-noble-ciphers: more auditable, but slower version of salsa20, chacha & poly1305.
// Implements the same algorithms that are present in other files,
// but without unrolled loops (https://en.wikipedia.org/wiki/Loop_unrolling).

import * as u from './utils.js';
import { salsaBasic } from './_salsa.js';
// Utils
function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  // Big Endian
  return BigInt(hex === '' ? '0' : `0x${hex}`);
}
function bytesToNumberLE(bytes: Uint8Array): bigint {
  return hexToNumber(u.bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesLE(n: number | bigint, len: number): Uint8Array {
  return u.hexToBytes(n.toString(16).padStart(len * 2, '0')).reverse();
}

const rotl = (a: number, b: number) => (a << b) | (a >>> (32 - b));
// /Utils

function salsaQR(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[b] ^= rotl((x[a] + x[d]) | 0, 7);
  x[c] ^= rotl((x[b] + x[a]) | 0, 9);
  x[d] ^= rotl((x[c] + x[b]) | 0, 13);
  x[a] ^= rotl((x[d] + x[c]) | 0, 18);
}
// prettier-ignore
function chachaQR(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 7);
}

function salsaRound(x: Uint32Array, rounds = 20) {
  for (let i = 0; i < rounds; i += 2) {
    salsaQR(x, 0, 4, 8, 12);
    salsaQR(x, 5, 9, 13, 1);
    salsaQR(x, 10, 14, 2, 6);
    salsaQR(x, 15, 3, 7, 11);
    salsaQR(x, 0, 1, 2, 3);
    salsaQR(x, 5, 6, 7, 4);
    salsaQR(x, 10, 11, 8, 9);
    salsaQR(x, 15, 12, 13, 14);
  }
}

function chachaRound(x: Uint32Array, rounds = 20) {
  for (let i = 0; i < rounds; i += 2) {
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

function salsaCore(
  c: Uint32Array,
  k: Uint32Array,
  n: Uint32Array,
  out: Uint32Array,
  cnt: number,
  rounds = 20
): void {
  // prettier-ignore
  const y = new Uint32Array([
    c[0], k[0], k[1], k[2], // "expa" Key     Key     Key
    k[3], c[1], n[0], n[1], // Key    "nd 3"  Nonce   Nonce
    cnt,  0   , c[2], k[4], // Pos.   Pos.    "2-by"	Key
    k[5], k[6], k[7], c[3], // Key    Key     Key     "te k"
  ]);
  const x = y.slice();
  salsaRound(x, rounds);
  for (let i = 0; i < 16; i++) out[i] = (y[i] + x[i]) | 0;
}

export function hsalsa(c: Uint32Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const k = u.u32(key);
  const i = u.u32(nonce);
  // prettier-ignore
  const x = new Uint32Array([
    c[0], k[0], k[1], k[2],
    k[3], c[1], i[0], i[1],
    i[2], i[3], c[2], k[4],
    k[5], k[6], k[7], c[3]
  ]);
  salsaRound(x);
  return u.u8(new Uint32Array([x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]]));
}

function chachaCore(
  c: Uint32Array,
  k: Uint32Array,
  n: Uint32Array,
  out: Uint32Array,
  cnt: number,
  rounds = 20
): void {
  // prettier-ignore
  const y = new Uint32Array([
    c[0], c[1], c[2], c[3], // "expa"   "nd 3"  "2-by"  "te k"
    k[0], k[1], k[2], k[3], // Key      Key     Key     Key
    k[4], k[5], k[6], k[7], // Key      Key     Key     Key
    cnt,  n[0], n[1], n[2], // Counter  Counter	Nonce   Nonce
  ]);
  const x = y.slice();
  chachaRound(x, rounds);
  for (let i = 0; i < 16; i++) out[i] = (y[i] + x[i]) | 0;
}

export function hchacha(c: Uint32Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const k = u.u32(key);
  const i = u.u32(nonce);
  // prettier-ignore
  const x = new Uint32Array([
    c[0], c[1], c[2], c[3],
    k[0], k[1], k[2], k[3],
    k[4], k[5], k[6], k[7],
    i[0], i[1], i[2], i[3],
  ]);
  chachaRound(x);
  return u.u8(new Uint32Array([x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15]]));
}

/**
 * salsa20, 12-byte nonce.
 */
export const salsa20 = salsaBasic({ core: salsaCore, counterRight: true });

/**
 * xsalsa20, 24-byte nonce.
 */
export const xsalsa20 = salsaBasic({
  core: salsaCore,
  counterRight: true,
  extendNonceFn: hsalsa,
  allow128bitKeys: false,
});

/**
 * chacha20 non-RFC, original version by djb. 8-byte nonce, 8-byte counter.
 */
export const chacha20orig = salsaBasic({ core: chachaCore, counterRight: false, counterLen: 8 });
/**
 * chacha20 RFC 8439 (IETF / TLS). 12-byte nonce, 4-byte counter.
 */
export const chacha20 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 4,
  allow128bitKeys: false,
});

/**
 * xchacha20 eXtended-nonce. https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
 */
export const xchacha20 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 8,
  extendNonceFn: hchacha,
  allow128bitKeys: false,
});

/**
 * 8-round chacha from the original paper.
 */
export const chacha8 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 4,
  rounds: 8,
});

/**
 * 12-round chacha from the original paper.
 */
export const chacha12 = salsaBasic({
  core: chachaCore,
  counterRight: false,
  counterLen: 4,
  rounds: 12,
});

const POW_2_130_5 = 2n ** 130n - 5n;
const POW_2_128_1 = 2n ** (16n * 8n) - 1n;
// Can be speed-up using BigUint64Array, but would be more complicated
export function poly1305(msg: Uint8Array, key: Uint8Array): Uint8Array {
  u.ensureBytes(msg);
  u.ensureBytes(key);
  let acc = 0n;
  const r = bytesToNumberLE(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = bytesToNumberLE(key.subarray(16));
  // Process by 16 byte chunks
  for (let i = 0; i < msg.length; i += 16) {
    const m = msg.subarray(i, i + 16);
    const n = bytesToNumberLE(m) | (1n << BigInt(8 * m.length));
    acc = ((acc + n) * r) % POW_2_130_5;
  }
  const res = (acc + s) & POW_2_128_1;
  return numberToBytesLE(res, 16);
}

function computeTag(
  fn: typeof chacha20,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  AAD?: Uint8Array
): Uint8Array {
  const res = [];
  if (AAD) {
    res.push(AAD);
    const leftover = AAD.length % 16;
    if (leftover > 0) res.push(new Uint8Array(16 - leftover));
  }
  res.push(ciphertext);
  const leftover = ciphertext.length % 16;
  if (leftover > 0) res.push(new Uint8Array(16 - leftover));
  // Lengths
  const num = new Uint8Array(16);
  const view = u.createView(num);
  u.setBigUint64(view, 0, BigInt(AAD ? AAD.length : 0), true);
  u.setBigUint64(view, 8, BigInt(ciphertext.length), true);
  res.push(num);
  const authKey = fn(key, nonce, new Uint8Array(32));
  return poly1305(u.concatBytes(...res), authKey);
}

/**
 * xsalsa20-poly1305 eXtended-nonce (24 bytes) salsa.
 */
export function xsalsa20_poly1305(key: Uint8Array, nonce: Uint8Array) {
  u.ensureBytes(key);
  u.ensureBytes(nonce);
  return {
    encrypt: (plaintext: Uint8Array) => {
      u.ensureBytes(plaintext);
      const m = u.concatBytes(new Uint8Array(32), plaintext);
      const c = xsalsa20(key, nonce, m);
      const authKey = c.subarray(0, 32);
      const data = c.subarray(32);
      const tag = poly1305(data, authKey);
      return u.concatBytes(tag, data);
    },
    decrypt: (ciphertext: Uint8Array) => {
      u.ensureBytes(ciphertext);
      if (ciphertext.length < 16) throw new Error('Encrypted data should be at least 16 bytes');
      const c = u.concatBytes(new Uint8Array(16), ciphertext);
      const authKey = xsalsa20(key, nonce, new Uint8Array(32));
      const tag = poly1305(c.subarray(32), authKey);
      if (!u.equalBytes(c.subarray(16, 32), tag)) throw new Error('Wrong tag');
      return xsalsa20(key, nonce, c).subarray(32);
    },
  };
}

/**
 * Alias to xsalsa20-poly1305
 */
export function secretbox(key: Uint8Array, nonce: Uint8Array) {
  u.ensureBytes(key);
  u.ensureBytes(nonce);
  const xs = xsalsa20_poly1305(key, nonce);
  return { seal: xs.encrypt, open: xs.decrypt };
}

export const _poly1305_aead =
  (fn: typeof chacha20) =>
  (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): u.Cipher => {
    const tagLength = 16;
    const keyLength = 32;
    u.ensureBytes(key, keyLength);
    u.ensureBytes(nonce);
    return {
      tagLength,
      encrypt: (plaintext: Uint8Array) => {
        u.ensureBytes(plaintext);
        const res = fn(key, nonce, plaintext, undefined, 1);
        const tag = computeTag(fn, key, nonce, res, AAD);
        return u.concatBytes(res, tag);
      },
      decrypt: (ciphertext: Uint8Array) => {
        u.ensureBytes(ciphertext);
        if (ciphertext.length < tagLength)
          throw new Error(`Encrypted data should be at least ${tagLength}`);
        const realTag = ciphertext.subarray(-tagLength);
        const data = ciphertext.subarray(0, -tagLength);
        const tag = computeTag(fn, key, nonce, data, AAD);
        if (!u.equalBytes(realTag, tag)) throw new Error('Wrong tag');
        return fn(key, nonce, data, undefined, 1);
      },
    };
  };

/**
 * chacha20-poly1305 12-byte-nonce chacha.
 */
export const chacha20_poly1305 = _poly1305_aead(chacha20);

/**
 * xchacha20-poly1305 eXtended-nonce (24 bytes) chacha.
 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
 */
export const xchacha20_poly1305 = _poly1305_aead(xchacha20);
