/**
 * GHash from AES-GCM and its little-endian "mirror image" Polyval from AES-SIV.
 *
 * Implemented in terms of GHash with conversion function for keys
 * GCM GHASH from
 * {@link https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf | NIST SP800-38d},
 * SIV from
 * {@link https://www.rfc-editor.org/rfc/rfc8452 | RFC 8452}.
 *
 * GHASH   modulo: x^128 + x^7   + x^2   + x     + 1
 * POLYVAL modulo: x^128 + x^127 + x^126 + x^121 + 1
 *
 * @module
 */
import {
  abytes,
  aexists,
  aoutput,
  clean,
  copyBytes,
  createView,
  swap32IfBE,
  swap8IfBE,
  u32,
  wrapMacConstructor,
  type CMac,
  type IHash2,
  type TArg,
  type TRet,
} from './utils.ts';

const BLOCK_SIZE = 16;
// TODO: rewrite
// temporary padding buffer
// ZEROS32 aliases these bytes, so clean(ZEROS32) also resets this shared tail-padding scratch.
const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
const ZEROS32 = /* @__PURE__ */ u32(ZEROS16);
// GHASH reduces modulo x^128 + x^7 + x^2 + x + 1, so the low-degree terms
// x^7 + x^2 + x + 1 become bits `11100001` = 0xe1 in R = 0xe1 || 0^120.
const POLY = 0xe1;

// v = 2*v % POLY
// NOTE: because x + x = 0 (add/sub is same), mul2(x) != x+x
// Montgomery ladder can multiply any field element with this doubling step;
// addition stays simple xor.
const mul2 = (s0: number, s1: number, s2: number, s3: number) => {
  const hiBit = s3 & 1;
  return {
    s3: (s2 << 31) | (s3 >>> 1),
    s2: (s1 << 31) | (s2 >>> 1),
    s1: (s0 << 31) | (s1 >>> 1),
    // NIST SP 800-38D §6.3 applies `V >> 1` and XORs R on carry. In this
    // 4x32-bit split, R = 0xe1 || 0^120 lives in the top byte of s0.
    s0: (s0 >>> 1) ^ ((POLY << 24) & -(hiBit & 1)), // reduce % poly
  };
};

// Per-word part of RFC 8452 `ByteReverse`; callers also reverse the 32-bit word order.
const swapLE = (n: number) =>
  (((n >>> 0) & 0xff) << 24) |
  (((n >>> 8) & 0xff) << 16) |
  (((n >>> 16) & 0xff) << 8) |
  ((n >>> 24) & 0xff) |
  0;
// POLYVAL first applies RFC 8452's per-word byte reversal, then re-normalizes
// host-endian u32 loads to the little-endian word value `_updateBlock()` expects.
const swap8IfLE = (n: number) => swap8IfBE(swapLE(n));

/**
 * `mulX_GHASH(ByteReverse(H))` from RFC 8452 Appendix A.
 * @param k mutated in place
 */
export function _toGHASHKey(k: TArg<Uint8Array>): TRet<Uint8Array> {
  // The input is the original POLYVAL key H; reverse() materializes
  // RFC 8452's `ByteReverse(H)` before the GHASH mulX step.
  k.reverse();
  const hiBit = k[15] & 1;
  // k >>= 1
  let carry = 0;
  for (let i = 0; i < k.length; i++) {
    const t = k[i];
    k[i] = (t >>> 1) | carry;
    carry = (t & 1) << 7;
  }
  k[0] ^= -hiBit & 0xe1; // if (hiBit) n ^= 0xe1000000000000000000000000000000;
  return k as TRet<Uint8Array>;
}

type Value = { s0: number; s1: number; s2: number; s3: number };

// Precompute-window heuristic only: larger inputs trade memory for fewer table lookups.
// Any caller-provided length hint still collapses to one of the supported windows {2, 4, 8}.
const estimateWindow = (bytes: number) => {
  if (bytes > 64 * 1024) return 8;
  if (bytes > 1024) return 4;
  return 2;
};

/**
 * Incremental GHASH state for AES-GCM.
 * @param key - 16-byte GHASH key.
 * @param expectedLength - Expected message length for table sizing.
 * Chunking is segment-based, not hash-streaming: every `update()` call is zero-padded
 * to the next 16-byte boundary before it is absorbed. This matches the internal AES/GCM
 * use where AAD, payload, and length block are separate padded segments.
 * @example
 * Feeds one ciphertext block into an incremental GHASH state with a fresh hash key.
 *
 * ```ts
 * import { GHASH } from '@noble/ciphers/_polyval.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const mac = new GHASH(key);
 * mac.update(new Uint8Array(16));
 * mac.digest();
 * ```
 */
export class GHASH implements IHash2 {
  readonly blockLen: number = BLOCK_SIZE;
  readonly outputLen: number = BLOCK_SIZE;
  protected s0 = 0;
  protected s1 = 0;
  protected s2 = 0;
  protected s3 = 0;
  protected finished = false;
  protected destroyed = false;
  protected t: Value[];
  private W: number;
  private windowSize: number;
  // We select bits per window adaptively based on expectedLength
  constructor(key: TArg<Uint8Array>, expectedLength?: number) {
    abytes(key, 16, 'key');
    key = copyBytes(key);
    const kView = createView(key);
    let k0 = kView.getUint32(0, false);
    let k1 = kView.getUint32(4, false);
    let k2 = kView.getUint32(8, false);
    let k3 = kView.getUint32(12, false);
    // generate table of doubled keys (half of montgomery ladder)
    const doubles: Value[] = [];
    for (let i = 0; i < 128; i++) {
      doubles.push({ s0: swapLE(k0), s1: swapLE(k1), s2: swapLE(k2), s3: swapLE(k3) });
      ({ s0: k0, s1: k1, s2: k2, s3: k3 } = mul2(k0, k1, k2, k3));
    }
    const W = estimateWindow(expectedLength || 1024);
    if (![1, 2, 4, 8].includes(W))
      throw new Error('ghash: invalid window size, expected 2, 4 or 8');
    this.W = W;
    const bits = 128; // always 128 bits;
    const windows = bits / W;
    const windowSize = (this.windowSize = 2 ** W);
    const items: Value[] = [];
    // Create precompute table for window of W bits
    for (let w = 0; w < windows; w++) {
      // truth table: 00, 01, 10, 11
      for (let byte = 0; byte < windowSize; byte++) {
        // prettier-ignore
        let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        for (let j = 0; j < W; j++) {
          const bit = (byte >>> (W - j - 1)) & 1;
          if (!bit) continue;
          const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
          ((s0 ^= d0), (s1 ^= d1), (s2 ^= d2), (s3 ^= d3));
        }
        items.push({ s0, s1, s2, s3 });
      }
    }
    this.t = items;
  }
  protected _updateBlock(s0: number, s1: number, s2: number, s3: number): void {
    ((s0 ^= this.s0), (s1 ^= this.s1), (s2 ^= this.s2), (s3 ^= this.s3));
    const { W, t, windowSize } = this;
    // prettier-ignore
    let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    const mask = (1 << W) - 1; // 2**W will kill performance.
    let w = 0;
    // NIST SP 800-38D §6.3 interprets blocks as little-endian polynomials,
    // so the lookup walk consumes each word byte-by-byte from
    // least-significant to most-significant bits.
    for (const num of [s0, s1, s2, s3]) {
      for (let bytePos = 0; bytePos < 4; bytePos++) {
        const byte = (num >>> (8 * bytePos)) & 0xff;
        for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
          const bit = (byte >>> (W * bitPos)) & mask;
          const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
          ((o0 ^= e0), (o1 ^= e1), (o2 ^= e2), (o3 ^= e3));
          w += 1;
        }
      }
    }
    this.s0 = o0;
    this.s1 = o1;
    this.s2 = o2;
    this.s3 = o3;
  }
  update(data: TArg<Uint8Array>): this {
    aexists(this);
    abytes(data);
    data = copyBytes(data);
    const b32 = u32(data);
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    const left = data.length % BLOCK_SIZE;
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(
        swap8IfBE(b32[i * 4 + 0]),
        swap8IfBE(b32[i * 4 + 1]),
        swap8IfBE(b32[i * 4 + 2]),
        swap8IfBE(b32[i * 4 + 3])
      );
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      // Tail blocks go through the shared ZEROS32 scratch, so they need the same host-endian
      // normalization as full blocks; otherwise segmented GHASH/POLYVAL updates diverge on BE.
      this._updateBlock(
        swap8IfBE(ZEROS32[0]),
        swap8IfBE(ZEROS32[1]),
        swap8IfBE(ZEROS32[2]),
        swap8IfBE(ZEROS32[3])
      );
      clean(ZEROS32); // clean tmp buffer
    }
    return this;
  }
  destroy(): void {
    // `aexists(this)` guards update/digest paths, so destroy must mark the instance unusable too.
    this.destroyed = true;
    const { t } = this;
    // Wipe the key-derived precompute table; scalar accumulator words remain,
    // but the destroyed guard blocks further use.
    // clean precompute table
    for (const elm of t) {
      ((elm.s0 = 0), (elm.s1 = 0), (elm.s2 = 0), (elm.s3 = 0));
    }
  }
  digestInto(out: TArg<Uint8Array>): void {
    aexists(this);
    // `digestInto(out)` is the no-allocation fast path, so callers must pass a
    // 32-bit-aligned buffer before we reinterpret it with `u32(out)`.
    aoutput(out, this, true);
    this.finished = true;
    // NIST SP 800-38D §6.4 returns the final 128-bit block Y_m.
    // `digestInto()` follows the relaxed `aoutput()` contract, so only
    // out[0..15] may be touched.
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(out);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    swap32IfBE(o32);
  }
  digest(): TRet<Uint8Array> {
    const res = new Uint8Array(BLOCK_SIZE);
    this.digestInto(res);
    // `res` is independent of internal state, so it stays valid after destroy() wipes the table.
    this.destroy();
    return res as TRet<Uint8Array>;
  }
}

/**
 * Incremental POLYVAL state for AES-SIV.
 * @param key - 16-byte POLYVAL key.
 * @param expectedLength - Expected message length for table sizing.
 * Inherits GHASH's segment-padded `update()` behavior: each call is padded
 * independently to a 16-byte boundary before absorption.
 * @example
 * Feeds one block into an incremental POLYVAL state with a fresh hash key.
 *
 * ```ts
 * import { Polyval } from '@noble/ciphers/_polyval.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const mac = new Polyval(key);
 * mac.update(new Uint8Array(16));
 * mac.digest();
 * ```
 */
export class Polyval extends GHASH {
  constructor(key: TArg<Uint8Array>, expectedLength?: number) {
    abytes(key);
    // RFC 8452 Appendix A converts the POLYVAL key with
    // `mulX_GHASH(ByteReverse(H))`; copy first because `_toGHASHKey(...)`
    // mutates in place.
    const ghKey = _toGHASHKey(copyBytes(key));
    super(ghKey, expectedLength);
    clean(ghKey);
  }
  update(data: TArg<Uint8Array>): this {
    aexists(this);
    abytes(data);
    data = copyBytes(data);
    const b32 = u32(data);
    const left = data.length % BLOCK_SIZE;
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    for (let i = 0; i < blocks; i++) {
      // RFC 8452 Appendix A feeds `ByteReverse(X_i)` into GHASH, so POLYVAL
      // reverses the 32-bit word order in addition to the per-word byte swap.
      this._updateBlock(
        swap8IfLE(b32[i * 4 + 3]),
        swap8IfLE(b32[i * 4 + 2]),
        swap8IfLE(b32[i * 4 + 1]),
        swap8IfLE(b32[i * 4 + 0])
      );
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      this._updateBlock(
        swap8IfLE(ZEROS32[3]),
        swap8IfLE(ZEROS32[2]),
        swap8IfLE(ZEROS32[1]),
        swap8IfLE(ZEROS32[0])
      );
      clean(ZEROS32);
    }
    return this;
  }
  digestInto(out: TArg<Uint8Array>): void {
    aexists(this);
    // `digestInto(out)` is the no-allocation fast path, so callers must pass a
    // 32-bit-aligned buffer before we reinterpret the output prefix with `u32(view)`.
    aoutput(out, this, true);
    this.finished = true;
    // RFC 8452 Appendix A maps POLYVAL output back through `ByteReverse(...)`.
    // `digestInto()` follows the relaxed `aoutput()` contract, so only out[0..15] may be touched.
    const view = out.subarray(0, this.outputLen);
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(view);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    swap32IfBE(o32);
    view.reverse();
  }
}

/**
 * GHash MAC for AES-GCM.
 * @param msg - Message bytes to authenticate.
 * @param key - 16-byte GHASH key.
 * @returns 16-byte authentication tag.
 * @example
 * Authenticates a short message with GHASH and a fresh hash key.
 *
 * ```ts
 * import { ghash } from '@noble/ciphers/_polyval.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * ghash(new Uint8Array(), key);
 * ```
 */
export const ghash: TRet<CMac<GHASH, [expectedLength?: number]>> =
  /* @__PURE__ */ wrapMacConstructor(
    16,
    (key: TArg<Uint8Array>, expectedLength?: number) => new GHASH(key, expectedLength),
    (msg: TArg<Uint8Array>): [expectedLength?: number] => [msg.length]
  );

/**
 * POLYVAL MAC for AES-SIV.
 * @param msg - Message bytes to authenticate.
 * @param key - 16-byte POLYVAL key.
 * @returns 16-byte authentication tag.
 * @example
 * Authenticates a short message with POLYVAL and a fresh hash key.
 *
 * ```ts
 * import { polyval } from '@noble/ciphers/_polyval.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * polyval(new Uint8Array(), key);
 * ```
 */
export const polyval: TRet<CMac<Polyval, [expectedLength?: number]>> =
  /* @__PURE__ */ wrapMacConstructor(
    16,
    (key: TArg<Uint8Array>, expectedLength?: number) => new Polyval(key, expectedLength),
    (msg: TArg<Uint8Array>): [expectedLength?: number] => [msg.length]
  );
