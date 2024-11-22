import { abytes, aexists, aoutput } from './_assert.js';
import { clean, copyBytes, createView, Hash, Input, toBytes, u32 } from './utils.js';

// GHash from AES-GCM and its little-endian "mirror image" Polyval from AES-SIV.
// Implemented in terms of GHash with conversion function for keys
// GCM GHASH from NIST SP800-38d, SIV from RFC 8452.
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

// GHASH   modulo: x^128 + x^7   + x^2   + x     + 1
// POLYVAL modulo: x^128 + x^127 + x^126 + x^121 + 1

const BLOCK_SIZE = 16;
// TODO: rewrite
// temporary padding buffer
const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
const ZEROS32 = u32(ZEROS16);
const POLY = 0xe1; // v = 2*v % POLY

// v = 2*v % POLY
// NOTE: because x + x = 0 (add/sub is same), mul2(x) != x+x
// We can multiply any number using montgomery ladder and this function (works as double, add is simple xor)
const mul2 = (s0: number, s1: number, s2: number, s3: number) => {
  const hiBit = s3 & 1;
  return {
    s3: (s2 << 31) | (s3 >>> 1),
    s2: (s1 << 31) | (s2 >>> 1),
    s1: (s0 << 31) | (s1 >>> 1),
    s0: (s0 >>> 1) ^ ((POLY << 24) & -(hiBit & 1)), // reduce % poly
  };
};

const swapLE = (n: number) =>
  (((n >>> 0) & 0xff) << 24) |
  (((n >>> 8) & 0xff) << 16) |
  (((n >>> 16) & 0xff) << 8) |
  ((n >>> 24) & 0xff) |
  0;

/**
 * `mulX_POLYVAL(ByteReverse(H))` from spec
 * @param k mutated in place
 */
export function _toGHASHKey(k: Uint8Array): Uint8Array {
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
  return k;
}

type Value = { s0: number; s1: number; s2: number; s3: number };

const estimateWindow = (bytes: number) => {
  if (bytes > 64 * 1024) return 8;
  if (bytes > 1024) return 4;
  return 2;
};

class GHASH implements Hash<GHASH> {
  readonly blockLen = BLOCK_SIZE;
  readonly outputLen = BLOCK_SIZE;
  protected s0 = 0;
  protected s1 = 0;
  protected s2 = 0;
  protected s3 = 0;
  protected finished = false;
  protected t: Value[];
  private W: number;
  private windowSize: number;
  // We select bits per window adaptively based on expectedLength
  constructor(key: Input, expectedLength?: number) {
    key = toBytes(key);
    abytes(key, 16);
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
          (s0 ^= d0), (s1 ^= d1), (s2 ^= d2), (s3 ^= d3);
        }
        items.push({ s0, s1, s2, s3 });
      }
    }
    this.t = items;
  }
  protected _updateBlock(s0: number, s1: number, s2: number, s3: number) {
    (s0 ^= this.s0), (s1 ^= this.s1), (s2 ^= this.s2), (s3 ^= this.s3);
    const { W, t, windowSize } = this;
    // prettier-ignore
    let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    const mask = (1 << W) - 1; // 2**W will kill performance.
    let w = 0;
    for (const num of [s0, s1, s2, s3]) {
      for (let bytePos = 0; bytePos < 4; bytePos++) {
        const byte = (num >>> (8 * bytePos)) & 0xff;
        for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
          const bit = (byte >>> (W * bitPos)) & mask;
          const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
          (o0 ^= e0), (o1 ^= e1), (o2 ^= e2), (o3 ^= e3);
          w += 1;
        }
      }
    }
    this.s0 = o0;
    this.s1 = o1;
    this.s2 = o2;
    this.s3 = o3;
  }
  update(data: Input): this {
    data = toBytes(data);
    aexists(this);
    const b32 = u32(data);
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    const left = data.length % BLOCK_SIZE;
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(b32[i * 4 + 0], b32[i * 4 + 1], b32[i * 4 + 2], b32[i * 4 + 3]);
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      this._updateBlock(ZEROS32[0], ZEROS32[1], ZEROS32[2], ZEROS32[3]);
      clean(ZEROS32); // clean tmp buffer
    }
    return this;
  }
  destroy() {
    const { t } = this;
    // clean precompute table
    for (const elm of t) {
      (elm.s0 = 0), (elm.s1 = 0), (elm.s2 = 0), (elm.s3 = 0);
    }
  }
  digestInto(out: Uint8Array) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(out);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    return out;
  }
  digest(): Uint8Array {
    const res = new Uint8Array(BLOCK_SIZE);
    this.digestInto(res);
    this.destroy();
    return res;
  }
}

class Polyval extends GHASH {
  constructor(key: Input, expectedLength?: number) {
    key = toBytes(key);
    const ghKey = _toGHASHKey(copyBytes(key));
    super(ghKey, expectedLength);
    clean(ghKey);
  }
  update(data: Input): this {
    data = toBytes(data);
    aexists(this);
    const b32 = u32(data);
    const left = data.length % BLOCK_SIZE;
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(
        swapLE(b32[i * 4 + 3]),
        swapLE(b32[i * 4 + 2]),
        swapLE(b32[i * 4 + 1]),
        swapLE(b32[i * 4 + 0])
      );
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      this._updateBlock(
        swapLE(ZEROS32[3]),
        swapLE(ZEROS32[2]),
        swapLE(ZEROS32[1]),
        swapLE(ZEROS32[0])
      );
      clean(ZEROS32);
    }
    return this;
  }
  digestInto(out: Uint8Array) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    // tmp ugly hack
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(out);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    return out.reverse();
  }
}

export type CHash = ReturnType<typeof wrapConstructorWithKey>;
function wrapConstructorWithKey<H extends Hash<H>>(
  hashCons: (key: Input, expectedLength?: number) => Hash<H>
) {
  const hashC = (msg: Input, key: Input): Uint8Array =>
    hashCons(key, msg.length).update(toBytes(msg)).digest();
  const tmp = hashCons(new Uint8Array(16), 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (key: Input, expectedLength?: number) => hashCons(key, expectedLength);
  return hashC;
}

export const ghash = wrapConstructorWithKey(
  (key, expectedLength) => new GHASH(key, expectedLength)
);
export const polyval = wrapConstructorWithKey(
  (key, expectedLength) => new Polyval(key, expectedLength)
);
