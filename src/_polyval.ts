import { createView, toBytes, Input, Hash, u32 } from './utils.js';
import { exists as aexists, output as aoutput } from './_assert.js';

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

// 128x128 multiplication table for key. Same as noble-curves, but window size=1.
// TODO: investigate perf boost using bigger window size.
function genMulTable(s0: number, s1: number, s2: number, s3: number): Uint32Array {
  const t = new Uint32Array(128 * 4); // 128x128 multiplication table for key
  for (let i = 0, pos = 0, t0, t1, t2, t3; i < 128; i++) {
    (t[pos++] = s0), (t[pos++] = s1), (t[pos++] = s2), (t[pos++] = s3);
    const hiBit = s3 & 1;
    t3 = (s2 << 31) | (s3 >>> 1);
    t2 = (s1 << 31) | (s2 >>> 1);
    t1 = (s0 << 31) | (s1 >>> 1);
    t0 = (s0 >>> 1) ^ ((POLY << 24) & -(hiBit & 1)); // reduce % poly
    s0 = t0;
    s1 = t1;
    s2 = t2;
    s3 = t3;
    // ({ s0, s1, s2, s3 } = mul2(s0, s1, s2, s3));
  }
  return t.map(swapLE); // convert to LE, so we can use u32
}

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

const swapLE = (n: number) =>
  ((((n >>> 0) & 0xff) << 24) |
    (((n >>> 8) & 0xff) << 16) |
    (((n >>> 16) & 0xff) << 8) |
    ((n >>> 24) & 0xff)) >>>
  0;

class GHASH implements Hash<GHASH> {
  readonly blockLen = BLOCK_SIZE;
  readonly outputLen = BLOCK_SIZE;
  protected s0 = 0;
  protected s1 = 0;
  protected s2 = 0;
  protected s3 = 0;
  protected mulTable: Uint32Array; // 128x128 multiplication table for key
  protected finished = false;

  constructor(key: Input) {
    key = toBytes(key);
    const v = createView(key);
    let k0 = v.getUint32(0, false);
    let k1 = v.getUint32(4, false);
    let k2 = v.getUint32(8, false);
    let k3 = v.getUint32(12, false);
    this.mulTable = genMulTable(k0, k1, k2, k3);
  }
  protected _updateBlock(s0: number, s1: number, s2: number, s3: number) {
    (s0 ^= this.s0), (s1 ^= this.s1), (s2 ^= this.s2), (s3 ^= this.s3);
    const { mulTable } = this;
    const mulNum = (num: number, pos: number, o0: number, o1: number, o2: number, o3: number) => {
      for (let bytePos = 0; bytePos < 4; bytePos++) {
        const byte = (num >>> (8 * bytePos)) & 0xff;
        for (let bitPos = 7; bitPos >= 0; bitPos--) {
          const bit = (byte >>> bitPos) & 1;
          const mask = ~(bit - 1);
          // const-time addition regardless of bit value
          o0 ^= mulTable[pos++] & mask;
          o1 ^= mulTable[pos++] & mask;
          o2 ^= mulTable[pos++] & mask;
          o3 ^= mulTable[pos++] & mask;
        }
      }
      return { o0, o1, o2, o3 };
    };
    // prettier-ignore
    let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    ({ o0, o1, o2, o3 } = mulNum(s0, 0, o0, o1, o2, o3));
    ({ o0, o1, o2, o3 } = mulNum(s1, 128, o0, o1, o2, o3));
    ({ o0, o1, o2, o3 } = mulNum(s2, 256, o0, o1, o2, o3));
    ({ o0: s0, o1: s1, o2: s2, o3: s3 } = mulNum(s3, 384, o0, o1, o2, o3));
    this.s0 = s0;
    this.s1 = s1;
    this.s2 = s2;
    this.s3 = s3;
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
      ZEROS32.fill(0); // clean tmp buffer
    }
    return this;
  }
  destroy() {}
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
  constructor(key: Input) {
    key = toBytes(key);
    const ghKey = _toGHASHKey(key.slice());
    super(ghKey);
    ghKey.fill(0);
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
      ZEROS32.fill(0); // clean tmp buffer
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
export function wrapConstructorWithKey<H extends Hash<H>>(hashCons: (key: Input) => Hash<H>) {
  const hashC = (msg: Input, key: Input): Uint8Array => hashCons(key).update(toBytes(msg)).digest();
  const tmp = hashCons(new Uint8Array(32));
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (key: Input) => hashCons(key);
  return hashC;
}

export const ghash = wrapConstructorWithKey((key) => new GHASH(key));
export const polyval = wrapConstructorWithKey((key) => new Polyval(key));
