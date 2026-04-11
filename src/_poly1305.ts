/**
 * Poly1305 ({@link https://cr.yp.to/mac/poly1305-20050329.pdf | PDF},
 * {@link https://en.wikipedia.org/wiki/Poly1305 | wiki})
 * is a fast and parallel secret-key message-authentication code suitable for
 * a wide variety of applications. It was standardized in
 * {@link https://www.rfc-editor.org/rfc/rfc8439 | RFC 8439} and is now used in TLS 1.3.
 *
 * Polynomial MACs are not perfect for every situation:
 * they lack Random Key Robustness: the MAC can be forged, and can't be used in PAKE schemes.
 * See {@link https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/ | the invisible salamanders attack writeup}.
 * To combat invisible salamanders, `hash(key)` can be included in ciphertext,
 * however, this would violate ciphertext indistinguishability:
 * an attacker would know which key was used - so `HKDF(key, i)`
 * could be used instead.
 *
 * Check out the {@link https://cr.yp.to/mac.html | original website}.
 * Based on public-domain {@link https://github.com/floodyberry/poly1305-donna | poly1305-donna}.
 * @module
 */
// prettier-ignore
import {
  abytes, aexists, aoutput, bytesToHex,
  clean, concatBytes, copyBytes, hexToNumber, numberToBytesBE,
  wrapMacConstructor, type CMac, type IHash2, type TArg, type TRet
} from './utils.ts';

// Little-endian 2-byte load used by the Poly1305 limb decomposition.
function u8to16(a: TArg<Uint8Array>, i: number) {
  return (a[i++] & 0xff) | ((a[i++] & 0xff) << 8);
}

function bytesToNumberLE(bytes: TArg<Uint8Array>): bigint {
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}

/** Small version of `poly1305` without loop unrolling. Unused, provided for auditability. */
function poly1305_small(msg: TArg<Uint8Array>, key: TArg<Uint8Array>): TRet<Uint8Array> {
  abytes(msg);
  abytes(key, 32, 'key');
  const POW_2_130_5 = BigInt(2) ** BigInt(130) - BigInt(5); // 2^130-5
  const POW_2_128_1 = BigInt(2) ** BigInt(128) - BigInt(1); // 2^128-1
  const CLAMP_R = BigInt('0x0ffffffc0ffffffc0ffffffc0fffffff');
  const r = bytesToNumberLE(key.subarray(0, 16)) & CLAMP_R;
  const s = bytesToNumberLE(key.subarray(16));
  // Process by 16 byte chunks
  let acc = BigInt(0);
  for (let i = 0; i < msg.length; i += 16) {
    const m = msg.subarray(i, i + 16);
    // RFC 8439 §2.5.1 / RFC 7539 §2.5.1 append [0x01] to each chunk before multiplying by r.
    const n = bytesToNumberLE(m) | (BigInt(1) << BigInt(8 * m.length));
    acc = ((acc + n) * r) % POW_2_130_5;
  }
  const res = (acc + s) & POW_2_128_1;
  // RFC 8439 §2.5 / RFC 7539 §2.5 serialize the low 128 bits in little-endian order.
  return numberToBytesBE(res, 16).reverse() as TRet<Uint8Array>; // LE
}

// Can be used to replace `computeTag` in chacha.ts. Unused, provided for auditability.
// @ts-expect-error
function poly1305_computeTag_small(
  authKey: TArg<Uint8Array>,
  // AEAD trailer must already be the 16-byte length block:
  // 8-byte little-endian AAD length || 8-byte little-endian ciphertext length.
  lengths: TArg<Uint8Array>,
  ciphertext: TArg<Uint8Array>,
  AAD?: TArg<Uint8Array>
): TRet<Uint8Array> {
  // RFC 8439 §2.8.1 / RFC 7539 §2.8.1 MAC input is
  // AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || lengths.
  const res = [];
  const updatePadded2 = (msg: TArg<Uint8Array>) => {
    res.push(msg);
    const leftover = msg.length % 16;
    // RFC 8439 §2.8.1 / RFC 7539 §2.8.1: pad16(x) is empty for aligned
    // inputs, else 16-(len%16) zero bytes.
    if (leftover) res.push(new Uint8Array(16).slice(leftover));
  };
  if (AAD) updatePadded2(AAD);
  updatePadded2(ciphertext);
  res.push(lengths);
  return poly1305_small(concatBytes(...res), authKey);
}

/**
 * Incremental Poly1305 MAC state.
 * Prefer `poly1305()` for one-shot use.
 * @param key - 32-byte Poly1305 one-time key.
 * @example
 * Feeds one chunk into an incremental Poly1305 state with a fresh one-time key.
 *
 * ```ts
 * import { Poly1305 } from '@noble/ciphers/_poly1305.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const mac = new Poly1305(key);
 * mac.update(new Uint8Array([1, 2, 3]));
 * mac.digest();
 * ```
 */
export class Poly1305 implements IHash2 {
  readonly blockLen = 16;
  readonly outputLen = 16;
  private buffer = new Uint8Array(16);
  private r = new Uint16Array(10); // Allocating 1 array with .subarray() here is slower than 3
  private h = new Uint16Array(10);
  private pad = new Uint16Array(8);
  private pos = 0;
  protected finished = false;
  protected destroyed = false;

  // Can be speed-up using BigUint64Array, at the cost of complexity
  constructor(key: TArg<Uint8Array>) {
    key = copyBytes(abytes(key, 32, 'key'));
    const t0 = u8to16(key, 0);
    const t1 = u8to16(key, 2);
    const t2 = u8to16(key, 4);
    const t3 = u8to16(key, 6);
    const t4 = u8to16(key, 8);
    const t5 = u8to16(key, 10);
    const t6 = u8to16(key, 12);
    const t7 = u8to16(key, 14);

    // RFC 8439 §2.5.1 / RFC 7539 §2.5.1 clamp r before multiplication.
    // These masks unpack that clamped value into 13-bit limbs, while pad
    // keeps the raw s half for finalize().
    // {@link https://github.com/floodyberry/poly1305-donna/blob/e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781/poly1305-donna-16.h#L47 | poly1305-donna reference}
    this.r[0] = t0 & 0x1fff;
    this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
    this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
    this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
    this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
    this.r[5] = (t4 >>> 1) & 0x1ffe;
    this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
    this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
    this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
    this.r[9] = (t7 >>> 5) & 0x007f;
    for (let i = 0; i < 8; i++) this.pad[i] = u8to16(key, 16 + 2 * i);
  }

  private process(data: TArg<Uint8Array>, offset: number, isLast = false) {
    // RFC 8439 §2.5 / §2.5.1 and RFC 7539 §2.5 / §2.5.1 add an extra high
    // bit to every full 16-byte block. The final partial block gets its
    // explicit `1` byte during digestInto(), so `hibit` stays zero there.
    const hibit = isLast ? 0 : 1 << 11;
    const { h, r } = this;
    const r0 = r[0];
    const r1 = r[1];
    const r2 = r[2];
    const r3 = r[3];
    const r4 = r[4];
    const r5 = r[5];
    const r6 = r[6];
    const r7 = r[7];
    const r8 = r[8];
    const r9 = r[9];

    const t0 = u8to16(data, offset + 0);
    const t1 = u8to16(data, offset + 2);
    const t2 = u8to16(data, offset + 4);
    const t3 = u8to16(data, offset + 6);
    const t4 = u8to16(data, offset + 8);
    const t5 = u8to16(data, offset + 10);
    const t6 = u8to16(data, offset + 12);
    const t7 = u8to16(data, offset + 14);

    let h0 = h[0] + (t0 & 0x1fff);
    let h1 = h[1] + (((t0 >>> 13) | (t1 << 3)) & 0x1fff);
    let h2 = h[2] + (((t1 >>> 10) | (t2 << 6)) & 0x1fff);
    let h3 = h[3] + (((t2 >>> 7) | (t3 << 9)) & 0x1fff);
    let h4 = h[4] + (((t3 >>> 4) | (t4 << 12)) & 0x1fff);
    let h5 = h[5] + ((t4 >>> 1) & 0x1fff);
    let h6 = h[6] + (((t4 >>> 14) | (t5 << 2)) & 0x1fff);
    let h7 = h[7] + (((t5 >>> 11) | (t6 << 5)) & 0x1fff);
    let h8 = h[8] + (((t6 >>> 8) | (t7 << 8)) & 0x1fff);
    let h9 = h[9] + ((t7 >>> 5) | hibit);

    let c = 0;

    let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
    c = d0 >>> 13;
    d0 &= 0x1fff;
    d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
    c += d0 >>> 13;
    d0 &= 0x1fff;

    let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
    c = d1 >>> 13;
    d1 &= 0x1fff;
    d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
    c += d1 >>> 13;
    d1 &= 0x1fff;

    let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
    c = d2 >>> 13;
    d2 &= 0x1fff;
    d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
    c += d2 >>> 13;
    d2 &= 0x1fff;

    let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
    c = d3 >>> 13;
    d3 &= 0x1fff;
    d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
    c += d3 >>> 13;
    d3 &= 0x1fff;

    let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    c = d4 >>> 13;
    d4 &= 0x1fff;
    d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
    c += d4 >>> 13;
    d4 &= 0x1fff;

    let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
    c = d5 >>> 13;
    d5 &= 0x1fff;
    d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
    c += d5 >>> 13;
    d5 &= 0x1fff;

    let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
    c = d6 >>> 13;
    d6 &= 0x1fff;
    d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
    c += d6 >>> 13;
    d6 &= 0x1fff;

    let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
    c = d7 >>> 13;
    d7 &= 0x1fff;
    d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
    c += d7 >>> 13;
    d7 &= 0x1fff;

    let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
    c = d8 >>> 13;
    d8 &= 0x1fff;
    d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
    c += d8 >>> 13;
    d8 &= 0x1fff;

    let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
    c = d9 >>> 13;
    d9 &= 0x1fff;
    d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
    c += d9 >>> 13;
    d9 &= 0x1fff;

    c = ((c << 2) + c) | 0;
    c = (c + d0) | 0;
    d0 = c & 0x1fff;
    c = c >>> 13;
    d1 += c;

    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
    h[5] = d5;
    h[6] = d6;
    h[7] = d7;
    h[8] = d8;
    h[9] = d9;
  }

  private finalize() {
    const { h, pad } = this;
    const g = new Uint16Array(10);
    let c = h[1] >>> 13;
    h[1] &= 0x1fff;
    for (let i = 2; i < 10; i++) {
      h[i] += c;
      c = h[i] >>> 13;
      h[i] &= 0x1fff;
    }
    h[0] += c * 5;
    c = h[0] >>> 13;
    h[0] &= 0x1fff;
    h[1] += c;
    c = h[1] >>> 13;
    h[1] &= 0x1fff;
    h[2] += c;

    // RFC 8439 §2.5 / RFC 7539 §2.5 reduce modulo 2^130-5 before repacking
    // to 16-bit words and adding the raw s half.
    g[0] = h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1fff;
    for (let i = 1; i < 10; i++) {
      g[i] = h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 0x1fff;
    }
    g[9] -= 1 << 13;

    let mask = (c ^ 1) - 1;
    for (let i = 0; i < 10; i++) g[i] &= mask;
    mask = ~mask;
    for (let i = 0; i < 10; i++) h[i] = (h[i] & mask) | g[i];
    h[0] = (h[0] | (h[1] << 13)) & 0xffff;
    h[1] = ((h[1] >>> 3) | (h[2] << 10)) & 0xffff;
    h[2] = ((h[2] >>> 6) | (h[3] << 7)) & 0xffff;
    h[3] = ((h[3] >>> 9) | (h[4] << 4)) & 0xffff;
    h[4] = ((h[4] >>> 12) | (h[5] << 1) | (h[6] << 14)) & 0xffff;
    h[5] = ((h[6] >>> 2) | (h[7] << 11)) & 0xffff;
    h[6] = ((h[7] >>> 5) | (h[8] << 8)) & 0xffff;
    h[7] = ((h[8] >>> 8) | (h[9] << 5)) & 0xffff;

    let f = h[0] + pad[0];
    h[0] = f & 0xffff;
    for (let i = 1; i < 8; i++) {
      f = (((h[i] + pad[i]) | 0) + (f >>> 16)) | 0;
      h[i] = f & 0xffff;
    }
    clean(g);
  }
  update(data: TArg<Uint8Array>): this {
    aexists(this);
    abytes(data);
    data = copyBytes(data);
    const { buffer, blockLen } = this;
    const len = data.length;

    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      // Fast path: we have at least one block in input
      if (take === blockLen) {
        for (; blockLen <= len - pos; pos += blockLen) this.process(data, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(buffer, 0, false);
        this.pos = 0;
      }
    }
    return this;
  }
  destroy(): void {
    // `aexists(this)` guards update/digest paths, so destroy must mark the instance unusable too.
    this.destroyed = true;
    clean(this.h, this.r, this.buffer, this.pad);
  }
  digestInto(out: TArg<Uint8Array>): void {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, h } = this;
    let { pos } = this;
    if (pos) {
      // RFC 8439 §2.5 / RFC 7539 §2.5: the final short block appends a
      // single `0x01` byte and zero-fills the remaining bytes before the
      // last multiplication step.
      buffer[pos++] = 1;
      for (; pos < 16; pos++) buffer[pos] = 0;
      this.process(buffer, 0, true);
    }
    this.finalize();
    let opos = 0;
    for (let i = 0; i < 8; i++) {
      out[opos++] = h[i] >>> 0;
      out[opos++] = h[i] >>> 8;
    }
  }
  digest(): TRet<Uint8Array> {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    // Copy out before destroy() zeroes the internal buffer.
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res as TRet<Uint8Array>;
  }
}

/** One-shot keyed hash helper with `.create()`. */
export type CHash = CMac<Poly1305>;

/**
 * Poly1305 MAC from RFC 8439.
 * @param msg - Message bytes to authenticate.
 * @param key - 32-byte Poly1305 one-time key.
 * @returns 16-byte authentication tag.
 * @example
 * Authenticates one message with a one-shot Poly1305 call and a fresh key.
 *
 * ```ts
 * import { poly1305 } from '@noble/ciphers/_poly1305.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * poly1305(new Uint8Array(), key);
 * ```
 */
export const poly1305: TRet<CHash> = /* @__PURE__ */ wrapMacConstructor(
  32,
  (key: TArg<Uint8Array>) => new Poly1305(key)
);
