/**
 * {@link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard | AES}
 * a.k.a. Advanced Encryption Standard
 * is a variant of Rijndael block cipher, standardized by NIST in 2001.
 * We provide the fastest available pure JS implementation.
 *
 * `cipher = encrypt(block, key)`
 *
 * Data is split into 128-bit blocks.
 * Encrypted in 10/12/14 rounds (128/192/256 bits). In every round:
 * 1. **S-box**, table substitution
 * 2. **Shift rows**, cyclic shift left of all rows of data array
 * 3. **Mix columns**, multiplying every column by fixed polynomial
 * 4. **Add round key**, round_key xor i-th column of array
 *
 * Check out
 * {@link https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf | FIPS-197},
 * {@link https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf | NIST 800-38G},
 * and {@link https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf | original proposal}.
 * @module
 */
import { ghash, polyval } from './_polyval.ts';
// prettier-ignore
import {
  abytes, anumber, aoutput,
  byteSwap,
  clean, complexOverlapBytes, concatBytes,
  copyBytes, createView, equalBytes, getOutput, isAligned32,
  isLE,
  overlapBytes,
  swap32IfBE,
  swap8IfBE,
  u32, u64Lengths, u8, wrapCipher, wrapMacConstructor,
  type Cipher, type CipherWithOutput,
  type CMac, type IHash2,
  type PRG, type TArg, type TRet, type Uint8ArrayBuffer
} from './utils.ts';

const BLOCK_SIZE = 16;
// AES operates on 16-byte blocks, i.e. 4 32-bit words.
const BLOCK_SIZE32 = 4;
// Shared zero block (`0^128`) used by GCM's `H = CIPH_K(0^128)` / J0 scratch
// and by CMAC / SIV helpers; callers take `.slice()` before mutating it.
const EMPTY_BLOCK = /* @__PURE__ */ new Uint8Array(BLOCK_SIZE);
// RFC 5297 §2.1 / §2.4: S2V uses `<one> = 0^127 || 1` for the `n = 0` special case.
const ONE_BLOCK = /* @__PURE__ */ Uint8Array.from([
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);
const POLY = 0x11b; // 1 + x + x**3 + x**4 + x**8
// Validates plain AES key sizes only; AES-SIV's doubled-key contract is checked elsewhere.
function validateKeyLength(key: TArg<Uint8Array>) {
  if (![16, 24, 32].includes(key.length))
    throw new Error('"aes key" expected Uint8Array of length 16/24/32, got length=' + key.length);
}

// TODO: remove multiplication, binary ops only
// Doubles one GF(2^8) field element; callers are expected to stay in byte range.
// FIPS 197 upd1 §4.3 equation (4.5): XTIMES(b) left-shifts by one and, when
// b7=1, reduces by m(x); using POLY=0x11b here yields the same byte result
// as XORing with {1b} after the shift.
function mul2(n: number) {
  return (n << 1) ^ (POLY & -(n >> 7));
}

// Shift-and-add multiplication in GF(2^8); callers are expected to pass byte values.
// FIPS 197 upd1 §4.3 equation (4.7): general products are XORs of repeated
// XTIMES() multiples, e.g. {57}•{13} = {57}⊕{ae}⊕{07}.
function mul(a: number, b: number) {
  let res = 0;
  for (; b > 0; b >>= 1) {
    // Usual shift-and-add step in GF(2^8), not a scalar-multiplication ladder.
    res ^= a & -(b & 1); // if (b&1) res ^=a (but const-time).
    a = mul2(a); // a = 2*a
  }
  return res;
}

/**
 * Increments a counter block with wrap around.
 * AES call sites here currently use the big-endian branch, but the helper supports both layouts.
 * NIST SP 800-38A Appendix B.1 and SP 800-38D §6.2 increment the
 * least-significant/rightmost bits.
 * `isLE=false` matches that standard counter-block layout, while `isLE=true`
 * is a generic extension for non-AES callers.
 * The implementation keeps a 32-bit bitwise carry path, so `carry` is capped at `0xffffff00`;
 * larger values throw instead of silently overflowing before the next-byte propagation step.
 */
// Keep the helper explicitly typed so `--isolatedDeclarations` can expose it
// through the test-only `__TESTS` export without inference errors.
const incBytes: (data: TArg<Uint8Array>, isLE: boolean, carry?: number) => void = (
  data: TArg<Uint8Array>,
  isLE: boolean,
  carry: number = 1
): void => {
  // Keep `carry + byte <= 0xffffffff` so the `| 0` / `>>> 8` path below
  // never truncates a real carry bit.
  if (!Number.isSafeInteger(carry) || carry > 0xffffff00)
    throw new Error('incBytes: wrong carry ' + carry);
  abytes(data);
  for (let i = 0; i < data.length; i++) {
    const pos = !isLE ? data.length - 1 - i : i;
    carry = (carry + (data[pos] & 0xff)) | 0;
    data[pos] = carry & 0xff;
    carry >>>= 8;
  }
};

// AES S-box is generated using finite field inversion,
// an affine transform, and xor of a constant 0x63.
const sbox = /* @__PURE__ */ (() => {
  const t = new Uint8Array(256);
  // Repeated multiplication by {03} walks all 255 nonzero field elements
  // once, so t[255 - i] is the multiplicative inverse of t[i] for the
  // affine step.
  for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x)) t[i] = x;
  const box = new Uint8Array(256);
  // FIPS 197 upd1 §5.1.1: SBOX({00}) = {63} because the inverse step leaves
  // {00} at {00}, then the affine transform xors in c = {63}.
  box[0] = 0x63;
  for (let i = 0; i < 255; i++) {
    let x = t[255 - i];
    x |= x << 8;
    box[t[i]] = (x ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63) & 0xff;
  }
  clean(t);
  return box;
})();

// FIPS 197 upd1 §5.3.2: INVSBOX() is derived from SBOX() by swapping input
// and output roles (Table 6).
// `indexOf` is only used once at module init, so the quadratic setup cost stays off hot paths.
const invSbox = /* @__PURE__ */ sbox.map((_, j) => sbox.indexOf(j));

// FIPS 197 upd1 §5.2: ROTWORD([a0,a1,a2,a3]) = [a1,a2,a3,a0]; with this LE
// word packing that is a right rotate by 8 bits.
const rotr32_8 = (n: number) => (n << 24) | (n >>> 8);
// LE T-table helper: rotates one precomputed word by one byte so T1/T2/T3
// reuse T0's substitution/mix result in the other byte lanes.
const rotl32_8 = (n: number) => (n << 8) | (n >>> 24);
// T-table is optimization suggested in 5.2 of original proposal (missed from FIPS-197). Changes:
// - LE instead of BE
// - bigger tables: T0 and T1 are merged into T01 table and T2 & T3 into T23;
//   so index is u16, instead of u8. This speeds up things, unexpectedly
function genTtable(sbox: TArg<Uint8Array>, fn: (n: number) => number) {
  if (sbox.length !== 256) throw new Error('Wrong sbox length');
  const T0 = new Uint32Array(256).map((_, j) => fn(sbox[j]));
  const T1 = T0.map(rotl32_8);
  const T2 = T1.map(rotl32_8);
  const T3 = T2.map(rotl32_8);
  // Pre-xor adjacent lanes so apply0123/applySbox can fetch two substituted
  // byte lanes per lookup in the LE round layout.
  const T01 = new Uint32Array(256 * 256);
  const T23 = new Uint32Array(256 * 256);
  const sbox2 = new Uint16Array(256 * 256);
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const idx = i * 256 + j;
      T01[idx] = T0[i] ^ T1[j];
      T23[idx] = T2[i] ^ T3[j];
      sbox2[idx] = (sbox[i] << 8) | sbox[j];
    }
  }
  return { sbox, sbox2, T0, T1, T2, T3, T01, T23 };
}

// Forward round precompute: the packed word stores the MIXCOLUMNS row
// [{02},{01},{01},{03}] in LE byte-lane order, and the returned `sbox2`
// is also reused by key expansion and the final round.
const tableEncoding = /* @__PURE__ */ genTtable(
  sbox,
  (s: number) => (mul(s, 3) << 24) | (s << 16) | (s << 8) | mul(s, 2)
);
// Inverse round precompute: the packed word stores the INVMIXCOLUMNS row
// [{0e},{09},{0d},{0b}] in LE byte-lane order, and the tables are reused
// by decrypt() and expandKeyDecLE().
const tableDecoding = /* @__PURE__ */ genTtable(
  invSbox,
  (s) => (mul(s, 11) << 24) | (mul(s, 13) << 16) | (mul(s, 9) << 8) | mul(s, 14)
);

// FIPS 197 upd1 §5.2 Table 5: left-most bytes of Rcon[j] = x^(j-1), generated by repeated XTIMES().
const xPowers = /* @__PURE__ */ (() => {
  const p = new Uint8Array(16);
  for (let i = 0, x = 1; i < 16; i++, x = mul2(x)) p[i] = x;
  return p;
})();

/** Forward AES key expansion used across ECB/CBC/CTR/GCM/CMAC/KW-style paths. */
function expandKeyLE(key: TArg<Uint8Array>): TRet<Uint32Array> {
  abytes(key);
  const len = key.length;
  validateKeyLength(key);
  const { sbox2 } = tableEncoding;
  const toClean = [];
  // Copy on BE or misaligned inputs so the LE word normalization below never
  // mutates caller key bytes in place.
  if (!isLE || !isAligned32(key)) toClean.push((key = copyBytes(key)));
  const k32 = swap32IfBE(u32(key));
  const Nk = k32.length;
  // `applySbox` normally reads one byte lane from each argument; repeating
  // `n` across all four lanes turns it into SUBWORD(n).
  const subByte = (n: number) => applySbox(sbox2, n, n, n, n);
  // AES key sizes are 16/24/32 bytes, so len + 28 yields the 44/52/60
  // schedule words from FIPS 197 §5.2 / Table 3.
  const xk = new Uint32Array(len + 28); // expanded key
  xk.set(k32);
  // 4.3.1 Key expansion
  for (let i = Nk; i < xk.length; i++) {
    let t = xk[i - 1];
    if (i % Nk === 0) t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
    else if (Nk > 6 && i % Nk === 4) t = subByte(t);
    xk[i] = xk[i - Nk] ^ t;
  }
  clean(...toClean);
  return xk as TRet<Uint32Array>;
}

function expandKeyDecLE(key: TArg<Uint8Array>): TRet<Uint32Array> {
  const encKey = expandKeyLE(key);
  const xk = encKey.slice();
  const Nk = encKey.length;
  const { sbox2 } = tableEncoding;
  const { T0, T1, T2, T3 } = tableDecoding;
  // Local decrypt() walks round keys forward from xk[0], so reverse the
  // encryption round-key blocks first before applying the equivalent-inverse
  // middle-round transform.
  for (let i = 0; i < Nk; i += 4) {
    for (let j = 0; j < 4; j++) xk[i + j] = encKey[Nk - i - 4 + j];
  }
  clean(encKey);
  // Apply InvMixColumn to the reversed round keys using the same LE sbox2
  // packing as the forward path.
  // apply InvMixColumn except first & last round
  for (let i = 4; i < Nk - 4; i++) {
    const x = xk[i];
    const w = applySbox(sbox2, x, x, x, x);
    xk[i] = T0[w & 0xff] ^ T1[(w >>> 8) & 0xff] ^ T2[(w >>> 16) & 0xff] ^ T3[w >>> 24];
  }
  return xk as TRet<Uint32Array>;
}

// Apply tables
function apply0123(
  T01: TArg<Uint32Array>,
  T23: TArg<Uint32Array>,
  s0: number,
  s1: number,
  s2: number,
  s3: number
) {
  // `T01` takes the low byte lane from `s0` plus the next lane from `s1`;
  // `T23` does the same for `s2`/`s3`.
  // Equivalent to `T0[s0&0xff] ^ T1[(s1>>>8)&0xff] ^ T2[(s2>>>16)&0xff] ^
  // T3[s3>>>24]`, but with two merged-table fetches.
  return (
    T01[((s0 << 8) & 0xff00) | ((s1 >>> 8) & 0xff)] ^
    T23[((s2 >>> 8) & 0xff00) | ((s3 >>> 24) & 0xff)]
  );
}

function applySbox(sbox2: TArg<Uint16Array>, s0: number, s1: number, s2: number, s3: number) {
  // `sbox2` packs two substituted byte lanes at a time in the same LE
  // layout used by the round code.
  // Equivalent to `SBOX(byte0(s0)) | SBOX(byte1(s1))<<8 |
  // SBOX(byte2(s2))<<16 | SBOX(byte3(s3))<<24`.
  return (
    sbox2[(s0 & 0xff) | (s1 & 0xff00)] |
    (sbox2[((s2 >>> 16) & 0xff) | ((s3 >>> 16) & 0xff00)] << 16)
  );
}

function encrypt(
  xk: TArg<Uint32Array>,
  s0: number,
  s1: number,
  s2: number,
  s3: number
): { s0: number; s1: number; s2: number; s3: number } {
  const { sbox2, T01, T23 } = tableEncoding;
  let k = 0;
  ((s0 ^= xk[k++]), (s1 ^= xk[k++]), (s2 ^= xk[k++]), (s3 ^= xk[k++]));
  // `xk` has Nr+1 round-key blocks, so after the initial AddRoundKey and the
  // final S-box-only round there are Nr-1 full table/MixColumns rounds left.
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t0 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
    const t1 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
    const t2 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
    const t3 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
    ((s0 = t0), (s1 = t1), (s2 = t2), (s3 = t3));
  }
  // last round (without mixcolumns, so using SBOX2 table)
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}

// Can't be merged with encrypt: arg positions for apply0123 / applySbox are different
function decrypt(
  xk: TArg<Uint32Array>,
  s0: number,
  s1: number,
  s2: number,
  s3: number
): {
  s0: number;
  s1: number;
  s2: number;
  s3: number;
} {
  const { sbox2, T01, T23 } = tableDecoding;
  let k = 0;
  ((s0 ^= xk[k++]), (s1 ^= xk[k++]), (s2 ^= xk[k++]), (s3 ^= xk[k++]));
  // With `expandKeyDecLE()` the round keys are already reversed and middle
  // rounds are InvMixColumns-adjusted, so this loop follows the equivalent
  // inverse cipher order directly.
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t0 = xk[k++] ^ apply0123(T01, T23, s0, s3, s2, s1);
    const t1 = xk[k++] ^ apply0123(T01, T23, s1, s0, s3, s2);
    const t2 = xk[k++] ^ apply0123(T01, T23, s2, s1, s0, s3);
    const t3 = xk[k++] ^ apply0123(T01, T23, s3, s2, s1, s0);
    ((s0 = t0), (s1 = t1), (s2 = t2), (s3 = t3));
  }
  // Final equivalent-inverse round omits InvMixColumns, so use inverse
  // S-box lanes in InvShiftRows order.
  const t0: number = xk[k++] ^ applySbox(sbox2, s0, s3, s2, s1);
  const t1: number = xk[k++] ^ applySbox(sbox2, s1, s0, s3, s2);
  const t2: number = xk[k++] ^ applySbox(sbox2, s2, s1, s0, s3);
  const t3: number = xk[k++] ^ applySbox(sbox2, s3, s2, s1, s0);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}

function ctrCounter(
  xk: TArg<Uint32Array>,
  nonce: TArg<Uint8Array>,
  src: TArg<Uint8Array>,
  dst?: TArg<Uint8Array>
): TRet<Uint8Array> {
  abytes(nonce, BLOCK_SIZE, 'nonce');
  abytes(src);
  const srcLen = src.length;
  dst = getOutput(srcLen, dst);
  complexOverlapBytes(src, dst);
  // Internal helper: mutate `nonce` in place as the live counter block so
  // each encrypted block uses the next CTR value.
  const ctr = nonce;
  const c32 = u32(ctr);
  const src32 = u32(src);
  const dst32 = u32(dst);
  // Fill block (empty, ctr=0)
  let { s0, s1, s2, s3 } = encrypt(
    xk,
    swap8IfBE(c32[0]),
    swap8IfBE(c32[1]),
    swap8IfBE(c32[2]),
    swap8IfBE(c32[3])
  );
  // process blocks
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
    dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
    dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
    dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
    incBytes(ctr, false, 1); // Full 128 bit counter with wrap around
    ({ s0, s1, s2, s3 } = encrypt(
      xk,
      swap8IfBE(c32[0]),
      swap8IfBE(c32[1]),
      swap8IfBE(c32[2]),
      swap8IfBE(c32[3])
    ));
  }
  // NIST SP 800-38A CTR mode uses the leading `u` bits of the next output
  // block for the final short block.
  // It's possible to handle > u32 fast, but is it worth it?
  const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    swap32IfBE(b32);
    const buf = u8(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos];
    clean(b32);
  }
  // Unsafe mutable-counter API only advances whole blocks. Callers that want to
  // resume after consuming part of this block must re-run from the same counter
  // with left-padding and strip the already-consumed prefix themselves.
  return dst as TRet<Uint8Array>;
}

// AES CTR with overflowing 32 bit counter
// It's possible to do 32le significantly simpler (and probably faster) by using u32.
// But, we need both, and perf bottleneck is in ghash anyway.
// Unsafe 32-bit CTR helper: mutates `nonce` in place, expects aligned `src`/`dst`,
// and uses `isLE` to choose which 32-bit counter word is incremented.
function ctr32(
  xk: TArg<Uint32Array>,
  isLE: boolean,
  nonce: TArg<Uint8Array>,
  src: TArg<Uint8Array>,
  dst?: TArg<Uint8Array>
): TRet<Uint8Array> {
  abytes(nonce, BLOCK_SIZE, 'nonce');
  abytes(src);
  dst = getOutput(src.length, dst);
  const ctr = nonce; // write new value to nonce, so it can be re-used
  const c32 = u32(ctr);
  const view = createView(ctr);
  const src32 = u32(src);
  const dst32 = u32(dst);
  // NIST SP 800-38D GCTR increments the rightmost 32 bits of J0, while
  // RFC 8452 AES-GCM-SIV increments the first 32 bits as a little-endian u32.
  const ctrPos = isLE ? 0 : 12;
  const srcLen = src.length;
  // Fill block (empty, ctr=0)
  let ctrNum = view.getUint32(ctrPos, isLE); // read current counter value
  let { s0, s1, s2, s3 } = encrypt(
    xk,
    swap8IfBE(c32[0]),
    swap8IfBE(c32[1]),
    swap8IfBE(c32[2]),
    swap8IfBE(c32[3])
  );
  // process blocks
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
    dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
    dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
    dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
    ctrNum = (ctrNum + 1) >>> 0; // u32 wrap
    view.setUint32(ctrPos, ctrNum, isLE);
    ({ s0, s1, s2, s3 } = encrypt(
      xk,
      swap8IfBE(c32[0]),
      swap8IfBE(c32[1]),
      swap8IfBE(c32[2]),
      swap8IfBE(c32[3])
    ));
  }
  // leftovers (less than a block)
  const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    swap32IfBE(b32);
    const buf = u8(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos];
    clean(b32);
  }
  // Same unsafe contract as ctrCounter(): only full blocks advance the stored
  // mutable counter state; partial-block continuation is caller-managed.
  return dst as TRet<Uint8Array>;
}

/**
 * **CTR** (Counter Mode): turns a block cipher into a stream cipher using a
 * full 16-byte counter block.
 * Efficient and parallelizable. Requires a unique nonce per encryption. Unauthenticated: needs MAC.
 * @param key - AES key bytes.
 * @param nonce - 16-byte counter block, incremented as a full AES block.
 * @returns Cipher instance with `encrypt()` and `decrypt()`.
 * @example
 * Encrypts a short payload with a fresh AES key and counter block.
 *
 * ```ts
 * import { ctr } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const nonce = randomBytes(16);
 * const cipher = ctr(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const ctr: TRet<
  ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>) => CipherWithOutput) & {
    blockSize: number;
    nonceLength: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16, nonceLength: 16 },
  function aesctr(key: TArg<Uint8Array>, nonce: TArg<Uint8Array>): TRet<CipherWithOutput> {
    function processCtr(buf: TArg<Uint8Array>, dst?: TArg<Uint8Array>): TRet<Uint8Array> {
      abytes(buf);
      if (dst !== undefined) {
        abytes(dst);
        // Optional output buffers must stay 4-byte aligned because
        // ctrCounter() reinterprets them as Uint32Array words.
        if (!isAligned32(dst)) throw new Error('unaligned destination');
      }
      const xk = expandKeyLE(key);
      // Public CTR keeps caller nonce bytes immutable even though ctrCounter()
      // advances the live 16-byte counter block in place.
      const n = copyBytes(nonce); // align + avoid changing
      const toClean = [xk, n];
      if (!isAligned32(buf)) toClean.push((buf = copyBytes(buf)));
      const out = ctrCounter(xk, n, buf, dst);
      clean(...toClean);
      return out as TRet<Uint8Array>;
    }
    return {
      encrypt: (plaintext: TArg<Uint8Array>, dst?: TArg<Uint8Array>) => processCtr(plaintext, dst),
      decrypt: (ciphertext: TArg<Uint8Array>, dst?: TArg<Uint8Array>) =>
        processCtr(ciphertext, dst),
    } as TRet<CipherWithOutput>;
  }
);

function validateBlockDecrypt(data: TArg<Uint8Array>) {
  abytes(data);
  // ECB/CBC decryption always consumes whole ciphertext blocks; PKCS#7/CMS
  // padding, when enabled, is removed only after decrypting the final block.
  if (data.length % BLOCK_SIZE !== 0) {
    throw new Error(
      'aes-(cbc/ecb).decrypt ciphertext should consist of blocks with size ' + BLOCK_SIZE
    );
  }
}

// ECB/CBC core modes operate on whole blocks; `pkcs5` enables the library's
// PKCS#7/CMS-compatible final-block padding convenience before encryption.
function validateBlockEncrypt(plaintext: TArg<Uint8Array>, pkcs5: boolean, dst?: TArg<Uint8Array>) {
  abytes(plaintext);
  let outLen = plaintext.length;
  const remaining = outLen % BLOCK_SIZE;
  if (!pkcs5 && remaining !== 0)
    throw new Error('aec/(cbc-ecb): unpadded plaintext with disabled padding');
  if (pkcs5) {
    let left = BLOCK_SIZE - remaining;
    // RFC 5652 pads even already-aligned inputs, so a full extra block is
    // appended when the plaintext length is already a multiple of 16 bytes.
    if (!left) left = BLOCK_SIZE; // if no bytes left, create empty padding block
    outLen = outLen + left;
  }
  dst = getOutput(outLen, dst);
  complexOverlapBytes(plaintext, dst);
  // Copy on BE or misaligned inputs so u32()/swap32IfBE() normalization never
  // mutates caller plaintext bytes in place before ECB/CBC processing.
  if (!isLE || !isAligned32(plaintext)) plaintext = copyBytes(plaintext);
  const b = u32(plaintext);
  swap32IfBE(b);
  const o = u32(dst);
  return { b, o, out: dst };
}

// `pkcs5` is the historical option name; for AES's 16-byte block this is the
// generic PKCS#7/CMS-style block-padding rule on decrypt.
function validatePKCS(data: TArg<Uint8Array>, pkcs5: boolean): TRet<Uint8Array> {
  if (!pkcs5) return data as TRet<Uint8Array>;

  const len = data.length;
  // RFC 5652 pads even empty / already-aligned inputs, so a valid padded
  // ECB/CBC ciphertext is never empty when PKCS#7/CMS unpadding is enabled.
  // AES-CBC/ECB ciphertext should be full blocks before unpadding
  if (len === 0) throw new Error('aes/pkcs7: empty ciphertext not allowed');
  const lastByte = data[len - 1];
  let valid = 1;
  valid &= ((lastByte - 1) >>> 31) ^ 1; // pad >= 1
  valid &= ((16 - lastByte) >>> 31) ^ 1; // pad <= 16
  // Check exactly 16 tail bytes in constant-shape loop
  // For i < pad: byte must equal pad
  // For i >= pad: ignore byte
  for (let i = 0; i < 16; i++) {
    // const b = data[len - 1 - i];
    const shouldCheck = (i - lastByte) >>> 31; // 1 if i < pad else 0
    const eq = (data[len - 1 - i] ^ lastByte) === 0 ? 1 : 0; // 1 if equal
    valid &= eq | (shouldCheck ^ 1); // pass if equal OR not checked
  }

  // if (invalidLen) throw new Error('aes/pkcs7: ciphertext length must be multiple of 16');
  if (!valid) throw new Error('aes/pkcs7: wrong padding');
  return data.subarray(0, len - lastByte) as TRet<Uint8Array>;
}

// ECB/CBC callers only pass the final short block here, so `left.length` is
// 0..15 and the helper always emits exactly one padded 16-byte block.
function padPCKS(left: TArg<Uint8Array>): TRet<Uint32Array> {
  const tmp = new Uint8Array(16);
  const tmp32 = u32(tmp);
  tmp.set(left);
  const paddingByte = BLOCK_SIZE - left.length;
  // RFC 5652 §6.3 fills the whole suffix with the padding length byte:
  // e.g. `aa 0f..0f` for a 1-byte tail, or `10..10` for a full extra block.
  for (let i = BLOCK_SIZE - paddingByte; i < BLOCK_SIZE; i++) tmp[i] = paddingByte;
  return tmp32;
}

/** Options for ECB and CBC. */
export type BlockOpts = {
  /** Disable the library's PKCS#7 padding/unpadding layer and require exact-block inputs. */
  disablePadding?: boolean;
};

/**
 * **ECB** (Electronic Codebook): Deterministic encryption; identical plaintext blocks yield
 * identical ciphertexts. Not secure due to pattern leakage.
 * See {@link https://words.filippo.io/the-ecb-penguin/ | the AES Penguin}.
 * @param key - AES key bytes.
 * @param opts - Padding options. See {@link BlockOpts}.
 * @returns Cipher instance with `encrypt()` and `decrypt()`.
 * @example
 * Shows the basic ECB encrypt call shape with a fresh key; avoid ECB in new designs.
 *
 * ```ts
 * import { ecb } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const cipher = ecb(key);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const ecb: TRet<
  ((key: TArg<Uint8Array>, opts?: BlockOpts) => CipherWithOutput) & {
    blockSize: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16 },
  function aesecb(key: TArg<Uint8Array>, opts: BlockOpts = {}): TRet<CipherWithOutput> {
    const pkcs5 = !opts.disablePadding;
    return {
      encrypt(plaintext: TArg<Uint8Array>, dst?: TArg<Uint8Array>): TRet<Uint8Array> {
        const { b, o, out: _out } = validateBlockEncrypt(plaintext, pkcs5, dst);
        const xk = expandKeyLE(key);
        let i = 0;
        for (; i + 4 <= b.length; ) {
          const { s0, s1, s2, s3 } = encrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
          ((o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3));
        }
        if (pkcs5) {
          const tmp32 = padPCKS(plaintext.subarray(i * 4));
          swap32IfBE(tmp32);
          const { s0, s1, s2, s3 } = encrypt(xk, tmp32[0], tmp32[1], tmp32[2], tmp32[3]);
          ((o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3));
        }
        swap32IfBE(o);
        clean(xk);
        return _out as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>, dst?: TArg<Uint8Array>): TRet<Uint8Array> {
        validateBlockDecrypt(ciphertext);
        const xk = expandKeyDecLE(key);
        dst = getOutput(ciphertext.length, dst);
        const toClean: (Uint8Array | Uint32Array)[] = [xk];
        complexOverlapBytes(ciphertext, dst);
        // Copy on BE or misaligned ciphertext so u32()/swap32IfBE()
        // normalization never mutates caller bytes in place before decrypt().
        if (!isLE || !isAligned32(ciphertext)) toClean.push((ciphertext = copyBytes(ciphertext)));
        const b = u32(ciphertext);
        const o = u32(dst);
        swap32IfBE(b);
        for (let i = 0; i + 4 <= b.length; ) {
          const { s0, s1, s2, s3 } = decrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
          ((o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3));
        }
        swap32IfBE(o);
        clean(...toClean);
        return validatePKCS(dst, pkcs5) as TRet<Uint8Array>;
      },
    } as TRet<CipherWithOutput>;
  }
);

/**
 * **CBC** (Cipher Block Chaining): Each plaintext block is XORed with the
 * previous block of ciphertext before encryption.
 * Hard to use: requires proper padding and an unpredictable IV. Unauthenticated: needs MAC.
 * @param key - AES key bytes.
 * @param iv - 16-byte unpredictable initialization vector.
 * @param opts - Padding options. See {@link BlockOpts}.
 * @returns Cipher instance with `encrypt()` and `decrypt()`.
 * @example
 * Encrypts a padded message with a fresh key and 16-byte IV.
 *
 * ```ts
 * import { cbc } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const iv = randomBytes(16);
 * const cipher = cbc(key, iv);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const cbc: TRet<
  ((key: TArg<Uint8Array>, iv: TArg<Uint8Array>, opts?: BlockOpts) => CipherWithOutput) & {
    blockSize: number;
    nonceLength: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16, nonceLength: 16 },
  function aescbc(
    key: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    opts: BlockOpts = {}
  ): TRet<CipherWithOutput> {
    const pkcs5 = !opts.disablePadding;
    return {
      encrypt(plaintext: TArg<Uint8Array>, dst?: TArg<Uint8Array>): TRet<Uint8Array> {
        const xk = expandKeyLE(key);
        const { b, o, out: _out } = validateBlockEncrypt(plaintext, pkcs5, dst);
        let _iv = iv;
        const toClean: (Uint8Array | Uint32Array)[] = [xk];
        // Copy on BE or misaligned inputs so IV normalization and the mutable
        // local chaining state never write back into caller IV bytes.
        if (!isLE || !isAligned32(_iv)) toClean.push((_iv = copyBytes(_iv)));
        const n32 = u32(_iv);
        swap32IfBE(n32);
        // prettier-ignore
        let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
        let i = 0;
        for (; i + 4 <= b.length; ) {
          ((s0 ^= b[i + 0]), (s1 ^= b[i + 1]), (s2 ^= b[i + 2]), (s3 ^= b[i + 3]));
          ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
          ((o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3));
        }
        if (pkcs5) {
          const tmp32 = padPCKS(plaintext.subarray(i * 4));
          swap32IfBE(tmp32);
          ((s0 ^= tmp32[0]), (s1 ^= tmp32[1]), (s2 ^= tmp32[2]), (s3 ^= tmp32[3]));
          ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
          ((o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3));
        }
        swap32IfBE(o);
        clean(...toClean);
        return _out as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>, dst?: TArg<Uint8Array>): TRet<Uint8Array> {
        validateBlockDecrypt(ciphertext);
        const xk = expandKeyDecLE(key);
        let _iv = iv;
        const toClean: (Uint8Array | Uint32Array)[] = [xk];
        // Copy on BE or misaligned inputs so IV normalization and the mutable
        // local chaining state never write back into caller IV bytes.
        if (!isLE || !isAligned32(_iv)) toClean.push((_iv = copyBytes(_iv)));
        const n32 = u32(_iv);
        swap32IfBE(n32);
        dst = getOutput(ciphertext.length, dst);
        complexOverlapBytes(ciphertext, dst);
        // Copy on BE or misaligned ciphertext so u32()/swap32IfBE()
        // normalization never mutates caller bytes in place before decrypt().
        if (!isLE || !isAligned32(ciphertext)) toClean.push((ciphertext = copyBytes(ciphertext)));
        const b = u32(ciphertext);
        const o = u32(dst);
        swap32IfBE(b);
        // prettier-ignore
        let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
        for (let i = 0; i + 4 <= b.length; ) {
          // prettier-ignore
          const ps0 = s0, ps1 = s1, ps2 = s2, ps3 = s3;
          ((s0 = b[i + 0]), (s1 = b[i + 1]), (s2 = b[i + 2]), (s3 = b[i + 3]));
          const { s0: o0, s1: o1, s2: o2, s3: o3 } = decrypt(xk, s0, s1, s2, s3);
          ((o[i++] = o0 ^ ps0), (o[i++] = o1 ^ ps1), (o[i++] = o2 ^ ps2), (o[i++] = o3 ^ ps3));
        }
        swap32IfBE(o);
        clean(...toClean);
        return validatePKCS(dst, pkcs5) as TRet<Uint8Array>;
      },
    } as TRet<CipherWithOutput>;
  }
);

/**
 * CFB (CFB-128): Cipher Feedback Mode with 128-bit segments. The input for the
 * block cipher is the previous cipher output.
 * Unauthenticated: needs MAC.
 * @param key - AES key bytes.
 * @param iv - 16-byte unpredictable initialization vector.
 * @returns Cipher instance with `encrypt()` and `decrypt()`.
 * @example
 * Encrypts a short message with feedback mode and a fresh key/IV pair.
 *
 * ```ts
 * import { cfb } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const iv = randomBytes(16);
 * const cipher = cfb(key, iv);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const cfb: TRet<
  ((key: TArg<Uint8Array>, iv: TArg<Uint8Array>) => CipherWithOutput) & {
    blockSize: number;
    nonceLength: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16, nonceLength: 16 },
  function aescfb(key: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<CipherWithOutput> {
    function processCfb(
      src: TArg<Uint8Array>,
      isEncrypt: boolean,
      dst?: TArg<Uint8Array>
    ): TRet<Uint8Array> {
      abytes(src);
      const srcLen = src.length;
      dst = getOutput(srcLen, dst);
      // CFB feeds back previous ciphertext, so overlapping src/dst could
      // overwrite bytes that are still needed as the next feedback block.
      if (overlapBytes(src, dst)) throw new Error('overlapping src and dst not supported.');
      const xk = expandKeyLE(key);
      let _iv = iv;
      const toClean: (Uint8Array | Uint32Array)[] = [xk];
      // Copy on BE or misaligned inputs so u32()/swap32IfBE() normalization
      // never mutates caller IV/src bytes in place before CFB processing.
      if (!isLE || !isAligned32(_iv)) toClean.push((_iv = copyBytes(_iv)));
      if (!isLE || !isAligned32(src)) toClean.push((src = copyBytes(src)));
      const src32 = u32(src);
      const dst32 = u32(dst);
      // NIST SP 800-38A §6.3 feeds back the previous ciphertext segment in
      // both directions: encrypt reuses freshly written dst words, decrypt
      // reuses the source ciphertext words.
      const next32 = isEncrypt ? dst32 : src32;
      const n32 = u32(_iv);
      swap32IfBE(src32);
      swap32IfBE(n32);
      // prettier-ignore
      let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
      for (let i = 0; i + 4 <= src32.length; ) {
        const { s0: e0, s1: e1, s2: e2, s3: e3 } = encrypt(xk, s0, s1, s2, s3);
        dst32[i + 0] = src32[i + 0] ^ e0;
        dst32[i + 1] = src32[i + 1] ^ e1;
        dst32[i + 2] = src32[i + 2] ^ e2;
        dst32[i + 3] = src32[i + 3] ^ e3;
        ((s0 = next32[i++]), (s1 = next32[i++]), (s2 = next32[i++]), (s3 = next32[i++]));
      }
      // leftovers (less than block)
      const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
      if (start < srcLen) {
        // Byte-oriented API: for a final short tail, reuse the next CFB-128
        // output block and XOR only the needed prefix. RFC 3826 §3.1.3 /
        // §3.1.4 describes the same no-padding rule at bit granularity for a
        // final r<=128 segment.
        ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
        const tmp = new Uint32Array([s0, s1, s2, s3]);
        swap32IfBE(tmp);
        const buf = u8(tmp);
        for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos];
        clean(buf);
      }
      swap32IfBE(dst32);
      clean(...toClean);
      return dst as TRet<Uint8Array>;
    }
    return {
      encrypt: (plaintext: TArg<Uint8Array>, dst?: TArg<Uint8Array>) =>
        processCfb(plaintext, true, dst),
      decrypt: (ciphertext: TArg<Uint8Array>, dst?: TArg<Uint8Array>) =>
        processCfb(ciphertext, false, dst),
    } as TRet<CipherWithOutput>;
  }
);

// TODO: merge with chacha, however gcm has bitLen while chacha has byteLen
// `data` is the payload covered by the polynomial MAC: ciphertext for GCM,
// plaintext for GCM-SIV. Keep AAD/data/length as separate updates because
// GHASH/POLYVAL pad each call to block boundaries, so the chunks must match the
// spec-defined segments instead of arbitrary concatenation boundaries.
function computeTag(
  fn: typeof ghash,
  isLE: boolean,
  key: TArg<Uint8Array>,
  data: TArg<Uint8Array>,
  AAD?: TArg<Uint8Array>
): TRet<Uint8Array> {
  const aadLength = AAD ? AAD.length : 0;
  const h = fn.create(key, data.length + aadLength);
  if (AAD) h.update(AAD);
  // u64Lengths() takes (dataBits, aadBits) but still serializes the final
  // block as len(AAD) || len(data), matching both GCM and GCM-SIV.
  const num = u64Lengths(8 * data.length, 8 * aadLength, isLE);
  h.update(data);
  h.update(num);
  const res = h.digest();
  clean(num);
  return res;
}

/**
 * **GCM** (Galois/Counter Mode): Combines CTR mode with polynomial MAC. Efficient and widely used.
 * Not perfect:
 * a) conservative key wear-out is `2**32` (4B) msgs.
 * b) key wear-out under random nonces is even smaller: `2**23` (8M) messages for `2**-50` chance.
 * c) MAC can be forged: see Poly1305 documentation.
 * @param key - AES key bytes.
 * @param nonce - Nonce bytes (12 recommended, minimum 8; other lengths use GHASH J0 derivation).
 * @param AAD - Additional authenticated data.
 * @returns AEAD cipher instance with a fixed 16-byte tag.
 * @example
 * Encrypts and authenticates plaintext with a fresh key and 12-byte nonce.
 *
 * ```ts
 * import { gcm } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const nonce = randomBytes(12);
 * const cipher = gcm(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const gcm: TRet<
  ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>) => Cipher) & {
    blockSize: number;
    nonceLength: number;
    tagLength: number;
    varSizeNonce: true;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16, nonceLength: 12, tagLength: 16, varSizeNonce: true },
  function aesgcm(
    key: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    AAD?: TArg<Uint8Array>
  ): TRet<Cipher> {
    // SP 800-38D lets implementations narrow supported IV lengths.
    // This wrapper intentionally requires at least 8 bytes; OpenSSL accepts shorter IVs too.
    // 12-byte nonces take the fast path; other allowed lengths use GHASH to derive J0.
    if (nonce.length < 8) throw new Error('aes/gcm: invalid nonce length');
    const tagLength = 16;
    function _computeTag(
      authKey: TArg<Uint8Array>,
      tagMask: TArg<Uint8Array>,
      data: TArg<Uint8Array>
    ): TRet<Uint8Array> {
      const tag = computeTag(ghash, false, authKey, data, AAD);
      for (let i = 0; i < tagMask.length; i++) tag[i] ^= tagMask[i];
      return tag;
    }
    function deriveKeys() {
      const xk = expandKeyLE(key);
      const authKey = EMPTY_BLOCK.slice();
      const counter = EMPTY_BLOCK.slice();
      ctr32(xk, false, counter, counter, authKey);
      // NIST 800-38d, page 15: different behavior for 96-bit and non-96-bit nonces
      if (nonce.length === 12) {
        counter.set(nonce);
      } else {
        const nonceLen = EMPTY_BLOCK.slice();
        const view = createView(nonceLen);
        view.setBigUint64(8, BigInt(nonce.length * 8), false);
        // GHASH.update() pads each call to 16 bytes, so
        // update(nonce).update(nonceLen) realizes
        // IV || 0^s || 0^64 || [len(IV)]_64 for non-96-bit nonces.
        // ghash(nonce || u64be(0) || u64be(nonceLen*8))
        const g = ghash.create(authKey).update(nonce).update(nonceLen);
        g.digestInto(counter); // digestInto doesn't trigger '.destroy'
        g.destroy();
      }
      // GCTR_K(J0, 0^128) = E_K(J0); reusing ctr32() here extracts that tag
      // mask and leaves `counter` advanced to inc32(J0) for payload GCTR.
      const tagMask = ctr32(xk, false, counter, EMPTY_BLOCK);
      return { xk, authKey, counter, tagMask };
    }
    return {
      encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        const { xk, authKey, counter, tagMask } = deriveKeys();
        const out = new Uint8Array(plaintext.length + tagLength);
        const toClean: (Uint8Array | Uint32Array)[] = [xk, authKey, counter, tagMask];
        if (!isAligned32(plaintext)) toClean.push((plaintext = copyBytes(plaintext)));
        ctr32(xk, false, counter, plaintext, out.subarray(0, plaintext.length));
        const tag = _computeTag(authKey, tagMask, out.subarray(0, out.length - tagLength));
        toClean.push(tag);
        out.set(tag, plaintext.length);
        clean(...toClean);
        return out as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        const { xk, authKey, counter, tagMask } = deriveKeys();
        const toClean: (Uint8Array | Uint32Array)[] = [xk, authKey, tagMask, counter];
        if (!isAligned32(ciphertext)) toClean.push((ciphertext = copyBytes(ciphertext)));
        const data = ciphertext.subarray(0, -tagLength);
        const passedTag = ciphertext.subarray(-tagLength);
        const tag = _computeTag(authKey, tagMask, data);
        toClean.push(tag);
        // NIST SP 800-38D §7.2 permits equivalent step orderings; verify the
        // tag before CTR so unauthenticated plaintext is never materialized.
        if (!equalBytes(tag, passedTag)) {
          clean(...toClean);
          throw new Error('aes/gcm: invalid ghash tag');
        }
        const out = ctr32(xk, false, counter, data);
        clean(...toClean);
        return out as TRet<Uint8Array>;
      },
    } as TRet<Cipher>;
  }
);

const limit = (name: string, min: number, max: number) => (value: number) => {
  // Current AES-SIV/GCM-SIV callers pass protocol limits from RFC 8452 / RFC 5297,
  // not arbitrary library-preference bounds.
  // Callers feed Uint8Array.length values here, so safe-integer rejection
  // does not exclude any representable input even when an RFC bound is larger.
  if (!Number.isSafeInteger(value) || min > value || value > max) {
    const minmax = '[' + min + '..' + max + ']';
    throw new Error('' + name + ': expected value in range ' + minmax + ', got ' + value);
  }
};

/**
 * **SIV** (Synthetic IV): GCM with nonce-misuse resistance.
 * Repeating nonces reveal only the fact plaintexts are identical.
 * Also suffers from GCM issues: key wear-out limits & MAC forging.
 * See {@link https://www.rfc-editor.org/rfc/rfc8452 | RFC 8452}.
 * RFC 8452 defines 16-byte and 32-byte AES keys for this mode.
 * This implementation also accepts 24-byte AES-192 keys as a local
 * extension; see the inline comment next to `validateKeyLength(key)` below
 * for the exact scope note.
 * @param key - AES key bytes.
 * @param nonce - 12-byte nonce.
 * @param AAD - Additional authenticated data.
 * @returns AEAD cipher instance.
 * @example
 * Encrypts and authenticates plaintext with a fresh key and nonce, while tolerating reuse.
 *
 * ```ts
 * import { gcmsiv } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const nonce = randomBytes(12);
 * const cipher = gcmsiv(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const gcmsiv: TRet<
  ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>) => Cipher) & {
    blockSize: number;
    nonceLength: number;
    tagLength: number;
    varSizeNonce: true;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16, nonceLength: 12, tagLength: 16, varSizeNonce: true },
  function aessiv(
    key: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    AAD?: TArg<Uint8Array>
  ): TRet<Cipher> {
    const tagLength = 16;
    // From RFC 8452: Section 6
    const AAD_LIMIT = limit('AAD', 0, 2 ** 36);
    const PLAIN_LIMIT = limit('plaintext', 0, 2 ** 36);
    const NONCE_LIMIT = limit('nonce', 12, 12);
    const CIPHER_LIMIT = limit('ciphertext', 16, 2 ** 36 + 16);
    abytes(key);
    // RFC 8452 only standardizes 16-byte and 32-byte key-generating keys.
    // The accepted 24-byte path is a local AES-192 extension outside the RFC-defined AEADs.
    validateKeyLength(key);
    NONCE_LIMIT(nonce.length);
    if (AAD !== undefined) AAD_LIMIT(AAD.length);
    function deriveKeys() {
      const xk = expandKeyLE(key);
      const encKey = new Uint8Array(key.length);
      const authKey = new Uint8Array(16);
      const toClean: (Uint8Array | Uint32Array)[] = [xk, encKey];
      let _nonce = nonce;
      // Copy on BE or misaligned nonce so u32()/swap32IfBE() normalization
      // never mutates caller nonce bytes before RFC 8452 key derivation.
      if (!isLE || !isAligned32(_nonce)) toClean.push((_nonce = copyBytes(_nonce)));
      const n32 = u32(_nonce);
      swap32IfBE(n32);
      // prettier-ignore
      let s0 = 0, s1 = n32[0], s2 = n32[1], s3 = n32[2];
      let counter = 0;
      for (const derivedKey of [authKey, encKey].map(u32)) {
        const d32 = u32(derivedKey);
        for (let i = 0; i < d32.length; i += 2) {
          // aes(u32le(0) || nonce)[:8] || aes(u32le(1) || nonce)[:8] ...
          const { s0: o0, s1: o1 } = encrypt(xk, s0, s1, s2, s3);
          d32[i + 0] = o0;
          d32[i + 1] = o1;
          s0 = ++counter; // increment counter inside state
        }
        swap32IfBE(d32);
      }
      const res = { authKey, encKey: expandKeyLE(encKey) };
      // Cleanup
      clean(...toClean);
      return res;
    }
    function _computeTag(
      encKey: TArg<Uint32Array>,
      authKey: TArg<Uint8Array>,
      data: TArg<Uint8Array>
    ): TRet<Uint8Array> {
      const tag = computeTag(polyval, true, authKey, data, AAD);
      // Compute the expected tag by XORing S_s and the nonce, clearing the
      // most significant bit of the last byte and encrypting with the
      // message-encryption key.
      for (let i = 0; i < 12; i++) tag[i] ^= nonce[i];
      tag[15] &= 0x7f; // Clear the highest bit
      // encrypt tag as block
      const t32 = u32(tag);
      swap32IfBE(t32);
      // prettier-ignore
      let s0 = t32[0], s1 = t32[1], s2 = t32[2], s3 = t32[3];
      ({ s0, s1, s2, s3 } = encrypt(encKey, s0, s1, s2, s3));
      ((t32[0] = s0), (t32[1] = s1), (t32[2] = s2), (t32[3] = s3));
      swap32IfBE(t32);
      return tag;
    }
    // actual decrypt/encrypt of message.
    function processSiv(
      encKey: TArg<Uint32Array>,
      tag: TArg<Uint8Array>,
      input: TArg<Uint8Array>
    ): TRet<Uint8Array> {
      let block = copyBytes(tag);
      // RFC 8452 §4 / §5 use the tag with the highest bit of the last byte
      // forced to one as the initial AES-CTR counter block.
      block[15] |= 0x80; // Force highest bit
      const res = ctr32(encKey, true, block, input);
      // Cleanup
      clean(block);
      return res;
    }
    return {
      encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        PLAIN_LIMIT(plaintext.length);
        const { encKey, authKey } = deriveKeys();
        const tag = _computeTag(encKey, authKey, plaintext);
        const toClean: (Uint8Array | Uint32Array)[] = [encKey, authKey, tag];
        if (!isAligned32(plaintext)) toClean.push((plaintext = copyBytes(plaintext)));
        const out = new Uint8Array(plaintext.length + tagLength);
        out.set(tag, plaintext.length);
        out.set(processSiv(encKey, tag, plaintext));
        // Cleanup
        clean(...toClean);
        return out as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        CIPHER_LIMIT(ciphertext.length);
        const tag = ciphertext.subarray(-tagLength);
        const { encKey, authKey } = deriveKeys();
        const toClean: (Uint8Array | Uint32Array)[] = [encKey, authKey];
        if (!isAligned32(ciphertext)) toClean.push((ciphertext = copyBytes(ciphertext)));
        const plaintext = processSiv(encKey, tag, ciphertext.subarray(0, -tagLength));
        const expectedTag = _computeTag(encKey, authKey, plaintext);
        toClean.push(expectedTag);
        // RFC 8452 §5: plaintext is unauthenticated here and MUST NOT be
        // returned until the expected-tag check completes successfully.
        if (!equalBytes(tag, expectedTag)) {
          clean(...toClean);
          throw new Error('invalid polyval tag');
        }
        // Cleanup
        clean(...toClean);
        return plaintext as TRet<Uint8Array>;
      },
    } as TRet<Cipher>;
  }
);

function isBytes32(a: unknown): a is Uint32Array {
  // Plain `instanceof Uint32Array` is too strict for cross-realm expanded-key views.
  // This is only a best-effort unsafe-export guard, not a provenance proof for `expandKeyLE`.
  return (
    a instanceof Uint32Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint32Array')
  );
}

// Unsafe single-block helpers: mutate `block` in place and require its 16-byte
// Uint8Array view to be 4-byte aligned because `u32(block)` reinterprets it.
function encryptBlock(xk: TArg<Uint32Array>, block: TArg<Uint8Array>): TRet<Uint8Array> {
  abytes(block, 16, 'block');
  if (!isBytes32(xk)) throw new Error('_encryptBlock accepts result of expandKeyLE');
  const b32 = u32(block);
  swap32IfBE(b32);
  let { s0, s1, s2, s3 } = encrypt(xk, b32[0], b32[1], b32[2], b32[3]);
  ((b32[0] = s0), (b32[1] = s1), (b32[2] = s2), (b32[3] = s3));
  swap32IfBE(b32);
  return block as TRet<Uint8Array>;
}

function decryptBlock(xk: TArg<Uint32Array>, block: TArg<Uint8Array>): TRet<Uint8Array> {
  abytes(block, 16, 'block');
  if (!isBytes32(xk)) throw new Error('_decryptBlock accepts result of expandKeyLE');
  const b32 = u32(block);
  swap32IfBE(b32);
  let { s0, s1, s2, s3 } = decrypt(xk, b32[0], b32[1], b32[2], b32[3]);
  ((b32[0] = s0), (b32[1] = s1), (b32[2] = s2), (b32[3] = s3));
  swap32IfBE(b32);
  return block as TRet<Uint8Array>;
}

/**
 * AES-W (base for AESKW/AESKWP).
 * Specs:
 * {@link https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf | SP800-38F},
 * {@link https://www.rfc-editor.org/rfc/rfc3394 | RFC 3394},
 * {@link https://www.rfc-editor.org/rfc/rfc5649 | RFC 5649}.
 * Shared core mutates `out` in place; callers are responsible for prepending
 * the right IV/AIV and checking the recovered value after decrypt.
 */
const AESW = {
  /*
  High-level pseudocode:
  ```
  A: u64 = IV
  out = []
  for (let i=0, ctr = 0; i<6; i++) {
    for (const chunk of chunks(plaintext, 8)) {
      A ^= swapEndianess(ctr++)
      [A, res] = chunks(encrypt(A || chunk), 8);
      out ||= res
    }
  }
  out = A || out
  ```
  Decrypt is the same, but reversed.
  */
  encrypt(kek: TArg<Uint8Array>, out: TArg<Uint8Array>) {
    // Current implementation keeps RFC 3394/5649 `t` in a u32-shaped counter,
    // so the shared core caps plaintext below 4 GiB even though the specs allow more.
    if (out.length >= 2 ** 32) throw new Error('plaintext should be less than 4gb');
    const xk = expandKeyLE(kek);
    // 16-byte `S = A || P[1]` is the RFC 5649 KWP special case for n=1;
    // KW callers never reach it because KW requires at least two plaintext semiblocks.
    if (out.length === 16) encryptBlock(xk, out);
    else {
      const o32 = u32(out);
      swap32IfBE(o32);
      // prettier-ignore
      let a0 = o32[0], a1 = o32[1]; // A
      for (let j = 0, ctr = 1; j < 6; j++) {
        for (let pos = 2; pos < o32.length; pos += 2, ctr++) {
          const { s0, s1, s2, s3 } = encrypt(xk, a0, a1, o32[pos], o32[pos + 1]);
          // A = MSB(64, B) ^ t where t = (n*j)+i. Under the 32-bit length cap
          // above, `t` fits in the low half of `[t]_64`, so xor only the low
          // 32 bits of A after converting `ctr` to network order.
          ((a0 = s0), (a1 = s1 ^ byteSwap(ctr)), (o32[pos] = s2), (o32[pos + 1] = s3));
        }
      }
      ((o32[0] = a0), (o32[1] = a1)); // out = A || out
      swap32IfBE(o32);
    }
    xk.fill(0);
  },
  decrypt(kek: TArg<Uint8Array>, out: TArg<Uint8Array>) {
    // Same implementation cap on the recovered plaintext length after
    // removing the 8-byte A/IV prefix.
    if (out.length - 8 >= 2 ** 32) throw new Error('ciphertext should be less than 4gb');
    const xk = expandKeyDecLE(kek);
    const chunks = out.length / 8 - 1; // first chunk is IV
    // `n = 2` semiblocks is the RFC 5649 KWP special case; KW ciphertexts
    // always have at least three semiblocks and therefore use the W^-1 loop.
    if (chunks === 1) decryptBlock(xk, out);
    else {
      const o32 = u32(out);
      swap32IfBE(o32);
      // prettier-ignore
      let a0 = o32[0], a1 = o32[1]; // A
      for (let j = 0, ctr = chunks * 6; j < 6; j++) {
        for (let pos = chunks * 2; pos >= 1; pos -= 2, ctr--) {
          a1 ^= byteSwap(ctr);
          const { s0, s1, s2, s3 } = decrypt(xk, a0, a1, o32[pos], o32[pos + 1]);
          ((a0 = s0), (a1 = s1), (o32[pos] = s2), (o32[pos + 1] = s3));
        }
      }
      ((o32[0] = a0), (o32[1] = a1));
      swap32IfBE(o32);
    }
    xk.fill(0);
  },
};

// RFC 3394 §2.2.3.1 / NIST SP 800-38F Algorithm 3 / Algorithm 4: KW prepends
// the default 64-bit ICV1 and unwrap must verify the same value.
const AESKW_IV = /* @__PURE__ */ new Uint8Array(8).fill(0xa6); // A6A6A6A6A6A6A6A6

/**
 * AES-KW (key-wrap). Injects static IV into plaintext, adds counter, encrypts 6 times.
 * Reduces block size from 16 to 8 bytes.
 * Plaintext must be a non-empty multiple of 8 bytes with minimum 16 bytes.
 * 8-byte inputs use aeskwp.
 * Wrapped ciphertext must be a multiple of 8 bytes with minimum 24 bytes.
 * For padded version, use aeskwp.
 * See {@link https://www.rfc-editor.org/rfc/rfc3394/ | RFC 3394} and
 * {@link https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf | NIST SP 800-38F}.
 * @param kek - AES key-encryption key.
 * @returns Key-wrap cipher instance.
 * As with other `wrapCipher(...)` wrappers, `encrypt()` is single-use per
 * instance.
 * @example
 * Wraps a 128-bit content-encryption key with a fresh key-encryption key.
 *
 * ```ts
 * import { aeskw } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const kek = randomBytes(16);
 * const cek = randomBytes(16);
 * const wrap = aeskw(kek);
 * wrap.encrypt(cek);
 * ```
 */
export const aeskw: TRet<
  ((kek: TArg<Uint8Array>) => Cipher) & {
    blockSize: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 8 },
  (kek: TArg<Uint8Array>): TRet<Cipher> =>
    ({
      encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        if (!plaintext.length || plaintext.length % 8 !== 0)
          throw new Error('invalid plaintext length');
        // RFC 3394 / NIST SP 800-38F define KW only for >=2 plaintext
        // semiblocks; the 1-semiblock case belongs to RFC 5649 KWP.
        if (plaintext.length === 8)
          throw new Error('8-byte keys not allowed in AESKW, use AESKWP instead');
        const out = concatBytes(AESKW_IV, plaintext);
        AESW.encrypt(kek, out);
        return out;
      },
      decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        // ciphertext must be at least 24 bytes and a multiple of 8 bytes
        // 24 because should have at least two block (1 iv + 2).
        // Replace with 16 to enable '8-byte keys'
        if (ciphertext.length % 8 !== 0 || ciphertext.length < 3 * 8)
          throw new Error('invalid ciphertext length');
        // AESW.decrypt() mutates its buffer in place, so keep caller ciphertext
        // immutable across the unwrap, ICV1 check, and IV scrubbing below.
        const out = copyBytes(ciphertext);
        AESW.decrypt(kek, out);
        if (!equalBytes(out.subarray(0, 8), AESKW_IV)) throw new Error('integrity check failed');
        out.subarray(0, 8).fill(0); // ciphertext.subarray(0, 8) === IV, but we clean it anyway
        return out.subarray(8) as TRet<Uint8Array>;
      },
    }) as TRet<Cipher>
);

/*
We don't support 8-byte keys. The rabbit hole:

- Wycheproof says: "NIST SP 800-38F does not define the wrapping of 8 byte keys.
  RFC 3394 Section 2  on the other hand specifies that 8 byte keys are wrapped
  by directly encrypting one block with AES."
    - {@link https://github.com/C2SP/wycheproof/blob/master/doc/key_wrap.md | Wycheproof key-wrap note}
    - "RFC 3394 specifies in Section 2, that the input for the key wrap
      algorithm must be at least two blocks and otherwise the constant
      field and key are simply encrypted with ECB as a single block"
- What RFC 3394 actually says (in Section 2):
    - "Before being wrapped, the key data is parsed into n blocks of 64 bits.
      The only restriction the key wrap algorithm places on n is that n be
      at least two"
    - "For key data with length less than or equal to 64 bits, the constant
      field used in this specification and the key data form a single
      128-bit codebook input making this key wrap unnecessary."
- Which means "assert(n >= 2)" and "use something else for 8 byte keys"
- NIST SP800-38F actually prohibits 8-byte in "5.3.1 Mandatory Limits".
  It states that plaintext for KW should be "2 to 2^54 -1 semiblocks".
- So, where does "directly encrypt single block with AES" come from?
    - Not RFC 3394. Pseudocode of key wrap in 2.2 explicitly uses
      loop of 6 for any code path
    - There is a weird W3C spec:
      {@link https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#kw-aes128 | XML Encryption AES key-wrap section}
    - This spec is outdated, as admitted by Wycheproof authors
    - There is RFC 5649 for padded key wrap, which is padding construction on
      top of AESKW. In '4.1.2' it says: "If the padded plaintext contains exactly
      eight octets, then prepend the AIV as defined in Section 3 above to P[1] and
      encrypt the resulting 128-bit block using AES in ECB mode [Modes] with key
      K (the KEK).  In this case, the output is two 64-bit blocks C[0] and C[1]:"
    - Browser subtle crypto is actually crashes on wrapping keys less than 16 bytes:
      `Error: error:1C8000E6:Provider routines::invalid input length]
       { opensslErrorStack: [ 'error:030000BD:digital envelope routines::update error' ]`

In the end, seems like a bug in Wycheproof.
The 8-byte check can be easily disabled inside of AES_W.
*/

// RFC 5649 §3 / NIST SP 800-38F Algorithm 5 / Algorithm 6: KWP uses ICV2 as
// the high 32 bits of the AIV; the low 32 bits carry the MLI in network order.
const AESKWP_IV = 0xa65959a6; // single u32le value

/**
 * AES-KW, but with padding and allows random keys.
 * Uses the RFC 5649 alternative initial value; the second u32 stores the
 * 32-bit MLI in network order.
 * Wrapped ciphertext must be at least 16 bytes; malformed lengths are
 * rejected during AIV/padding checks.
 * See {@link https://www.rfc-editor.org/rfc/rfc5649 | RFC 5649}.
 * @param kek - AES key-encryption key.
 * @returns Padded key-wrap cipher instance.
 * @example
 * Wraps a short key blob using the padded variant and a fresh key-encryption key.
 *
 * ```ts
 * import { aeskwp } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const kek = randomBytes(16);
 * const wrap = aeskwp(kek);
 * wrap.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const aeskwp: TRet<
  ((kek: TArg<Uint8Array>) => Cipher) & {
    blockSize: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 8 },
  (kek: TArg<Uint8Array>): TRet<Cipher> =>
    ({
      encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        if (!plaintext.length) throw new Error('invalid plaintext length');
        const padded = Math.ceil(plaintext.length / 8) * 8;
        const out = new Uint8Array(8 + padded);
        out.set(plaintext, 8);
        const out32 = u32(out);
        out32[0] = swap8IfBE(AESKWP_IV);
        // RFC 5649 §3: the low 32 bits of the AIV carry the octet-length MLI in
        // network order, even though this buffer is addressed through LE u32s.
        out32[1] = swap8IfBE(byteSwap(plaintext.length));
        AESW.encrypt(kek, out);
        return out as TRet<Uint8Array>;
      },
      decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        // 16 because should have at least one block
        if (ciphertext.length < 16) throw new Error('invalid ciphertext length');
        // AESW.decrypt() mutates its buffer in place, so keep caller ciphertext
        // immutable across the unwrap, AIV checks, and IV scrubbing below.
        const out = copyBytes(ciphertext);
        const o32 = u32(out);
        AESW.decrypt(kek, out);
        const len = byteSwap(swap8IfBE(o32[1])) >>> 0;
        const padded = Math.ceil(len / 8) * 8;
        if (swap8IfBE(o32[0]) !== AESKWP_IV || out.length - 8 !== padded)
          throw new Error('integrity check failed');
        // RFC 5649 §3 / NIST SP 800-38F Algorithm 6: recovered padding length
        // must be in [0,7], and every recovered pad octet must be zero.
        for (let i = len; i < padded; i++)
          if (out[8 + i] !== 0) throw new Error('integrity check failed');
        out.subarray(0, 8).fill(0); // ciphertext.subarray(0, 8) === IV, but we clean it anyway
        return out.subarray(8, 8 + len) as TRet<Uint8Array>;
      },
    }) as TRet<Cipher>
);

class _AesCtrDRBG implements PRG {
  readonly blockLen: number;
  private key: TRet<Uint8Array>;
  private nonce: TRet<Uint8Array>;
  private state: TRet<Uint8Array>;
  private reseedCnt: number;
  constructor(keyLen: number, seed: TArg<Uint8Array>, personalization?: TArg<Uint8Array>) {
    this.blockLen = ctr.blockSize;
    const keyLenBytes = keyLen / 8;
    const nonceLen = 16;
    // Store the full seedlen state as key || V so CTR_DRBG_Update-style steps
    // can rewrite the entire internal state in place.
    this.state = new Uint8Array(keyLenBytes + nonceLen) as TRet<Uint8Array>;
    this.key = this.state.subarray(0, keyLenBytes) as TRet<Uint8Array>;
    this.nonce = this.state.subarray(keyLenBytes, keyLenBytes + nonceLen) as TRet<Uint8Array>;
    this.reseedCnt = 1;
    // Keep the stored counter one step ahead of SP 800-90A's formal V so
    // ctr(key, nonce) uses the next counter block directly.
    incBytes(this.nonce, false, 1);
    this.addEntropy(seed, personalization);
  }
  private update(data?: TArg<Uint8Array>) {
    // cannot re-use state here, because we will wipe current key
    ctr(this.key, this.nonce).encrypt(new Uint8Array(this.state.length), this.state);
    if (data) {
      abytes(data);
      // CTR_DRBG without a derivation function pads shorter additional_input
      // with zeros to seedlen, so XOR only the provided prefix here.
      for (let i = 0; i < data.length; i++) this.state[i] ^= data[i];
    }
    // Keep storing V+1 so the next ctr(key, nonce) call starts from the
    // spec's post-update counter state.
    incBytes(this.nonce, false, 1);
  }
  // Optional `info` is additional input XORed into the reseed block and is
  // limited to the internal state width.
  addEntropy(seed: TArg<Uint8Array>, info?: TArg<Uint8Array>): void {
    abytes(seed, this.state.length, 'seed');
    // Copy caller entropy before XORing in personalization/additional input,
    // then wipe the mixed seed material after CTR_DRBG_Update consumes it.
    const _seed = seed.slice();
    if (info) {
      abytes(info);
      if (info.length > _seed.length) throw new Error('info length is too big');
      for (let i = 0; i < info.length; i++) _seed[i] ^= info[i];
    }
    this.update(_seed);
    _seed.fill(0);
    this.reseedCnt = 1;
  }
  // Optional `info` is additional input for the pre/post-update steps; bytes
  // SP 800-90A Rev. 1 CTR_DRBG without a derivation function limits
  // additional_input to seedlen, which is exactly this internal state width.
  randomBytes(len: number, info?: TArg<Uint8Array>): TRet<Uint8Array> {
    anumber(len);
    // SP 800-90A Table 3 caps AES CTR_DRBG requests at 2^16 bits = 65536 bytes.
    if (len > 2 ** 16) throw new Error('requested output is too big');
    // The spec allows generate while reseed_counter == reseed_interval and increments afterwards.
    if (this.reseedCnt > 2 ** 48) throw new Error('entropy exhausted');
    if (info) {
      abytes(info);
      if (info.length > this.state.length) throw new Error('info length is too big');
      this.update(info);
    }
    const res = new Uint8Array(len);
    ctr(this.key, this.nonce).encrypt(res, res);
    incBytes(this.nonce, false, Math.ceil(len / this.blockLen));
    this.update(info);
    this.reseedCnt++;
    return res as TRet<Uint8Array>;
  }
  // Zeroes the current state and resets the counter, but does not make the
  // instance unusable: later calls continue from the zeroed state.
  clean(): void {
    // `key` and `nonce` alias this backing buffer, so one fill wipes the full
    // secret state in place.
    this.state.fill(0);
    this.reseedCnt = 0;
  }
}

/**
 * Factory for AES-CTR DRBG instances.
 * @param seed - Initial entropy input.
 * @param personalization - Optional personalization string mixed into the state.
 * @returns Seeded AES-CTR DRBG instance.
 */
export type AesCtrDrbg = (
  seed: TArg<Uint8Array>,
  personalization?: TArg<Uint8Array>
) => TRet<_AesCtrDRBG>;

// Internal helper for the exported 128-bit and 256-bit aliases; other key
// lengths are not validated here.
const createAesDrbg: (keyLen: number) => TRet<AesCtrDrbg> = (keyLen) => {
  return (seed, personalization = undefined) =>
    new _AesCtrDRBG(keyLen, seed, personalization) as TRet<_AesCtrDRBG>;
};

/**
 * AES-CTR DRBG 128-bit - CSPRNG (cryptographically secure pseudorandom number generator).
 * It's best to limit usage to non-production, non-critical cases: for example, test-only.
 * @param seed - Initial 32-byte entropy input.
 * @param personalization - Optional personalization string.
 * @returns Seeded DRBG instance. The concrete methods also accept optional additional-input bytes.
 * @example
 * Seeds the test-only AES-CTR DRBG from fresh entropy and reads bytes from it.
 *
 * ```ts
 * import { rngAesCtrDrbg128 } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const seed = randomBytes(32);
 * const prg = rngAesCtrDrbg128(seed);
 * prg.randomBytes(8);
 * ```
 */
export const rngAesCtrDrbg128: TRet<AesCtrDrbg> = /* @__PURE__ */ createAesDrbg(128);
/**
 * AES-CTR DRBG 256-bit - CSPRNG (cryptographically secure pseudorandom number generator).
 * It's best to limit usage to non-production, non-critical cases: for example, test-only.
 * @param seed - Initial 48-byte entropy input.
 * @param personalization - Optional personalization string.
 * @returns Seeded DRBG instance. The concrete methods also accept optional additional-input bytes.
 * @example
 * Seeds the test-only AES-CTR DRBG from fresh entropy and reads bytes from it.
 *
 * ```ts
 * import { rngAesCtrDrbg256 } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const seed = randomBytes(48);
 * const prg = rngAesCtrDrbg256(seed);
 * prg.randomBytes(8);
 * ```
 */
export const rngAesCtrDrbg256: TRet<AesCtrDrbg> = /* @__PURE__ */ createAesDrbg(256);

//#region CMAC

/**
 * Left-shift by one bit and conditionally XOR with 0x87:
 * ```
 * if MSB(L) is equal to 0
 * then    K1 := L << 1;
 * else    K1 := (L << 1) XOR const_Rb;
 * ```
 *
 * Specs:
 * {@link https://www.rfc-editor.org/rfc/rfc4493.html#section-2.3 | RFC 4493 Section 2.3},
 * {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.3 | RFC 5297 Section 2.3}
 *
 * @returns modified `block` (for chaining)
 */
function dbl<T extends Uint8Array>(block: T): T {
  let carry = 0;

  // Left shift by 1 bit
  for (let i = BLOCK_SIZE - 1; i >= 0; i--) {
    const newCarry = (block[i] & 0x80) >>> 7;
    block[i] = (block[i] << 1) | carry;
    carry = newCarry;
  }

  // XOR with 0x87 if there was a carry from the most significant bit
  if (carry) {
    // RFC 4493 §2.3 / RFC 5297 §2.1: 0x87 is const_Rb for doubling in the
    // CMAC/S2V finite field with primitive polynomial x^128 + x^7 + x^2 + x + 1.
    block[BLOCK_SIZE - 1] ^= 0x87;
  }

  return block;
}

/**
 * `a XOR b`, running in-place on `a`.
 * @param a left operand and output
 * @param b right operand
 * @returns `a` (for chaining)
 */
function xorBlock<T extends TArg<Uint8Array>>(a: T, b: TArg<Uint8Array>): T {
  if (a.length !== b.length) throw new Error('xorBlock: blocks must have same length');
  for (let i = 0; i < a.length; i++) {
    a[i] = a[i] ^ b[i];
  }
  return a;
}

/**
 * xorend as defined in
 * {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.1 | RFC 5297 Section 2.1}.
 *
 * ```
 * leftmost(A, len(A)-len(B)) || (rightmost(A, len(B)) xor B)
 * ```
 *
 * Mutates `a` in place so the left prefix stays untouched and only the
 * rightmost `len(B)` bytes are xored with `b`.
 */
function xorend<T extends TArg<Uint8Array>>(a: T, b: TArg<Uint8Array>): T {
  if (b.length > a.length) {
    throw new Error('xorend: len(B) must be less than or equal to len(A)');
  }
  // keep leftmost part of `a` unchanged
  // and xor only the rightmost part:
  const offset = a.length - b.length;
  for (let i = 0; i < b.length; i++) {
    a[offset + i] = a[offset + i] ^ b[i];
  }
  return a;
}

/**
 * Internal CMAC class.
 */
class _CMAC implements IHash2 {
  readonly blockLen: number = BLOCK_SIZE;
  readonly outputLen: number = BLOCK_SIZE;
  // CMAC can only decide between `K1` and `K2` once the true final block is known,
  // so updates process older blocks eagerly but keep one pending block buffered.
  private buffer: Uint8Array;
  private pos: number;
  private finished: boolean;
  private destroyed: boolean;
  private k1: Uint8Array;
  private k2: Uint8Array;
  private x: Uint8Array;
  private xk: Uint32Array;

  constructor(key: TArg<Uint8Array>) {
    abytes(key);
    validateKeyLength(key);
    this.xk = expandKeyLE(key);
    this.buffer = new Uint8Array(BLOCK_SIZE);
    this.pos = 0;
    this.finished = false;
    this.destroyed = false;
    this.x = new Uint8Array(BLOCK_SIZE);
    // L = AES_encrypt(K, const_Zero)
    const L = new Uint8Array(BLOCK_SIZE);
    encryptBlock(this.xk, L);
    // Generate subkeys K1 and K2 from the main key according to
    // {@link https://www.rfc-editor.org/rfc/rfc4493.html#section-2.3 | RFC 4493 Section 2.3}
    // K1
    this.k1 = dbl(L);
    this.k2 = dbl(new Uint8Array(this.k1));
  }

  private process(data: TArg<Uint8Array>): void {
    // RFC 4493 §2.4 step 6 loop body: Y := X XOR M_i; X := AES-128(K, Y).
    xorBlock(this.x, data);
    encryptBlock(this.xk, this.x);
  }

  update(data: TArg<Uint8Array>): this {
    if (this.destroyed) throw new Error('Hash instance has been destroyed');
    if (this.finished) throw new Error('Hash#digest() has already been called');
    abytes(data);
    let pos = 0;
    if (this.pos) {
      const take = Math.min(BLOCK_SIZE - this.pos, data.length);
      this.buffer.set(data.subarray(0, take), this.pos);
      this.pos += take;
      pos = take;
      if (this.pos === BLOCK_SIZE && pos < data.length) {
        this.process(this.buffer);
        this.pos = 0;
      }
    }
    // Keep one complete block buffered: an exact 16-byte tail may still be
    // M_n, and digestInto() must decide there whether RFC 4493 uses K1 or K2.
    while (pos + BLOCK_SIZE < data.length) {
      this.process(data.subarray(pos, pos + BLOCK_SIZE));
      pos += BLOCK_SIZE;
    }
    if (pos < data.length) {
      this.buffer.set(data.subarray(pos), 0);
      this.pos = data.length - pos;
    }
    return this;
  }

  // See {@link https://www.rfc-editor.org/rfc/rfc4493.html#section-2.4 | RFC 4493 Section 2.4}.
  digestInto(out: TArg<Uint8Array>): void {
    if (this.destroyed) throw new Error('Hash instance has been destroyed');
    if (this.finished) throw new Error('Hash#digest() has already been called');
    // `digestInto(out)` is the no-allocation fast path, so AES block re-use below
    // requires a 32-bit-aligned caller buffer instead of hidden temp copies.
    aoutput(out, this, true);
    this.finished = true;
    // `digestInto()` accepts out.length >= outputLen, so only the first block stores the tag.
    const view = out.subarray(0, this.outputLen);
    let last = new Uint8Array(BLOCK_SIZE);
    if (this.pos === BLOCK_SIZE) {
      // M_last := M_n XOR K1;
      last.set(this.buffer);
      xorBlock(last, this.k1);
    } else {
      // M_last := padding(M_n) XOR K2;
      //
      // [...] padding(x) is the concatenation of x and a single '1',
      // followed by the minimum number of '0's, so that the total length is
      // equal to 128 bits.
      last.set(this.buffer.subarray(0, this.pos));
      last[this.pos] = 0x80; // single '1' bit
      xorBlock(last, this.k2);
    }
    view.set(this.x); // X := AES_CBC(K, M_1..M_{n-1})
    xorBlock(view, last); // Y := X XOR M_last
    encryptBlock(this.xk, view); // T := AES-128(K, Y)
    clean(last);
  }

  digest(): Uint8ArrayBuffer {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    // Copy out before destroy() wipes the internal digest buffer in place.
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }

  destroy(): void {
    const { buffer, destroyed, x, xk, k1, k2 } = this;
    if (destroyed) return;
    this.destroyed = true;
    // Wipe the buffered tail, chaining value, expanded AES key, and both CMAC subkeys.
    clean(buffer, x, xk, k1, k2);
  }
}

/**
 * AES-CMAC (Cipher-based Message Authentication Code).
 * Specs: {@link https://www.rfc-editor.org/rfc/rfc4493.html | RFC 4493}.
 * @param msg - Message bytes to authenticate.
 * @param key - AES key bytes.
 * @returns 16-byte authentication tag. `cmac.create(...)` follows the same incremental MAC shape as
 * the other keyed helpers in this repo, including `blockLen`,
 * `outputLen`, `digestInto()` and `destroy()`.
 * @example
 * Authenticates a message with AES-CMAC and a fresh key.
 *
 * ```ts
 * import { cmac } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * cmac(new Uint8Array(), key);
 * ```
 */
// The 16-byte probe key is only used to read static metadata; runtime CMAC
// still accepts AES-128/192/256 keys.
export const cmac: TRet<CMac<_CMAC>> = /* @__PURE__ */ wrapMacConstructor(
  16,
  (key: TArg<Uint8Array>) => new _CMAC(key)
);

/**
 * S2V (Synthetic Initialization Vector) function as described in
 * {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.4 | RFC 5297 Section 2.4}.
 *
 * ```
 * S2V(K, S1, ..., Sn) {
 *   if n = 0 then
 *     return V = AES-CMAC(K, <one>)
 *   fi
 *   D = AES-CMAC(K, <zero>)
 *   for i = 1 to n-1 do
 *     D = dbl(D) xor AES-CMAC(K, Si)
 *   done
 *   if len(Sn) >= 128 then
 *     T = Sn xorend D
 *   else
 *     T = dbl(D) xor pad(Sn)
 *   fi
 *   return V = AES-CMAC(K, T)
 * }
 * ```
 *
 * S2V takes a key and a vector of strings S1, S2, ..., Sn and returns a 128-bit string.
 * The S2V function is used to generate a synthetic IV for AES-SIV.
 *
 * @param key - AES key (128, 192, or 256 bits)
 * @param strings - Array of byte arrays to process
 * @returns 128-bit synthetic IV
 */
function s2v(key: TArg<Uint8Array>, strings: TArg<Uint8Array[]>): TRet<Uint8Array> {
  validateKeyLength(key);
  const len = strings.length;
  if (len > 127) {
    // RFC 5297 §7 only proves S2V secure for at most 127 components; SIV
    // spends one of those on the plaintext, leaving at most 126 AAD inputs.
    throw new Error('s2v: number of input strings must be less than or equal to 127');
  }

  if (len === 0) return cmac(ONE_BLOCK, key);

  // D = AES-CMAC(K, <zero>)
  let d = cmac(EMPTY_BLOCK, key);

  // for i = 1 to n-1 do
  //   D = dbl(D) xor AES-CMAC(K, Si)
  for (let i = 0; i < len - 1; i++) {
    dbl(d);
    const cmacResult = cmac(strings[i], key);
    xorBlock(d, cmacResult);
    clean(cmacResult);
  }

  const s_n = strings[len - 1];
  // Earlier components are validated through cmac(...); validate the final one explicitly because
  // the Uint8Array.from()/set() paths below would otherwise coerce array-like inputs silently.
  abytes(s_n);
  let t: Uint8Array;

  // if len(Sn) >= 128 then
  if (s_n.byteLength >= BLOCK_SIZE) {
    // T = Sn xorend D
    t = xorend(Uint8Array.from(s_n), d);
  } else {
    // pad(Sn):
    const paddedSn = new Uint8Array(BLOCK_SIZE);
    paddedSn.set(s_n);
    paddedSn[s_n.length] = 0x80; // padding: 0x80 followed by zeros

    // T = dbl(D) xor pad(Sn)
    t = xorBlock(dbl(d), paddedSn);
    clean(paddedSn);
  }

  // V = AES-CMAC(K, T)
  const result = cmac(t, key);
  clean(d, t);
  return result;
}

/**
 * Use `gcmsiv` or `aessiv`.
 * @returns Never; always throws with the migration hint.
 * @throws If called; `siv()` is a removed v1 alias. {@link Error}
 * @example
 * `siv()` was removed in v2; use `gcmsiv()` for nonce-based SIV instead.
 *
 * ```ts
 * import { gcmsiv } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const nonce = randomBytes(12);
 * const cipher = gcmsiv(key, nonce);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const siv: () => never = () => {
  throw new Error('"siv" from v1 is now "gcmsiv"');
};

/**
 * **SIV**: Synthetic Initialization Vector (SIV) Authenticated Encryption
 * Nonce is derived from the plaintext and AAD using the S2V function.
 * Supports at most 126 AAD components. RFC 5297 nonce-based use is expressed by
 * passing the nonce as the final AAD component before the plaintext.
 * See {@link https://datatracker.ietf.org/doc/html/rfc5297.html | RFC 5297}.
 * @param key - 32-byte, 48-byte, or 64-byte key.
 * @param AAD - Additional authenticated data chunks (up to 126).
 * @returns AEAD cipher instance.
 * @example
 * Authenticates and encrypts plaintext with a fresh key without requiring unique nonces.
 *
 * ```ts
 * import { aessiv } from '@noble/ciphers/aes.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(32);
 * const cipher = aessiv(key);
 * cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const aessiv: TRet<
  ((key: TArg<Uint8Array>, ...AAD: TArg<Uint8Array[]>) => Cipher) & {
    blockSize: number;
    tagLength: number;
  }
> = /* @__PURE__ */ wrapCipher(
  { blockSize: 16, tagLength: 16 },
  function aessiv(key: TArg<Uint8Array>, ...AAD: TArg<Uint8Array[]>): TRet<Cipher> {
    // From RFC 5297: Section 6.1, 6.2, 6.3:
    const PLAIN_LIMIT = limit('plaintext', 0, 2 ** 132);
    const CIPHER_LIMIT = limit('ciphertext', 16, 2 ** 132 + 16);
    if (AAD.length > 126) {
      // RFC 5297 §2.6 / §2.7 / §7: SIV passes the plaintext as the last S2V
      // component, so callers only get 126 associated-data components.
      throw new Error('"AAD" number of elements must be less than or equal to 126');
    }
    AAD.forEach((aad) => abytes(aad));
    abytes(key);
    if (![32, 48, 64].includes(key.length))
      throw new Error('"aes key" expected Uint8Array of length 32/48/64, got length=' + key.length);

    // The key is split into equal halves, K1 = leftmost(K, len(K)/2) and
    // K2 = rightmost(K, len(K)/2).  K1 is used for S2V and K2 is used for CTR.
    // This borrows caller key/AAD buffers by reference; mutating them after
    // construction changes future encrypt/decrypt results.
    const k1 = key.subarray(0, key.length / 2);
    const k2 = key.subarray(key.length / 2);

    return {
      // {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.6 | RFC 5297 Section 2.6}
      encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        PLAIN_LIMIT(plaintext.length);

        const v = s2v(k1, [...AAD, plaintext]);

        // clear out the 31st and 63rd (rightmost) bit:
        const q = Uint8Array.from(v);
        q[8] &= 0x7f;
        q[12] &= 0x7f;

        // encrypt:
        const c = ctr(k2, q).encrypt(plaintext);

        return concatBytes(v, c);
      },
      // {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.7 | RFC 5297 Section 2.7}
      decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        CIPHER_LIMIT(ciphertext.length);
        const v = ciphertext.subarray(0, BLOCK_SIZE);
        const c = ciphertext.subarray(BLOCK_SIZE);

        // clear out the 31st and 63rd (rightmost) bit:
        const q = Uint8Array.from(v);
        q[8] &= 0x7f;
        q[12] &= 0x7f;

        // decrypt:
        const p = ctr(k2, q).decrypt(c);

        // verify tag:
        const t = s2v(k1, [...AAD, p]);

        if (equalBytes(t, v)) {
          return p as TRet<Uint8Array>;
        } else {
          throw new Error('invalid siv tag');
        }
      },
    } as TRet<Cipher>;
  }
);
//#endregion

/**
 * Unsafe low-level internal methods. May change at any time.
 * Callers are expected to use reviewed expanded-key outputs, pass mutable and
 * aligned 16-byte blocks where required, and treat several helpers as in-place
 * mutations of their input buffers or counters.
 */
export const unsafe: {
  expandKeyLE: typeof expandKeyLE;
  expandKeyDecLE: typeof expandKeyDecLE;
  encrypt: typeof encrypt;
  decrypt: typeof decrypt;
  encryptBlock: typeof encryptBlock;
  decryptBlock: typeof decryptBlock;
  ctrCounter: typeof ctrCounter;
  ctr32: typeof ctr32;
  dbl: typeof dbl;
  xorBlock: typeof xorBlock;
  xorend: typeof xorend;
  s2v: typeof s2v;
} = /* @__PURE__ */ Object.freeze({
  expandKeyLE,
  expandKeyDecLE,
  encrypt,
  decrypt,
  encryptBlock,
  decryptBlock,
  ctrCounter,
  ctr32,
  dbl,
  xorBlock,
  xorend,
  s2v,
});

export const __TESTS: { incBytes: typeof incBytes } = /* @__PURE__ */ Object.freeze({
  incBytes: incBytes,
});
