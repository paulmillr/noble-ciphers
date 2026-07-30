/**
 * Micro (reference) versions of noble-ciphers algorithms: simple loops instead
 * of unrolling, bigint math instead of limbs. Roughly 4-6x slower than the
 * production cores in `src/`, but much smaller and easier to read - provided
 * for auditability. Extracted out of `src/` to keep production bundles small;
 * `arx.test.ts` checks they stay aligned with the optimized cores.
 *
 * Intentionally dependency-free: helpers from `src/_arx.ts` / `src/utils.ts`
 * are re-implemented here in their simplest (slower) form, so this file can
 * be audited standalone.
 * @module
 */

// Helpers (simple, slow re-implementations of src/ utilities) --------------

/** Rotate left over 32 bits. Same as `rotl` from `src/_arx.ts`. */
function rotl(a: number, b: number): number {
  return (a << b) | (a >>> (32 - b));
}

/** Minimal input validation; production code uses `abytes` from `src/utils.ts`. */
function abytes(b: Uint8Array, len?: number): void {
  if (!(b instanceof Uint8Array)) throw new Error('Uint8Array expected');
  if (len !== undefined && b.length !== len)
    throw new Error('Uint8Array of length ' + len + ' expected');
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let sum = 0;
  for (const a of arrays) sum += a.length;
  const res = new Uint8Array(sum);
  let pad = 0;
  for (const a of arrays) {
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let n = BigInt(0);
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << BigInt(8)) | BigInt(bytes[i]);
  return n;
}

function numberToBytesLE(n: bigint, len: number): Uint8Array {
  const res = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    res[i] = Number(n & BigInt(0xff));
    n >>= BigInt(8);
  }
  return res;
}

/** Bytes to 32-bit little-endian words. Endianness-explicit version of `u32` from `src/utils.ts`. */
function u32le(b: Uint8Array): Uint32Array {
  const out = new Uint32Array(b.length / 4);
  for (let i = 0; i < out.length; i++)
    out[i] = b[4 * i] | (b[4 * i + 1] << 8) | (b[4 * i + 2] << 16) | (b[4 * i + 3] << 24);
  return out;
}

/** 32-bit words to little-endian bytes. */
function u32ToBytesLE(w: Uint32Array): Uint8Array {
  const out = new Uint8Array(w.length * 4);
  for (let i = 0; i < w.length; i++) {
    out[4 * i] = w[i] & 0xff;
    out[4 * i + 1] = (w[i] >>> 8) & 0xff;
    out[4 * i + 2] = (w[i] >>> 16) & 0xff;
    out[4 * i + 3] = (w[i] >>> 24) & 0xff;
  }
  return out;
}

/** Tag comparison. Production uses `equalBytes` from `src/utils.ts`; same xor-accumulate shape. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** RFC 8439 §2.8 length block: LE64(AAD length) || LE64(ciphertext length). */
function u64Lengths(ciphertextLen: number, aadLen: number): Uint8Array {
  return concatBytes(numberToBytesLE(BigInt(aadLen), 8), numberToBytesLE(BigInt(ciphertextLen), 8));
}

/** "expand 32-byte k" sigma constant as LE words. Micro versions only support 32-byte keys. */
const SIGMA32 = Uint32Array.from([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

/**
 * XORs data with a 64-byte-block keystream produced by `core(counter, block)`.
 * Unlike `createCipher` from `src/_arx.ts`, this skips counter-overflow
 * checks, output buffers and non-32-byte-key support.
 */
function xorStream(
  data: Uint8Array,
  counter: number,
  core: (cnt: number, block: Uint32Array) => void
): Uint8Array {
  const out = new Uint8Array(data.length);
  const block = new Uint32Array(16);
  for (let pos = 0, cnt = counter; pos < data.length; pos += 64, cnt++) {
    core(cnt, block);
    const ks = u32ToBytesLE(block);
    const lim = Math.min(64, data.length - pos);
    for (let j = 0; j < lim; j++) out[pos + j] = data[pos + j] ^ ks[j];
  }
  return out;
}

// ChaCha ------------------------------------------------------------------

/** RFC 8439 §2.1 quarter round on words a, b, c, d. */
// prettier-ignore
function chachaQR(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 7);
}

/** Repeated ChaCha double rounds; callers are expected to pass an even round count. */
function chachaRound(x: Uint32Array, rounds = 20) {
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

/** Small version of chacha without loop unrolling. */
// prettier-ignore
export function chacha(
  s: Uint32Array, k: Uint32Array, i: Uint32Array, out: Uint32Array,
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
  const x = y.slice();
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

/** Identical to `chachaCore` from `src/chacha.ts` (compared in arx.test.ts). */
export const chachaCore_small = (
  s: Uint32Array,
  k: Uint32Array,
  n: Uint32Array,
  out: Uint32Array,
  cnt: number,
  rounds = 20
): void =>
  // Keep the reference wrapper on the same [counter, nonce0, nonce1, nonce2] layout as chacha().
  chacha(s, k, Uint32Array.from([cnt, n[0], n[1], n[2]]), out, false, rounds);
/** Identical to `hchacha` from `src/chacha.ts`, minus BE-host word normalization. */
export const hchacha_small: (
  s: Uint32Array,
  k: Uint32Array,
  i: Uint32Array,
  out: Uint32Array
) => void = chacha;

// Salsa -------------------------------------------------------------------

/** RFC 7914 §3 Salsa20/8 core quarter-round on words a, b, c, d. */
function salsaQR(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[b] ^= rotl((x[a] + x[d]) | 0, 7);
  x[c] ^= rotl((x[b] + x[a]) | 0, 9);
  x[d] ^= rotl((x[c] + x[b]) | 0, 13);
  x[a] ^= rotl((x[d] + x[c]) | 0, 18);
}

/** RFC 7914 §3 double-round schedule: four column rounds, then four row rounds. */
function salsaRound(x: Uint32Array, rounds = 20) {
  for (let r = 0; r < rounds; r += 2) {
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

/** Small version of salsa without loop unrolling. */
// prettier-ignore
export function salsa(
  s: Uint32Array, k: Uint32Array, i: Uint32Array, out: Uint32Array,
  isHSalsa: boolean = true, rounds: number = 20
): void {
  // Create initial array using common pattern
  const y = Uint32Array.from([
    s[0], k[0], k[1], k[2], // "expa" Key     Key     Key
    k[3], s[1], i[0], i[1], // Key    "nd 3"  Nonce   Nonce
    i[2], i[3], s[2], k[4], // Pos.   Pos.    "2-by"  Key
    k[5], k[6], k[7], s[3], // Key    Key     Key     "te k"
  ]);
  const x = y.slice();
  salsaRound(x, rounds);

  // hsalsa extracts 8 specific words for the 32-byte subkey; salsa adds the original state.
  if (isHSalsa) {
    const xindexes = [0, 5, 10, 15, 6, 7, 8, 9];
    for (let i = 0; i < 8; i++) out[i] = x[xindexes[i]];
  } else {
    for (let i = 0; i < 16; i++) out[i] = (y[i] + x[i]) | 0;
  }
}

/** Identical to `salsaCore` from `src/salsa.ts` (compared in arx.test.ts). */
export const salsaCore_small = (
  s: Uint32Array,
  k: Uint32Array,
  n: Uint32Array,
  out: Uint32Array,
  cnt: number,
  rounds = 20
): void => salsa(s, k, Uint32Array.from([n[0], n[1], cnt, 0]), out, false, rounds);
/** Identical to `hsalsa` from `src/salsa.ts`, minus BE-host word normalization. */
export const hsalsa_small: (
  s: Uint32Array,
  k: Uint32Array,
  i: Uint32Array,
  out: Uint32Array
) => void = salsa;

// Poly1305 ----------------------------------------------------------------

/** Small version of `poly1305` without loop unrolling, using bigint math. */
export function poly1305_small(msg: Uint8Array, key: Uint8Array): Uint8Array {
  abytes(msg);
  abytes(key, 32);
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
  return numberToBytesLE(res, 16);
}

/** Small version of `computeTag` from `src/chacha.ts`. */
export function poly1305_computeTag_small(
  authKey: Uint8Array,
  // AEAD trailer must already be the 16-byte length block:
  // 8-byte little-endian AAD length || 8-byte little-endian ciphertext length.
  lengths: Uint8Array,
  ciphertext: Uint8Array,
  AAD?: Uint8Array
): Uint8Array {
  // RFC 8439 §2.8.1 / RFC 7539 §2.8.1 MAC input is
  // AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || lengths.
  const res: Uint8Array[] = [];
  const updatePadded2 = (msg: Uint8Array) => {
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

// Stream ciphers ----------------------------------------------------------

/** RFC 8439 ChaCha20 stream: 32-byte key, 12-byte nonce, 32-bit counter. */
export function chacha20_small(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter = 0
): Uint8Array {
  abytes(key, 32);
  abytes(nonce, 12);
  const k = u32le(key);
  const n = u32le(nonce);
  return xorStream(data, counter, (cnt, block) =>
    chacha(SIGMA32, k, Uint32Array.from([cnt, n[0], n[1], n[2]]), block, false)
  );
}

/** XChaCha20: hchacha-derived subkey, then ChaCha with the last 8 nonce bytes. */
export function xchacha20_small(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter = 0
): Uint8Array {
  abytes(key, 32);
  abytes(nonce, 24);
  const n = u32le(nonce);
  const subkey = new Uint32Array(8);
  hchacha_small(SIGMA32, u32le(key), n.subarray(0, 4), subkey);
  // State words 12..15 = [counter, 0, nonce4, nonce5]: equivalent to IETF
  // ChaCha20 with nonce = 4 zero bytes || nonce[16..24].
  return xorStream(data, counter, (cnt, block) =>
    chacha(SIGMA32, subkey, Uint32Array.from([cnt, 0, n[4], n[5]]), block, false)
  );
}

/** Salsa20 stream: 32-byte key, 8-byte nonce, 32-bit counter. */
export function salsa20_small(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter = 0
): Uint8Array {
  abytes(key, 32);
  abytes(nonce, 8);
  const k = u32le(key);
  const n = u32le(nonce);
  return xorStream(data, counter, (cnt, block) =>
    salsa(SIGMA32, k, Uint32Array.from([n[0], n[1], cnt, 0]), block, false)
  );
}

/** XSalsa20: hsalsa-derived subkey, then Salsa with the last 8 nonce bytes. */
export function xsalsa20_small(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter = 0
): Uint8Array {
  abytes(key, 32);
  abytes(nonce, 24);
  const n = u32le(nonce);
  const subkey = new Uint32Array(8);
  hsalsa_small(SIGMA32, u32le(key), n.subarray(0, 4), subkey);
  return xorStream(data, counter, (cnt, block) =>
    salsa(SIGMA32, subkey, Uint32Array.from([n[4], n[5], cnt, 0]), block, false)
  );
}

// AEADs -------------------------------------------------------------------

export type MicroCipher = {
  encrypt: (plaintext: Uint8Array) => Uint8Array;
  decrypt: (ciphertext: Uint8Array) => Uint8Array;
};

type MicroXorStream = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter?: number
) => Uint8Array;

/**
 * RFC 8439 AEAD composition, small version of `_poly1305_aead` from
 * `src/chacha.ts`: block 0 makes the Poly1305 one-time key, payload starts at
 * block 1, tag is appended to ciphertext. Unlike production `wrapCipher`,
 * this skips input validation and encrypt-once enforcement.
 */
const _poly1305_aead_small =
  (stream: MicroXorStream) =>
  (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): MicroCipher => {
    const computeTag = (ciphertext: Uint8Array) => {
      const authKey = stream(key, nonce, new Uint8Array(32), 0);
      const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0);
      return poly1305_computeTag_small(authKey, lengths, ciphertext, AAD);
    };
    return {
      encrypt(plaintext: Uint8Array): Uint8Array {
        const ciphertext = stream(key, nonce, plaintext, 1);
        return concatBytes(ciphertext, computeTag(ciphertext));
      },
      decrypt(combined: Uint8Array): Uint8Array {
        const ciphertext = combined.subarray(0, -16);
        // RFC 8439 §2.8: authenticate the ciphertext before decrypting it.
        if (!equalBytes(combined.subarray(-16), computeTag(ciphertext)))
          throw new Error('invalid tag');
        return stream(key, nonce, ciphertext, 1);
      },
    };
  };

/** Identical to `chacha20poly1305` from `src/chacha.ts` (compared in arx.test.ts). */
export const chacha20poly1305_small: (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
) => MicroCipher = _poly1305_aead_small(chacha20_small);
/** Identical to `xchacha20poly1305` from `src/chacha.ts` (compared in arx.test.ts). */
export const xchacha20poly1305_small: (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
) => MicroCipher = _poly1305_aead_small(xchacha20_small);

/**
 * NaCl secretbox, small version of `xsalsa20poly1305` from `src/salsa.ts`:
 * the first 32 keystream bytes make the Poly1305 one-time key, the rest
 * encrypts the message, output is tag || ciphertext.
 */
export function xsalsa20poly1305_small(key: Uint8Array, nonce: Uint8Array): MicroCipher {
  abytes(key, 32);
  abytes(nonce, 24);
  return {
    encrypt(plaintext: Uint8Array): Uint8Array {
      // keystream ^ (zeros(32) || plaintext) = authKey || ciphertext
      const s = xsalsa20_small(key, nonce, concatBytes(new Uint8Array(32), plaintext));
      const authKey = s.subarray(0, 32);
      const ciphertext = s.subarray(32);
      return concatBytes(poly1305_small(ciphertext, authKey), ciphertext);
    },
    decrypt(combined: Uint8Array): Uint8Array {
      const passedTag = combined.subarray(0, 16);
      const ciphertext = combined.subarray(16);
      const authKey = xsalsa20_small(key, nonce, new Uint8Array(32));
      if (!equalBytes(passedTag, poly1305_small(ciphertext, authKey)))
        throw new Error('invalid tag');
      return xsalsa20_small(key, nonce, concatBytes(new Uint8Array(32), ciphertext)).subarray(32);
    },
  };
}
