/**
 * Micro (reference) version of AES with GCM, CBC and CTR modes: byte-oriented
 * FIPS 197 cipher with a computed S-box instead of T-tables, and bigint GF(2^128)
 * math for GHASH instead of limbs. Orders of magnitude slower than `src/aes.ts`,
 * but much smaller and easier to read - provided for auditability.
 * `aes.test.ts` checks the modes stay aligned with the production ones.
 *
 * Intentionally dependency-free, like `micro-ciphers.ts`: helpers from
 * `src/utils.ts` are re-implemented here in their simplest (slower) form,
 * so this file can be audited standalone.
 * @module
 */

// Helpers (simple, slow re-implementations of src/ utilities) --------------

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

/** Tag comparison. Production uses `equalBytes` from `src/utils.ts`; same xor-accumulate shape. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function bytesToNumberBE(bytes: Uint8Array): bigint {
  let n = BigInt(0);
  for (let i = 0; i < bytes.length; i++) n = (n << BigInt(8)) | BigInt(bytes[i]);
  return n;
}

function numberToBytesBE(n: bigint, len: number): Uint8Array {
  const res = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    res[i] = Number(n & BigInt(0xff));
    n >>= BigInt(8);
  }
  return res;
}

// AES block cipher (FIPS 197) ---------------------------------------------

/** Multiply by x (i.e. 2) in GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1. */
const xtime = (n: number) => ((n << 1) ^ ((n >> 7) * 0x1b)) & 0xff;

/** Multiply a*b in GF(2^8), bit by bit. Production uses T-tables instead. */
function mul(a: number, b: number): number {
  let res = 0;
  for (; b; b >>= 1) {
    if (b & 1) res ^= a;
    a = xtime(a);
  }
  return res;
}

// FIPS 197 §5.1.1 S-box, computed instead of hardcoded: walk all non-zero
// field elements as powers of the generator 3 (p) alongside their inverses
// (q = p^-1), then apply the affine transformation to the inverse.
const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
{
  const rotl8 = (n: number, b: number) => ((n << b) | (n >>> (8 - b))) & 0xff;
  let p = 1;
  let q = 1;
  do {
    p = (p ^ xtime(p)) & 0xff; // p *= 3
    // q /= 3, i.e. q *= 0xf6 (the inverse of 3)
    q = (q ^ (q << 1)) & 0xff;
    q = (q ^ (q << 2)) & 0xff;
    q = (q ^ (q << 4)) & 0xff;
    if (q & 0x80) q ^= 0x09;
    SBOX[p] = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63;
  } while (p !== 1);
  SBOX[0] = 0x63; // 0 has no inverse; affine transformation of 0
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
}

/** FIPS 197 §5.2 key expansion, byte-oriented. Key length 16/24/32 selects AES-128/192/256. */
function expandKey(key: Uint8Array): { rk: Uint8Array; rounds: number } {
  abytes(key);
  if (![16, 24, 32].includes(key.length)) throw new Error('aes: wrong key length ' + key.length);
  const Nk = key.length / 4;
  const rounds = Nk + 6;
  const rk = new Uint8Array(16 * (rounds + 1));
  rk.set(key);
  let rcon = 1;
  for (let i = key.length; i < rk.length; i += 4) {
    let [t0, t1, t2, t3] = rk.subarray(i - 4, i);
    if ((i / 4) % Nk === 0) {
      // RotWord, SubWord, xor Rcon
      [t0, t1, t2, t3] = [SBOX[t1] ^ rcon, SBOX[t2], SBOX[t3], SBOX[t0]];
      rcon = xtime(rcon);
    } else if (Nk > 6 && (i / 4) % Nk === 4) {
      // AES-256 extra SubWord
      [t0, t1, t2, t3] = [SBOX[t0], SBOX[t1], SBOX[t2], SBOX[t3]];
    }
    rk[i] = rk[i - 4 * Nk] ^ t0;
    rk[i + 1] = rk[i + 1 - 4 * Nk] ^ t1;
    rk[i + 2] = rk[i + 2 - 4 * Nk] ^ t2;
    rk[i + 3] = rk[i + 3 - 4 * Nk] ^ t3;
  }
  return { rk, rounds };
}

// FIPS 197 state is column-major: byte 4*c + r is row r of column c.
function addRoundKey(s: Uint8Array, rk: Uint8Array, off: number) {
  for (let i = 0; i < 16; i++) s[i] ^= rk[off + i];
}
function subBytes(s: Uint8Array, box: Uint8Array) {
  for (let i = 0; i < 16; i++) s[i] = box[s[i]];
}
/** FIPS 197 §5.1.2 / §5.3.1: row r rotates by r positions (left, or right when inv). */
function shiftRows(s: Uint8Array, inv: boolean) {
  const t = s.slice();
  for (let r = 1; r < 4; r++)
    for (let c = 0; c < 4; c++) s[4 * c + r] = t[4 * (((inv ? c - r : c + r) + 4) % 4) + r];
}
/** FIPS 197 §5.1.3 / §5.3.3: multiply each column by the circulant matrix m. */
function mixColumns(s: Uint8Array, m: number[]) {
  for (let c = 0; c < 4; c++) {
    const col = s.slice(4 * c, 4 * c + 4);
    for (let r = 0; r < 4; r++)
      s[4 * c + r] =
        mul(m[0], col[r]) ^
        mul(m[1], col[(r + 1) % 4]) ^
        mul(m[2], col[(r + 2) % 4]) ^
        mul(m[3], col[(r + 3) % 4]);
  }
}
const MIX = [2, 3, 1, 1];
const INV_MIX = [14, 11, 13, 9];

/** FIPS 197 §5.1 Cipher(). */
function encryptBlock(rk: Uint8Array, rounds: number, block: Uint8Array): Uint8Array {
  const s = block.slice();
  addRoundKey(s, rk, 0);
  for (let i = 1; i < rounds; i++) {
    subBytes(s, SBOX);
    shiftRows(s, false);
    mixColumns(s, MIX);
    addRoundKey(s, rk, 16 * i);
  }
  subBytes(s, SBOX);
  shiftRows(s, false);
  addRoundKey(s, rk, 16 * rounds);
  return s;
}
/** FIPS 197 §5.3 InvCipher(). Only CBC decryption needs it; CTR/GCM always encrypt. */
function decryptBlock(rk: Uint8Array, rounds: number, block: Uint8Array): Uint8Array {
  const s = block.slice();
  addRoundKey(s, rk, 16 * rounds);
  for (let i = rounds - 1; i >= 1; i--) {
    shiftRows(s, true);
    subBytes(s, INV_SBOX);
    addRoundKey(s, rk, 16 * i);
    mixColumns(s, INV_MIX);
  }
  shiftRows(s, true);
  subBytes(s, INV_SBOX);
  addRoundKey(s, rk, 0);
  return s;
}

// Modes -------------------------------------------------------------------

export type MicroCipher = {
  encrypt: (plaintext: Uint8Array) => Uint8Array;
  decrypt: (ciphertext: Uint8Array) => Uint8Array;
};

/**
 * CTR mode, identical to `ctr` from `src/aes.ts` (compared in aes.test.ts):
 * the full 16-byte nonce is the initial big-endian counter block.
 */
export function ctr_small(key: Uint8Array, nonce: Uint8Array): MicroCipher {
  abytes(nonce, 16);
  const { rk, rounds } = expandKey(key);
  const xor = (data: Uint8Array) => {
    const c = nonce.slice();
    const out = new Uint8Array(data.length);
    for (let pos = 0; pos < data.length; pos += 16) {
      const ks = encryptBlock(rk, rounds, c);
      const lim = Math.min(16, data.length - pos);
      for (let j = 0; j < lim; j++) out[pos + j] = data[pos + j] ^ ks[j];
      for (let i = 15; i >= 0; i--) {
        c[i] = (c[i] + 1) & 0xff;
        if (c[i]) break;
      }
    }
    return out;
  };
  return { encrypt: xor, decrypt: xor };
}

/**
 * CBC mode with PKCS#7 padding, identical to `cbc` from `src/aes.ts` with
 * default options (compared in aes.test.ts).
 */
export function cbc_small(key: Uint8Array, iv: Uint8Array): MicroCipher {
  abytes(iv, 16);
  const { rk, rounds } = expandKey(key);
  return {
    encrypt(plaintext: Uint8Array): Uint8Array {
      // PKCS#7: always append 1..16 bytes, each equal to the pad length.
      const padLen = 16 - (plaintext.length % 16);
      const padded = concatBytes(plaintext, new Uint8Array(padLen).fill(padLen));
      const out = new Uint8Array(padded.length);
      let prev = iv;
      for (let pos = 0; pos < padded.length; pos += 16) {
        const b = padded.slice(pos, pos + 16);
        for (let j = 0; j < 16; j++) b[j] ^= prev[j];
        prev = encryptBlock(rk, rounds, b);
        out.set(prev, pos);
      }
      return out;
    },
    decrypt(ciphertext: Uint8Array): Uint8Array {
      if (!ciphertext.length || ciphertext.length % 16)
        throw new Error('aes/cbc: invalid ciphertext length');
      const out = new Uint8Array(ciphertext.length);
      let prev = iv;
      for (let pos = 0; pos < ciphertext.length; pos += 16) {
        const block = ciphertext.subarray(pos, pos + 16);
        const d = decryptBlock(rk, rounds, block);
        for (let j = 0; j < 16; j++) d[j] ^= prev[j];
        out.set(d, pos);
        prev = block;
      }
      const padLen = out[out.length - 1];
      if (!padLen || padLen > 16) throw new Error('aes/cbc: wrong padding');
      for (let i = out.length - padLen; i < out.length; i++)
        if (out[i] !== padLen) throw new Error('aes/cbc: wrong padding');
      return out.subarray(0, out.length - padLen);
    },
  };
}

// GF(2^128) multiplication for GHASH (SP 800-38D §6.3), bit by bit over
// bigints. The bigint MSB is GCM's bit 0; R is x^128 + x^7 + x^2 + x + 1.
const R = BigInt('0xe1000000000000000000000000000000');
function gmul(x: bigint, y: bigint): bigint {
  let z = BigInt(0);
  let v = y;
  for (let i = 127; i >= 0; i--) {
    if ((x >> BigInt(i)) & BigInt(1)) z ^= v;
    v = v & BigInt(1) ? (v >> BigInt(1)) ^ R : v >> BigInt(1);
  }
  return z;
}

/** SP 800-38D §6.4 GHASH. Each segment is processed in zero-padded 16-byte blocks. */
function ghash(H: bigint, ...segments: Uint8Array[]): Uint8Array {
  let acc = BigInt(0);
  for (const seg of segments) {
    for (let i = 0; i < seg.length; i += 16) {
      const b = new Uint8Array(16);
      b.set(seg.subarray(i, i + 16));
      acc = gmul(acc ^ bytesToNumberBE(b), H);
    }
  }
  return numberToBytesBE(acc, 16);
}

/** SP 800-38D length block: BE64(a in bits) || BE64(b in bits). */
const gcmLengths = (aBytes: number, bBytes: number) =>
  concatBytes(numberToBytesBE(BigInt(aBytes * 8), 8), numberToBytesBE(BigInt(bBytes * 8), 8));

/**
 * GCM mode (SP 800-38D), identical to `gcm` from `src/aes.ts` with the
 * default 16-byte tag (compared in aes.test.ts). Any nonce length >= 1;
 * non-12-byte nonces go through the GHASH-based J0 derivation.
 */
export function gcm_small(
  key: Uint8Array,
  nonce: Uint8Array,
  AAD: Uint8Array = new Uint8Array(0)
): MicroCipher {
  const { rk, rounds } = expandKey(key);
  abytes(nonce);
  if (!nonce.length) throw new Error('aes/gcm: empty nonce');
  const E = (b: Uint8Array) => encryptBlock(rk, rounds, b);
  const H = bytesToNumberBE(E(new Uint8Array(16)));
  // SP 800-38D §7.1 step 2: derive the pre-counter block J0 from the nonce.
  const j0 =
    nonce.length === 12
      ? concatBytes(nonce, new Uint8Array([0, 0, 0, 1]))
      : ghash(H, nonce, gcmLengths(0, nonce.length));
  // GCTR with ICB = inc32(J0): only the last 4 counter bytes increment.
  const gctr = (data: Uint8Array) => {
    const c = j0.slice();
    const out = new Uint8Array(data.length);
    for (let pos = 0; pos < data.length; pos += 16) {
      for (let i = 15; i >= 12; i--) {
        c[i] = (c[i] + 1) & 0xff;
        if (c[i]) break;
      }
      const ks = E(c);
      const lim = Math.min(16, data.length - pos);
      for (let j = 0; j < lim; j++) out[pos + j] = data[pos + j] ^ ks[j];
    }
    return out;
  };
  // Tag = E(J0) xor GHASH(AAD || pad || C || pad || lengths).
  const computeTag = (ciphertext: Uint8Array) => {
    const s = ghash(H, AAD, ciphertext, gcmLengths(AAD.length, ciphertext.length));
    const tag = E(j0);
    for (let i = 0; i < 16; i++) tag[i] ^= s[i];
    return tag;
  };
  return {
    encrypt(plaintext: Uint8Array): Uint8Array {
      const ciphertext = gctr(plaintext);
      return concatBytes(ciphertext, computeTag(ciphertext));
    },
    decrypt(combined: Uint8Array): Uint8Array {
      if (combined.length < 16) throw new Error('aes/gcm: ciphertext less than tagLen');
      const ciphertext = combined.subarray(0, -16);
      // SP 800-38D §7.2: authenticate before decrypting.
      if (!equalBytes(combined.subarray(-16), computeTag(ciphertext)))
        throw new Error('invalid tag');
      return gctr(ciphertext);
    },
  };
}
