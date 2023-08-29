import { ensureBytes, u32, equalBytes, Cipher } from './utils.js';
import { salsaBasic } from './_salsa.js';
import { poly1305 } from './_poly1305.js';

// Salsa20 stream cipher was released in 2005.
// Salsa's goal was to implement AES replacement that does not rely on S-Boxes,
// which are hard to implement in a constant-time manner.
// https://cr.yp.to/snuffle.html, https://cr.yp.to/snuffle/salsafamily-20071225.pdf

// Left rotate for uint32
const rotl = (a: number, b: number) => (a << b) | (a >>> (32 - b));

/**
 * Salsa20 core function.
 */
// prettier-ignore
function salsaCore(
  c: Uint32Array, k: Uint32Array, i: Uint32Array, out: Uint32Array, cnt: number, rounds = 20
): void {
  // Based on https://cr.yp.to/salsa20.html
  let y00 = c[0], y01 = k[0], y02 = k[1], y03 = k[2]; // "expa" Key     Key     Key
  let y04 = k[3], y05 = c[1], y06 = i[0], y07 = i[1]; // Key    "nd 3"  Nonce   Nonce
  let y08 = cnt,  y09 = 0   , y10 = c[2], y11 = k[4]; // Pos.   Pos.    "2-by"	Key
  let y12 = k[5], y13 = k[6], y14 = k[7], y15 = c[3]; // Key    Key     Key     "te k"
  // Save state to temporary variables
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  // Main loop
  for (let i = 0; i < rounds; i += 2) {
    x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0,  9);
    x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18);
    x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0,  9);
    x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18);
    x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0,  9);
    x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18);
    x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0,  9);
    x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18);
    x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0,  9);
    x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18);
    x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0,  9);
    x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18);
    x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0,  9);
    x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18);
    x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0,  9);
    x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18);
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
 * hsalsa hashing function, used primarily in xsalsa, to hash
 * key and nonce into key' and nonce'.
 * Same as salsaCore, but there doesn't seem to be a way to move the block
 * out without 25% performance hit.
 */
// prettier-ignore
export function hsalsa(
  c: Uint32Array, key: Uint8Array, nonce: Uint8Array, out: Uint8Array
): Uint8Array {
  const k32 = u32(key);
  const i32 = u32(nonce);
  const o32 = u32(out);
  let x00 = c[0], x01 = k32[0], x02 = k32[1], x03 = k32[2], x04 = k32[3];
  let x05 = c[1], x06 = i32[0], x07 = i32[1], x08 = i32[2], x09 = i32[3];
  let x10 = c[2], x11 = k32[4], x12 = k32[5], x13 = k32[6], x14 = k32[7];
  let x15 = c[3];
  // Main loop
  for (let i = 0; i < 20; i += 2) {
    x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0,  9);
    x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18);
    x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0,  9);
    x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18);
    x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0,  9);
    x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18);
    x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0,  9);
    x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18);
    x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0,  9);
    x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18);
    x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0,  9);
    x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18);
    x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0,  9);
    x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18);
    x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0,  9);
    x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18);
  }
  o32[0] = x00;
  o32[1] = x05;
  o32[2] = x10;
  o32[3] = x15;
  o32[4] = x06;
  o32[5] = x07;
  o32[6] = x08;
  o32[7] = x09;
  return out;
}

/**
 * Salsa20 from original paper.
 * With 12-byte nonce, it's not safe to use fill it with random (CSPRNG), due to collision chance.
 */
export const salsa20 = /* @__PURE__ */ salsaBasic({ core: salsaCore, counterRight: true });

/**
 * xsalsa20 eXtended-nonce salsa.
 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
 */
export const xsalsa20 = /* @__PURE__ */ salsaBasic({
  core: salsaCore,
  counterRight: true,
  extendNonceFn: hsalsa,
  allow128bitKeys: false,
});

/**
 * xsalsa20-poly1305 eXtended-nonce salsa.
 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
 * Also known as secretbox from libsodium / nacl.
 */
export const xsalsa20poly1305 = (key: Uint8Array, nonce: Uint8Array): Cipher => {
  const tagLength = 16;
  ensureBytes(key, 32);
  ensureBytes(nonce, 24);
  return {
    tagLength,
    encrypt: (plaintext: Uint8Array, output?: Uint8Array) => {
      ensureBytes(plaintext);
      // This is small optimization (calculate auth key with same call as encryption itself) makes it hard
      // to separate tag calculation and encryption itself, since 32 byte is half-block of salsa (64 byte)
      const clength = plaintext.length + 32;
      if (output) {
        ensureBytes(output, clength);
      } else {
        output = new Uint8Array(clength);
      }
      output.set(plaintext, 32);
      xsalsa20(key, nonce, output, output);
      const authKey = output.subarray(0, 32);
      const tag = poly1305(output.subarray(32), authKey);
      // Clean auth key, even though JS provides no guarantees about memory cleaning
      output.set(tag, tagLength);
      output.subarray(0, tagLength).fill(0);
      return output.subarray(tagLength);
    },
    decrypt: (ciphertext: Uint8Array) => {
      ensureBytes(ciphertext);
      const clength = ciphertext.length;
      if (clength < tagLength) throw new Error('encrypted data should be at least 16 bytes');
      // Create new ciphertext array:
      // auth tag      auth tag from ciphertext ciphertext
      // [bytes 0..16] [bytes 16..32]           [bytes 32..]
      // 16 instead of 32, because we already have 16 byte tag
      const ciphertext_ = new Uint8Array(clength + tagLength); // alloc
      ciphertext_.set(ciphertext, tagLength);
      // Each xsalsa20 calls to hsalsa to calculate key, but seems not much perf difference
      // Separate call to calculate authkey, since first bytes contains tag
      const authKey = xsalsa20(key, nonce, new Uint8Array(32)); // alloc(32)
      const tag = poly1305(ciphertext_.subarray(32), authKey);
      if (!equalBytes(ciphertext_.subarray(16, 32), tag)) throw new Error('invalid tag');

      const plaintext = xsalsa20(key, nonce, ciphertext_); // alloc
      // Clean auth key, even though JS provides no guarantees about memory cleaning
      plaintext.subarray(0, 32).fill(0);
      authKey.fill(0);
      return plaintext.subarray(32);
    },
  };
};

/**
 * Alias to xsalsa20poly1305, for compatibility with libsodium / nacl
 */
export function secretbox(key: Uint8Array, nonce: Uint8Array) {
  ensureBytes(key);
  ensureBytes(nonce);
  const xs = xsalsa20poly1305(key, nonce);
  return { seal: xs.encrypt, open: xs.decrypt };
}
