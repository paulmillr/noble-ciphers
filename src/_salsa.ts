// Basic utils for salsa-like ciphers
// Check out _micro.ts for descriptive documentation.
import assert from './_assert.js';
import { u32, utf8ToBytes, checkOpts } from './utils.js';

/*
RFC8439 requires multi-step cipher stream, where
authKey starts with counter: 0, actual msg with counter: 1.

For this, we need a way to re-use nonce / counter:

    const counter = new Uint8Array(4);
    chacha(..., counter, ...); // counter is now 1
    chacha(..., counter, ...); // counter is now 2

This is complicated:

- Original papers don't allow mutating counters
- Counter overflow is undefined: https://mailarchive.ietf.org/arch/msg/cfrg/gsOnTJzcbgG6OqD8Sc0GO5aR_tU/
- 3rd-party library stablelib implementation uses an approach where you can provide
  nonce and counter instead of just nonce - and it will re-use it
- We could have did something similar, but ChaCha has different counter position
  (counter | nonce), which is not composable with XChaCha, because full counter
  is (nonce16 | counter | nonce16). Stablelib doesn't support in-place counter for XChaCha.
- We could separate nonce & counter and provide separate API for counter re-use, but
  there are different counter sizes depending on an algorithm.
- Salsa & ChaCha also differ in structures of key / sigma:

    salsa:     c0 | k(4) | c1 | nonce(2) | ctr(2) | c2 | k(4) | c4
    chacha:    c(4) | k(8) | ctr(1) | nonce(3)
    chachaDJB: c(4) | k(8) | ctr(2) | nonce(2)
- Creating function such as `setSalsaState(key, nonce, sigma, data)` won't work,
  because we can't re-use counter array
- 32-bit nonce is `2 ** 32 * 64` = 256GB with 32-bit counter
- JS does not allow UintArrays bigger than 4GB, so supporting 64-bit counters doesn't matter

Structure is as following:

key=16 -> sigma16, k=key|key
key=32 -> sigma32, k=key

nonces:
salsa20:      8   (8-byte counter)
chacha20djb:  8   (8-byte counter)
chacha20tls:  12  (4-byte counter)
xsalsa:       24  (16 -> hsalsa, 8 -> old nonce)
xchacha:      24  (16 -> hchacha, 8 -> old nonce)

https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.2
Use the subkey and remaining 8 byte nonce with ChaCha20 as normal
(prefixed by 4 NUL bytes, since [RFC8439] specifies a 12-byte nonce).
*/

const sigma16 = utf8ToBytes('expand 16-byte k');
const sigma32 = utf8ToBytes('expand 32-byte k');
const sigma16_32 = u32(sigma16);
const sigma32_32 = u32(sigma32);

export type SalsaOpts = {
  core: (
    c: Uint32Array,
    key: Uint32Array,
    nonce: Uint32Array,
    out: Uint32Array,
    counter: number,
    rounds?: number
  ) => void;
  rounds?: number;
  counterRight?: boolean; // counterRight ? nonce | counter : counter | nonce;
  counterLen?: number;
  blockLen?: number; // NOTE: not tested with different blockLens!
  allow128bitKeys?: boolean; // Original salsa/chacha allows these, but not tested!
  extendNonceFn?: (c: Uint32Array, key: Uint8Array, src: Uint8Array, dst: Uint8Array) => Uint8Array;
};

// Is byte array aligned to 4 byte offset (u32)?
const isAligned32 = (b: Uint8Array) => !(b.byteOffset % 4);

export const salsaBasic = (opts: SalsaOpts) => {
  const { core, rounds, counterRight, counterLen, allow128bitKeys, extendNonceFn, blockLen } =
    checkOpts(
      { rounds: 20, counterRight: false, counterLen: 8, allow128bitKeys: true, blockLen: 64 },
      opts
    );
  assert.number(counterLen);
  assert.number(rounds);
  assert.number(blockLen);
  assert.bool(counterRight);
  assert.bool(allow128bitKeys);
  const blockLen32 = blockLen / 4;
  if (blockLen % 4 !== 0) throw new Error('Salsa/ChaCha: blockLen should be aligned to 4 bytes');
  return (
    key: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
    output?: Uint8Array,
    counter = 0
  ): Uint8Array => {
    assert.bytes(key);
    assert.bytes(nonce);
    assert.bytes(data);
    if (!output) output = new Uint8Array(data.length);
    assert.bytes(output);
    assert.number(counter);
    // > new Uint32Array([2**32])
    // Uint32Array(1) [ 0 ]
    // > new Uint32Array([2**32-1])
    // Uint32Array(1) [ 4294967295 ]
    if (counter < 0 || counter >= 2 ** 32 - 1) throw new Error('Salsa/ChaCha: counter overflow');
    if (output.length < data.length) {
      throw new Error(
        `Salsa/ChaCha: output (${output.length}) is shorter than data (${data.length})`
      );
    }
    const toClean = [];
    let k, sigma;
    // Handle 128 byte keys
    if (key.length === 32) {
      k = key;
      sigma = sigma32_32;
    } else if (key.length === 16 && allow128bitKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else throw new Error(`Salsa/ChaCha: wrong key length=${key.length}, expected`);
    // Handle extended nonce (HChaCha/HSalsa)
    if (extendNonceFn) {
      if (nonce.length <= 16)
        throw new Error(`Salsa/ChaCha: extended nonce should be bigger than 16 bytes`);
      k = extendNonceFn(sigma, k, nonce.subarray(0, 16), new Uint8Array(32));
      toClean.push(k);
      nonce = nonce.subarray(16);
    }
    // Handle nonce counter
    const nonceLen = 16 - counterLen;
    if (nonce.length !== nonceLen)
      throw new Error(`Salsa/ChaCha: nonce should be ${nonceLen} or 16 bytes`);
    // Pad counter when nonce is 64 bit
    if (nonceLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      toClean.push((nonce = nc));
    }
    // Counter positions
    const block = new Uint8Array(blockLen);
    // Cast to Uint32Array for speed
    const b32 = u32(block);
    const k32 = u32(k);
    const n32 = u32(nonce);
    // Make sure that buffers aligned to 4 bytes
    const d32 = isAligned32(data) && u32(data);
    const o32 = isAligned32(output) && u32(output);
    toClean.push(b32);
    const len = data.length;
    for (let pos = 0, ctr = counter; pos < len; ctr++) {
      core(sigma, k32, n32, b32, ctr, rounds);
      if (ctr >= 2 ** 32 - 1) throw new Error('Salsa/ChaCha: counter overflow');
      const take = Math.min(blockLen, len - pos);
      // full block && aligned to 4 bytes
      if (take === blockLen && o32 && d32) {
        const pos32 = pos / 4;
        if (pos % 4 !== 0) throw new Error('Salsa/ChaCha: wrong block position');
        for (let j = 0; j < blockLen32; j++) o32[pos32 + j] = d32[pos32 + j] ^ b32[j];
        pos += blockLen;
        continue;
      }
      for (let j = 0; j < take; j++) output[pos + j] = data[pos + j] ^ block[j];
      pos += take;
    }
    for (let i = 0; i < toClean.length; i++) toClean[i].fill(0);
    return output;
  };
};
