import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { createCipheriv, createDecipheriv, getCiphers } from 'node:crypto';
import * as aes from '../src/aes.ts';
import { chacha20, chacha20poly1305, xchacha20poly1305 } from '../src/chacha.ts';
import { xsalsa20poly1305 } from '../src/salsa.ts';
import { concatBytes } from '../src/utils.ts';

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;
const SLOW = process.argv.includes('slow'); // we can run manually by adding 'slow' into args
const SMALL_KEYS = false; // quickly test 128bit only

const isDeno = 'deno' in process.versions; // https://github.com/denoland/deno/issues/24864 etc

// Node fails on >~2gb stuff
function chunks(array, length) {
  const chunks = [];
  const totalChunks = Math.ceil(array.length / length);
  for (let i = 0; i < totalChunks; i++) {
    const start = i * length;
    const end = Math.min(start + length, array.length);
    chunks.push(array.subarray(start, end));
  }
  return chunks;
}

const empty = new Uint8Array(0);

const nodeCiphers = new Set(getCiphers());

const nodeTagCipher = (name) => {
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv || empty);
      if (opts.aad) c.setAAD(opts.aad);
      for (const b of chunks(buf, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      res.push(c.getAuthTag());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice(0, -16);
      const authTag = buf.slice(-16);
      const decipher = createDecipheriv(name, opts.key, opts.iv || empty);
      if (opts.aad) c.setAAD(opts.aad);
      decipher.setAuthTag(authTag);
      const res = [];
      for (const b of chunks(ciphertext, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
  };
};

const nodeCipher = (name, pcks7 = true) => {
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv || empty);
      c.setAutoPadding(pcks7); // disable  pkcs7Padding
      for (const b of chunks(buf, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice();
      const res = [];
      const c = createDecipheriv(name, opts.key, opts.iv || empty);
      c.setAutoPadding(pcks7); // disable  pkcs7Padding
      for (const b of chunks(ciphertext, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
  };
};

function buf(n) {
  return new Uint8Array(n).fill(n % 251);
}
// TODO: re-use in benchmarks?
// There is more ciphers, also 192 versions
const CIPHERS = {
  aes_ctr128: {
    opts: { key: buf(16), iv: buf(16) },
    node: nodeCipher('aes-128-ctr'),
    noble: {
      encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_ctr192: !SMALL_KEYS && {
    opts: { key: buf(24), iv: buf(16) },
    node: nodeCipher('aes-192-ctr'),
    noble: {
      encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_ctr256: !SMALL_KEYS && {
    opts: { key: buf(32), iv: buf(16) },
    node: nodeCipher('aes-256-ctr'),
    noble: {
      encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
    },
  },
  aec_cbc_128: {
    opts: { key: buf(16), iv: buf(16) },
    node: nodeCipher('aes-128-cbc'),
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_cbc_192: !SMALL_KEYS && {
    opts: { key: buf(24), iv: buf(16) },
    node: nodeCipher('aes-192-cbc'),
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_cbc_256: !SMALL_KEYS && {
    opts: { key: buf(32), iv: buf(16) },
    node: nodeCipher('aes-256-cbc'),
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_ecb_128: {
    opts: { key: buf(16), iv: null },
    node: nodeCipher('aes-128-ecb'),
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key).decrypt(buf),
    },
  },
  aes_ecb_192: !SMALL_KEYS && {
    opts: { key: buf(24), iv: null },
    node: nodeCipher('aes-192-ecb'),
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key).decrypt(buf),
    },
  },
  aes_ecb_256: !SMALL_KEYS && {
    opts: { key: buf(32), iv: null },
    node: nodeCipher('aes-256-ecb'),
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key).decrypt(buf),
    },
  },
  aes_cbc_128_no_padding: {
    opts: { key: buf(16), iv: buf(16), blockSize: 16 },
    node: nodeCipher('aes-128-cbc', false),
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
    },
  },
  aes_cbc_192_no_padding: !SMALL_KEYS && {
    opts: { key: buf(24), iv: buf(16), blockSize: 16 },
    node: nodeCipher('aes-192-cbc', false),
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
    },
  },
  aes_cbc_256_no_padding: !SMALL_KEYS && {
    opts: { key: buf(32), iv: buf(16), blockSize: 16 },
    node: nodeCipher('aes-256-cbc', false),
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
    },
  },
  aes_ecb_128_no_padding: {
    opts: { key: buf(16), iv: null, blockSize: 16 },
    node: nodeCipher('aes-128-ecb', false),
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
    },
  },
  aes_ecb_192_no_padding: !SMALL_KEYS && {
    opts: { key: buf(24), iv: null, blockSize: 16 },
    node: nodeCipher('aes-192-ecb', false),
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
    },
  },
  aes_ecb_256_no_padding: !SMALL_KEYS && {
    opts: { key: buf(32), iv: null, blockSize: 16 },
    node: nodeCipher('aes-256-ecb', false),
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
    },
  },
  aes_gcm_128: {
    opts: { key: buf(16), iv: buf(12) },
    node: nodeTagCipher('aes-128-gcm'),
    noble: {
      encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_gcm_192: !SMALL_KEYS && {
    opts: { key: buf(24), iv: buf(12) },
    node: nodeTagCipher('aes-192-gcm'),
    noble: {
      encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes_gcm_256: !SMALL_KEYS && {
    opts: { key: buf(32), iv: buf(12) },
    node: nodeTagCipher('aes-256-gcm'),
    noble: {
      encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).decrypt(buf),
    },
  },
  chacha20poly1305: {
    opts: { key: buf(32), iv: buf(12) },
    node: nodeCiphers.has('chacha20-poly1305') && nodeTagCipher('chacha20-poly1305'),
    noble: {
      encrypt: (buf, opts) => chacha20poly1305(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => chacha20poly1305(opts.key, opts.iv).decrypt(buf),
    },
  },
  xchacha20poly1305: {
    opts: { key: buf(32), iv: buf(24) },
    noble: {
      encrypt: (buf, opts) => xchacha20poly1305(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => xchacha20poly1305(opts.key, opts.iv).decrypt(buf),
    },
  },
  xsalsa20poly1305: {
    opts: { key: buf(32), iv: buf(24) },
    noble: {
      encrypt: (buf, opts) => xsalsa20poly1305(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => xsalsa20poly1305(opts.key, opts.iv).decrypt(buf),
    },
  },
  aes128_wrap: {
    opts: { key: buf(16), iv: buf(8).fill(0xa6) }, // Node is fun and is not broken at all.
    node: nodeCiphers.has('aes128-wrap') && nodeCipher('aes128-wrap'),
    noble: {
      encrypt: (buf, opts) => aes.aeskw(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.aeskw(opts.key).decrypt(buf),
    },
  },
  aes192_wrap: !SMALL_KEYS && {
    opts: { key: buf(24), iv: buf(8).fill(0xa6) }, // Node is fun and is not broken at all.
    node: nodeCiphers.has('aes192-wrap') && nodeCipher('aes192-wrap'),
    noble: {
      encrypt: (buf, opts) => aes.aeskw(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.aeskw(opts.key).decrypt(buf),
    },
  },
  aes256_wrap: !SMALL_KEYS && {
    opts: { key: buf(32), iv: buf(8).fill(0xa6) }, // Node is fun and is not broken at all.
    node: nodeCiphers.has('aes256-wrap') && nodeCipher('aes256-wrap'),
    noble: {
      encrypt: (buf, opts) => aes.aeskw(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.aeskw(opts.key).decrypt(buf),
    },
  },
  chacha20: {
    opts: { key: buf(32), iv: buf(12), iv16: concatBytes(new Uint8Array(4), buf(12)) },
    // padded iv
    node: nodeCiphers.has('chacha20') && {
      encrypt: (buf, opts) => {
        const c = createCipheriv('chacha20', opts.key, opts.iv16);
        const res = c.update(buf);
        c.final();
        return Uint8Array.from(res);
      },
      decrypt: (buf, opts) => {
        const decipher = createDecipheriv('chacha20', opts.key, opts.iv16);
        const res = decipher.update(buf);
        decipher.final();
        return Uint8Array.from(res);
      },
    },
    noble: {
      encrypt: (buf, opts) => chacha20(opts.key, opts.iv, buf),
      decrypt: (buf, opts) => chacha20(opts.key, opts.iv, buf),
    },
  },
};

const ALGO_4GB_LIMIT = ['aes128_wrap', 'aes192_wrap', 'aes256_wrap', 'chacha20'];
let supports5GB = false;
try {
  let ZERO_5GB = new Uint8Array(5 * GB); // catches u32 overflow in ints
  ZERO_5GB = null; // clean up ram immediately
  supports5GB = true;
} catch (error) {}

describe('Cross-test (node)', () => {
  for (const k in CIPHERS) {
    const v = CIPHERS[k];
    if (isDeno || !v) continue;
    describe(k, () => {
      should('basic round-trip', () => {
        const BUF = buf(32);
        const enc = v.noble.encrypt(BUF, v.opts);
        eql(v.noble.decrypt(enc, v.opts), BUF);
      });
      if (v.node) {
        describe('node', () => {
          should('basic', () => {
            const BUF = buf(32);
            const enc = v.node.encrypt(BUF, v.opts);
            eql(v.noble.encrypt(BUF, v.opts), enc);
            eql(v.noble.decrypt(enc, v.opts), BUF);
          });
          should('1 MB', () => {
            const BUF = new Uint8Array(1 * MB);
            const enc = v.node.encrypt(BUF, v.opts);
            eql(v.noble.encrypt(BUF, v.opts), enc);
            eql(v.noble.decrypt(enc, v.opts), BUF);
          });
          if (SLOW) {
            // NOTE: this is actually super important even if nobody will use 5GB arrays,
            // because it tests counter overflow behaviour inside ciphers
            /*
            aeskw - limit, error at 4 gb (ours)
            TODO: test at ~3gb, was OOM?
            chacha20 - ~2gb node limit
            chacha20poly1305 - somehow works with 5gb? How?
            - counter is per block, block is 64 bytes
            - we need bigger than 256gb array to overflow this counter
            - seems unreasonable? and there is actual test for counter overflow!
            */
            // (4*GB).toString(2).length == 33 -> should crash
            if (supports5GB && !ALGO_4GB_LIMIT.includes(k)) {
              should('5 GB', () => {
                const BUF = new Uint8Array(5 * GB);
                const enc = v.node.encrypt(BUF, v.opts);
                eql(v.noble.encrypt(BUF, v.opts), enc);
                eql(v.noble.decrypt(enc, v.opts), BUF);
              });
            }
          }
        });
      }
    });
  }
});

should.runWhen(import.meta.url);
