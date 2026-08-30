import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { createCipheriv, createDecipheriv, getCiphers } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import * as aes from '../src/aes.ts';
import { chacha20, chacha20poly1305 } from '../src/chacha.ts';
import { concatBytes } from '../src/utils.ts';

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;
const SLOW = process.argv.includes('slow'); // we can run manually by adding 'slow' into args
const SMALL_KEYS = false; // quickly cross-test 128-bit AES only

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
const BT = { describe, it };

const nodeTagCipher = (name) => {
  if (!nodeCiphers.has(name)) return;
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv || empty);
      if (opts.aad) c.setAAD(opts.aad);
      for (const b of chunks(buf, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      res.push(c.getAuthTag());
      return concatBytes(...res);
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice(0, -16);
      const authTag = buf.slice(-16);
      const decipher = createDecipheriv(name, opts.key, opts.iv || empty);
      if (opts.aad) decipher.setAAD(opts.aad);
      decipher.setAuthTag(authTag);
      const res = [];
      for (const b of chunks(ciphertext, 1 * GB)) res.push(decipher.update(b));
      res.push(decipher.final());
      return concatBytes(...res);
    },
  };
};

const nodeCipher = (name, pkcs7 = true) => {
  if (!nodeCiphers.has(name)) return;
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv || empty);
      c.setAutoPadding(pkcs7);
      for (const b of chunks(buf, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      return concatBytes(...res);
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice();
      const res = [];
      const c = createDecipheriv(name, opts.key, opts.iv || empty);
      c.setAutoPadding(pkcs7);
      for (const b of chunks(ciphertext, 1 * GB)) res.push(c.update(b));
      res.push(c.final());
      return concatBytes(...res);
    },
  };
};

function buf(n) {
  return new Uint8Array(n).fill(n % 251);
}

const PARTIAL_LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65];
const BLOCK_LENGTHS = [0, 16, 32, 48];
const WRAP_LENGTHS = [16, 24, 32, 40];
const WRAP_PAD_LENGTHS = [1, 7, 8, 9, 15, 16, 17, 31, 32, 33];

function smallLengths(name) {
  if (name.endsWith('_no_padding')) return BLOCK_LENGTHS;
  if (name.endsWith('_wrap_pad')) return WRAP_PAD_LENGTHS;
  if (name.endsWith('_wrap')) return WRAP_LENGTHS;
  return PARTIAL_LENGTHS;
}

export function test(
  variant = 'noble',
  platform = { ...aes, chacha20, chacha20poly1305 },
  { describe, it } = BT
) {
  const { chacha20, chacha20poly1305 } = platform;
  const aes = platform;
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
    aes_ctr192: {
      opts: { key: buf(24), iv: buf(16) },
      node: nodeCipher('aes-192-ctr'),
      noble: {
        encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_ctr256: {
      opts: { key: buf(32), iv: buf(16) },
      node: nodeCipher('aes-256-ctr'),
      noble: {
        encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_cbc_128: {
      opts: { key: buf(16), iv: buf(16) },
      node: nodeCipher('aes-128-cbc'),
      noble: {
        encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_cbc_192: {
      opts: { key: buf(24), iv: buf(16) },
      node: nodeCipher('aes-192-cbc'),
      noble: {
        encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_cbc_256: {
      opts: { key: buf(32), iv: buf(16) },
      node: nodeCipher('aes-256-cbc'),
      noble: {
        encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_cfb_128: {
      opts: { key: buf(16), iv: buf(16) },
      node: nodeCipher('aes-128-cfb'),
      noble: {
        encrypt: (buf, opts) => aes.cfb(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.cfb(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_cfb_192: {
      opts: { key: buf(24), iv: buf(16) },
      node: nodeCipher('aes-192-cfb'),
      noble: {
        encrypt: (buf, opts) => aes.cfb(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.cfb(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_cfb_256: {
      opts: { key: buf(32), iv: buf(16) },
      node: nodeCipher('aes-256-cfb'),
      noble: {
        encrypt: (buf, opts) => aes.cfb(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf, opts) => aes.cfb(opts.key, opts.iv).decrypt(buf),
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
    aes_ecb_192: {
      opts: { key: buf(24), iv: null },
      node: nodeCipher('aes-192-ecb'),
      noble: {
        encrypt: (buf, opts) => aes.ecb(opts.key).encrypt(buf),
        decrypt: (buf, opts) => aes.ecb(opts.key).decrypt(buf),
      },
    },
    aes_ecb_256: {
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
    aes_cbc_192_no_padding: {
      opts: { key: buf(24), iv: buf(16), blockSize: 16 },
      node: nodeCipher('aes-192-cbc', false),
      noble: {
        encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
        decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
      },
    },
    aes_cbc_256_no_padding: {
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
    aes_ecb_192_no_padding: {
      opts: { key: buf(24), iv: null, blockSize: 16 },
      node: nodeCipher('aes-192-ecb', false),
      noble: {
        encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
        decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
      },
    },
    aes_ecb_256_no_padding: {
      opts: { key: buf(32), iv: null, blockSize: 16 },
      node: nodeCipher('aes-256-ecb', false),
      noble: {
        encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
        decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
      },
    },
    aes_gcm_128: {
      opts: { key: buf(16), iv: buf(12), aad: buf(17) },
      node: nodeTagCipher('aes-128-gcm'),
      noble: {
        encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv, opts.aad).encrypt(buf),
        decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv, opts.aad).decrypt(buf),
      },
    },
    aes_gcm_192: {
      opts: { key: buf(24), iv: buf(12), aad: buf(17) },
      node: nodeTagCipher('aes-192-gcm'),
      noble: {
        encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv, opts.aad).encrypt(buf),
        decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv, opts.aad).decrypt(buf),
      },
    },
    aes_gcm_256: {
      opts: { key: buf(32), iv: buf(12), aad: buf(17) },
      node: nodeTagCipher('aes-256-gcm'),
      noble: {
        encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv, opts.aad).encrypt(buf),
        decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv, opts.aad).decrypt(buf),
      },
    },
    chacha20poly1305: {
      opts: { key: buf(32), iv: buf(12), aad: buf(17) },
      node: nodeCiphers.has('chacha20-poly1305') && nodeTagCipher('chacha20-poly1305'),
      noble: {
        encrypt: (buf, opts) => chacha20poly1305(opts.key, opts.iv, opts.aad).encrypt(buf),
        decrypt: (buf, opts) => chacha20poly1305(opts.key, opts.iv, opts.aad).decrypt(buf),
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
    aes192_wrap: {
      opts: { key: buf(24), iv: buf(8).fill(0xa6) }, // Node is fun and is not broken at all.
      node: nodeCiphers.has('aes192-wrap') && nodeCipher('aes192-wrap'),
      noble: {
        encrypt: (buf, opts) => aes.aeskw(opts.key).encrypt(buf),
        decrypt: (buf, opts) => aes.aeskw(opts.key).decrypt(buf),
      },
    },
    aes256_wrap: {
      opts: { key: buf(32), iv: buf(8).fill(0xa6) }, // Node is fun and is not broken at all.
      node: nodeCiphers.has('aes256-wrap') && nodeCipher('aes256-wrap'),
      noble: {
        encrypt: (buf, opts) => aes.aeskw(opts.key).encrypt(buf),
        decrypt: (buf, opts) => aes.aeskw(opts.key).decrypt(buf),
      },
    },
    aes128_wrap_pad: {
      opts: { key: buf(16), iv: new Uint8Array([0xa6, 0x59, 0x59, 0xa6]) },
      node: nodeCiphers.has('id-aes128-wrap-pad') && nodeCipher('id-aes128-wrap-pad'),
      noble: {
        encrypt: (buf, opts) => aes.aeskwp(opts.key).encrypt(buf),
        decrypt: (buf, opts) => aes.aeskwp(opts.key).decrypt(buf),
      },
    },
    aes192_wrap_pad: {
      opts: { key: buf(24), iv: new Uint8Array([0xa6, 0x59, 0x59, 0xa6]) },
      node: nodeCiphers.has('id-aes192-wrap-pad') && nodeCipher('id-aes192-wrap-pad'),
      noble: {
        encrypt: (buf, opts) => aes.aeskwp(opts.key).encrypt(buf),
        decrypt: (buf, opts) => aes.aeskwp(opts.key).decrypt(buf),
      },
    },
    aes256_wrap_pad: {
      opts: { key: buf(32), iv: new Uint8Array([0xa6, 0x59, 0x59, 0xa6]) },
      node: nodeCiphers.has('id-aes256-wrap-pad') && nodeCipher('id-aes256-wrap-pad'),
      noble: {
        encrypt: (buf, opts) => aes.aeskwp(opts.key).encrypt(buf),
        decrypt: (buf, opts) => aes.aeskwp(opts.key).decrypt(buf),
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

  describe(`Cross-test (node, ${variant})`, () => {
    for (const k in CIPHERS) {
      const v = CIPHERS[k];
      const largeAesKey = k.startsWith('aes') && v.opts.key.length > 16;
      if (isDeno || !v.node || (SMALL_KEYS && largeAesKey)) continue;
      describe(k, () => {
        it('small inputs', () => {
          for (const length of smallLengths(k)) {
            const input = buf(length);
            const nodeEncrypted = v.node.encrypt(input, v.opts);
            const nobleEncrypted = v.noble.encrypt(input, v.opts);
            eql(nobleEncrypted, nodeEncrypted, `encrypt length=${length}`);
            eql(v.noble.decrypt(nodeEncrypted, v.opts), input, `noble decrypt length=${length}`);
            eql(v.node.decrypt(nobleEncrypted, v.opts), input, `node decrypt length=${length}`);
          }
        });
        it('1 MB', () => {
          const input = new Uint8Array(1 * MB);
          const nodeEncrypted = v.node.encrypt(input, v.opts);
          const nobleEncrypted = v.noble.encrypt(input, v.opts);
          eql(nobleEncrypted, nodeEncrypted);
          eql(v.noble.decrypt(nodeEncrypted, v.opts), input);
          eql(v.node.decrypt(nobleEncrypted, v.opts), input);
        });
        if (SLOW && k !== 'chacha20' && !k.includes('wrap')) {
          // This crosses the 32-bit byte-offset boundary to catch truncated lengths and indexes.
          // Cryptographic counter-wrap boundaries are covered directly in aes.test.ts/arx.test.ts.
          // Failure to allocate is intentional: the scheduled large-input gate must not pass by
          // silently omitting the cases it exists to run.
          it.serial('5 GB large input', () => {
            // Peak RSS is the constraint: holding plaintext, both ciphertexts and the
            // decrypted copy at once (~20 GB) OOM-kills a 16 GB CI runner. Drop each
            // buffer as soon as it is checked, and verify decryption against the known
            // all-zero plaintext instead of keeping a second 5 GB reference alive.
            let input = new Uint8Array(5 * GB);
            let nodeEncrypted = v.node.encrypt(input, v.opts);
            let nobleEncrypted = v.noble.encrypt(input, v.opts);
            input = null;
            eql(nobleEncrypted, nodeEncrypted);
            nodeEncrypted = null;
            const decrypted = v.noble.decrypt(nobleEncrypted, v.opts);
            nobleEncrypted = null;
            eql(decrypted.length, 5 * GB);
            for (let i = 0; i < decrypted.length; i++) {
              if (decrypted[i] !== 0) throw new Error(`decrypt mismatch at offset ${i}`);
            }
          });
        }
      });
    }
  });
}
if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
it.runWhen(import.meta.url);
