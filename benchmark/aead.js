import { deepStrictEqual } from 'assert';
import { compare, utils as butils } from 'micro-bmark';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import { concatBytes } from '@noble/ciphers/utils';
import { xchacha20poly1305, chacha20poly1305 } from '@noble/ciphers/chacha';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import * as micro from '@noble/ciphers/_micro';

import { ChaCha20Poly1305 as StableChachaPoly } from '@stablelib/chacha20poly1305';
import { XChaCha20Poly1305 as StableXchachaPoly } from '@stablelib/xchacha20poly1305';
import { default as tweetnacl } from 'tweetnacl'; // secretbox = xsalsa20-poly1305.
import {
  ChaCha20Poly1305 as ChsfChachaPoly,
  newInstance as chainsafe_init_wasm,
} from '@chainsafe/as-chacha20poly1305';

const ONLY_NOBLE = process.argv[2] === 'noble';
const buf = (n) => new Uint8Array(n).fill(n);
// buffer title, sample count, data
const buffers = {
  '32B': [500000, buf(32)],
  '64B': [500000, buf(64)],
  '1KB': [150000, buf(1024)],
  '8KB': [20000, buf(1024 * 8)],
  '1MB': [500, buf(1024 * 1024)],
};

let chainsafe_chacha_poly;

export const CIPHERS = {
  xsalsa20_poly1305: {
    opts: { key: buf(32), nonce: buf(24) },
    tweetnacl: {
      encrypt: (buf, opts) => tweetnacl.secretbox(buf, opts.nonce, opts.key),
      decrypt: (buf, opts) => tweetnacl.secretbox.open(buf, opts.nonce, opts.key),
    },
    noble: {
      encrypt: (buf, opts) => xsalsa20poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => xsalsa20poly1305(opts.key, opts.nonce).decrypt(buf),
    },
    micro: {
      encrypt: (buf, opts) => micro.xsalsa20poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => micro.xsalsa20poly1305(opts.key, opts.nonce).decrypt(buf),
    },
  },
  chacha20_poly1305: {
    opts: { key: buf(32), nonce: buf(12) },
    node: {
      encrypt: (buf, opts) => {
        const c = createCipheriv('chacha20-poly1305', opts.key, opts.nonce);
        const res = [];
        res.push(c.update(buf));
        res.push(c.final());
        res.push(c.getAuthTag());
        return concatBytes(...res.map((i) => Uint8Array.from(i)));
      },
      decrypt: (buf, opts) => {
        const ciphertext = buf.slice(0, -16);
        const authTag = buf.slice(-16);
        const decipher = createDecipheriv('chacha20-poly1305', opts.key, opts.nonce);
        decipher.setAuthTag(authTag);
        return concatBytes(
          ...[decipher.update(ciphertext), decipher.final()].map((i) => Uint8Array.from(i))
        );
      },
    },
    stable: {
      encrypt: (buf, opts) => new StableChachaPoly(opts.key).seal(opts.nonce, buf),
      decrypt: (buf, opts) => new StableChachaPoly(opts.key).open(opts.nonce, buf),
    },
    chainsafe: {
      encrypt: (buf, opts) => {
        return chainsafe_chacha_poly.seal(opts.key, opts.nonce, buf);
      },
      decrypt: (buf, opts) => {
        return chainsafe_chacha_poly.open(opts.key, opts.nonce, buf);
      },
    },
    noble: {
      encrypt: (buf, opts) => chacha20poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => chacha20poly1305(opts.key, opts.nonce).decrypt(buf),
    },
    micro: {
      encrypt: (buf, opts) => micro.chacha20poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => micro.chacha20poly1305(opts.key, opts.nonce).decrypt(buf),
    },
  },
  xchacha20poly1305: {
    opts: { key: buf(32), nonce: buf(24) },
    stable: {
      encrypt: (buf, opts) => new StableXchachaPoly(opts.key).seal(opts.nonce, buf),
      decrypt: (buf, opts) => new StableXchachaPoly(opts.key).open(opts.nonce, buf),
    },
    noble: {
      encrypt: (buf, opts) => xchacha20poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => xchacha20poly1305(opts.key, opts.nonce).decrypt(buf),
    },
    micro: {
      encrypt: (buf, opts) => micro.xchacha20poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => micro.xchacha20poly1305(opts.key, opts.nonce).decrypt(buf),
    },
  },
};

async function validate() {
  // Verify that things we bench actually work
  const bufs = [...Object.entries(buffers).map((i) => i[1][1])];
  // Verify different buffer sizes
  for (let i = 0; i < 2048; i++) bufs.push(buf(i));
  // Verify different subarrays positions
  const b2 = buf(2048);
  //for (let i = 0; i < 2048; i++) bufs.push(b2.subarray(i));
  for (const buf of bufs) {
    const b = buf.slice();
    // ciphers
    for (let [k, libs] of Object.entries(CIPHERS)) {
      let encrypted;
      for (const [lib, fn] of Object.entries(libs)) {
        if (lib === 'opts') continue;
        if (encrypted === undefined) encrypted = await fn.encrypt(buf, libs.opts);
        else {
          const cur = await fn.encrypt(buf, libs.opts);
          deepStrictEqual(encrypted, cur, `encrypt verify (${lib})`);
        }
        deepStrictEqual(buf, b, `encrypt mutates buffer (${lib})`);
        const res = await fn.decrypt(encrypted, libs.opts);
        deepStrictEqual(res, buf, `decrypt verify (${lib})`);
      }
    }
  }
  console.log('VALIDATED');
}

export const main = () =>
  (async () => {
    const ctx = chainsafe_init_wasm();
    chainsafe_chacha_poly = new ChsfChachaPoly(ctx);
    await validate();
    if (ONLY_NOBLE) {
      // Benchmark different noble-ciphers
      for (const [size, [samples, buf]] of Object.entries(buffers)) {
        const c = Object.entries(CIPHERS)
          .map(([k, lib]) => [k, lib.noble, lib.opts])
          .filter(([k, noble, _]) => !!noble);
        await compare(
          `encrypt (${size})`,
          samples,
          Object.fromEntries(c.map(([k, noble, opts]) => [k, () => noble.encrypt(buf, opts)]))
        );
      }
      return;
    }
    // Benchmark against other libraries
    for (let [k, libs] of Object.entries(CIPHERS)) {
      console.log(`==== ${k} ====`);
      for (const [size, [samples, buf]] of Object.entries(buffers)) {
        const l = Object.entries(libs).filter(([lib, _]) => lib !== 'opts');
        await compare(
          `${k} (encrypt, ${size})`,
          samples,
          Object.fromEntries(l.map(([lib, fn]) => [lib, () => fn.encrypt(buf, libs.opts)]))
        );
        const encrypted = await l[0][1].encrypt(buf, libs.opts);
        await compare(
          `${k} (decrypt, ${size})`,
          samples,
          Object.fromEntries(l.map(([lib, fn]) => [lib, () => fn.decrypt(encrypted, libs.opts)]))
        );
      }
    }
    // Log current RAM
    butils.logMem();
  })();

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
