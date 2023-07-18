import { deepStrictEqual } from 'assert';
import { compare, utils as butils } from 'micro-bmark';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import { concatBytes } from '@noble/ciphers/utils';
import { salsa20, xsalsa20 } from '@noble/ciphers/salsa';
import { chacha20, xchacha20 } from '@noble/ciphers/chacha';
import * as micro from '@noble/ciphers/_micro';

import { streamXOR as stableSalsa } from '@stablelib/salsa20';
import { streamXOR as stableXSalsa } from '@stablelib/xsalsa20';
import { streamXOR as stableChacha } from '@stablelib/chacha';
import { streamXOR as stableXchacha } from '@stablelib/xchacha20';

const ONLY_NOBLE = process.argv[2] === 'noble';
const buf = (n) => new Uint8Array(n).fill(n);

// Non-authenticated ciphers. aead.js contains authenticated ones

// buffer title, sample count, data
const buffers = {
  '32B': [1500000, buf(32)],
  '64B': [1500000, buf(64)],
  '1KB': [300000, buf(1024)],
  '8KB': [50000, buf(1024 * 8)],
  '1MB': [300, buf(1024 * 1024)],
};

const cipherSame = (fn) => ({ encrypt: fn, decrypt: fn });

export const CIPHERS = {
  salsa: {
    opts: { key: buf(32), nonce: buf(8) },
    stablelib: cipherSame((buf, opts) =>
      stableSalsa(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => salsa20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => micro.salsa20(opts.key, opts.nonce, buf)),
  },
  chacha: {
    opts: { key: buf(32), nonce: buf(12), nonce16: concatBytes(new Uint8Array(4), buf(12)) },
    node: {
      encrypt: (buf, opts) => {
        const c = createCipheriv('chacha20', opts.key, opts.nonce16);
        const res = c.update(buf);
        c.final();
        return Uint8Array.from(res);
      },
      decrypt: (buf, opts) => {
        const decipher = createDecipheriv('chacha20', opts.key, opts.nonce16);
        const res = decipher.update(buf);
        decipher.final();
        return Uint8Array.from(res);
      },
    },
    stablelib: cipherSame((buf, opts) =>
      stableChacha(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => chacha20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => micro.chacha20(opts.key, opts.nonce, buf)),
  },
  xsalsa: {
    opts: { key: buf(32), nonce: buf(24) },
    stablelib: cipherSame((buf, opts) =>
      stableXSalsa(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => xsalsa20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => micro.xsalsa20(opts.key, opts.nonce, buf)),
  },
  xchacha: {
    opts: { key: buf(32), nonce: buf(24) },
    stablelib: cipherSame((buf, opts) =>
      stableXchacha(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => xchacha20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => micro.xchacha20(opts.key, opts.nonce, buf)),
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
