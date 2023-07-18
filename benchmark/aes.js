import { deepStrictEqual } from 'assert';
import { compare, utils as butils } from 'micro-bmark';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import { aes_256_gcm } from '@noble/ciphers/webcrypto/aes';
// import { aes_256_gcm_siv } from '@noble/ciphers/webcrypto/siv';
import { concatBytes } from '@noble/ciphers/utils';

const ONLY_NOBLE = process.argv[2] === 'noble';
const buf = (n) => new Uint8Array(n).fill(n);

// Works for gcm only?
const nodeGCM = (name) => {
  return {
    encrypt: (buf, opts) => {
      const res = [opts.iv];
      const c = createCipheriv(name, opts.key, opts.iv);
      if (opts.aad) c.setAAD(opts.aad);
      res.push(c.update(buf));
      res.push(c.final());
      res.push(c.getAuthTag());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice(12, -16);
      const authTag = buf.slice(-16);
      const decipher = createDecipheriv(name, opts.key, opts.iv);
      if (opts.aad) c.setAAD(opts.aad);
      decipher.setAuthTag(authTag);
      return concatBytes(
        ...[decipher.update(ciphertext), decipher.final()].map((i) => Uint8Array.from(i))
      );
    },
  };
};

const cipherSame = (fn) => ({ encrypt: fn, decrypt: fn });

export const CIPHERS = {
  // TODO: why this is so slow?
  'gcm-256': {
    opts: { key: buf(32), iv: buf(12) },
    node: nodeGCM('aes-256-gcm'),
    noble: {
      encrypt: (buf, opts) => aes_256_gcm.encrypt(opts.key, buf, opts.iv),
      decrypt: (buf, opts) => aes_256_gcm.decrypt(opts.key, buf, opts.iv),
    },
  },
  'gcm-siv-128': {
    opts: { key: buf(16), aad: buf(0), nonce: buf(12) },
    noble: {
      encrypt: async (buf, opts) =>
        await (await aes_256_gcm_siv(opts.key, opts.nonce, opts.aad)).encrypt(buf),
      decrypt: async (buf, opts) =>
        await (await aes_256_gcm_siv(opts.key, opts.nonce, opts.aad)).decrypt(buf),
    },
  },
  'gcm-siv-256': {
    opts: { key: buf(32), aad: buf(0), nonce: buf(12) },
    noble: {
      encrypt: async (buf, opts) =>
        await (await aes_256_gcm_siv(opts.key, opts.nonce, opts.aad)).encrypt(buf),
      decrypt: async (buf, opts) =>
        await (await aes_256_gcm_siv(opts.key, opts.nonce, opts.aad)).decrypt(buf),
    },
  },
};

// buffer title, sample count, data
const buffers = {
  '32B': [2000000, buf(32)],
  '64B': [1000000, buf(64)],
  '1KB': [66667, buf(1024)],
  '8KB': [8333, buf(1024 * 8)],
  '1MB': [524, buf(1024 * 1024)],
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
    for (let [k, libs] of Object.entries(HASHES)) {
      for (const [size, [samples, buf]] of Object.entries(buffers)) {
        await compare(
          `${k} (${size})`,
          samples,
          Object.fromEntries(
            Object.entries(libs)
              .filter(([lib, _]) => lib !== 'opts')
              .map(([lib, fn]) => [lib, () => fn(buf, libs.opts)])
          )
        );
      }
    }
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
