import { utils as butils } from 'micro-bmark';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import { aes_256_gcm } from '@noble/ciphers/webcrypto/aes';
// import { aes_256_gcm_siv } from '@noble/ciphers/webcrypto/siv';
import { concatBytes } from '@noble/ciphers/utils';
import { crossValidate, onlyNoble, buf } from './_utils.js';

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

export async function main() {
  await crossValidate(buffers, ciphers);
  if (onlyNoble) return benchmarkOnlyNoble(buffers, ciphers);
  benchmarkAllLibraries(buffers, ciphers);
  butils.logMem();
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
