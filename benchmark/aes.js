import { utils as butils } from 'micro-bmark';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import * as webcrypto from '@noble/ciphers/webcrypto';
import { concatBytes } from '@noble/ciphers/utils';
import * as aes from '@noble/ciphers/aes';
import {
  crossValidate,
  onlyNoble,
  buf,
  benchmarkAllLibraries,
  benchmarkOnlyNoble,
} from './_utils.js';
import { CTR as STABLE_CTR } from '@stablelib/ctr';
import { AES as STABLE_AES } from '@stablelib/aes';
import { GCM as STABLE_GCM } from '@stablelib/gcm';
import { default as aesjs } from 'aes-js';

// Works for gcm only?
const nodeGCM = (name) => {
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv);
      if (opts.aad) c.setAAD(opts.aad);
      res.push(c.update(buf));
      res.push(c.final());
      res.push(c.getAuthTag());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice(0, -16);
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

const nodeAES = (name, pcks7 = true) => {
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv);
      c.setAutoPadding(pcks7); // disable  pkcs7Padding
      res.push(c.update(buf));
      res.push(c.final());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice();
      const c = createDecipheriv(name, opts.key, opts.iv);
      c.setAutoPadding(pcks7); // disable  pkcs7Padding
      return concatBytes(...[c.update(ciphertext), c.final()].map((i) => Uint8Array.from(i)));
    },
  };
};

// Stablellib doesn't support, so we create simple version
const stableCBC = {
  encrypt: (buf, opts) => {
    const c = new STABLE_AES(opts.key);
    let left = c.blockSize - (buf.length % c.blockSize);
    if (!left) left = c.blockSize;
    const out = new Uint8Array(buf.length + left);
    let prev = opts.iv.slice();
    let b = buf,
      o = out;
    while (b.length) {
      for (let i = 0; i < c.blockSize; i++) prev[i] ^= b[i];
      if (b.length < c.blockSize) break;
      c.encryptBlock(prev, prev);
      o.set(prev, 0);
      b = b.subarray(c.blockSize);
      o = o.subarray(c.blockSize);
    }
    // pcks7 padding
    for (let i = c.blockSize - left; i < c.blockSize; i++) prev[i] ^= left;
    c.encryptBlock(prev, o);
    return out;
  },
  decrypt: (buf, opts) => {
    const c = new STABLE_AES(opts.key);
    let prev = opts.iv.slice();
    const out = new Uint8Array(buf.length);
    let b = buf,
      o = out;
    while (b.length) {
      let pad = prev;
      prev = b;
      c.decryptBlock(b, o);
      for (let i = 0; i < c.blockSize; i++) o[i] ^= pad[i];
      b = b.subarray(c.blockSize);
      o = o.subarray(c.blockSize);
    }
    // strip pcks7 padding
    return out.subarray(0, -out[out.length - 1]);
  },
};
const stableECB = {
  encrypt: (buf, opts) => {
    const c = new STABLE_AES(opts.key);
    let left = c.blockSize - (buf.length % c.blockSize);
    if (!left) left = c.blockSize;
    const out = new Uint8Array(buf.length + left);
    let b = buf,
      o = out;
    while (b.length) {
      if (b.length < c.blockSize) break;
      c.encryptBlock(b, o);
      b = b.subarray(c.blockSize);
      o = o.subarray(c.blockSize);
    }
    // pcks7 padding
    for (let i = 0; i < b.length; i++) o[i] = b[i];
    for (let i = c.blockSize - left; i < c.blockSize; i++) o[i] = left;
    c.encryptBlock(o, o);
    return out;
  },
  decrypt: (buf, opts) => {
    const c = new STABLE_AES(opts.key);
    const out = new Uint8Array(buf.length);
    let b = buf,
      o = out;
    while (b.length) {
      c.decryptBlock(b, o);
      b = b.subarray(c.blockSize);
      o = o.subarray(c.blockSize);
    }
    // strip pcks7 padding
    return out.subarray(0, -out[out.length - 1]);
  },
};

const stableCTR = {
  encrypt: (buf, opts) => {
    const cipher = new STABLE_AES(opts.key);
    const ctr = new STABLE_CTR(cipher, opts.iv);
    const res = new Uint8Array(buf.length);
    ctr.streamXOR(buf, res);
    return res;
  },
  decrypt: (buf, opts) => {
    const cipher = new STABLE_AES(opts.key);
    const ctr = new STABLE_CTR(cipher, opts.iv);
    const res = new Uint8Array(buf.length);
    ctr.streamXOR(buf, res);
    return res;
  },
};

export const CIPHERS = {
  'ctr-128': {
    opts: { key: buf(16), iv: buf(16) },
    node: nodeAES('aes-128-ctr'),
    stablelib: stableCTR,
    aesjs: {
      encrypt: (buf, opts) => new aesjs.ModeOfOperation.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => new aesjs.ModeOfOperation.ctr(opts.key, opts.iv).decrypt(buf),
    },
    'noble-webcrypto': {
      encrypt: (buf, opts) => webcrypto.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => webcrypto.ctr(opts.key, opts.iv).decrypt(buf),
    },
    noble: {
      encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
    },
  },
  'ctr-256': {
    opts: { key: buf(32), iv: buf(16) },
    node: nodeAES('aes-256-ctr'),
    stablelib: stableCTR,
    aesjs: {
      encrypt: (buf, opts) => new aesjs.ModeOfOperation.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => new aesjs.ModeOfOperation.ctr(opts.key, opts.iv).decrypt(buf),
    },
    'noble-webcrypto': {
      encrypt: (buf, opts) => webcrypto.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => webcrypto.ctr(opts.key, opts.iv).decrypt(buf),
    },
    noble: {
      encrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.ctr(opts.key, opts.iv).decrypt(buf),
    },
  },
  'cbc-128': {
    opts: { key: buf(16), iv: buf(16) },
    node: nodeAES('aes-128-cbc'),
    stablelib: stableCBC,
    aesjs: {
      encrypt: (buf, opts) =>
        new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(aesjs.padding.pkcs7.pad(buf)),
      decrypt: (buf, opts) =>
        aesjs.padding.pkcs7.strip(new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf)),
    },
    'noble-webcrypto': {
      encrypt: (buf, opts) => webcrypto.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => webcrypto.cbc(opts.key, opts.iv).decrypt(buf),
    },
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
    },
  },
  'cbc-256': {
    opts: { key: buf(32), iv: buf(16) },
    node: nodeAES('aes-256-cbc'),
    stablelib: stableCBC,
    aesjs: {
      encrypt: (buf, opts) =>
        new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(aesjs.padding.pkcs7.pad(buf)),
      decrypt: (buf, opts) =>
        aesjs.padding.pkcs7.strip(new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf)),
    },
    'noble-webcrypto': {
      encrypt: (buf, opts) => webcrypto.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => webcrypto.cbc(opts.key, opts.iv).decrypt(buf),
    },
    noble: {
      encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv).decrypt(buf),
    },
  },
  'ecb-128': {
    opts: { key: buf(16), iv: null },
    node: nodeAES('aes-128-ecb'),
    stablelib: stableECB,
    aesjs: {
      encrypt: (buf, opts) =>
        new aesjs.ModeOfOperation.ecb(opts.key).encrypt(aesjs.padding.pkcs7.pad(buf)),
      decrypt: (buf, opts) =>
        aesjs.padding.pkcs7.strip(new aesjs.ModeOfOperation.ecb(opts.key).decrypt(buf)),
    },
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key).decrypt(buf),
    },
  },
  'ecb-256': {
    opts: { key: buf(32), iv: null },
    node: nodeAES('aes-256-ecb'),
    stablelib: stableECB,
    aesjs: {
      encrypt: (buf, opts) =>
        new aesjs.ModeOfOperation.ecb(opts.key).encrypt(aesjs.padding.pkcs7.pad(buf)),
      decrypt: (buf, opts) =>
        aesjs.padding.pkcs7.strip(new aesjs.ModeOfOperation.ecb(opts.key).decrypt(buf)),
    },
    noble: {
      encrypt: (buf, opts) => aes.ecb(opts.key).encrypt(buf),
      decrypt: (buf, opts) => aes.ecb(opts.key).decrypt(buf),
    },
  },
  // Not very important, but useful (also cross-test)
  // 'cbc-128-no-padding': {
  //   opts: { key: buf(16), iv: buf(16), blockSize: 16 },
  //   node: nodeAES('aes-128-cbc', false),
  //   aesjs: {
  //     encrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(buf),
  //     decrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf),
  //   },
  //   noble: {
  //     encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
  //     decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
  //   },
  // },
  // 'cbc-256-no-padding': {
  //   opts: { key: buf(32), iv: buf(16), blockSize: 16 },
  //   node: nodeAES('aes-256-cbc', false),
  //   aesjs: {
  //     encrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(buf),
  //     decrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf),
  //   },
  //   noble: {
  //     encrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
  //     decrypt: (buf, opts) => aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
  //   },
  // },
  // 'ecb-128-no-padding': {
  //   opts: { key: buf(16), iv: null, blockSize: 16 },
  //   node: nodeAES('aes-128-ecb', false),
  //   aesjs: {
  //     encrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).encrypt(buf),
  //     decrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).decrypt(buf),
  //   },
  //   noble: {
  //     encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
  //     decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
  //   },
  // },
  // 'ecb-256-no-padding': {
  //   opts: { key: buf(32), iv: null, blockSize: 16 },
  //   node: nodeAES('aes-256-ecb', false),
  //   aesjs: {
  //     encrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).encrypt(buf),
  //     decrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).decrypt(buf),
  //   },
  //   noble: {
  //     encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
  //     decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
  //   },
  // },
  // GCM related (slow)
  'gcm-128': {
    opts: { key: buf(16), iv: buf(12) },
    node: nodeGCM('aes-128-gcm'),
    stablelib: {
      encrypt: (buf, opts) => new STABLE_GCM(new STABLE_AES(opts.key)).seal(opts.iv, buf),
      decrypt: (buf, opts) => new STABLE_GCM(new STABLE_AES(opts.key)).open(opts.iv, buf),
    },
    'noble-webcrypto': {
      encrypt: (buf, opts) => webcrypto.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => webcrypto.gcm(opts.key, opts.iv).decrypt(buf),
    },
    noble: {
      encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).decrypt(buf),
    },
  },
  'gcm-256': {
    opts: { key: buf(32), iv: buf(12) },
    node: nodeGCM('aes-256-gcm'),
    stablelib: {
      encrypt: (buf, opts) => new STABLE_GCM(new STABLE_AES(opts.key)).seal(opts.iv, buf),
      decrypt: (buf, opts) => new STABLE_GCM(new STABLE_AES(opts.key)).open(opts.iv, buf),
    },
    'noble-webcrypto': {
      encrypt: (buf, opts) => webcrypto.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => webcrypto.gcm(opts.key, opts.iv).decrypt(buf),
    },
    noble: {
      encrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).encrypt(buf),
      decrypt: (buf, opts) => aes.gcm(opts.key, opts.iv).decrypt(buf),
    },
  },
  'gcm-siv-128': {
    opts: { key: buf(16), aad: buf(0), nonce: buf(12) },
    noble: {
      encrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).encrypt(buf),
      decrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).decrypt(buf),
    },
  },
  'gcm-siv-256': {
    opts: { key: buf(32), nonce: buf(12), aad: buf(16) },
    noble: {
      encrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).encrypt(buf),
      decrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).decrypt(buf),
    },
  },
};

// buffer title, sample count, data
const buffers = [
  // { size: '16B', samples: 1_500_000, data: buf(16) }, // common block size
  // { size: '32B', samples: 1_500_000, data: buf(32) },
  { size: '64B', samples: 1_000_000, data: buf(64) },
  { size: '1KB', samples: 50_000, data: buf(1024) },
  { size: '8KB', samples: 10_000, data: buf(1024 * 8) },
  { size: '1MB', samples: 100, data: buf(1024 * 1024) },
];

export async function main() {
  await crossValidate(buffers, CIPHERS);
  if (onlyNoble) return benchmarkOnlyNoble(buffers, CIPHERS);
  benchmarkAllLibraries(buffers, CIPHERS);
  butils.logMem();
}

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
