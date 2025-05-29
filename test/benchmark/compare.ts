import {
  ChaCha20Poly1305 as ChsfChachaPoly,
  newInstance as chainsafe_init_wasm,
} from '@chainsafe/as-chacha20poly1305';
import { AES as STABLE_AES } from '@stablelib/aes';
import { ChaCha20Poly1305 as StableChachaPoly } from '@stablelib/chacha20poly1305';
import { CTR as STABLE_CTR } from '@stablelib/ctr';
import { GCM as STABLE_GCM } from '@stablelib/gcm';
import { XChaCha20Poly1305 as StableXchachaPoly } from '@stablelib/xchacha20poly1305';
import { default as aesjs } from 'aes-js';
import compareMatrix from 'micro-bmark/compare.js';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { default as tweetnacl } from 'tweetnacl'; // secretbox = xsalsa20-poly1305.
import * as aes from '../../src/aes.ts';
import { chacha20poly1305, xchacha20poly1305 } from '../../src/chacha.ts';
import { xsalsa20poly1305 } from '../../src/salsa.ts';
import { concatBytes } from '../../src/utils.ts';
import * as webcrypto from '../../src/webcrypto.ts';
import { buf, crossValidate } from './_utils.ts';
// ciphers.js
import { streamXOR as stableChacha } from '@stablelib/chacha';
import { streamXOR as stableSalsa } from '@stablelib/salsa20';
import { streamXOR as stableXchacha } from '@stablelib/xchacha20';
import { streamXOR as stableXSalsa } from '@stablelib/xsalsa20';
import { chacha20, xchacha20 } from '../../src/chacha.ts';
import { salsa20, xsalsa20 } from '../../src/salsa.ts';

const cipherSame = (fn) => ({ encrypt: fn, decrypt: fn });

let chainsafe_chacha_poly;

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

// type: 'AES/AEAD', 'Algorithm', Padding, keySize, direction
export const CIPHERS = {
  // Previously AES, changed for easier filtering
  Basic: {
    'aes-ctr': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(16) },
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
        256: {
          options: { key: buf(32), iv: buf(16) },
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
      },
    },
    'aes-cbc': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(16) },
          node: nodeAES('aes-128-cbc'),
          stablelib: stableCBC,
          aesjs: {
            encrypt: (buf, opts) =>
              new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(
                aesjs.padding.pkcs7.pad(buf)
              ),
            decrypt: (buf, opts) =>
              aesjs.padding.pkcs7.strip(
                new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf)
              ),
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
        256: {
          options: { key: buf(32), iv: buf(16) },
          node: nodeAES('aes-256-cbc'),
          stablelib: stableCBC,
          aesjs: {
            encrypt: (buf, opts) =>
              new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(
                aesjs.padding.pkcs7.pad(buf)
              ),
            decrypt: (buf, opts) =>
              aesjs.padding.pkcs7.strip(
                new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf)
              ),
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
      },
      NoPadding: {
        128: {
          options: { key: buf(16), iv: buf(16), blockSize: 16 },
          node: nodeAES('aes-128-cbc', false),
          aesjs: {
            encrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(buf),
            decrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf),
          },
          noble: {
            encrypt: (buf, opts) =>
              aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
            decrypt: (buf, opts) =>
              aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
          },
        },
        256: {
          options: { key: buf(32), iv: buf(16), blockSize: 16 },
          node: nodeAES('aes-256-cbc', false),
          aesjs: {
            encrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).encrypt(buf),
            decrypt: (buf, opts) => new aesjs.ModeOfOperation.cbc(opts.key, opts.iv).decrypt(buf),
          },
          noble: {
            encrypt: (buf, opts) =>
              aes.cbc(opts.key, opts.iv, { disablePadding: true }).encrypt(buf),
            decrypt: (buf, opts) =>
              aes.cbc(opts.key, opts.iv, { disablePadding: true }).decrypt(buf),
          },
        },
      },
    },
    'aec-ecb': {
      padding: {
        128: {
          options: { key: buf(16), iv: null },
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
        256: {
          options: { key: buf(32), iv: null },
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
      },
      NoPadding: {
        128: {
          options: { key: buf(16), iv: null, blockSize: 16 },
          node: nodeAES('aes-128-ecb', false),
          aesjs: {
            encrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).encrypt(buf),
            decrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).decrypt(buf),
          },
          noble: {
            encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
            decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
          },
        },
        256: {
          options: { key: buf(32), iv: null, blockSize: 16 },
          node: nodeAES('aes-256-ecb', false),
          aesjs: {
            encrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).encrypt(buf),
            decrypt: (buf, opts) => new aesjs.ModeOfOperation.ecb(opts.key).decrypt(buf),
          },
          noble: {
            encrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).encrypt(buf),
            decrypt: (buf, opts) => aes.ecb(opts.key, { disablePadding: true }).decrypt(buf),
          },
        },
      },
    },
  },
  Same: {
    salsa: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(8) },
          stablelib: cipherSame((buf, opts) =>
            stableSalsa(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
          ),
          noble: cipherSame((buf, opts) => salsa20(opts.key, opts.nonce, buf)),
        },
      },
    },
    chacha: {
      padding: {
        256: {
          options: {
            key: buf(32),
            nonce: buf(12),
            nonce16: concatBytes(new Uint8Array(4), buf(12)),
          },
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
        },
      },
    },
    xsalsa: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          stablelib: cipherSame((buf, opts) =>
            stableXSalsa(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
          ),
          noble: cipherSame((buf, opts) => xsalsa20(opts.key, opts.nonce, buf)),
        },
      },
    },
    xchacha: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          stablelib: cipherSame((buf, opts) =>
            stableXchacha(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
          ),
          noble: cipherSame((buf, opts) => xchacha20(opts.key, opts.nonce, buf)),
        },
      },
    },
  },
  AEAD: {
    xsalsa20poly1305: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          tweetnacl: {
            encrypt: (buf, opts) => tweetnacl.secretbox(buf, opts.nonce, opts.key),
            decrypt: (buf, opts) => tweetnacl.secretbox.open(buf, opts.nonce, opts.key),
          },
          noble: {
            encrypt: (buf, opts) => xsalsa20poly1305(opts.key, opts.nonce).encrypt(buf),
            decrypt: (buf, opts) => xsalsa20poly1305(opts.key, opts.nonce).decrypt(buf),
          },
        },
      },
    },
    chacha20poly1305: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(12) },
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
        },
      },
    },
    xchacha20poly1305: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          stable: {
            encrypt: (buf, opts) => new StableXchachaPoly(opts.key).seal(opts.nonce, buf),
            decrypt: (buf, opts) => new StableXchachaPoly(opts.key).open(opts.nonce, buf),
          },
          noble: {
            encrypt: (buf, opts) => xchacha20poly1305(opts.key, opts.nonce).encrypt(buf),
            decrypt: (buf, opts) => xchacha20poly1305(opts.key, opts.nonce).decrypt(buf),
          },
        },
      },
    },
    'AES-GCM': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(12) },
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
        256: {
          options: { key: buf(32), iv: buf(12) },
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
      },
    },
    'AES-SIV': {
      padding: {
        128: {
          options: { key: buf(16), aad: buf(0), nonce: buf(12) },
          noble: {
            encrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).encrypt(buf),
            decrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).decrypt(buf),
          },
        },
        256: {
          options: { key: buf(32), nonce: buf(12), aad: buf(16) },
          noble: {
            encrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).encrypt(buf),
            decrypt: (buf, opts) => aes.siv(opts.key, opts.nonce, opts.aad).decrypt(buf),
          },
        },
      },
    },
  },
};

const BUFFERS = {
  '16B': buf(16),
  '32B': buf(32),
  '64B': buf(64),
  '1KB': buf(1024),
  '8KB': buf(1024 * 8),
  '1MB': buf(1024 * 1024),
};

export async function main() {
  const ctx = chainsafe_init_wasm();
  chainsafe_chacha_poly = new ChsfChachaPoly(ctx);

  // Usage:
  // Basic: node basic.js
  // Complex: MBENCH_DIMS='buffer,type,padding,key size,algorithm,library,direction' node basic.js
  // NOTE: we doing iterations here, because it depends on structure, also we need encrypted buffers!
  const encrypted = {};
  for (const [type, algorithms] of Object.entries(CIPHERS)) {
    for (const [algo, paddings] of Object.entries(algorithms)) {
      for (const [padding, keySizes] of Object.entries(paddings)) {
        for (const [keySize, libraries] of Object.entries(keySizes)) {
          const name = `${type}/${algo}/${padding}/${keySize}`;
          encrypted[name] = await crossValidate(
            `${type}/${algo}/${padding}/${keySize}`,
            BUFFERS,
            libraries
          );
        }
      }
    }
  }
  console.log('Libraries cross-validated against each other correctly');

  await compareMatrix('Ciphers', { buffer: BUFFERS }, CIPHERS, {
    // type: Basic/Same/AEAD
    // 'Algorithm', Padding, keySize, direction (encrypt/decrypt)
    libDims: ['type', 'algorithm', 'padding', 'key size', 'library', 'direction'],
    defaults: {
      buffer: '64B',
      library: 'noble',
      direction: 'encrypt',
      'key size': '256',
      padding: 'padding',
    },
    samples: (buf) => {
      if (buf.length <= 64) return 1_000_000;
      if (buf.length <= 8 * 1024) return 50_000;
      return 100;
    },
    patchArgs: (args, obj) => {
      // Replace buffer with "encrypted" version
      if (obj['direction'] === 'decrypt') {
        const buf =
          encrypted[`${obj.type}/${obj.algorithm}/${obj.padding}/${obj['key size']}`][obj.buffer];
        return [buf, args[1]];
      }
      return args;
    },
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
