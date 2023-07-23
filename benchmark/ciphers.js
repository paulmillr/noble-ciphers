import { createCipheriv, createDecipheriv } from 'node:crypto';

import { concatBytes } from '@noble/ciphers/utils';
import { salsa20, xsalsa20 } from '@noble/ciphers/salsa';
import { chacha20, xchacha20 } from '@noble/ciphers/chacha';
import * as micro from '@noble/ciphers/_micro';

import { streamXOR as stableSalsa } from '@stablelib/salsa20';
import { streamXOR as stableXSalsa } from '@stablelib/xsalsa20';
import { streamXOR as stableChacha } from '@stablelib/chacha';
import { streamXOR as stableXchacha } from '@stablelib/xchacha20';

import {
  crossValidate,
  onlyNoble,
  benchmarkAllLibraries,
  benchmarkOnlyNoble,
  buf,
} from './_utils.js';

// Non-authenticated ciphers. aead.js contains authenticated ones
const buffers = [
  { size: '64B', samples: 1_500_000, data: buf(64) },
  { size: '1KB', samples: 300_000, data: buf(1024) },
  { size: '8KB', samples: 50_000, data: buf(1024 * 8) },
  { size: '1MB', samples: 300, data: buf(1024 * 1024) },
];

const cipherSame = (fn) => ({ encrypt: fn, decrypt: fn });

export const ciphers = {
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

export async function main() {
  await crossValidate(buffers, ciphers);
  if (onlyNoble) return benchmarkOnlyNoble(buffers, ciphers);
  benchmarkAllLibraries(buffers, ciphers);
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
