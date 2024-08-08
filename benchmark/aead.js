import { utils as butils } from 'micro-bmark';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import { concatBytes } from '@noble/ciphers/utils';
import { xchacha20poly1305, chacha20poly1305 } from '@noble/ciphers/chacha';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { gcm, siv } from '@noble/ciphers/aes';
import * as micro from '@noble/ciphers/_micro';

import { ChaCha20Poly1305 as StableChachaPoly } from '@stablelib/chacha20poly1305';
import { XChaCha20Poly1305 as StableXchachaPoly } from '@stablelib/xchacha20poly1305';
import { default as tweetnacl } from 'tweetnacl'; // secretbox = xsalsa20-poly1305.
import {
  ChaCha20Poly1305 as ChsfChachaPoly,
  newInstance as chainsafe_init_wasm,
} from '@chainsafe/as-chacha20poly1305';
import {
  crossValidate,
  onlyNoble,
  buf,
  benchmarkOnlyNoble,
  benchmarkAllLibraries,
} from './_utils.js';

const buffers = [
  { size: '64B', samples: 500_000, data: buf(64) },
  { size: '1KB', samples: 150_000, data: buf(1024) },
  { size: '8KB', samples: 20_000, data: buf(1024 * 8) },
  { size: '1MB', samples: 500, data: buf(1024 * 1024) },
];

let chainsafe_chacha_poly;

export const ciphers = {
  xsalsa20poly1305: {
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
  chacha20poly1305: {
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
  'aes-256-gcm': {
    opts: { key: buf(32), nonce: buf(12) },
    noble: {
      encrypt: (buf, opts) => gcm(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => gcm(opts.key, opts.nonce).decrypt(buf),
    },
  },
  'aes-256-gcm-siv': {
    opts: { key: buf(64), nonce: buf(12) },
    noble: {
      encrypt: (buf, opts) => siv(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => siv(opts.key, opts.nonce).decrypt(buf),
    },
  },
};

export async function main() {
  const ctx = chainsafe_init_wasm();
  chainsafe_chacha_poly = new ChsfChachaPoly(ctx);
  await crossValidate(buffers, ciphers);
  if (onlyNoble) return benchmarkOnlyNoble(buffers, ciphers);
  benchmarkAllLibraries(buffers, ciphers);
  butils.logMem();
}

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
