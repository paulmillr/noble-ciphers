import { deepStrictEqual } from 'assert';
import { run, mark, compare, utils as butils } from 'micro-bmark';
import * as crypto from 'node:crypto';
// import { AES as siv } from '../esm/webcrypto/siv.js';
// import * as gcm from '../esm/webcrypto/aes.js';
import * as utils from '../esm/utils.js';
import { salsa20, xsalsa20, xsalsa20_poly1305 } from '../esm/salsa.js';
import { chacha20, xchacha20, xchacha20_poly1305, chacha20_poly1305 } from '../esm/chacha.js';
import { poly1305 } from '../esm/_poly1305.js';
import * as slow from '../esm/_micro.js';
// StableLib
import * as stableSalsa from '@stablelib/salsa20';
import * as stableXSalsa from '@stablelib/xsalsa20';
import * as stableChacha from '@stablelib/chacha';
import * as stableXchacha from '@stablelib/xchacha20';
import { ChaCha20Poly1305 as StableChachaPoly } from '@stablelib/chacha20poly1305';
import { XChaCha20Poly1305 as StableXchachaPoly } from '@stablelib/xchacha20poly1305';
import { oneTimeAuth as stablePoly1305 } from '@stablelib/poly1305';
import { default as tweetnacl } from 'tweetnacl'; // secretbox = xsalsa20-poly1305.

const ONLY_NOBLE = process.argv[2] === 'noble';

const buf = (n) => new Uint8Array(n).fill(n);

// Works for gcm only?
const nodeGCM = (name) => {
  return {
    encrypt: (buf, opts) => {
      const res = [opts.iv];
      const c = crypto.createCipheriv(name, opts.key, opts.iv);
      if (opts.aad) c.setAAD(opts.aad);
      res.push(c.update(buf));
      res.push(c.final());
      res.push(c.getAuthTag());
      return utils.concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice(12, -16);
      const authTag = buf.slice(-16);
      const decipher = crypto.createDecipheriv(name, opts.key, opts.iv);
      if (opts.aad) c.setAAD(opts.aad);
      decipher.setAuthTag(authTag);
      return utils.concatBytes(
        ...[decipher.update(ciphertext), decipher.final()].map((i) => Uint8Array.from(i))
      );
    },
  };
};

const cipherSame = (fn) => ({ encrypt: fn, decrypt: fn });

export const CIPHERS = {
  salsa: {
    opts: { key: buf(32), nonce: buf(8) },
    stablelib: cipherSame((buf, opts) =>
      stableSalsa.streamXOR(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => salsa20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => slow.salsa20(opts.key, opts.nonce, buf)),
  },
  chacha: {
    opts: { key: buf(32), nonce: buf(12), nonce16: utils.concatBytes(new Uint8Array(4), buf(12)) },
    node: {
      encrypt: (buf, opts) => {
        const c = crypto.createCipheriv('chacha20', opts.key, opts.nonce16);
        const res = c.update(buf);
        c.final();
        return Uint8Array.from(res);
      },
      decrypt: (buf, opts) => {
        const decipher = crypto.createDecipheriv('chacha20', opts.key, opts.nonce16);
        const res = decipher.update(buf);
        decipher.final();
        return Uint8Array.from(res);
      },
    },
    stablelib: cipherSame((buf, opts) =>
      stableChacha.streamXOR(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => chacha20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => slow.chacha20(opts.key, opts.nonce, buf)),
  },
  xsalsa: {
    opts: { key: buf(32), nonce: buf(24) },
    stablelib: cipherSame((buf, opts) =>
      stableXSalsa.streamXOR(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => xsalsa20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => slow.xsalsa20(opts.key, opts.nonce, buf)),
  },
  xchacha: {
    opts: { key: buf(32), nonce: buf(24) },
    stablelib: cipherSame((buf, opts) =>
      stableXchacha.streamXOR(opts.key, opts.nonce, buf, new Uint8Array(buf.length))
    ),
    noble: cipherSame((buf, opts) => xchacha20(opts.key, opts.nonce, buf)),
    micro: cipherSame((buf, opts) => slow.xchacha20(opts.key, opts.nonce, buf)),
  },
  xsalsa20_poly1305: {
    opts: { key: buf(32), nonce: buf(24) },
    tweetnacl: {
      encrypt: (buf, opts) => tweetnacl.secretbox(buf, opts.nonce, opts.key),
      decrypt: (buf, opts) => tweetnacl.secretbox.open(buf, opts.nonce, opts.key),
    },
    noble: {
      encrypt: (buf, opts) => xsalsa20_poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => xsalsa20_poly1305(opts.key, opts.nonce).decrypt(buf),
    },
    micro: {
      encrypt: (buf, opts) => slow.xsalsa20_poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => slow.xsalsa20_poly1305(opts.key, opts.nonce).decrypt(buf),
    },
  },
  chacha20_poly1305: {
    opts: { key: buf(32), nonce: buf(12) },
    node: {
      encrypt: (buf, opts) => {
        const c = crypto.createCipheriv('chacha20-poly1305', opts.key, opts.nonce);
        const res = [];
        res.push(c.update(buf));
        res.push(c.final());
        res.push(c.getAuthTag());
        return utils.concatBytes(...res.map((i) => Uint8Array.from(i)));
      },
      decrypt: (buf, opts) => {
        const ciphertext = buf.slice(0, -16);
        const authTag = buf.slice(-16);
        const decipher = crypto.createDecipheriv('chacha20-poly1305', opts.key, opts.nonce);
        decipher.setAuthTag(authTag);
        return utils.concatBytes(
          ...[decipher.update(ciphertext), decipher.final()].map((i) => Uint8Array.from(i))
        );
      },
    },
    stable: {
      encrypt: (buf, opts) => new StableChachaPoly(opts.key).seal(opts.nonce, buf),
      decrypt: (buf, opts) => new StableChachaPoly(opts.key).open(opts.nonce, buf),
    },
    noble: {
      encrypt: (buf, opts) => chacha20_poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => chacha20_poly1305(opts.key, opts.nonce).decrypt(buf),
    },
    micro: {
      encrypt: (buf, opts) => slow.chacha20_poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => slow.chacha20_poly1305(opts.key, opts.nonce).decrypt(buf),
    },
  },
  xchacha20poly1305: {
    opts: { key: buf(32), nonce: buf(24) },
    stable: {
      encrypt: (buf, opts) => new StableXchachaPoly(opts.key).seal(opts.nonce, buf),
      decrypt: (buf, opts) => new StableXchachaPoly(opts.key).open(opts.nonce, buf),
    },
    noble: {
      encrypt: (buf, opts) => xchacha20_poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => xchacha20_poly1305(opts.key, opts.nonce).decrypt(buf),
    },
    micro: {
      encrypt: (buf, opts) => slow.xchacha20_poly1305(opts.key, opts.nonce).encrypt(buf),
      decrypt: (buf, opts) => slow.xchacha20_poly1305(opts.key, opts.nonce).decrypt(buf),
    },
  },
  // TODO: why this is so slow?
  // 'gcm-256': {
  //   opts: { key: buf(32), iv: buf(12) },
  //   node: nodeGCM('aes-256-gcm'),
  //   noble: {
  //     encrypt: (buf, opts) => gcm.encrypt(opts.key, buf, opts.iv),
  //     decrypt: (buf, opts) => gcm.decrypt(opts.key, buf, opts.iv),
  //   },
  // },
  // 'gcm-siv-128': {
  //   opts: { key: buf(16), aad: buf(0), nonce: buf(12) },
  //   noble: {
  //     encrypt: async (buf, opts) => await (await siv(opts.key, opts.nonce, opts.aad)).encrypt(buf),
  //     decrypt: async (buf, opts) => await (await siv(opts.key, opts.nonce, opts.aad)).decrypt(buf),
  //   },
  // },
  // 'gcm-siv-256': {
  //   opts: { key: buf(32), aad: buf(0), nonce: buf(12) },
  //   noble: {
  //     encrypt: async (buf, opts) => await (await siv(opts.key, opts.nonce, opts.aad)).encrypt(buf),
  //     decrypt: async (buf, opts) => await (await siv(opts.key, opts.nonce, opts.aad)).decrypt(buf),
  //   },
  // },
};

const HASHES = {
  poly1305: {
    opts: { key: buf(32) },
    stable: (buf, opts) => stablePoly1305(opts.key, buf),
    // function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
    tweetnacl: (buf, opts) => {
      // Such awesome API!
      const res = new Uint8Array(16);
      tweetnacl.lowlevel.crypto_onetimeauth(res, 0, buf, 0, buf.length, opts.key);
      return res;
    },
    noble: (buf, opts) => poly1305(buf, opts.key),
    micro: (buf, opts) => slow.poly1305(buf, opts.key),
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
  for (const [size, [samples, buf]] of Object.entries(buffers)) {
    const b = buf.slice();
    // hashes
    for (let [k, libs] of Object.entries(HASHES)) {
      let value;
      for (const [lib, fn] of Object.entries(libs)) {
        if (lib === 'opts') continue;
        if (value === undefined) value = fn(buf, libs.opts);
        else {
          const cur = fn(buf, libs.opts);
          deepStrictEqual(value, cur, `hash verify (${lib})`);
        }
        deepStrictEqual(buf, b, `hash mutates buffer (${lib})`);
      }
    }
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
}

export const main = () =>
  run(async () => {
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
  });

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
