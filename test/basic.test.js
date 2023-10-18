const { deepStrictEqual } = require('assert');
const { should, describe } = require('micro-should');
const { hex } = require('@scure/base');
const { managedNonce, randomBytes } = require('../webcrypto/utils.js');

const { siv, gcm, ctr, ecb, cbc } = require('../aes.js');
const { xsalsa20poly1305 } = require('../salsa.js');
const { chacha20poly1305, xchacha20poly1305 } = require('../chacha.js');
const micro = require('../_micro.js');

const CIPHERS = {
  xsalsa20poly1305: { fn: xsalsa20poly1305, keyLen: 32, withNonce: true },
  chacha20poly1305: { fn: chacha20poly1305, keyLen: 32, withNonce: true },
  xchacha20poly1305: { fn: xchacha20poly1305, keyLen: 32, withNonce: true },

  micro_xsalsa20poly1305: { fn: micro.xsalsa20poly1305, keyLen: 32, withNonce: true },
  micro_chacha20poly1305: { fn: micro.chacha20poly1305, keyLen: 32, withNonce: true },
  micro_xchacha20poly1305: { fn: micro.xchacha20poly1305, keyLen: 32, withNonce: true },
};

for (const [name, fn] of Object.entries({ ecb, cbc, ctr, gcm, siv })) {
  for (const keyLen of [16, 24, 32]) {
    CIPHERS[`${name}_${keyLen * 8}`] = { fn, keyLen, withNonce: name !== 'ecb' };
  }
}

for (const k in CIPHERS) {
  const opts = CIPHERS[k];
  if (!opts.withNonce) continue;
  CIPHERS[`${k}_managedNonce`] = { ...opts, fn: managedNonce(opts.fn), withNonce: false };
}

// Just to verify parameter passing works, should throw on round-trip test, but pass blockSize
// CIPHERS.test = { fn: managedNonce(cbc), args: [{ disablePadding: true }] };

const initCipher = (opts) => {
  const { fn, keyLen, withNonce } = opts;
  const args = opts.args || [];
  const key = randomBytes(keyLen);
  if (withNonce) {
    const nonce = randomBytes(fn.nonceLength);
    return fn(key, nonce, ...args);
  }
  return fn(key, ...args);
};

describe('Basic', () => {
  for (const k in CIPHERS) {
    const opts = CIPHERS[k];
    should(`${k}: blockSize`, () => {
      const c = initCipher(opts);
      const msg = new Uint8Array(opts.fn.blockSize).fill(12);
      deepStrictEqual(c.decrypt(c.encrypt(msg.slice())), msg);
    });

    should(`${k}: round-trip`, () => {
      const c = initCipher(opts);
      // slice, so cipher has no way to corrupt msg
      const msg = new Uint8Array(2).fill(12);
      deepStrictEqual(c.decrypt(c.encrypt(msg.slice())), msg);
      const msg2 = new Uint8Array(2048).fill(255);
      deepStrictEqual(c.decrypt(c.encrypt(msg2.slice())), msg2);
      const msg3 = new Uint8Array(256);
      deepStrictEqual(c.decrypt(c.encrypt(msg3.slice())), msg3);
    });
    should(`${k}: different sizes`, () => {
      const c = initCipher(opts);
      for (let i = 0; i < 2048; i++) {
        const msg = new Uint8Array(i).fill(i);
        deepStrictEqual(c.decrypt(c.encrypt(msg.slice())), msg);
      }
    });
  }
});

if (require.main === module) should.run();
