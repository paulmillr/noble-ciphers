const { deepStrictEqual, throws } = require('assert');
const { should, describe } = require('micro-should');
const { managedNonce, randomBytes } = require('../webcrypto.js');
const { siv, gcm, ctr, ecb, cbc, cfb, aeskw, aeskwp } = require('../aes.js');
const { xsalsa20poly1305 } = require('../salsa.js');
const { chacha20poly1305, xchacha20poly1305 } = require('../chacha.js');
const { unalign, TYPE_TEST } = require('./utils.js');
const micro = require('../_micro.js');

const CIPHERS = {
  xsalsa20poly1305: { fn: xsalsa20poly1305, keyLen: 32, withNonce: true },
  chacha20poly1305: { fn: chacha20poly1305, keyLen: 32, withNonce: true, withDST: true },
  xchacha20poly1305: { fn: xchacha20poly1305, keyLen: 32, withNonce: true, withDST: true },

  micro_xsalsa20poly1305: { fn: micro.xsalsa20poly1305, keyLen: 32, withNonce: true },
  micro_chacha20poly1305: { fn: micro.chacha20poly1305, keyLen: 32, withNonce: true },
  micro_xchacha20poly1305: { fn: micro.xchacha20poly1305, keyLen: 32, withNonce: true },
};

for (const keyLen of [16, 24, 32]) {
  for (const [name, fn] of Object.entries({ cbc, ctr, gcm, siv, cfb }))
    CIPHERS[`${name}_${keyLen * 8}`] = { fn, keyLen, withNonce: true };
  CIPHERS[`ecb_${keyLen * 8}`] = { fn: ecb, keyLen, withNonce: false };
  CIPHERS[`aeskw_${keyLen * 8}`] = {
    fn: aeskw,
    keyLen,
    withNonce: false,
    blockSize: 8,
    minLength: 16,
  };
  CIPHERS[`aeskwp_${keyLen * 8}`] = { fn: aeskwp, keyLen, disableEmptyBlock: true };
}

for (const k in CIPHERS) {
  const opts = CIPHERS[k];
  if (!opts.withNonce) continue;
  CIPHERS[`${k}_managedNonce`] = { ...opts, fn: managedNonce(opts.fn), withNonce: false };
}
CIPHERS.managedCbcNoPadding = {
  fn: managedNonce(cbc),
  args: [{ disablePadding: true }],
  blockSize: 16,
};

const checkBlockSize = (opts, len) => {
  if (opts.minLength && len < opts.minLength) return false;
  if (!len && opts.disableEmptyBlock) return false;
  if (!opts.blockSize) return true;
  if (len % opts.blockSize === 0) return true;
  return false;
};

const initCipher = (opts) => {
  const { fn, keyLen, withNonce } = opts;
  const args = opts.args || [];
  const key = randomBytes(keyLen);
  const nonce = randomBytes(fn.nonceLength);
  const c = withNonce ? fn(key, nonce, ...args) : fn(key, ...args);
  return { c, key, nonce, copy: { key: key.slice(), nonce: nonce.slice() } };
};

describe('Basic', () => {
  for (const k in CIPHERS) {
    const opts = CIPHERS[k];
    should(`${k}: blockSize`, () => {
      const { c, key, nonce, copy } = initCipher(opts);
      const msg = new Uint8Array(opts.fn.blockSize).fill(12);
      const msgCopy = msg.slice();
      if (checkBlockSize(opts, msgCopy.length)) {
        deepStrictEqual(c.decrypt(c.encrypt(msgCopy)), msg);
        deepStrictEqual(msg, msgCopy);
        // Verify that key/nonce is not modified
        deepStrictEqual(key, copy.key);
        deepStrictEqual(nonce, copy.nonce);
      }
    });

    should(`${k}: round-trip`, () => {
      // slice, so cipher has no way to corrupt msg
      const msg = new Uint8Array(2).fill(12);
      const msgCopy = msg.slice();
      if (checkBlockSize(opts, msgCopy.length)) {
        const { c, key, nonce, copy } = initCipher(opts);
        deepStrictEqual(c.decrypt(c.encrypt(msgCopy)), msg);
        deepStrictEqual(msg, msgCopy);
      }

      const msg2 = new Uint8Array(2048).fill(255);
      const msg2Copy = msg2.slice();
      if (checkBlockSize(opts, msg2Copy.length)) {
        const { c, key, nonce, copy } = initCipher(opts);
        deepStrictEqual(c.decrypt(c.encrypt(msg2)), msg2);
        deepStrictEqual(msg2, msg2Copy);
      }

      const { c, key, nonce, copy } = initCipher(opts);
      const msg3 = new Uint8Array(256);
      const msg3Copy = msg3.slice();
      if (!checkBlockSize(opts, msg3Copy.length)) {
        deepStrictEqual(c.decrypt(c.encrypt(msg3Copy)), msg3);
        deepStrictEqual(msg3, msg3Copy);
      }
      // Verify that key/nonce is not modified
      deepStrictEqual(key, copy.key);
      deepStrictEqual(nonce, copy.nonce);
    });
    should(`${k}: different sizes`, () => {
      for (let i = 0; i < 2048; i++) {
        const msg = new Uint8Array(i).fill(i);
        const msgCopy = msg.slice();
        if (checkBlockSize(opts, msgCopy.length)) {
          const { c, key, nonce, copy } = initCipher(opts);
          deepStrictEqual(c.decrypt(c.encrypt(msg)), msg);
          deepStrictEqual(msg, msgCopy);

          deepStrictEqual(key, copy.key);
          deepStrictEqual(nonce, copy.nonce);
        }
      }
    });
    for (let i = 0; i < 8; i++) {
      should(`${k} (unalign ${i})`, () => {
        const { fn, keyLen } = opts;
        const key = unalign(randomBytes(keyLen), i);
        const nonce = unalign(randomBytes(fn.nonceLength), i);
        const AAD = unalign(randomBytes(64), i);
        const msg = unalign(new Uint8Array(2048).fill(255), i);
        if (checkBlockSize(opts, msg.length)) {
          const cipher = fn(key, nonce, AAD);
          const encrypted = unalign(cipher.encrypt(msg), i);
          const decrypted = cipher.decrypt(encrypted);
          deepStrictEqual(decrypted, msg);
        }
      });
    }

    const msg_10 = new Uint8Array(10);
    if (checkBlockSize(opts, msg_10.length) && !k.endsWith('_managedNonce')) {
      should(`${k}: prohibit encrypting twice`, () => {
        const { c } = initCipher(opts);
        c.encrypt(msg_10);
        throws(() => {
          c.encrypt(msg_10);
        });
      });
    }
  }
});

// In basic.test.js, add after existing tests:

describe('input validation', () => {
  const INVALID_BYTE_ARRAYS = TYPE_TEST.bytes;

  for (const k in CIPHERS) {
    const opts = CIPHERS[k];
    const { fn, keyLen } = opts;

    if (k.includes('managed')) continue;
    describe(k, () => {
      // Constructor tests
      should('reject invalid key', () => {
        const nonce = new Uint8Array(fn.nonceLength);
        const aad = new Uint8Array(16);

        for (const invalid of INVALID_BYTE_ARRAYS) {
          throws(() => fn(invalid, nonce), 'non-u8a');
        }

        // Test wrong key length
        const msg = new Uint8Array(1);
        throws(() => fn(new Uint8Array(keyLen + 1), nonce).encrypt(msg), 'key length + 1');
        throws(() => fn(new Uint8Array(keyLen - 1), nonce).encrypt(msg), 'key length - 1');
      });

      if (fn.nonceLength) {
        should('reject invalid nonce', () => {
          const key = new Uint8Array(keyLen);
          const aad = new Uint8Array(16);

          for (const invalid of INVALID_BYTE_ARRAYS) {
            throws(() => fn(key, invalid));
          }

          // Test wrong nonce length
          if (fn.varSizeNonce) return;
          const msg = new Uint8Array(1);
          throws(() => fn(key, new Uint8Array(fn.nonceLength + 1)).encrypt(msg));
          throws(() => fn(key, new Uint8Array(fn.nonceLength - 1)).encrypt(msg));
        });
      }

      if (fn.tagLength && k !== 'xsalsa20poly1305') {
        should('reject invalid AAD', () => {
          const key = new Uint8Array(keyLen);
          const nonce = new Uint8Array(fn.nonceLength);

          for (const invalid of INVALID_BYTE_ARRAYS) {
            if (invalid == null) return;
            throws(() => fn(key, nonce, invalid));
          }
        });
      }

      // Method tests
      should('reject invalid encrypt input', () => {
        const key = new Uint8Array(keyLen);
        const nonce = fn.nonceLength ? new Uint8Array(fn.nonceLength) : undefined;
        const cipher = nonce ? fn(key, nonce) : fn(key);

        for (const invalid of INVALID_BYTE_ARRAYS) {
          throws(() => cipher.encrypt(invalid));
        }
      });

      should('reject invalid decrypt input', () => {
        const key = new Uint8Array(keyLen);
        const nonce = fn.nonceLength ? new Uint8Array(fn.nonceLength) : undefined;
        const cipher = nonce ? fn(key, nonce) : fn(key);

        for (const invalid of INVALID_BYTE_ARRAYS) {
          throws(() => cipher.decrypt(invalid));
        }
      });

      if (opts.blockSize) {
        should('validate block size on encrypt', () => {
          const key = new Uint8Array(keyLen);
          const nonce = fn.nonceLength ? new Uint8Array(fn.nonceLength) : undefined;
          const cipher = nonce ? fn(key, nonce) : fn(key);

          // Test invalid block size if padding is disabled
          if (opts.disablePadding) {
            throws(() => cipher.encrypt(new Uint8Array(opts.blockSize - 1)));
            throws(() => cipher.encrypt(new Uint8Array(opts.blockSize + 1)));
          }
        });
      }

      if (fn.tagLength) {
        should('validate tag length on decrypt', () => {
          const key = new Uint8Array(keyLen);
          const nonce = new Uint8Array(fn.nonceLength);
          const cipher = fn(key, nonce);

          // Test ciphertext lengths that would result in invalid tag
          throws(() => cipher.decrypt(new Uint8Array(fn.tagLength - 1)));
          throws(() => cipher.decrypt(new Uint8Array(15)));
        });
      }
    });
  }
});

if (require.main === module) should.run();
