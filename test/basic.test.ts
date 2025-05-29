import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { aeskw, aeskwp, cbc, cfb, ctr, ecb, gcm, gcmsiv } from '../src/aes.ts';
import { chacha20poly1305, xchacha20poly1305 } from '../src/chacha.ts';
import { xsalsa20poly1305 } from '../src/salsa.ts';
import { managedNonce, randomBytes } from '../src/webcrypto.ts';
import { TYPE_TEST, unalign } from './utils.ts';

const CIPHERS = {
  xsalsa20poly1305: { fn: xsalsa20poly1305, keyLen: 32, withNonce: true },
  chacha20poly1305: { fn: chacha20poly1305, keyLen: 32, withNonce: true, withDST: true },
  xchacha20poly1305: { fn: xchacha20poly1305, keyLen: 32, withNonce: true, withDST: true },
};

for (const keyLen of [16, 24, 32]) {
  for (const [name, fn] of Object.entries({ cbc, ctr, gcm, gcmsiv, cfb }))
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
      const msg = new Uint8Array(opts.blockSize).fill(12);
      const msgCopy = msg.slice();
      if (checkBlockSize(opts, msgCopy.length)) {
        eql(c.decrypt(c.encrypt(msgCopy)), msg);
        eql(msg, msgCopy);
        // Verify that key/nonce is not modified
        eql(key, copy.key);
        eql(nonce, copy.nonce);
      }
    });
    if (opts.blockSize) {
      should(`${k}: wrong blockSize`, () => {
        const { c } = initCipher(opts);
        const msg = new Uint8Array(opts.blockSize - 1).fill(12);
        throws(() => c.encrypt(msg));
        throws(() => c.decrypt(msg));
      });
    }
    should(`${k}: round-trip`, () => {
      // slice, so cipher has no way to corrupt msg
      const msg = new Uint8Array(2).fill(12);
      const msgCopy = msg.slice();
      if (checkBlockSize(opts, msgCopy.length)) {
        const { c, key, nonce, copy } = initCipher(opts);
        eql(c.decrypt(c.encrypt(msgCopy)), msg);
        eql(msg, msgCopy);
      }

      const msg2 = new Uint8Array(2048).fill(255);
      const msg2Copy = msg2.slice();
      if (checkBlockSize(opts, msg2Copy.length)) {
        const { c, key, nonce, copy } = initCipher(opts);
        eql(c.decrypt(c.encrypt(msg2)), msg2);
        eql(msg2, msg2Copy);
      }

      const { c, key, nonce, copy } = initCipher(opts);
      const msg3 = new Uint8Array(256).fill(3);
      const msg3Copy = msg3.slice();
      if (!checkBlockSize(opts, msg3Copy.length)) {
        eql(c.decrypt(c.encrypt(msg3Copy)), msg3);
        eql(msg3, msg3Copy);
      }
      // Verify that key/nonce is not modified
      eql(key, copy.key);
      eql(nonce, copy.nonce);
    });
    should(`${k}: different sizes`, () => {
      for (let i = 0; i < 2048; i++) {
        const msg = new Uint8Array(i).fill(i);
        const msgCopy = msg.slice();
        if (checkBlockSize(opts, msgCopy.length)) {
          const { c, key, nonce, copy } = initCipher(opts);
          eql(c.decrypt(c.encrypt(msg)), msg);
          eql(msg, msgCopy);

          eql(key, copy.key);
          eql(nonce, copy.nonce);
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
          eql(decrypted, msg);
        }
      });
    }
    const overlapTest = (a, b, cb) => {
      const buffer = new Uint8Array(a.length + b.length);
      let inputPos = 0;
      let outputPos = a.length;
      const t = () => {
        const aBuf = buffer.subarray(inputPos, inputPos + a.length);
        const bBuf = buffer.subarray(outputPos, outputPos + b.length);
        cb(aBuf, bBuf, buffer);
      };
      for (; outputPos > 0; outputPos--) t(); // first we decreate outputPos
      for (; inputPos <= b.length; inputPos++) t(); // then we move inputPos
    };
    const getIntersection = (a, b) => {
      if (a.buffer !== b.buffer) return new Uint8Array(0);
      const overlapStart = Math.max(a.byteOffset, b.byteOffset);
      const overlapEnd = Math.min(a.byteOffset + a.byteLength, b.byteOffset + b.byteLength);
      if (overlapStart >= overlapEnd) return new Uint8Array(0);
      return new Uint8Array(a.buffer, overlapStart, overlapEnd - overlapStart);
    };
    // should('overlapTest test', () => {
    //   // Test:
    //   overlapTest(new Uint8Array(5), new Uint8Array(4), (a, b, all) => {
    //     all.fill(0);
    //     a.fill(1);
    //     b.fill(2);
    //     getIntersection(a, b).fill(3);
    //     console.log('AB', a, b, all);
    //   });
    //   throw 'lol';
    // });

    should(`${k} (re-use)`, () => {
      const { fn, keyLen } = opts;

      const key = randomBytes(keyLen);
      const nonce = randomBytes(fn.nonceLength);
      const AAD = randomBytes(64);

      let cipher = fn(key, nonce, AAD);
      // Throws if output provided to function without output support
      if (['micro', 'gcm', 'gcmsiv', 'aeskw'].map((i) => k.includes(i)).includes(true)) {
        const msg = randomBytes(2 * opts.fn.blockSize);
        throws(() => cipher.encrypt(msg, new Uint8Array(msg.length)));
        cipher = fn(key, nonce, AAD);
        const exp = cipher.encrypt(msg);
        throws(() => cipher.decrypt(exp, new Uint8Array(exp.length)));
        return;
      }
      const pcksOutput = (len) => {
        const remaining = len % fn.blockSize;
        let left = fn.blockSize - remaining;
        if (!left) left = fn.blockSize; // if no bytes left, create empty padding block
        return left;
      };

      const messageLengths = [
        4,
        8,
        fn.blockSize,
        2 * fn.blockSize,
        5 * fn.blockSize,
        10 * fn.blockSize,
      ];
      messageLengths.push((1.5 * fn.blockSize) | 0);
      messageLengths.push((1.75 * fn.blockSize) | 0);

      const stats = { e_ok: 0, e_fail: 0, d_ok: 0, d_fail: 0 };
      for (const msgLen of messageLengths) {
        const msg = randomBytes(msgLen);
        const key = randomBytes(keyLen);
        const nonce = randomBytes(fn.nonceLength);
        const AAD = randomBytes(64);
        let cipher = fn(key, nonce, AAD);
        const mayThrow = ['cbc', 'ctr', 'ecb'].map((i) => k.includes(i)).includes(true);
        const pkcs5 = ['cbc', 'ecb'].map((i) => k.includes(i)).includes(true);
        for (let fillByte = 0; fillByte < 256; fillByte++) {
          // Wrapper changes length :(
          if (cipher.encrypt.length === 2) {
            // Tmp buffer
            let outLen = msg.length;
            if (fn.tagLength) outLen += fn.tagLength;
            if (k === 'xsalsa20poly1305') outLen += 16;
            if (pkcs5) outLen += pcksOutput(msg.length);
            // Expected result
            cipher = fn(key, nonce, AAD);
            const exp = cipher.encrypt(msg);
            const out = new Uint8Array(outLen);
            // First pass
            cipher = fn(key, nonce, AAD);
            const res = cipher.encrypt(msg, out);
            eql(res, exp);
            // check if res is output
            eql(res, out.subarray(res.byteOffset, res.byteOffset + res.length));
            eql(res.buffer, out.buffer); // make sure that underlying array buffer is same
            // Second pass
            out.fill(fillByte);
            cipher = fn(key, nonce, AAD);
            const res2 = cipher.encrypt(msg, out);
            eql(res2, exp);
            eql(res2, out.subarray(res2.byteOffset, res2.byteOffset + res2.length));
            eql(res2.buffer, out.buffer); // make sure that underlying array buffer is same
            // Overlap
            cipher = fn(key, nonce, AAD);
            out.fill(fillByte);
            out.set(msg);
            const msg2 = out.subarray(0, msg.length);
            // CFB cannot support overlap
            if (k.includes('cfb')) return throws(() => cipher.encrypt(msg2, out));
            eql(cipher.encrypt(msg2, out), exp);

            overlapTest(msg2, out, (msg2, out2, all) => {
              all.fill(fillByte);
              msg2.set(msg);
              cipher = fn(key, nonce, AAD);
              let newOut;
              try {
                newOut = cipher.encrypt(msg2, out2);
                stats.e_ok++;
              } catch (e) {
                stats.e_fail++;
                if (mayThrow) return;
                throw e;
              }
              eql(newOut.buffer, all.buffer); // make sure that underlying array buffer is same
              eql(newOut.buffer, out2.buffer); // make sure that underlying array buffer is same
              eql(newOut, exp);
            });
          }
          if (cipher.decrypt.length === 2) {
            // Expected result
            cipher = fn(key, nonce, AAD);
            const input = cipher.encrypt(msg);
            // Tmp buffer
            let outLen = msg.length;
            if (k.endsWith('xsalsa20poly1305')) outLen += 32 + 16;
            if (pkcs5) outLen += pcksOutput(msg.length);
            const out = new Uint8Array(outLen);
            // First pass
            const res = cipher.decrypt(input, out);
            eql(res, msg);
            eql(res, out.subarray(res.byteOffset, res.byteOffset + res.length));
            eql(res.buffer, out.buffer); // make sure that underlying array buffer is same
            // Second pass
            out.fill(fillByte);
            const res2 = cipher.decrypt(input, out);
            eql(res2, msg);
            eql(res2, out.subarray(res2.byteOffset, res2.byteOffset + res2.length));
            eql(res2.buffer, out.buffer); // make sure that underlying array buffer is same
            // Overlap
            const tmp = new Uint8Array(Math.max(out.length, input.length));
            tmp.fill(fillByte);
            tmp.set(input);
            const out2 = tmp.subarray(0, out.length);
            const input2 = tmp.subarray(0, input.length);
            // CFB cannot support overlap
            if (k.includes('cfb')) return throws(() => cipher.decrypt(input2, out2));
            eql(cipher.decrypt(input2, out2), msg);

            overlapTest(input2, out2, (input2, out2, all) => {
              all.fill(fillByte);
              input2.set(input);
              let newOut;
              try {
                newOut = cipher.decrypt(input2, out2);
                stats.d_ok++;
              } catch (e) {
                stats.d_fail++;
                if (mayThrow) return;
                throw e;
              }
              eql(newOut.buffer, all.buffer); // make sure that underlying array buffer is same
              eql(newOut.buffer, out2.buffer); // make sure that underlying array buffer is same
              eql(newOut, msg);
            });
          }
        }
      }
      // console.log('OVERLAP STATS', k, stats);
    });
    // Human tests ^, AI abomination v
    should('unaligned', () => {
      if (!['xsalsa20poly1305', 'xchacha20poly1305', 'chacha20poly1305'].includes(k)) return;
      if (k.includes('managedNonce')) return;

      const isSalsa = k.includes('salsa');

      const { fn, keyLen } = opts;
      const msg = new TextEncoder().encode('hello');

      const key = randomBytes(keyLen);
      const nonce = randomBytes(fn.nonceLength);

      const sample_enc = fn(key.slice(), nonce.slice()).encrypt(msg);

      const L = msg.length;
      const ciphertextLen = sample_enc.length;

      const tmp = new Uint8Array(512).fill(5);
      for (let start = 0; start < 32; start++) {
        const i = {};
        i.p_start = start;
        i.p_end = start + L; // .encrypt() output needs L + 32
        if (isSalsa) {
          i.c_start = i.p_end;
          i.c_end = i.c_start + L + 32;

          i.dec_start = i.c_end;
          i.dec_end = i.dec_start + L + 48;
        } else {
          i.c_start = i.p_end;
          i.c_end = i.c_start + ciphertextLen;

          i.dec_start = i.c_end;
          i.dec_end = i.dec_start + L;
        }
        tmp.set(msg, i.p_start);
        const cipher = fn(key, nonce);
        const buf_p = tmp.subarray(i.p_start, i.p_end);
        const buf_dec = tmp.subarray(i.dec_start, i.dec_end);

        // Encrypt
        let ciphertext = cipher.encrypt(buf_p, tmp.subarray(i.c_start, i.c_end));
        eql(ciphertext, sample_enc, '.encrypt() differs');

        // Decrypt
        let plaintext = cipher.decrypt(ciphertext, buf_dec);
        eql(msg, plaintext, '.decrypt() differs');
      }
      // deepStrictEqual(data.subarray(0, 8), data.subarray(32, 40))
    });

    should('be able to reuse input and output arrays', () => {
      // TODO: test AES
      // TODO: test different values of FILL_BYTE

      if (!['xsalsa20poly1305', 'xchacha20poly1305', 'chacha20poly1305'].includes(k)) return;
      if (k.includes('managedNonce')) return;
      const isSalsa = k === 'xsalsa20poly1305';
      const { fn, keyLen } = opts;
      const TMP_FILL_BYTE = 0;

      const msg = new TextEncoder().encode('hello');
      const key = new Uint8Array(keyLen).fill(1);
      const nonce = new Uint8Array(fn.nonceLength).fill(2);
      let tmp;
      const get = () => fn(key, nonce);
      const initTmp = () => (tmp = new Uint8Array(64).fill(TMP_FILL_BYTE));

      const encryptedMsg = get().encrypt(msg);
      const decryptedMsg = fn(key, nonce).decrypt(encryptedMsg); // == msg
      eql(decryptedMsg, msg, 'decryption works');

      const L = msg.length;

      // To encrypt 5-byte input, salsa needs 5 + 32 byte (half-block) output.
      //   However, it would effectively ONLY use 5 + 16 bytes (nonce size).
      //   And the output would be 5 + 16.
      // To encrypt 5-byte input, chacha needs 5 + 16 byte (nonce size) output

      // Part 1: Simply use existing `tmp`
      initTmp();
      eql(
        get().encrypt(msg, tmp.subarray(0, isSalsa ? L + 32 : L + 16)),
        encryptedMsg,
        'example 1'
      );
      // To decrypt
      eql(get().decrypt(encryptedMsg, tmp.subarray(0, isSalsa ? L + 48 : 5)), msg, 'example 2');

      // Part 2: Share `tmp` between input and output
      initTmp();
      tmp.set(msg, 0);
      const reusedEnc = get().encrypt(msg, tmp.subarray(0, isSalsa ? L + 32 : L + 16));
      eql(reusedEnc, encryptedMsg, 'example 3');

      const reusedDec = get().decrypt(reusedEnc, tmp.subarray(0, isSalsa ? L + 48 : 5));
      eql(reusedDec, msg, 'example 4');
    });

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

should.runWhen(import.meta.url);
