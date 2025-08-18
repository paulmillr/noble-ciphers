import { should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { aeskw, aeskwp, cbc, cfb, ctr, ecb, gcm, gcmsiv } from '../src/aes.ts';
import { chacha20poly1305, xchacha20poly1305 } from '../src/chacha.ts';
import { xsalsa20poly1305 } from '../src/salsa.ts';
import { bytesToHex, managedNonce, randomBytes } from '../src/utils.ts';

const CIPHERS = {
  xsalsa20poly1305: {
    fn: xsalsa20poly1305,
    keyLen: 32,
    withNonce: true,
    withDST: true,
    DSTAdditionalBytes: 16,
    DSTMsgAdditionalBytes: 48,
  },
  chacha20poly1305: {
    fn: chacha20poly1305,
    keyLen: 32,
    withNonce: true,
    withDST: true,
    withAAD: true,
  },
  xchacha20poly1305: {
    fn: xchacha20poly1305,
    keyLen: 32,
    withNonce: true,
    withDST: true,
    withAAD: true,
  },
};
//ctr, ecb, cbc, cfb
for (const keyLen of [16, 24, 32]) {
  for (const [name, fn] of Object.entries({ cbc, ctr, cfb }))
    CIPHERS[`${name}_${keyLen * 8}`] = {
      fn,
      keyLen,
      withNonce: true,
      withDST: true,
      DSTMsgAdditionalBytes: name === 'cbc' ? 16 : 0,
    };
  for (const [name, fn] of Object.entries({ gcm, gcmsiv }))
    CIPHERS[`${name}_${keyLen * 8}`] = { fn, keyLen, withNonce: true, withAAD: true };

  CIPHERS[`ecb_${keyLen * 8}`] = {
    fn: ecb,
    keyLen,
    withNonce: false,
    withDST: true,
    DSTMsgAdditionalBytes: 16,
  };
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
  const opt = {
    ...opts,
    fn: managedNonce(opts.fn),
    withNonce: false,
    DSTAdditionalBytes: opts.DSTAdditionalBytes || 0,
    withDST: false,
  };
  CIPHERS[`${k}_managedNonce`] = opt;
}
CIPHERS.managedCbcNoPadding = {
  fn: managedNonce(cbc),
  args: [{ disablePadding: true }],
  blockSize: 16,
};
const ALGO = CIPHERS;

function getError(fn) {
  try {
    fn();
    throw new Error('NO ERROR!');
  } catch (e) {
    return e;
  }
}
const green = (s) => `\x1b[32m${s}\x1b[0m`;

should('Errors', () => {
  const res = {}; // Record<string, [string, string][]>
  const algoNameLength = Object.keys(ALGO)
    .map((i) => i.length)
    .reduce((acc, i) => Math.max(acc, i));
  for (const name in ALGO) {
    const C = ALGO[name];
    const CE = (s, fn) => {
      if (!res[s]) res[s] = [];
      res[s].push({ algoName: name, name: s, error: getError(fn) });
    };
    const CEG = (s, manglers, value, fn) => {
      for (const m in manglers) CE(s + m, () => fn(manglers[m](value)));
    };
    const BYTES10 = randomBytes(10);
    const U8 = {
      false: () => false,
      bytes10: () => BYTES10,
      empty: () => new Uint8Array(0),
      zero: (b) => new Uint8Array(b.length),
      slice1: (b) => b.slice(1),
      hex: (b) => bytesToHex(b),
      array: (b) => Array.from(b),
    };
    const B = {
      1: () => 1,
      0: () => 0,
      null: () => null,
      string: () => 'true',
    };
    const EMPTY = {
      id: (x) => x,
    };
    console.log('a', name, C);
    const key = randomBytes(C.keyLen);
    const nonce = C.withNonce ? randomBytes(C.fn.nonceLength) : undefined;
    const AAD = C.withAAD ? BYTES10 : undefined;
    const msg = randomBytes(C.minLength || C.fn.blockSize);
    C.fn(key, nonce, AAD);
    CEG('cipher: wrong key=', U8, key, (s) => C.fn(s, nonce, AAD).encrypt(msg));
    if (C.withNonce) CEG('cipher: wrong nonce=', U8, key, (s) => C.fn(key, s, AAD).encrypt(msg));
    if (C.withAAD) {
      console.log(name);
      CEG('cipher: wrong AAD=', U8, AAD, (s) => C.fn(key, s).encrypt(msg));
    }
    const getC = () => C.fn(key, nonce);
    const enc = getC().encrypt(msg);
    eql(getC().decrypt(enc), msg);
    CEG('cipher: wrong plainText=', U8, msg, (s) => getC().encrypt(s));
    CEG('cipher: wrong cipherText=', U8, enc, (s) => getC().decrypt(s));
    if (C.withNonce) {
      const cc = getC();
      cc.encrypt(msg);
      CEG('cipher: second encrypt=', EMPTY, msg, (s) => cc.encrypt(s));
    }
    if (C.withDST) {
      const out = new Uint8Array(enc.length + (C.DSTAdditionalBytes || 0));
      const x = getC().encrypt(msg, out);
      console.log('xXX', x.byteOffset);
      eql(out.subarray(x.byteOffset, x.byteOffset + x.length), enc);
      CEG('cipher/encrypt: wrong dst=', U8, out, (s) => getC().encrypt(msg, s));
      const msgOut = new Uint8Array(msg.length + (C.DSTMsgAdditionalBytes || 0));
      const y = getC().decrypt(enc, msgOut);
      eql(msgOut.subarray(y.byteOffset, y.byteOffset + y.length), msg);
      CEG('cipher/decrypt: wrong dst=', U8, msgOut, (s) => getC().decrypt(enc, s));
    }
  }

  for (const k in res) {
    console.log(green(k));
    for (const { algoName, error } of res[k])
      console.log(`- ${algoName.padEnd(algoNameLength, ' ')}: ${error.message}`);
  }
});

should.runWhen(import.meta.url);
