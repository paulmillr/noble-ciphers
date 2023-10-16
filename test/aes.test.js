const { deepStrictEqual, throws } = require('assert');
const { should, describe } = require('micro-should');
const crypto = require('node:crypto');
const { hex } = require('@scure/base');
const { concatBytes } = require('../utils.js');
const { ecb, cbc, ctr, siv, gcm } = require('../aes.js');
// https://datatracker.ietf.org/doc/html/rfc8452#appendix-C
const NIST_VECTORS = require('./vectors/nist_800_38a.json');
const VECTORS = require('./vectors/siv.json');
const aes_gcm_test = require('./wycheproof/aes_gcm_test.json');
const aes_gcm_siv_test = require('./wycheproof/aes_gcm_siv_test.json');
const aes_cbc = require('./wycheproof/aes_cbc_pkcs5_test.json');

// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

const CIPHERS = { ecb, cbc, ctr, siv, gcm };

describe('AES', () => {
  should('CTR', () => {
    const nodeAES = (name) => ({
      encrypt: (buf, opts) =>
        Uint8Array.from(crypto.createCipheriv(name, opts.key, opts.nonce).update(buf)),
      decrypt: (buf, opts) =>
        Uint8Array.from(crypto.createDecipheriv(name, opts.key, opts.nonce).update(buf)),
    });
    // MDN says counter should be 64 bit
    // https://developer.mozilla.org/en-US/docs/Web/API/AesCtrParams
    // and links NIST SP800-38A which actually says in B.1 that standard increment function
    // uses all bits, so 128 bit counter. Which is the same as in OpenSSL.
    const key = new Uint8Array(32).fill(32);
    const msg = new Uint8Array(64).fill(64);
    const nonces = [
      new Uint8Array(16).fill(1),
      // 64 bit
      concatBytes(new Uint8Array(8), new Uint8Array(8).fill(255)),
      concatBytes(new Uint8Array(8).fill(255), new Uint8Array(8)),
      // 32 bit
      concatBytes(new Uint8Array(12), new Uint8Array(4).fill(255)),
      concatBytes(new Uint8Array(4).fill(255), new Uint8Array(12)),
      new Uint8Array(16).fill(255), // this wraps in 128 bit
    ];
    // So, current behaviour seems reasonable.
    // We don't have variable counter length at web version for now, but it works.
    for (const nonce of nonces) {
      const nodeVal = nodeAES('aes-256-ctr').encrypt(msg, { key, nonce });
      const c = ctr(key, nonce);
      deepStrictEqual(c.encrypt(msg), nodeVal);
      deepStrictEqual(c.decrypt(nodeVal), msg);
    }
  });
  describe('NIST 800-38a', () => {
    for (const t of NIST_VECTORS) {
      should(`${t.name}`, () => {
        let c;
        const cipher = CIPHERS[t.cipher];
        if (t.iv) c = cipher(hex.decode(t.key), hex.decode(t.iv || ''), { disablePadding: true });
        else c = cipher(hex.decode(t.key), { disablePadding: true });
        const ciphertext = concatBytes(...t.blocks.map((i) => hex.decode(i.ciphertext)));
        const plaintext = concatBytes(...t.blocks.map((i) => hex.decode(i.plaintext)));
        deepStrictEqual(c.decrypt(ciphertext), plaintext);
        deepStrictEqual(c.encrypt(plaintext), ciphertext);
      });
    }
  });
  describe('GCM-SIV', () => {
    for (const flavor of ['aes128', 'aes256', 'counterWrap']) {
      for (let i = 0; i < VECTORS[flavor].length; i++) {
        const v = VECTORS[flavor][i];
        should(`${flavor}(${i}).encrypt`, () => {
          let a = siv(hex.decode(v.key), hex.decode(v.nonce), hex.decode(v.AAD));
          deepStrictEqual(a.encrypt(hex.decode(v.plaintext)), hex.decode(v.result));
        });
        should(`${flavor}(${i}).decrypt`, () => {
          let a = siv(hex.decode(v.key), hex.decode(v.nonce), hex.decode(v.AAD));
          deepStrictEqual(a.decrypt(hex.decode(v.result)), hex.decode(v.plaintext));
        });
      }
    }
  });

  describe('Wycheproof', () => {
    const cases = [
      { name: 'GCM-SIV', groups: aes_gcm_siv_test.testGroups, cipher: 'siv' },
      { name: 'GCM', groups: aes_gcm_test.testGroups, cipher: 'gcm' },
      { name: 'CBC', groups: aes_cbc.testGroups, cipher: 'cbc' }, // PCKS5 is enabled by default
    ];
    for (const c of cases) {
      for (const g of c.groups) {
        const name = `Wycheproof/${c.name}/${g.ivSize}/${g.keySize}/${g.tagSize}/${g.type}`;
        for (let i = 0; i < g.tests.length; i++) {
          const t = g.tests[i];
          should(`${name}: ${i}`, () => {
            const ct = concatBytes(hex.decode(t.ct), hex.decode(t.tag || ''));
            const msg = hex.decode(t.msg);
            const cipher = CIPHERS[c.cipher];
            if (t.result === 'valid') {
              const a = cipher(hex.decode(t.key), hex.decode(t.iv), hex.decode(t.aad || ''));
              const ct = concatBytes(hex.decode(t.ct), hex.decode(t.tag || ''));
              deepStrictEqual(a.decrypt(ct), msg);
              deepStrictEqual(a.encrypt(msg), ct);
            } else {
              throws(() =>
                cipher(hex.decode(t.key), hex.decode(t.iv), hex.decode(t.aad || '')).decrypt(ct)
              );
            }
          });
        }
      }
    }
  });
});

if (require.main === module) should.run();
