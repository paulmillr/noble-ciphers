const { deepStrictEqual, rejects } = require('assert');
const { should, describe } = require('micro-should');
const { hex } = require('@scure/base');
const utils = require('../utils.js');
const siv = require('../webcrypto/siv.js');
const { polyval } = require('../_polyval.js');

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-C
const VECTORS = require('./vectors/siv.json');
const aes_gcm_siv_test = require('./wycheproof/aes_gcm_siv_test.json');

describe('AES-GCM-SIV', () => {
  should('Polyval', () => {
    const h = polyval(
      hex.decode('25629347589242761d31f826ba4b757b'),
      hex.decode('4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362')
    );
    deepStrictEqual(hex.encode(h), 'f7a3b47b846119fae5b7866cf5e5b77e');
  });
  for (const flavor of ['aes128', 'aes256', 'counterWrap']) {
    for (let i = 0; i < VECTORS[flavor].length; i++) {
      const v = VECTORS[flavor][i];
      should(`${flavor}(${i}): init`, async () => {
        const { encKey, authKey } = await siv.deriveKeys(hex.decode(v.key), hex.decode(v.nonce));
        deepStrictEqual(encKey, hex.decode(v.encKey));
        deepStrictEqual(authKey, hex.decode(v.authKey));
      });
      should(`${flavor}(${i}): polyval`, async () => {
        deepStrictEqual(
          polyval(hex.decode(v.authKey), hex.decode(v.polyvalInput)),
          hex.decode(v.polyvalResult)
        );
      });
      should(`${flavor}(${i}).encrypt`, async () => {
        let a = await siv.aes_256_gcm_siv(
          hex.decode(v.key),
          hex.decode(v.nonce),
          hex.decode(v.AAD)
        );
        deepStrictEqual(await a.encrypt(hex.decode(v.plaintext)), hex.decode(v.result));
      });
      should(`${flavor}(${i}).decrypt`, async () => {
        let a = await siv.aes_256_gcm_siv(
          hex.decode(v.key),
          hex.decode(v.nonce),
          hex.decode(v.AAD)
        );
        deepStrictEqual(await a.decrypt(hex.decode(v.result)), hex.decode(v.plaintext));
      });
    }
  }
});

describe('Wycheproof', () => {
  for (const g of aes_gcm_siv_test.testGroups) {
    const name = `Wycheproof/${g.ivSize}/${g.keySize}/${g.tagSize}/${g.type}`;
    for (let i = 0; i < g.tests.length; i++) {
      const t = g.tests[i];
      should(`${name}: ${i}`, async () => {
        const a = await siv.aes_256_gcm_siv(hex.decode(t.key), hex.decode(t.iv), hex.decode(t.aad));
        const ct = utils.concatBytes(hex.decode(t.ct), hex.decode(t.tag));
        const msg = hex.decode(t.msg);
        if (t.result === 'valid') {
          deepStrictEqual(await a.decrypt(ct), msg);
          deepStrictEqual(await a.encrypt(msg), ct);
        } else {
          await rejects(async () => await a.decrypt(ct));
        }
      });
    }
  }
});

if (require.main === module) should.run();
