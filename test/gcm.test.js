const { deepStrictEqual, rejects } = require('assert');
const { should, describe } = require('micro-should');
const utils = require('../utils.js');
const { aes_256_gcm, aes_128_gcm } = require('../webcrypto/aes.js');
const { randomBytes } = require('../webcrypto/utils.js');
const aes_gcm_test = require('./wycheproof/aes_gcm_test.json');

describe('AES-GCM', () => {
  should('encrypt and decrypt', async () => {
    const plaintext = utils.utf8ToBytes('Hello world');
    const knownKey = Uint8Array.from([
      64, 196, 127, 247, 172, 2, 34, 159, 6, 241, 30, 174, 183, 229, 41, 114, 253, 122, 119, 168,
      177, 243, 155, 236, 164, 159, 98, 72, 162, 243, 224, 195,
    ]);
    const settings = [
      [aes_256_gcm, knownKey],
      [aes_128_gcm, randomBytes(16)],
    ];
    const aads = [randomBytes(16), new Uint8Array(), utils.utf8ToBytes('data'), undefined];
    for (const [cipher, key] of settings) {
      for (const aad of aads) {
        const gcm = cipher(key, randomBytes(12), aad);
        const ciphertext = await gcm.encrypt(plaintext);
        const plaintext2 = await gcm.decrypt(ciphertext);
        deepStrictEqual(plaintext2, plaintext);
      }
    }
  });
});

describe('Wycheproof', () => {
  for (const g of aes_gcm_test.testGroups) {
    let cipher;
    if (g.keySize === 256) {
      cipher = aes_256_gcm;
    } else if (g.keySize === 128) {
      cipher = aes_128_gcm;
    } else {
      continue;
    }

    // invalid iv sizes for webcrypto
    if ([8, 16, 32, 48, 64, 80, 2056].includes(g.ivSize)) continue;

    const name = `Wycheproof/${g.ivSize}/${g.keySize}/${g.tagSize}/${g.type}`;
    for (let i = 0; i < g.tests.length; i++) {
      const t = g.tests[i];
      should(`${name}: ${t.tcId}`, async () => {
        const key = utils.hexToBytes(t.key);
        const iv = utils.hexToBytes(t.iv);
        const msg = utils.hexToBytes(t.msg);
        const aad = utils.hexToBytes(t.aad);
        const gcm = cipher(key, iv, aad);
        const ct = utils.concatBytes(utils.hexToBytes(t.ct), utils.hexToBytes(t.tag));

        if (t.result === 'valid') {
          deepStrictEqual(await gcm.encrypt(msg), ct);
          deepStrictEqual(await gcm.decrypt(ct), msg);
        } else {
          await rejects(async () => await a.decrypt(ct));
        }
      });
    }
  }
});

if (require.main === module) should.run();
