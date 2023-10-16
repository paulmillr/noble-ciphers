const { webcrypto } = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const assert = require('assert');
const { should } = require('micro-should');
const { FF1, BinaryFF1 } = require('../webcrypto/ff1.js');
const v = require('./vectors/ff1.json');
const BIN_VECTORS = v.v;
// @ts-ignore

const fromHex = (hex) =>
  hex ? Uint8Array.from(Buffer.from(hex.replace(/ /g, ''), 'hex')) : new Uint8Array([]);

// NIST Vectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
const VECTORS = [
  // AES-128
  {
    key: fromHex('2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C'),
    radix: 10,
    tweak: new Uint8Array([]),
    PT: '0123456789',
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    CT: '2433477484',
    AB: [2, 4, 3, 3, 4, 7, 7, 4, 8, 4],
  },
  {
    key: fromHex('2B7E151628AED2A6ABF7158809CF4F3C'),
    radix: 10,
    tweak: fromHex('39383736353433323130'),
    PT: '0123456789',
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    CT: '6124200773',
    AB: [6, 1, 2, 4, 2, 0, 0, 7, 7, 3],
  },
  {
    key: fromHex('2B7E151628AED2A6ABF7158809CF4F3C'),
    radix: 36,
    tweak: fromHex('3737373770717273373737'),
    PT: '0123456789abcdefghi',
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    CT: 'a9tv40mll9kdu509eum',
    AB: [10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22],
  },
  // AES-256
  {
    key: fromHex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'),
    radix: 10,
    tweak: fromHex(''),
    PT: '0123456789',
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    CT: '6657667009',
    AB: [6, 6, 5, 7, 6, 6, 7, 0, 0, 9],
  },
  {
    key: fromHex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'),
    radix: 10,
    tweak: fromHex('39383736353433323130'),
    PT: '0123456789',
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    CT: '1001623463',
    AB: [1, 0, 0, 1, 6, 2, 3, 4, 6, 3],
  },
  {
    key: fromHex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'),
    radix: 36,
    tweak: fromHex('3737373770717273373737'),
    PT: '0123456789abcdefghi',
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    CT: 'xs8a0azh2avyalyzuwd',
    AB: [33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13],
  },
];

should('FF1: simple test', async () => {
  const bytes = new Uint8Array([
    156, 161, 238, 80, 84, 230, 40, 147, 212, 166, 85, 71, 189, 19, 216, 222, 239, 239, 247, 244,
    254, 223, 161, 182, 178, 156, 92, 134, 113, 32, 54, 74,
  ]);
  const ff1 = BinaryFF1(bytes);
  let res = await ff1.encrypt([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepStrictEqual(res, new Uint8Array([59, 246, 250, 31, 131, 191, 69, 99, 200, 167, 19]));
});

for (let i = 0; i < VECTORS.length; i++) {
  const v = VECTORS[i];
  const ff1 = FF1(v.radix, v.key, v.tweak);
  should(`NIST vector (${i}): encrypt`, async () => {
    assert.deepStrictEqual(await ff1.encrypt(v.X), v.AB);
  });
  should(`NIST vector (${i}): decrypt`, async () => {
    assert.deepStrictEqual(await ff1.decrypt(v.AB), v.X);
  });
}

should(`Binary FF1 encrypt`, async () => {
  for (let i = 0; i < BIN_VECTORS.length; i++) {
    const v = BIN_VECTORS[i];
    const ff1 = BinaryFF1(fromHex(v.key));
    // minLen is 2 by spec
    if (v.data.length < 2) continue;
    const res = await ff1.encrypt(fromHex(v.data));
    assert.deepStrictEqual(res, fromHex(v.exp), i);
  }
});

should(`Binary FF1 decrypt`, async () => {
  for (let i = 0; i < BIN_VECTORS.length; i++) {
    const v = BIN_VECTORS[i];
    const ff1 = BinaryFF1(fromHex(v.key));
    // minLen is 2 by spec
    if (v.data.length < 2) continue;
    const res = await ff1.decrypt(fromHex(v.exp));
    assert.deepStrictEqual(res, fromHex(v.data), i);
  }
});

if (require.main === module) should.run();
