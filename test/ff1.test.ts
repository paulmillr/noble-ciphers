import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { BinaryFF1, FF1 } from '../src/ff1.ts';
import { hexToBytes, json } from './utils.ts';

const fromHex = (hex) => {
  return hex ? hexToBytes(hex) : Uint8Array.from([]);
};

// NIST Vectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
const VECTORS = [
  // AES-128
  {
    // key: fromHex('2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C'),
    key: fromHex('2B7E151628AED2A6ABF7158809CF4F3C'),
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

describe('FF1', () => {
  should('FF1: simple test', () => {
    const bytes = new Uint8Array([
      156, 161, 238, 80, 84, 230, 40, 147, 212, 166, 85, 71, 189, 19, 216, 222, 239, 239, 247, 244,
      254, 223, 161, 182, 178, 156, 92, 134, 113, 32, 54, 74,
    ]);
    const ff1 = BinaryFF1(bytes);
    let res = ff1.encrypt([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    eql(res, new Uint8Array([59, 246, 250, 31, 131, 191, 69, 99, 200, 167, 19]));
  });

  for (let i = 0; i < VECTORS.length; i++) {
    const v = VECTORS[i];
    const ff1 = FF1(v.radix, v.key, v.tweak);
    should(`NIST vector (${i}): encrypt`, () => {
      eql(ff1.encrypt(v.X), v.AB);
    });
    should(`NIST vector (${i}): decrypt`, () => {
      eql(ff1.decrypt(v.AB), v.X);
    });
  }

  should(`Binary FF1 encrypt`, () => {
    const BIN_VECTORS = json('./vectors/ff1.json').v;
    for (let i = 0; i < BIN_VECTORS.length; i++) {
      const v = BIN_VECTORS[i];
      const ff1 = BinaryFF1(fromHex(v.key));
      // minLen is 2 by spec
      if (v.data.length < 2) continue;
      const res = ff1.encrypt(fromHex(v.data));
      eql(res, fromHex(v.exp), i);
    }

    for (let i = 0; i < BIN_VECTORS.length; i++) {
      const v = BIN_VECTORS[i];
      const ff1 = BinaryFF1(fromHex(v.key));
      // minLen is 2 by spec
      if (v.data.length < 2) continue;
      const res = ff1.decrypt(fromHex(v.exp));
      eql(res, fromHex(v.data), i);
    }
  });

  should('throw on wrong radix', () => {
    throws(() => FF1(1, new Uint8Array(10)).encrypt([1]));
  });
});

should.runWhen(import.meta.url);
