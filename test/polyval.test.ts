import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { _toGHASHKey, ghash, polyval } from '../src/_polyval.ts';
import * as utils from '../src/utils.ts';
import { json } from './utils.ts';

const hex = { decode: utils.hexToBytes, encode: utils.bytesToHex };

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-C
const VECTORS = json('./vectors/siv.json');

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-A
const VECTORS_GHASH = [
  {
    fn: polyval,
    key: hex.decode('25629347589242761d31f826ba4b757b'),
    msg: ['4f4f95668c83dfb6401762bb2d01a262', 'd1a24ddd2721d006bbe45f20d3c9f362'].map(hex.decode),
    exp: hex.decode('f7a3b47b846119fae5b7866cf5e5b77e'),
  },
  {
    fn: ghash,
    key: hex.decode('25629347589242761d31f826ba4b757b'),
    msg: ['4f4f95668c83dfb6401762bb2d01a262', 'd1a24ddd2721d006bbe45f20d3c9f362'].map(hex.decode),
    exp: hex.decode('bd9b3997046731fb96251b91f9c99d7a'),
  },
  // Ghash as polyval
  {
    fn: ghash,
    key: _toGHASHKey(hex.decode('25629347589242761d31f826ba4b757b')),
    msg: ['4f4f95668c83dfb6401762bb2d01a262', 'd1a24ddd2721d006bbe45f20d3c9f362']
      .map(hex.decode)
      .map((i) => i.reverse()),
    exp: hex.decode('f7a3b47b846119fae5b7866cf5e5b77e').reverse(),
  },
];

describe('Polyval', () => {
  should('_toGHASHKey', () => {
    const vectors = {
      '7b754bba26f8311d7642925847936225': 'dcbaa5dd137c188ebb21492c23c9b112',
      '01000000000000000000000000000000': '00800000000000000000000000000000',
      '9c98c04df9387ded828175a92ba652d8': '4e4c6026fc9c3ef6c140bad495d3296c',
    };
    for (const k in vectors) eql(hex.encode(_toGHASHKey(hex.decode(k).reverse())), vectors[k]);
  });

  should('Basic', () => {
    for (const v of VECTORS_GHASH) {
      const concated = utils.concatBytes(...v.msg);
      eql(hex.encode(v.fn(concated, v.key)), hex.encode(v.exp));
      const h = v.fn.create(v.key);
      for (const m of v.msg) h.update(m);
      eql(hex.encode(h.digest()), hex.encode(v.exp));
    }
  });

  for (const flavor of ['aes128', 'aes256', 'counterWrap']) {
    for (let i = 0; i < VECTORS[flavor].length; i++) {
      const v = VECTORS[flavor][i];
      should(`${flavor}(${i}): polyval`, () => {
        eql(
          hex.encode(polyval(hex.decode(v.polyvalInput), hex.decode(v.authKey))),
          v.polyvalResult
        );
      });
    }
  }
});

should.runWhen(import.meta.url);
