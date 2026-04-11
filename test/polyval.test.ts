import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { _toGHASHKey, ghash, Polyval, polyval } from '../src/_polyval.ts';
import { pathToFileURL } from 'node:url';
import * as utils from '../src/utils.ts';
import { json } from './utils.ts';

const hex = { decode: utils.hexToBytes, encode: utils.bytesToHex };

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-C
const VECTORS = json('./vectors/siv.json');
const BT = { describe, should };

export function test(
  variant = 'noble',
  platform = { _toGHASHKey, ghash, polyval },
  { describe, should } = BT
) {
  const { _toGHASHKey, ghash, polyval } = platform;
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
  ];
  if (typeof _toGHASHKey === 'function') {
    VECTORS_GHASH.push({
      fn: ghash,
      key: _toGHASHKey(hex.decode('25629347589242761d31f826ba4b757b')),
      msg: ['4f4f95668c83dfb6401762bb2d01a262', 'd1a24ddd2721d006bbe45f20d3c9f362']
        .map(hex.decode)
        .map((i) => i.reverse()),
      exp: hex.decode('f7a3b47b846119fae5b7866cf5e5b77e').reverse(),
    });
  }
  describe(`Polyval (${variant})`, () => {
    if (typeof _toGHASHKey === 'function') {
      should('_toGHASHKey', () => {
        const vectors = {
          '7b754bba26f8311d7642925847936225': 'dcbaa5dd137c188ebb21492c23c9b112',
          '01000000000000000000000000000000': '00800000000000000000000000000000',
          '9c98c04df9387ded828175a92ba652d8': '4e4c6026fc9c3ef6c140bad495d3296c',
        };
        for (const k in vectors) eql(hex.encode(_toGHASHKey(hex.decode(k).reverse())), vectors[k]);
      });
    }

    should('Basic', () => {
      for (const v of VECTORS_GHASH) {
        const concated = utils.concatBytes(...v.msg);
        eql(hex.encode(v.fn(concated, v.key)), hex.encode(v.exp));
        const h = v.fn.create(v.key);
        for (const m of v.msg) h.update(m);
        eql(hex.encode(h.digest()), hex.encode(v.exp));
      }
    });

    should('digestInto writes the tag into out[0..15] only', () => {
      const key = hex.decode('25629347589242761d31f826ba4b757b');
      const msg = utils.concatBytes(
        hex.decode('4f4f95668c83dfb6401762bb2d01a262'),
        hex.decode('d1a24ddd2721d006bbe45f20d3c9f362')
      );
      const out = new Uint8Array(20).fill(0xaa);
      const mac = new Polyval(key).update(msg);
      mac.digestInto(out);
      eql(out, new Uint8Array([...polyval(msg, key), 0xaa, 0xaa, 0xaa, 0xaa]));
    });

    should(
      'digestInto either rejects misaligned outputs explicitly or writes into them directly',
      () => {
        const key = hex.decode('25629347589242761d31f826ba4b757b');
        const msg = utils.concatBytes(
          hex.decode('4f4f95668c83dfb6401762bb2d01a262'),
          hex.decode('d1a24ddd2721d006bbe45f20d3c9f362')
        );
        const g = ghash.create(key);
        const p = polyval.create(key);
        const gOut = new Uint8Array(21).subarray(1).fill(0xaa);
        const pOut = new Uint8Array(21).subarray(1).fill(0xaa);
        const gBefore = gOut.slice();
        const pBefore = pOut.slice();
        const gExpect = new Uint8Array(20).fill(0xaa);
        const pExpect = new Uint8Array(20).fill(0xaa);
        gExpect.set(ghash(msg, key), 0);
        pExpect.set(polyval(msg, key), 0);
        try {
          g.update(msg);
          try {
            g.digestInto(gOut);
            eql(gOut, gExpect);
          } catch (error) {
            eql(error, new Error('invalid output, must be aligned'));
            eql(gOut, gBefore);
          }
          p.update(msg);
          try {
            p.digestInto(pOut);
            eql(pOut, pExpect);
          } catch (error) {
            eql(error, new Error('invalid output, must be aligned'));
            eql(pOut, pBefore);
          }
        } finally {
          g.destroy();
          p.destroy();
        }
      }
    );

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
}
if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
should.runWhen(import.meta.url);
