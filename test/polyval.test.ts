import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { _toGHASHKey, ghash, Polyval, polyval } from '../src/_polyval.ts';
import * as utils from '../src/utils.ts';
import { json } from './utils.ts';

const hex = { decode: utils.hexToBytes, encode: utils.bytesToHex };

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-C
const VECTORS = json('./vectors/siv.json');
const BT = { describe, it };

export function test(
  variant = 'noble',
  platform = { _toGHASHKey, ghash, polyval },
  { describe, it } = BT
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
      it('_toGHASHKey', () => {
        const vectors = {
          '7b754bba26f8311d7642925847936225': 'dcbaa5dd137c188ebb21492c23c9b112',
          '01000000000000000000000000000000': '00800000000000000000000000000000',
          '9c98c04df9387ded828175a92ba652d8': '4e4c6026fc9c3ef6c140bad495d3296c',
        };
        for (const k in vectors) eql(hex.encode(_toGHASHKey(hex.decode(k).reverse())), vectors[k]);
      });
    }

    it('Basic', () => {
      for (const v of VECTORS_GHASH) {
        const concated = utils.concatBytes(...v.msg);
        eql(hex.encode(v.fn(concated, v.key)), hex.encode(v.exp));
        const h = v.fn.create(v.key);
        for (const m of v.msg) h.update(m);
        eql(hex.encode(h.digest()), hex.encode(v.exp));
      }
    });

    it('digestInto writes the tag into out[0..15] only', () => {
      const key = hex.decode('25629347589242761d31f826ba4b757b');
      const msg = utils.concatBytes(
        hex.decode('4f4f95668c83dfb6401762bb2d01a262'),
        hex.decode('d1a24ddd2721d006bbe45f20d3c9f362')
      );
      // Non-repeating tail bytes make BE word-swaps past the tag observable.
      const tail = new Uint8Array([0xa0, 0xa1, 0xa2, 0xa3]);
      const gOut = new Uint8Array(20);
      const pOut = new Uint8Array(20);
      gOut.set(tail, 16);
      pOut.set(tail, 16);
      ghash.create(key).update(msg).digestInto(gOut);
      new Polyval(key).update(msg).digestInto(pOut);
      eql(gOut, new Uint8Array([...ghash(msg, key), ...tail]));
      eql(pOut, new Uint8Array([...polyval(msg, key), ...tail]));
    });

    it('digestInto either rejects misaligned outputs explicitly or writes into them directly', () => {
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
    });

    it('window sizes W=2/4/8 produce identical digests', () => {
      // expectedLength only tunes the precompute window (2 for <=1KB, 4 for
      // <=64KB, 8 above); results must not depend on it. Pins the unrolled
      // W=4 / W=8 fast paths against the generic walk.
      const key = hex.decode('25629347589242761d31f826ba4b757b');
      for (const len of [0, 1, 15, 16, 17, 64, 79, 256]) {
        const msg = Uint8Array.from({ length: len }, (_, i) => (i * 37 + 11) & 0xff);
        for (const fn of [ghash, polyval]) {
          const ref = hex.encode(fn(msg, key)); // one-shot: hint = msg.length -> W=2
          for (const hint of [2000, 100000]) {
            const h = fn.create(key, hint);
            eql(hex.encode(h.update(msg).digest()), ref, `len=${len} hint=${hint}`);
          }
        }
      }
    });

    it('SIV vectors', () => {
      for (const flavor of ['aes128', 'aes256', 'counterWrap']) {
        for (let i = 0; i < VECTORS[flavor].length; i++) {
          const v = VECTORS[flavor][i];
          eql(
            hex.encode(polyval(hex.decode(v.polyvalInput), hex.decode(v.authKey))),
            v.polyvalResult,
            `${flavor}(${i}): polyval`
          );
        }
      }
    });
  });
}
if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
it.runWhen(import.meta.url);
