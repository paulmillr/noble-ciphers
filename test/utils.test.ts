import fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import * as u from '../src/utils.ts';
import {
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  getOutput,
  hexToBytes,
  overlapBytes,
  u64Lengths,
} from '../src/utils.ts';
import { TYPE_TEST, unalign } from './utils.ts';

function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) eql(hexToBytes(v.hex), v.bytes);
    for (let v of staticHexVectors) eql(hexToBytes(v.hex.toUpperCase()), v.bytes);
    for (let v of TYPE_TEST.hex) {
      throws(() => hexToBytes(v));
    }
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) eql(bytesToHex(v.bytes), v.hex);
    for (let v of TYPE_TEST.bytes) {
      throws(() => bytesToHex(v));
    }
  });
  should('hexToBytes <=> bytesToHex roundtrip', () =>
    fc.assert(
      fc.property(hexaString({ minLength: 2, maxLength: 64 }), (hex) => {
        if (hex.length % 2 !== 0) return;
        eql(hex, bytesToHex(hexToBytes(hex)));
        eql(hex, bytesToHex(hexToBytes(hex.toUpperCase())));
        if (typeof Buffer !== 'undefined')
          eql(hexToBytes(hex), Uint8Array.from(Buffer.from(hex, 'hex')));
      })
    )
  );
  should('concatBytes', () => {
    const a = 1;
    const b = 2;
    const c = 0xff;
    const aa = Uint8Array.from([a]);
    const bb = Uint8Array.from([b]);
    const cc = Uint8Array.from([c]);
    eql(concatBytes(), new Uint8Array());
    eql(concatBytes(aa, bb), Uint8Array.from([a, b]));
    eql(concatBytes(aa, bb, cc), Uint8Array.from([a, b, c]));
    for (let v of TYPE_TEST.bytes)
      throws(() => {
        concatBytes(v);
      });
  });
  should('concatBytes random', () =>
    fc.assert(
      fc.property(fc.uint8Array(), fc.uint8Array(), fc.uint8Array(), (a, b, c) => {
        const expected = Uint8Array.from([...a, ...b, ...c]);
        eql(concatBytes(a.slice(), b.slice(), c.slice()), expected);
      })
    )
  );
  should('overlapBytes', () => {
    // Basic
    const buffer = new ArrayBuffer(20);
    const a = new Uint8Array(buffer, 0, 10); // Bytes 0-9
    const b = new Uint8Array(buffer, 5, 10); // Bytes 5-14
    const c = new Uint8Array(buffer, 10, 10); // Bytes 10-19
    const d = new Uint8Array(new ArrayBuffer(20), 0, 10); // Different buffer
    eql(overlapBytes(a, b), true);
    eql(overlapBytes(a, c), false);
    eql(overlapBytes(b, c), true);
    eql(overlapBytes(a, d), false);
    // Scan
    const res = [];
    const main = new Uint8Array(8 + 4); // 2byte + first + 2byte
    const first = main.subarray(2).subarray(0, 8);
    for (let i = 0; i < main.length; i++) {
      const second = main.subarray(i).subarray(0, 1); // one byte window
      eql(second, new Uint8Array(1));
      res.push(overlapBytes(first, second));
    }
    eql(res, [false, false, true, true, true, true, true, true, true, true, false, false]);
    const main2 = new Uint8Array(buffer, 5, 10); // main
    const inside = new Uint8Array(buffer, 6, 4); // left overlap
    const leftOverlap = new Uint8Array(buffer, 0, 6); // left overlap
    const rightOverlap = new Uint8Array(buffer, 9, 10); // right overlap
    const before = new Uint8Array(buffer, 0, 5); // before
    const after = new Uint8Array(buffer, 15, 5); // after

    eql(overlapBytes(before, main2), false);
    eql(overlapBytes(after, main2), false);
    eql(overlapBytes(leftOverlap, rightOverlap), false);

    eql(overlapBytes(main2, leftOverlap), true);
    eql(overlapBytes(main2, rightOverlap), true);
    eql(overlapBytes(main2, inside), true);
  });
  should('bytesToUtf8', () => {
    eql(bytesToUtf8(new Uint8Array([97, 98, 99])), 'abc');
  });
  should('getOutput', () => {
    eql(getOutput(32), new Uint8Array(32));
    throws(() => getOutput(32, new Uint8Array(31)));
    throws(() => getOutput(32, new Uint8Array(33)));
    const t = new Uint8Array(33).subarray(1);
    throws(() => getOutput(32, t));
    eql(getOutput(32, t, false), new Uint8Array(32));
  });
  should('u64Lengths', () => {
    eql(
      bytesToHex(u64Lengths(new Uint8Array(10).length, 0, true)),
      '00000000000000000a00000000000000'
    );
    eql(
      bytesToHex(u64Lengths(new Uint8Array(10).length, new Uint8Array(7).length, true)),
      '07000000000000000a00000000000000'
    );
  });
});

describe('assert', () => {
  should('anumber', () => {
    eql(u.anumber(10), undefined);
    throws(() => u.anumber(1.2));
    throws(() => u.anumber('1'));
    throws(() => u.anumber(true));
    throws(() => u.anumber(NaN));
  });
  should('abytes', () => {
    eql(u.abytes(new Uint8Array(0)), undefined);
    if (typeof Buffer !== 'undefined') eql(u.abytes(Buffer.alloc(10)), undefined);
    eql(u.abytes(new Uint8Array(10)), undefined);
    u.abytes(new Uint8Array(11), 11, 12);
    u.abytes(new Uint8Array(12), 12, 12);
    throws(() => u.abytes('test'));
    throws(() => u.abytes(new Uint8Array(10), 11, 12));
    throws(() => u.abytes(new Uint8Array(10), 11, 12));
  });
  should('aexists', () => {
    eql(u.aexists({}), undefined);
    throws(() => u.aexists({ destroyed: true }));
  });
  should('aoutput', () => {
    eql(u.aoutput(new Uint8Array(10), { outputLen: 5 }), undefined);
    throws(() => u.aoutput(new Uint8Array(1), { outputLen: 5 }));
  });
});

describe('utils etc', () => {
  should('unalign', () => {
    const arr = new Uint8Array([1, 2, 3]);
    for (let i = 0; i < 16; i++) {
      const tmp = unalign(arr, i);
      eql(tmp, arr);
      eql(tmp.byteOffset, i);
      // check that it doesn't modify original
      tmp[1] = 9;
      eql(tmp, new Uint8Array([1, 9, 3]));
      eql(arr, new Uint8Array([1, 2, 3]));
    }
  });
});

should.runWhen(import.meta.url);
