import { deepStrictEqual, throws } from 'node:assert';
import fc from 'fast-check';
import { describe, should } from 'micro-should';
import { TYPE_TEST, unalign } from './utils.js';
import * as assert from '../esm/_assert.js';
import {
  createView,
  bytesToHex,
  concatBytes,
  hexToBytes,
  overlapBytes,
  toBytes,
  bytesToUtf8,
  getOutput,
  setBigUint64,
  u64Lengths,
} from '../esm/utils.js';

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex), v.bytes);
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex.toUpperCase()), v.bytes);
    for (let v of TYPE_TEST.hex) {
      throws(() => hexToBytes(v));
    }
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) deepStrictEqual(bytesToHex(v.bytes), v.hex);
    for (let v of TYPE_TEST.bytes) {
      throws(() => bytesToHex(v));
    }
  });
  should('hexToBytes <=> bytesToHex roundtrip', () =>
    fc.assert(
      fc.property(fc.hexaString({ minLength: 2, maxLength: 64 }), (hex) => {
        if (hex.length % 2 !== 0) return;
        deepStrictEqual(hex, bytesToHex(hexToBytes(hex)));
        deepStrictEqual(hex, bytesToHex(hexToBytes(hex.toUpperCase())));
        if (typeof Buffer !== 'undefined')
          deepStrictEqual(hexToBytes(hex), Uint8Array.from(Buffer.from(hex, 'hex')));
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
    deepStrictEqual(concatBytes(), new Uint8Array());
    deepStrictEqual(concatBytes(aa, bb), Uint8Array.from([a, b]));
    deepStrictEqual(concatBytes(aa, bb, cc), Uint8Array.from([a, b, c]));
    for (let v of TYPE_TEST.bytes)
      throws(() => {
        concatBytes(v);
      });
  });
  should('concatBytes random', () =>
    fc.assert(
      fc.property(fc.uint8Array(), fc.uint8Array(), fc.uint8Array(), (a, b, c) => {
        const expected = Uint8Array.from([...a, ...b, ...c]);
        deepStrictEqual(concatBytes(a.slice(), b.slice(), c.slice()), expected);
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
    deepStrictEqual(overlapBytes(a, b), true);
    deepStrictEqual(overlapBytes(a, c), false);
    deepStrictEqual(overlapBytes(b, c), true);
    deepStrictEqual(overlapBytes(a, d), false);
    // Scan
    const res = [];
    const main = new Uint8Array(8 + 4); // 2byte + first + 2byte
    const first = main.subarray(2).subarray(0, 8);
    for (let i = 0; i < main.length; i++) {
      const second = main.subarray(i).subarray(0, 1); // one byte window
      deepStrictEqual(second, new Uint8Array(1));
      res.push(overlapBytes(first, second));
    }
    deepStrictEqual(res, [
      false,
      false,
      true,
      true,
      true,
      true,
      true,
      true,
      true,
      true,
      false,
      false,
    ]);
    const main2 = new Uint8Array(buffer, 5, 10); // main
    const inside = new Uint8Array(buffer, 6, 4); // left overlap
    const leftOverlap = new Uint8Array(buffer, 0, 6); // left overlap
    const rightOverlap = new Uint8Array(buffer, 9, 10); // right overlap
    const before = new Uint8Array(buffer, 0, 5); // before
    const after = new Uint8Array(buffer, 15, 5); // after

    deepStrictEqual(overlapBytes(before, main2), false);
    deepStrictEqual(overlapBytes(after, main2), false);
    deepStrictEqual(overlapBytes(leftOverlap, rightOverlap), false);

    deepStrictEqual(overlapBytes(main2, leftOverlap), true);
    deepStrictEqual(overlapBytes(main2, rightOverlap), true);
    deepStrictEqual(overlapBytes(main2, inside), true);
  });
  should('bytesToUtf8', () => {
    deepStrictEqual(bytesToUtf8(new Uint8Array([97, 98, 99])), 'abc');
  });
  should('toBytes', () => {
    deepStrictEqual(toBytes(new Uint8Array([97, 98, 99])), new Uint8Array([97, 98, 99]));
    deepStrictEqual(toBytes('abc'), new Uint8Array([97, 98, 99]));
    throws(() => toBytes(1));
  });
  should('getOutput', () => {
    deepStrictEqual(getOutput(32), new Uint8Array(32));
    throws(() => getOutput(32, new Uint8Array(31)));
    throws(() => getOutput(32, new Uint8Array(33)));
    const t = new Uint8Array(33).subarray(1);
    throws(() => getOutput(32, t));
    deepStrictEqual(getOutput(32, t, false), new Uint8Array(32));
  });
  should('setBigUint64', () => {
    const t = new Uint8Array(20);
    const v = createView(t);
    const VECTORS = [
      {
        n: 123n,
        le: false,
        hex: '000000000000007b000000000000000000000000',
      },
      {
        n: 123n,
        le: true,
        hex: '7b00000000000000000000000000000000000000',
      },
      {
        n: 2n ** 64n - 1n,
        le: true,
        hex: 'ffffffffffffffff000000000000000000000000',
      },
      {
        n: 2n ** 64n - 1n,
        le: true,
        hex: '000000ffffffffffffffff000000000000000000',
        pos: 3,
      },
      {
        n: 0x123456789abcdef0n,
        le: true,
        hex: 'f0debc9a78563412000000000000000000000000',
      },
      {
        n: 0x123456789abcdef0n,
        le: false,
        hex: '123456789abcdef0000000000000000000000000',
      },
    ];
    const createViewMock = (u8) => {
      const v = createView(u8);
      return {
        setUint32: (o, wh, isLE) => v.setUint32(o, wh, isLE),
      };
    };

    for (const cv of [createView, createViewMock]) {
      for (const t of VECTORS) {
        const b = new Uint8Array(20);
        const v = cv(b);
        setBigUint64(v, t.pos || 0, t.n, t.le);
        deepStrictEqual(bytesToHex(b), t.hex);
      }
    }
  });
  should('u64Lengths', () => {
    deepStrictEqual(bytesToHex(u64Lengths(new Uint8Array(10))), '00000000000000000a00000000000000');
    deepStrictEqual(
      bytesToHex(u64Lengths(new Uint8Array(10), new Uint8Array(7))),
      '07000000000000000a00000000000000'
    );
  });
});

describe('assert', () => {
  should('anumber', () => {
    deepStrictEqual(assert.anumber(10), undefined);
    throws(() => assert.anumber(1.2));
    throws(() => assert.anumber('1'));
    throws(() => assert.anumber(true));
    throws(() => assert.anumber(NaN));
  });
  should('abytes', () => {
    deepStrictEqual(assert.abytes(new Uint8Array(0)), undefined);
    if (typeof Buffer !== 'undefined') deepStrictEqual(assert.abytes(Buffer.alloc(10)), undefined);
    deepStrictEqual(assert.abytes(new Uint8Array(10)), undefined);
    assert.abytes(new Uint8Array(11), 11, 12);
    assert.abytes(new Uint8Array(12), 12, 12);
    throws(() => assert.abytes('test'));
    throws(() => assert.abytes(new Uint8Array(10), 11, 12));
    throws(() => assert.abytes(new Uint8Array(10), 11, 12));
  });
  should('ahash', () => {
    const sha256 = () => {};
    sha256.blockLen = 1;
    sha256.outputLen = 1;
    sha256.create = () => {};
    deepStrictEqual(assert.ahash(sha256), undefined);
    throws(() => assert.ahash({}));
    throws(() => assert.ahash({ blockLen: 1, outputLen: 1, create: () => {} }));
  });
  should('aexists', () => {
    deepStrictEqual(assert.aexists({}), undefined);
    throws(() => assert.aexists({ destroyed: true }));
  });
  should('aoutput', () => {
    deepStrictEqual(assert.aoutput(new Uint8Array(10), { outputLen: 5 }), undefined);
    throws(() => assert.aoutput(new Uint8Array(1), { outputLen: 5 }));
  });
});

describe('utils etc', () => {
  should('unalign', () => {
    const arr = new Uint8Array([1, 2, 3]);
    for (let i = 0; i < 16; i++) {
      const tmp = unalign(arr, i);
      deepStrictEqual(tmp, arr);
      deepStrictEqual(tmp.byteOffset, i);
      // check that it doesn't modify original
      tmp[1] = 9;
      deepStrictEqual(tmp, new Uint8Array([1, 9, 3]));
      deepStrictEqual(arr, new Uint8Array([1, 2, 3]));
    }
  });
});

should.runWhen(import.meta.url);
