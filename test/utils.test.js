const { deepStrictEqual, throws } = require('assert');
const fc = require('fast-check');
const { describe, should } = require('micro-should');
const { TYPE_TEST, unalign } = require('./utils.js');
const { bytesToHex, concatBytes, hexToBytes } = require('../utils.js');

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
        const expected = Uint8Array.from(Buffer.concat([a, b, c]));
        deepStrictEqual(concatBytes(a.slice(), b.slice(), c.slice()), expected);
      })
    )
  );
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

if (require.main === module) should.run();
