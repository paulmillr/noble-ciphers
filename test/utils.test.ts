import { describe, should } from '@paulmillr/jsbt/test.js';
import fc from 'fast-check';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
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
const BT = { describe, should };

function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}

export function test({ describe, should } = BT) {
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
    throws(() => hexToBytes(1 as any), TypeError);
    throws(() => hexToBytes('a'), RangeError);
    throws(() => hexToBytes('gg'), RangeError);
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
    eql(concatBytes(), Uint8Array.of());
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

    const emptyInside = new Uint8Array(buffer, 6, 0);
    eql(overlapBytes(main2, emptyInside), false);
    eql(overlapBytes(emptyInside, main2), false);
  });
  should('bytesToUtf8', () => {
    eql(bytesToUtf8(new Uint8Array([97, 98, 99])), 'abc');
  });
  should('hexToNumber', () => {
    eql(u.hexToNumber(''), 0n);
    eql(u.hexToNumber('ff'), 255n);
    throws(() => u.hexToNumber(1 as any), TypeError);
  });
  should('numberToBytesBE', () => {
    eql(u.numberToBytesBE(1, 2), Uint8Array.of(0, 1));
    throws(() => u.numberToBytesBE('1' as any, 2), TypeError);
    throws(() => u.numberToBytesBE(true as any, 2), TypeError);
    throws(() => u.numberToBytesBE(1, '2' as any), TypeError);
  });
  should('utf8ToBytes', () => {
    eql(u.utf8ToBytes('abc'), new Uint8Array([97, 98, 99]));
    throws(() => u.utf8ToBytes(1 as any), TypeError);
  });
  should('getOutput', () => {
    eql(getOutput(32), new Uint8Array(32));
    throws(() => getOutput(32, new Uint8Array(31)));
    throws(() => getOutput(32, new Uint8Array(33)));
    const t = new Uint8Array(33).subarray(1);
    throws(() => getOutput(32, t));
    eql(getOutput(32, t, false), new Uint8Array(32));
    if (typeof Buffer !== 'undefined') {
      const out = Buffer.alloc(32);
      eql(getOutput(32, out as any, false), out);
    }
    throws(() => getOutput(32, { length: 32, byteOffset: 0 } as any, false), TypeError);
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
    throws(() => u64Lengths('10' as any, 0, true), TypeError);
    throws(() => u64Lengths(10, '7' as any, true), TypeError);
  });
});

describe('assert', () => {
  should('abool', () => {
    eql(u.abool(true), undefined);
    throws(() => u.abool('1' as any), TypeError);
    throws(() => u.abool(1 as any), TypeError);
  });
  should('anumber', () => {
    eql(u.anumber(10), undefined);
    throws(() => u.anumber(1.2), RangeError);
    throws(() => u.anumber('1' as any), TypeError);
    throws(() => u.anumber(true as any), TypeError);
    throws(() => u.anumber(NaN), RangeError);
  });
  should('abytes', () => {
    eql(u.abytes(new Uint8Array(0)), new Uint8Array(0));
    if (typeof Buffer !== 'undefined') eql(u.abytes(Buffer.alloc(10)), Buffer.alloc(10));
    eql(u.abytes(new Uint8Array(10)), new Uint8Array(10));
    u.abytes(new Uint8Array(11), 11, '11');
    u.abytes(new Uint8Array(12), 12, '12');
    throws(() => u.abytes('test' as any), TypeError);
    throws(() => u.abytes(new Uint8Array(10), 11, '11'), RangeError);
    throws(() => u.abytes(new Uint8Array(10), 12, '12'), RangeError);
  });
  should('aexists', () => {
    eql(u.aexists({}), undefined);
    throws(() => u.aexists({ destroyed: true }));
  });
  should('aoutput', () => {
    eql(u.aoutput(new Uint8Array(10), { outputLen: 5 }), undefined);
    throws(() => u.aoutput(new Uint8Array(1), { outputLen: 5 }), RangeError);
  });
});

describe('utils etc', () => {
  should('wrapMacConstructor', () => {
    class Hash16 {
      blockLen = 7;
      outputLen = 3;
      finished = false;
      destroyed = false;

      constructor(key: Uint8Array) {
        if (key.length !== 16) throw new Error(`expected 16-byte key, got ${key.length}`);
      }
      update(_msg: Uint8Array): this {
        return this;
      }
      digestInto(out: Uint8Array): void {
        out.set([1, 2, 3]);
      }
      digest(): Uint8Array {
        return Uint8Array.from([1, 2, 3]);
      }
      destroy(): void {
        this.destroyed = true;
      }
    }

    const hash = u.wrapMacConstructor(16, (key) => new Hash16(key));
    eql(hash.outputLen, 3);
    eql(hash.blockLen, 7);
    eql(Array.from(hash(new Uint8Array([9]), new Uint8Array(16))), [1, 2, 3]);
  });
  should('complexOverlapBytes', () => {
    const buffer = new Uint8Array(10);
    const input = buffer.subarray(0, 4);
    const output = buffer.subarray(2, 2);
    u.complexOverlapBytes(input, output);
  });
  should('copyBytes', () => {
    const out = u.copyBytes(Uint8Array.of(1, 2, 3));
    eql(out, Uint8Array.of(1, 2, 3));
    if (typeof Buffer !== 'undefined') {
      const src = Buffer.from([1, 2, 3]);
      const copy = u.copyBytes(src as any);
      eql(copy, Uint8Array.of(1, 2, 3));
      copy[0] = 9;
      eql(src, Buffer.from([1, 2, 3]));
    }
    throws(() => u.copyBytes('ab' as any), TypeError);
  });
  should('randomBytes', () => {
    eql(u.randomBytes(0).length, 0);
    throws(() => u.randomBytes(1.5 as any), RangeError);
    throws(() => u.randomBytes('2' as any), TypeError);
    throws(() => u.randomBytes(true as any), TypeError);
  });
  should('managedNonce does not wipe plaintext when wrapped encrypt aliases it', () => {
    const fn = ((_: Uint8Array, __: Uint8Array) => ({
      encrypt(plaintext: Uint8Array) {
        return plaintext;
      },
      decrypt(ciphertext: Uint8Array) {
        return ciphertext;
      },
    })) as any;
    fn.nonceLength = 2;
    const wrapped = u.managedNonce(fn, () => Uint8Array.of(9, 8));
    const key = Uint8Array.of(1, 2, 3, 4);
    const plaintext = Uint8Array.of(1, 2, 3);
    eql(wrapped(key).encrypt(plaintext), Uint8Array.of(9, 8, 1, 2, 3));
    eql(plaintext, Uint8Array.of(1, 2, 3));
  });
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
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
should.runWhen(import.meta.url);
