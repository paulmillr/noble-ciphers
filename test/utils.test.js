const { deepStrictEqual, throws } = require('assert');
const { describe, should } = require('micro-should');
const utils = require('./utils.js');

// Here goes test for tests...
describe('Tests', () => {
  should('Unalign', () => {
    const arr = new Uint8Array([1, 2, 3]);
    for (let i = 0; i < 16; i++) {
      const tmp = utils.unalign(arr, i);
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
